package action

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type lifecyclePlaybook struct {
	verifyError error
	calls       []Operation
}

func (p *lifecyclePlaybook) Type() Type { return "test_action" }
func (p *lifecyclePlaybook) Validate(raw json.RawMessage) error {
	value, err := decodeStrict[struct {
		Safe bool `json:"safe"`
	}](raw)
	if err != nil || !value.Safe {
		return errors.New("bad parameters")
	}
	return nil
}
func (p *lifecyclePlaybook) step(operation Operation) Result {
	p.calls = append(p.calls, operation)
	return Result{Summary: string(operation)}
}
func (p *lifecyclePlaybook) Precheck(context.Context, Invocation) (Result, error) {
	return p.step(OperationPrecheck), nil
}
func (p *lifecyclePlaybook) Preview(context.Context, Invocation) (Result, error) {
	return p.step(OperationPreview), nil
}
func (p *lifecyclePlaybook) Apply(context.Context, Invocation) (ApplyResult, error) {
	return ApplyResult{Result: p.step(OperationApply), State: json.RawMessage(`{"secretSnapshot":"do-not-audit"}`)}, nil
}
func (p *lifecyclePlaybook) Verify(context.Context, Invocation) (Result, error) {
	result := p.step(OperationVerify)
	return result, p.verifyError
}
func (p *lifecyclePlaybook) Rollback(context.Context, Invocation) (Result, error) {
	return p.step(OperationRollback), nil
}

func TestEngineReceiptIsFinalizedAndOmitsRollbackStateFromAuditJSON(t *testing.T) {
	playbook := &lifecyclePlaybook{}
	engine, err := NewEngine(playbook)
	if err != nil {
		t.Fatal(err)
	}
	receipt := engine.Run(context.Background(), Request{
		ActionID: "action-1", Actor: "tester", Type: playbook.Type(),
		Operation: OperationExecute, Parameters: json.RawMessage(`{"safe":true}`),
	})
	if !receipt.Success {
		t.Fatalf("execute failed: %s", receipt.Error)
	}
	if receipt.FinishedAt.IsZero() || receipt.FinishedAt.Before(receipt.StartedAt) {
		t.Fatalf("receipt was not finalized: %#v", receipt)
	}
	if !strings.HasPrefix(receipt.Digest, "sha256:") || len(receipt.Digest) != len("sha256:")+64 {
		t.Fatalf("missing receipt digest: %q", receipt.Digest)
	}
	if len(receipt.State) == 0 {
		t.Fatal("rollback state not returned programmatically")
	}
	if receipt.RollbackStateDigest != digestBytes(receipt.State) {
		t.Fatal("audit receipt does not bind the returned rollback payload")
	}
	encoded, err := json.Marshal(receipt)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "secretSnapshot") || strings.Contains(string(encoded), "do-not-audit") {
		t.Fatalf("rollback snapshot leaked into audit JSON: %s", encoded)
	}
	wantCalls := []Operation{OperationPrecheck, OperationPreview, OperationApply, OperationVerify}
	if fmt.Sprint(playbook.calls) != fmt.Sprint(wantCalls) {
		t.Fatalf("calls = %v, want %v", playbook.calls, wantCalls)
	}
}

func TestEngineRollsBackWhenVerificationFails(t *testing.T) {
	playbook := &lifecyclePlaybook{verifyError: errors.New("verification detail that is safe")}
	engine, _ := NewEngine(playbook)
	receipt := engine.Run(context.Background(), Request{
		ActionID: "action-2", Actor: "tester", Type: playbook.Type(),
		Operation: OperationExecute, Parameters: json.RawMessage(`{"safe":true}`),
	})
	if receipt.Success {
		t.Fatal("verification failure unexpectedly succeeded")
	}
	if len(receipt.Steps) != 5 || receipt.Steps[4].Operation != OperationRollback || !receipt.Steps[4].Success {
		t.Fatalf("automatic rollback step missing: %#v", receipt.Steps)
	}
	if receipt.FinishedAt.IsZero() || receipt.Digest == "" {
		t.Fatal("failed receipt was not finalized")
	}
}

func TestEngineRejectsUnknownActionWithoutFallback(t *testing.T) {
	engine, _ := NewEngine(&lifecyclePlaybook{})
	receipt := engine.Run(context.Background(), Request{
		ActionID: "action-3", Actor: "tester", Type: "run_shell",
		Operation: OperationExecute, Parameters: json.RawMessage(`{}`),
	})
	if receipt.Success || receipt.Error != ErrUnsupportedAction.Error() {
		t.Fatalf("unknown action was not rejected exactly: %#v", receipt)
	}
}

func TestEngineRejectsTamperedOrCrossActionRollbackState(t *testing.T) {
	key := []byte(strings.Repeat("k", 32))
	playbook := &lifecyclePlaybook{}
	engine, err := NewEngineWithStateKey(key, playbook)
	if err != nil {
		t.Fatal(err)
	}
	parameters := json.RawMessage(`{"safe":true}`)
	apply := engine.Run(context.Background(), Request{
		ActionID: "signed-action", Actor: "tester", Type: playbook.Type(),
		Operation: OperationApply, Parameters: parameters,
	})
	if !apply.Success {
		t.Fatal(apply.Error)
	}
	var sealed sealedRollbackState
	if err := json.Unmarshal(apply.State, &sealed); err != nil {
		t.Fatal(err)
	}
	sealed.Payload = json.RawMessage(`{"mode":511,"uid":0}`)
	tampered, _ := json.Marshal(sealed)
	receipt := engine.Run(context.Background(), Request{
		ActionID: "signed-action", Actor: "tester", Type: playbook.Type(),
		Operation: OperationRollback, Parameters: parameters, State: tampered,
	})
	if receipt.Success || !strings.Contains(receipt.Error, "signature") {
		t.Fatalf("tampered rollback state was not rejected: %#v", receipt)
	}
	crossAction := engine.Run(context.Background(), Request{
		ActionID: "different-action", Actor: "tester", Type: playbook.Type(),
		Operation: OperationRollback, Parameters: parameters, State: apply.State,
	})
	if crossAction.Success || !strings.Contains(crossAction.Error, "does not match") {
		t.Fatalf("cross-action rollback state was not rejected: %#v", crossAction)
	}
}

func TestRollbackStateSurvivesEngineRestartWithPersistentKey(t *testing.T) {
	key := []byte(strings.Repeat("p", 32))
	firstPlaybook := &lifecyclePlaybook{}
	first, _ := NewEngineWithStateKey(key, firstPlaybook)
	parameters := json.RawMessage(`{"safe":true}`)
	apply := first.Run(context.Background(), Request{
		ActionID: "restart-action", Actor: "tester", Type: firstPlaybook.Type(),
		Operation: OperationApply, Parameters: parameters,
	})
	secondPlaybook := &lifecyclePlaybook{}
	second, _ := NewEngineWithStateKey(key, secondPlaybook)
	rollback := second.Run(context.Background(), Request{
		ActionID: "restart-action", Actor: "tester", Type: secondPlaybook.Type(),
		Operation: OperationRollback,
		// Reordered/whitespace-different JSON remains semantically identical.
		Parameters: json.RawMessage("{ \"safe\" : true }"), State: apply.State,
	})
	if !rollback.Success {
		t.Fatalf("persistent signed rollback failed after restart: %s", rollback.Error)
	}
	if len(secondPlaybook.calls) != 1 || secondPlaybook.calls[0] != OperationRollback {
		t.Fatalf("rollback playbook not called: %v", secondPlaybook.calls)
	}
}

func TestNewEngineWithStateKeyRejectsWeakKey(t *testing.T) {
	if _, err := NewEngineWithStateKey([]byte("weak"), &lifecyclePlaybook{}); err == nil {
		t.Fatal("weak rollback-state key was accepted")
	}
}

func TestExecRunnerCapsCapturedOutput(t *testing.T) {
	executable, err := filepath.Abs(os.Args[0])
	if err != nil {
		t.Fatal(err)
	}
	runner := NewExecRunner(executable)
	runner.MaxOutputBytes = 64
	result, err := runner.Run(context.Background(), Command{
		Path:    executable,
		Args:    []string{"-test.run=TestExecRunnerOutputChild", "--", "emit-output"},
		Timeout: 10 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !result.OutputTruncated {
		t.Fatal("large child output was not marked truncated")
	}
	if len(result.Stdout) > 64 || len(result.Stderr) > 64 {
		t.Fatalf("captured output exceeded limit: stdout=%d stderr=%d", len(result.Stdout), len(result.Stderr))
	}
}

func TestExecRunnerOutputChild(t *testing.T) {
	for _, argument := range os.Args {
		if argument == "emit-output" {
			_, _ = os.Stdout.WriteString(strings.Repeat("o", 4096))
			_, _ = os.Stderr.WriteString(strings.Repeat("e", 4096))
			return
		}
		if argument == "print-secret-environment" {
			_, _ = os.Stdout.WriteString(os.Getenv("WITSHIELD_TEST_SECRET"))
			return
		}
		if argument == "emit-secret-failure" {
			_, _ = os.Stderr.WriteString("raw-secret-stderr")
			os.Exit(7)
		}
		if argument == "sleep-until-killed" {
			time.Sleep(30 * time.Second)
			return
		}
	}
}

func TestExecRunnerRejectsNonAllowlistedPath(t *testing.T) {
	runner := NewExecRunner("/approved/command")
	_, err := runner.Run(context.Background(), Command{Path: "/bin/sh", Args: []string{"-c", "true"}})
	if err == nil || !strings.Contains(err.Error(), "not allowlisted") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestExecRunnerSanitizesEnvironmentAndErrorText(t *testing.T) {
	executable, err := filepath.Abs(os.Args[0])
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("WITSHIELD_TEST_SECRET", "must-not-reach-root-child")
	runner := NewExecRunner(executable)
	result, err := runner.Run(context.Background(), Command{
		Path: executable, Args: []string{"-test.run=TestExecRunnerOutputChild", "--", "print-secret-environment"}, Timeout: 10 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(result.Stdout, "must-not-reach-root-child") {
		t.Fatal("helper process environment leaked into a root child")
	}
	result, err = runner.Run(context.Background(), Command{
		Path: executable, Args: []string{"-test.run=TestExecRunnerOutputChild", "--", "emit-secret-failure"}, Timeout: 10 * time.Second,
	})
	if err == nil {
		t.Fatal("failing child unexpectedly succeeded")
	}
	if strings.Contains(err.Error(), "raw-secret-stderr") {
		t.Fatalf("raw stderr leaked into execution error: %v", err)
	}
	if !strings.Contains(result.Stderr, "raw-secret-stderr") {
		t.Fatal("test child did not produce the expected private stderr")
	}
}

func TestExecRunnerEnforcesTimeout(t *testing.T) {
	executable, err := filepath.Abs(os.Args[0])
	if err != nil {
		t.Fatal(err)
	}
	runner := NewExecRunner(executable)
	started := time.Now()
	_, err = runner.Run(context.Background(), Command{
		Path: executable, Args: []string{"-test.run=TestExecRunnerOutputChild", "--", "sleep-until-killed"}, Timeout: 50 * time.Millisecond,
	})
	if err == nil || !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("timeout was not enforced: %v", err)
	}
	if time.Since(started) > 3*time.Second {
		t.Fatalf("timed-out command took too long to terminate: %s", time.Since(started))
	}
}
