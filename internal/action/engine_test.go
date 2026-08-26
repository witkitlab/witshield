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
	verifyError            error
	applyError             error
	applyErrorWithoutState bool
	invalidApplyState      bool
	rollbackError          error
	confirmError           error
	calls                  []Operation
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
	state := json.RawMessage(`{"secretSnapshot":"do-not-audit"}`)
	if p.applyErrorWithoutState {
		state = nil
	} else if p.invalidApplyState {
		state = json.RawMessage(`null`)
	}
	return ApplyResult{Result: p.step(OperationApply), State: state}, p.applyError
}
func (p *lifecyclePlaybook) Verify(context.Context, Invocation) (Result, error) {
	result := p.step(OperationVerify)
	return result, p.verifyError
}
func (p *lifecyclePlaybook) Rollback(context.Context, Invocation) (Result, error) {
	return p.step(OperationRollback), p.rollbackError
}
func (p *lifecyclePlaybook) Confirm(context.Context, Invocation) (Result, error) {
	return p.step(OperationConfirm), p.confirmError
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
	if len(receipt.State) != 0 || receipt.RollbackStateDigest != "" || receipt.ConfirmBy != nil {
		t.Fatalf("successful automatic rollback leaked replayable recovery state: %#v", receipt)
	}
	if receipt.FinishedAt.IsZero() || receipt.Digest == "" {
		t.Fatal("failed receipt was not finalized")
	}
}

func TestEngineApplyFailureUsesMutationBoundaryState(t *testing.T) {
	tests := []struct {
		name              string
		playbook          *lifecyclePlaybook
		wantIndeterminate bool
		wantState         bool
		wantSteps         int
	}{
		{
			name:      "automatic rollback proves recovery",
			playbook:  &lifecyclePlaybook{applyError: errors.New("partial apply")},
			wantSteps: 4,
		},
		{
			name:              "failed automatic rollback preserves recovery state",
			playbook:          &lifecyclePlaybook{applyError: errors.New("partial apply"), rollbackError: errors.New("restore failed")},
			wantIndeterminate: true, wantState: true, wantSteps: 4,
		},
		{
			name:      "pre-mutation failure remains a known failure",
			playbook:  &lifecyclePlaybook{applyError: errors.New("pre-mutation failure"), applyErrorWithoutState: true},
			wantSteps: 3,
		},
		{
			name:              "unusable state after reported mutation is unknown",
			playbook:          &lifecyclePlaybook{invalidApplyState: true},
			wantIndeterminate: true, wantSteps: 3,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			engine, _ := NewEngine(test.playbook)
			receipt := engine.Run(context.Background(), Request{
				ActionID: "apply-boundary", Actor: "tester", Type: test.playbook.Type(),
				Operation: OperationExecute, Parameters: json.RawMessage(`{"safe":true}`),
			})
			if receipt.Success || receipt.Indeterminate != test.wantIndeterminate || (len(receipt.State) > 0) != test.wantState || len(receipt.Steps) != test.wantSteps {
				t.Fatalf("receipt=%#v", receipt)
			}
			if test.wantState && receipt.RollbackStateDigest != digestBytes(receipt.State) {
				t.Fatal("indeterminate apply did not bind its recovery state")
			}
			if !test.wantState && receipt.RollbackStateDigest != "" {
				t.Fatalf("terminal receipt retained stale state digest %q", receipt.RollbackStateDigest)
			}
		})
	}
}

func TestEngineDirectApplyFailureUsesTheSameAutomaticRecovery(t *testing.T) {
	playbook := &lifecyclePlaybook{applyError: errors.New("partial direct apply"), rollbackError: errors.New("direct restore failed")}
	engine, _ := NewEngine(playbook)
	receipt := engine.Run(context.Background(), Request{
		ActionID: "direct-apply-boundary", Actor: "tester", Type: playbook.Type(),
		Operation: OperationApply, Parameters: json.RawMessage(`{"safe":true}`),
	})
	if receipt.Success || !receipt.Indeterminate || len(receipt.State) == 0 || len(receipt.Steps) != 2 || receipt.Steps[0].Operation != OperationApply || receipt.Steps[1].Operation != OperationRollback {
		t.Fatalf("direct apply did not use compensated failure semantics: %#v", receipt)
	}
}

func TestEngineRejectsInjectedStateOnApplyBeforeCallingPlaybook(t *testing.T) {
	playbook := &lifecyclePlaybook{applyError: errors.New("pre-mutation failure"), applyErrorWithoutState: true}
	engine, _ := NewEngine(playbook)
	receipt := engine.Run(context.Background(), Request{
		ActionID: "injected-apply-state", Actor: "tester", Type: playbook.Type(),
		Operation: OperationApply, Parameters: json.RawMessage(`{"safe":true}`), State: json.RawMessage(`{"attacker":"chosen"}`),
	})
	if receipt.Success || !strings.Contains(receipt.Error, "rollback state is not accepted") || len(receipt.Steps) != 0 || len(playbook.calls) != 0 {
		t.Fatalf("caller-controlled apply state reached the playbook: receipt=%#v calls=%v", receipt, playbook.calls)
	}
}

func TestEngineTypedRollbackFailureIsIndeterminate(t *testing.T) {
	playbook := &lifecyclePlaybook{}
	engine, _ := NewEngine(playbook)
	parameters := json.RawMessage(`{"safe":true}`)
	apply := engine.Run(context.Background(), Request{
		ActionID: "rollback-boundary", Actor: "tester", Type: playbook.Type(),
		Operation: OperationApply, Parameters: parameters,
	})
	if !apply.Success {
		t.Fatal(apply.Error)
	}
	playbook.rollbackError = errors.New("restore response lost")
	receipt := engine.Run(context.Background(), Request{
		ActionID: "rollback-boundary", Actor: "tester", Type: playbook.Type(),
		Operation: OperationRollback, Parameters: parameters, State: apply.State,
	})
	if receipt.Success || !receipt.Indeterminate || len(receipt.Steps) != 1 || receipt.Steps[0].Operation != OperationRollback || receipt.Steps[0].Success {
		t.Fatalf("rollback error was not kept unknown: %#v", receipt)
	}
}

func TestEngineTypedConfirmFailureIsIndeterminate(t *testing.T) {
	playbook := &lifecyclePlaybook{}
	engine, _ := NewEngine(playbook)
	parameters := json.RawMessage(`{"safe":true}`)
	apply := engine.Run(context.Background(), Request{
		ActionID: "confirm-boundary", Actor: "tester", Type: playbook.Type(),
		Operation: OperationApply, Parameters: parameters,
	})
	if !apply.Success {
		t.Fatal(apply.Error)
	}
	playbook.confirmError = errors.New("confirmation response lost")
	receipt := engine.Run(context.Background(), Request{
		ActionID: "confirm-boundary", Actor: "tester", Type: playbook.Type(),
		Operation: OperationConfirm, Parameters: parameters, State: apply.State,
	})
	if receipt.Success || !receipt.Indeterminate || len(receipt.Steps) != 1 || receipt.Steps[0].Operation != OperationConfirm || receipt.Steps[0].Success {
		t.Fatalf("confirmation error was not kept unknown: %#v", receipt)
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
