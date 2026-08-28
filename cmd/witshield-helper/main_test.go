package main

import (
	"bufio"
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/witkitlab/witshield/internal/action"
	"github.com/witkitlab/witshield/internal/observation"
)

type helperTestPlaybook struct{}

func (helperTestPlaybook) Type() action.Type              { return "helper_test" }
func (helperTestPlaybook) Validate(json.RawMessage) error { return nil }
func (helperTestPlaybook) Precheck(context.Context, action.Invocation) (action.Result, error) {
	return action.Result{Summary: "checked"}, nil
}
func (helperTestPlaybook) Preview(context.Context, action.Invocation) (action.Result, error) {
	return action.Result{Summary: "previewed"}, nil
}
func (helperTestPlaybook) Apply(context.Context, action.Invocation) (action.ApplyResult, error) {
	return action.ApplyResult{Result: action.Result{Summary: "applied"}, State: json.RawMessage(`{"snapshot":"sensitive-rollback-material"}`)}, nil
}
func (helperTestPlaybook) Verify(context.Context, action.Invocation) (action.Result, error) {
	return action.Result{Summary: "verified"}, nil
}
func (helperTestPlaybook) Rollback(context.Context, action.Invocation) (action.Result, error) {
	return action.Result{Summary: "rolled back"}, nil
}

func TestLoadOrCreateTokenCreatesAndValidatesStrongPrivateToken(t *testing.T) {
	path := filepath.Join(t.TempDir(), "auth", "helper.token")
	created, err := loadOrCreateToken(path, -1)
	if err != nil {
		t.Fatal(err)
	}
	if len(created) != 64 {
		t.Fatalf("token length = %d, want 64 hex bytes", len(created))
	}
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 || !info.Mode().IsRegular() {
		t.Fatalf("token mode/type is unsafe: %v", info.Mode())
	}
	loaded, err := loadOrCreateToken(path, -1)
	if err != nil {
		t.Fatal(err)
	}
	if string(loaded) != string(created) {
		t.Fatal("existing token changed")
	}
	fileToken, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	fileToken = []byte(strings.TrimSuffix(string(fileToken), "\n"))
	if len(loaded) != 64 || !tokenMatches(string(fileToken), loaded) {
		t.Fatalf("token stopped authenticating after reload: created=%d loaded=%d file=%d", len(created), len(loaded), len(fileToken))
	}
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := loadOrCreateToken(path, -1); err == nil {
		t.Fatal("world-readable token was accepted")
	}
}

func TestLoadOrCreateTokenRejectsWeakAndSymlinkTokens(t *testing.T) {
	root := t.TempDir()
	weak := filepath.Join(root, "weak.token")
	if err := os.WriteFile(weak, []byte("short\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadOrCreateToken(weak, -1); err == nil {
		t.Fatal("weak token was accepted")
	}
	real := filepath.Join(root, "real.token")
	if err := os.WriteFile(real, []byte(strings.Repeat("a", 64)), 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link.token")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	if _, err := loadOrCreateToken(link, -1); err == nil {
		t.Fatal("symlink token was accepted")
	}
}

func TestTokenMatchesRequiresExactStrongToken(t *testing.T) {
	expected := []byte(strings.Repeat("c", 64))
	if !tokenMatches(string(expected), expected) {
		t.Fatal("exact token did not authenticate")
	}
	if tokenMatches(strings.Repeat("d", 64), expected) || tokenMatches("short", expected) {
		t.Fatal("incorrect token authenticated")
	}
}

func TestHelperProtocolReturnsRollbackPayloadSeparatelyFromAudit(t *testing.T) {
	engine, err := action.NewEngine(helperTestPlaybook{})
	if err != nil {
		t.Fatal(err)
	}
	root, err := os.MkdirTemp("/tmp", "witshield-helper-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	socketPath := filepath.Join(root, "helper.sock")
	listener, err := listenUnix(socketPath, -1)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	token := []byte(strings.Repeat("b", 64))
	helper := &server{engine: engine, token: token}
	done := make(chan struct{})
	go func() {
		defer close(done)
		connection, acceptErr := listener.AcceptUnix()
		if acceptErr == nil {
			helper.handle(context.Background(), connection)
		}
	}()
	client, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: socketPath, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	request := helperRequest{
		Token: string(token), AttemptID: "helper-command", ActionID: "helper-action", Type: "helper_test",
		Parameters: json.RawMessage(`{}`),
	}
	encoded, _ := json.Marshal(request)
	if _, err := client.Write(append(encoded, '\n')); err != nil {
		t.Fatal(err)
	}
	line, err := bufio.NewReader(client).ReadBytes('\n')
	client.Close()
	if err != nil {
		t.Fatal(err)
	}
	<-done
	var response helperResponse
	if err := json.Unmarshal(line, &response); err != nil {
		t.Fatal(err)
	}
	if !response.OK || response.AuditReceipt == nil || len(response.RollbackPayload) == 0 {
		t.Fatalf("unexpected helper response: %s", line)
	}
	if response.AuditReceipt.Actor == "tester" || !strings.HasPrefix(response.AuditReceipt.Actor, "local-") {
		t.Fatalf("audit actor was not derived locally: %q", response.AuditReceipt.Actor)
	}
	if !strings.Contains(string(response.RollbackPayload), "sensitive-rollback-material") {
		t.Fatalf("rollback payload missing: %s", response.RollbackPayload)
	}
	auditJSON, _ := json.Marshal(response.AuditReceipt)
	if strings.Contains(string(auditJSON), "sensitive-rollback-material") || strings.Contains(string(auditJSON), "snapshot") {
		t.Fatalf("rollback material leaked into audit receipt: %s", auditJSON)
	}
}

func TestHelperProtocolServesFixedReadOnlyProcessObservation(t *testing.T) {
	root, err := os.MkdirTemp("/tmp", "witshield-helper-observation-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	socketPath := filepath.Join(root, "helper.sock")
	listener, err := listenUnix(socketPath, -1)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	token := []byte(strings.Repeat("e", 64))
	called := 0
	helper := &server{token: token, observeProcesses: func(context.Context) (observation.ProcessSnapshot, error) {
		called++
		return observation.ProcessSnapshot{Processes: []observation.Process{{Identity: strings.Repeat("f", 64), EventType: "deleted_executable_process_running", Reason: "deleted", Name: "daemon", Executable: "/usr/bin/daemon (deleted)", PID: 42, PPID: 1, UID: 0}}, Observed: 1}, nil
	}}
	done := make(chan struct{})
	go func() {
		defer close(done)
		connection, acceptErr := listener.AcceptUnix()
		if acceptErr == nil {
			helper.handle(context.Background(), connection)
		}
	}()
	client, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: socketPath, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	request, _ := json.Marshal(map[string]any{"token": string(token), "kind": observation.ProcessQueryKind})
	if _, err = client.Write(append(request, '\n')); err != nil {
		t.Fatal(err)
	}
	line, err := bufio.NewReader(client).ReadBytes('\n')
	client.Close()
	if err != nil {
		t.Fatal(err)
	}
	<-done
	var response helperResponse
	if err = json.Unmarshal(line, &response); err != nil || !response.OK || len(response.Processes) != 1 || response.ProcessObserved != 1 || called != 1 {
		t.Fatalf("response=%s called=%d err=%v", line, called, err)
	}
}

func TestListenUnixRefusesToReplaceRegularFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "helper.sock")
	if err := os.WriteFile(path, []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	listener, err := listenUnix(path, -1)
	if listener != nil {
		listener.Close()
	}
	if err == nil {
		t.Fatal("regular file at socket path was replaced")
	}
	content, readErr := os.ReadFile(path)
	if readErr != nil || string(content) != "keep" {
		t.Fatalf("regular file was damaged: content=%q err=%v", content, readErr)
	}
}

func TestParseProtectedInputsRejectsInvalidValues(t *testing.T) {
	if _, err := parseProtectedPrefixes([]string{"not-a-prefix"}); err == nil {
		t.Fatal("invalid prefix accepted")
	}
	if _, err := parseAddresses([]string{"not-an-ip"}); err == nil {
		t.Fatal("invalid administrator IP accepted")
	}
}

func TestEnsureJSONEOF(t *testing.T) {
	decoder := json.NewDecoder(strings.NewReader(`{} {}`))
	var first any
	if err := decoder.Decode(&first); err != nil {
		t.Fatal(err)
	}
	if err := ensureJSONEOF(decoder); err == nil || !strings.Contains(err.Error(), "multiple") {
		t.Fatalf("multiple JSON values not rejected: %v", err)
	}
}

func TestHelperRequestDoesNotAcceptClientSuppliedActor(t *testing.T) {
	decoder := json.NewDecoder(strings.NewReader(`{"actionId":"a","type":"helper_test","parameters":{},"actor":"forged-admin"}`))
	decoder.DisallowUnknownFields()
	var request helperRequest
	if err := decoder.Decode(&request); err == nil {
		t.Fatal("client-supplied audit actor was accepted")
	}
}
