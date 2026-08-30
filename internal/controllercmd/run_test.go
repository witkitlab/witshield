package controllercmd

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/user"
	"path/filepath"
	"testing"
	"time"

	"github.com/witkitlab/witshield/internal/store"
)

func TestSeedEnrollmentConsumesControllerTokenCopy(t *testing.T) {
	dir := t.TempDir()
	db, err := store.Open(context.Background(), filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	path := filepath.Join(dir, "initial-enrollment.token")
	if err = os.WriteFile(path, []byte("0123456789abcdef0123456789abcdef\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err = seedEnrollment(context.Background(), db, path); err != nil {
		t.Fatal(err)
	}
	if _, err = os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("controller token copy still exists: %v", err)
	}
	items, err := db.ListEnrollmentTokens(context.Background())
	if err != nil || len(items) != 1 || items[0].MaxUses != 1 {
		t.Fatalf("tokens=%v err=%v", items, err)
	}
}

func TestLoopbackListenAddress(t *testing.T) {
	tests := map[string]bool{
		"127.0.0.1:8080":  true,
		"127.42.0.1:8080": true,
		"[::1]:8080":      true,
		"localhost:8080":  true,
		"LOCALHOST.:8080": true,
		"0.0.0.0:8080":    false,
		":8080":           false,
		"10.0.0.2:8080":   false,
		"invalid":         false,
	}
	for address, want := range tests {
		if got := loopbackListenAddress(address); got != want {
			t.Errorf("loopbackListenAddress(%q)=%v want=%v", address, got, want)
		}
	}
}

func TestIsolatedLocalListenAddress(t *testing.T) {
	tests := map[string]bool{
		"admin-listener:8081": true,
		"127.0.0.1:8081":      true,
		"[::1]:8081":          true,
		"0.0.0.0:8081":        false,
		"[::]:8081":           false,
		":8081":               false,
		"admin-listener":      false,
	}
	for address, want := range tests {
		if got := isolatedLocalListenAddress(address); got != want {
			t.Errorf("isolatedLocalListenAddress(%q)=%v want=%v", address, got, want)
		}
	}
}

func TestControllerWriteTimeoutCoversBoundedAIInvestigation(t *testing.T) {
	server := controllerHTTPServer("127.0.0.1:0", http.NotFoundHandler())
	if server.WriteTimeout < 90*time.Second || server.WriteTimeout > 2*time.Minute {
		t.Fatalf("controller write timeout does not cover the bounded investigation window: %s", server.WriteTimeout)
	}
	if server.ReadHeaderTimeout <= 0 || server.ReadTimeout <= 0 || server.MaxHeaderBytes > 32<<10 {
		t.Fatalf("HTTP input bounds were weakened: %#v", server)
	}
}

func TestNativeAgentUnixListenerAndRouteBoundary(t *testing.T) {
	dir, err := os.MkdirTemp("/tmp", "witshield-controller-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	current, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	group, err := user.LookupGroupId(current.Gid)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "agent.sock")
	listener, err := listenAgentUnix(path, group.Name)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSocket == 0 || info.Mode().Perm() != 0660 {
		t.Fatalf("socket info=%v err=%v", info, err)
	}
	handler := agentOnlyHandler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	server := &http.Server{Handler: handler}
	go server.Serve(listener)
	defer server.Close()
	client := &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", path)
	}}}
	for route, want := range map[string]int{"/agent/v1/sync": http.StatusNoContent, "/healthz": http.StatusNoContent, "/api/v1/system/health": http.StatusNotFound} {
		response, requestErr := client.Get("http://witshield-controller" + route)
		if requestErr != nil {
			t.Fatal(requestErr)
		}
		response.Body.Close()
		if response.StatusCode != want {
			t.Fatalf("route %s status=%d want=%d", route, response.StatusCode, want)
		}
	}
}

func TestUpgradeGateBlocksWritesButKeepsReadinessVisible(t *testing.T) {
	gate := filepath.Join(t.TempDir(), "upgrade.gate")
	if err := os.WriteFile(gate, []byte("upgrade\n"), 0600); err != nil {
		t.Fatal(err)
	}
	called := 0
	handler := upgradeGateHandler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called++
		w.WriteHeader(http.StatusNoContent)
	}), gate)
	for path, want := range map[string]int{"/api/v1/actions": http.StatusServiceUnavailable, "/agent/v1/sync": http.StatusServiceUnavailable, "/readyz": http.StatusNoContent} {
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, path, nil))
		if recorder.Code != want {
			t.Fatalf("path=%s status=%d want=%d", path, recorder.Code, want)
		}
	}
	if called != 1 {
		t.Fatalf("downstream calls=%d want=1", called)
	}
	if err := os.Remove(gate); err != nil {
		t.Fatal(err)
	}
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/api/v1/actions", nil))
	if recorder.Code != http.StatusNoContent || called != 2 {
		t.Fatalf("ungated status=%d calls=%d", recorder.Code, called)
	}
}
