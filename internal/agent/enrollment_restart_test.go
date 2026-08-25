package agent_test

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/witkitlab/witshield/internal/agent"
	"github.com/witkitlab/witshield/internal/domain"
	"github.com/witkitlab/witshield/internal/httpapi"
	"github.com/witkitlab/witshield/internal/secret"
	"github.com/witkitlab/witshield/internal/store"
)

func TestAgentRestartAfterLostEnrollmentResponseReusesPendingIdentity(t *testing.T) {
	ctx := context.Background()
	db, err := store.Open(ctx, filepath.Join(t.TempDir(), "controller.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	rawToken := "wse_test_lost_response_012345678901234567890123456789"
	now := time.Now().UTC()
	expires := now.Add(time.Hour)
	if err = db.CreateEnrollmentToken(ctx, domain.EnrollmentToken{ID: "enr_lost_response", Name: "lost", Hint: "hidden", MaxUses: 1, ExpiresAt: &expires, CreatedAt: now}, secret.Hash(rawToken)); err != nil {
		t.Fatal(err)
	}
	vault, err := secret.New(bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	webDir := t.TempDir()
	if err = os.WriteFile(filepath.Join(webDir, "index.html"), []byte("test"), 0o600); err != nil {
		t.Fatal(err)
	}
	api, err := httpapi.New(httpapi.Config{Store: db, Vault: vault, WebDir: webDir})
	if err != nil {
		t.Fatal(err)
	}
	backend := httptest.NewServer(api.Handler())
	t.Cleanup(backend.Close)
	var dropFirstFinalResponse atomic.Bool
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		outbound, requestErr := http.NewRequestWithContext(r.Context(), r.Method, backend.URL+r.URL.RequestURI(), r.Body)
		if requestErr != nil {
			http.Error(w, "proxy request", http.StatusInternalServerError)
			return
		}
		outbound.Header = r.Header.Clone()
		response, requestErr := http.DefaultClient.Do(outbound)
		if requestErr != nil {
			http.Error(w, "proxy backend", http.StatusBadGateway)
			return
		}
		defer response.Body.Close()
		if r.URL.Path == "/agent/v1/enroll" && dropFirstFinalResponse.CompareAndSwap(false, true) {
			// The Controller has committed enrollment, but the proxy discards the
			// response. A real network reset is equivalent from the Agent's point
			// of view; the empty 200 is deliberately rejected by Client.Enroll.
			_, _ = io.Copy(io.Discard, response.Body)
			return
		}
		for name, values := range response.Header {
			for _, value := range values {
				w.Header().Add(name, value)
			}
		}
		w.WriteHeader(response.StatusCode)
		_, _ = io.Copy(w, response.Body)
	}))
	t.Cleanup(proxy.Close)

	dataDir := filepath.Join(t.TempDir(), "agent")
	hostRoot := t.TempDir()
	cfg := agent.Config{ControllerURL: proxy.URL, Name: "restart-node", DataDir: dataDir, EnrollmentToken: rawToken, ScanInterval: 24 * time.Hour, HostRoot: hostRoot, ObserverOnly: true}
	if _, err = agent.New(ctx, cfg); err == nil {
		t.Fatal("first enrollment unexpectedly succeeded despite its response being discarded")
	}
	pendingPath := filepath.Join(dataDir, "pending-enrollment.json")
	pending, err := agent.LoadPendingEnrollment(pendingPath)
	if err != nil {
		t.Fatalf("pending identity was not durably persisted: %v", err)
	}
	if _, err = os.Stat(filepath.Join(dataDir, "state.json")); !os.IsNotExist(err) {
		t.Fatalf("final state exists after lost response: %v", err)
	}

	if _, err = agent.New(ctx, cfg); err != nil {
		t.Fatalf("restart could not recover enrollment: %v", err)
	}
	state, err := agent.LoadState(filepath.Join(dataDir, "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	if state.IdentityPublicKey != pending.IdentityPublicKey || state.IdentityPrivateKey != pending.IdentityPrivateKey {
		t.Fatal("restart replaced the pending Agent identity")
	}
	if _, err = os.Stat(pendingPath); !os.IsNotExist(err) {
		t.Fatalf("pending private state was not removed after commit: %v", err)
	}
	if count, err := db.DeviceCount(ctx); err != nil || count != 1 {
		t.Fatalf("device count=%d err=%v", count, err)
	}
	items, err := db.ListEnrollmentTokens(ctx)
	if err != nil || len(items) != 1 || items[0].Uses != 1 {
		t.Fatalf("one-use token was consumed more than once: %#v err=%v", items, err)
	}
	if _, err = db.AgentDevice(ctx, secret.Hash(state.DeviceToken)); err != nil {
		t.Fatalf("recovered device token is invalid: %v", err)
	}
}
