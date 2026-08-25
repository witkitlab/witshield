package agent

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/witkitlab/witshield/internal/domain"
	"github.com/witkitlab/witshield/internal/scanner"
)

func TestStalePrivilegedCommandNeverReachesHelper(t *testing.T) {
	requestPath := make(chan string, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestPath <- r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"authorized":false}`)
	}))
	defer server.Close()
	client := authenticatedTestClient(t, server.URL, "device-token")
	queue, err := NewQueue(filepath.Join(t.TempDir(), "queue"))
	if err != nil {
		t.Fatal(err)
	}
	runner := &Runner{client: client, queue: queue, helper: nil}
	command := domain.DeviceCommand{ID: "cmd-stale", Type: domain.CommandExecuteAction, CreatedAt: time.Now().Add(-domain.ActionCommandTTL - time.Second)}
	if err = runner.handleCommand(context.Background(), command); err != nil {
		t.Fatal(err)
	}
	select {
	case path := <-requestPath:
		if path != "/agent/v1/commands/cmd-stale/start" {
			t.Fatalf("stale command used unexpected endpoint: %s", path)
		}
	case <-time.After(time.Second):
		t.Fatal("stale command was not rejected by the controller gate")
	}
}

func TestPolicyAuthorizedCommandReachesFinalAuthorizationGate(t *testing.T) {
	requestPath := make(chan string, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestPath <- r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"authorized":false}`)
	}))
	defer server.Close()
	client := authenticatedTestClient(t, server.URL, "device-token")
	queue, err := NewQueue(filepath.Join(t.TempDir(), "queue"))
	if err != nil {
		t.Fatal(err)
	}
	runner := &Runner{client: client, queue: queue}
	command := domain.DeviceCommand{
		ID:        "cmd-policy",
		Type:      domain.CommandExecuteAction,
		CreatedAt: time.Now(),
		Payload:   []byte(`{"actionId":"act-policy","type":"temporary_ip_ban","parameters":{"address":"203.0.113.55","ttlSeconds":900,"currentAdminIp":"198.51.100.10","reason":"test"},"policyAuthorized":true}`),
	}
	if err = runner.handleCommand(context.Background(), command); err != nil {
		t.Fatal(err)
	}
	select {
	case path := <-requestPath:
		if path != "/agent/v1/commands/cmd-policy/start" {
			t.Fatalf("policy command was rejected before the final authorization gate: %s", path)
		}
	case <-time.After(time.Second):
		t.Fatal("policy command never reached the final authorization gate")
	}
}

func TestMalformedAndObserverActionsCrossStartGateBeforeResult(t *testing.T) {
	for _, testCase := range []struct {
		name         string
		observerOnly bool
		payload      json.RawMessage
	}{
		{name: "malformed", payload: json.RawMessage(`{"actionId":"act"}`)},
		{name: "observer", observerOnly: true, payload: json.RawMessage(`{"actionId":"act","type":"temporary_ip_ban","parameters":{"address":"8.8.8.8","ttlSeconds":900,"currentAdminIp":"1.1.1.10"}}`)},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			var mu sync.Mutex
			var paths []string
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				mu.Lock()
				paths = append(paths, r.URL.Path)
				mu.Unlock()
				if strings.HasSuffix(r.URL.Path, "/start") {
					w.Header().Set("Content-Type", "application/json")
					_, _ = io.WriteString(w, `{"authorized":true}`)
					return
				}
				w.WriteHeader(http.StatusNoContent)
			}))
			defer server.Close()
			client := authenticatedTestClient(t, server.URL, "device-token")
			queue, err := NewQueue(filepath.Join(t.TempDir(), "queue"))
			if err != nil {
				t.Fatal(err)
			}
			publicKey, privateKey, err := NewIdentity()
			if err != nil {
				t.Fatal(err)
			}
			runner := &Runner{cfg: Config{ObserverOnly: testCase.observerOnly}, state: State{DeviceID: "dev_test", IdentityPublicKey: publicKey, IdentityPrivateKey: privateKey}, client: client, queue: queue}
			command := domain.DeviceCommand{ID: "cmd_gate", Type: domain.CommandExecuteAction, CreatedAt: time.Now(), Payload: testCase.payload}
			if err = runner.handleCommand(context.Background(), command); err != nil {
				t.Fatal(err)
			}
			mu.Lock()
			defer mu.Unlock()
			if len(paths) != 2 || paths[0] != "/agent/v1/commands/cmd_gate/start" || paths[1] != "/agent/v1/commands/cmd_gate/result" {
				t.Fatalf("action result bypassed start ordering: %v", paths)
			}
		})
	}
}

func TestRunPerformsStartupScanOnlyWithoutLocalRecurringSchedule(t *testing.T) {
	var scans atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/agent/v1/heartbeat":
			w.WriteHeader(http.StatusNoContent)
		case "/agent/v1/reports":
			w.WriteHeader(http.StatusCreated)
		case "/agent/v1/sync":
			select {
			case <-r.Context().Done():
				return
			case <-time.After(5 * time.Millisecond):
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"commands":[]}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	client := authenticatedTestClient(t, server.URL, "device-token")
	queue, err := NewQueue(filepath.Join(t.TempDir(), "queue"))
	if err != nil {
		t.Fatal(err)
	}
	scan := scanner.New(scanner.CheckFunc{NameValue: "count", Fn: func(context.Context, scanner.Host) ([]domain.Finding, error) {
		scans.Add(1)
		return nil, nil
	}})
	runner := &Runner{
		cfg: Config{ScanInterval: 10 * time.Millisecond}, client: client, queue: queue, scanner: scan,
		log: slog.New(slog.NewTextHandler(io.Discard, nil)), watcher: &authLogWatcher{path: filepath.Join(t.TempDir(), "missing-auth.log"), statePath: filepath.Join(t.TempDir(), "offset")},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Millisecond)
	defer cancel()
	if err = runner.Run(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("runner error=%v", err)
	}
	if got := scans.Load(); got != 1 {
		t.Fatalf("Agent ran %d scans without Controller commands; want startup scan only", got)
	}
}

func TestSyncBackoffIsExponentiallyBoundedAndJittered(t *testing.T) {
	for attempt := 1; attempt <= 10; attempt++ {
		base := time.Duration(1<<min(attempt, 6)) * time.Second
		if base > time.Minute {
			base = time.Minute
		}
		minimum, maximum := base-base/5, base+base/5
		for sample := 0; sample < 32; sample++ {
			got := backoffDuration(attempt)
			if got < minimum || got > maximum {
				t.Fatalf("attempt %d backoff %s outside [%s,%s]", attempt, got, minimum, maximum)
			}
		}
	}
}
