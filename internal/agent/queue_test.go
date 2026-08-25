package agent

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/witkitlab/witshield/internal/identity"
)

func TestQueueConcurrentFlushSendsEachEntryOnce(t *testing.T) {
	var received atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { received.Add(1); w.WriteHeader(201) }))
	defer srv.Close()
	client := authenticatedTestClient(t, srv.URL, "token")
	queue, err := NewQueue(filepath.Join(t.TempDir(), "queue"))
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 100; i++ {
		if err = queue.Enqueue("report", "", map[string]any{"n": i}); err != nil {
			t.Fatal(err)
		}
	}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := queue.Flush(context.Background(), client); err != nil {
				t.Errorf("flush: %v", err)
			}
		}()
	}
	wg.Wait()
	if received.Load() != 100 {
		t.Fatalf("received=%d", received.Load())
	}
	files, _, err := queue.files()
	if err != nil || len(files) != 0 {
		t.Fatalf("files=%v err=%v", files, err)
	}
}

func TestQueueFlushPreservesSignedRawCommandResult(t *testing.T) {
	publicKey, privateKey, err := NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	const commandID = "cmd_signed_raw"
	result := json.RawMessage(`{"z":1,"a":2}`)
	rollback := json.RawMessage(`{"before":{"z":true,"a":false}}`)
	receipt := json.RawMessage(`{"success":true,"details":{"z":1,"a":2}}`)
	signature, err := identity.SignCommandResult(privateKey, identity.CommandResultProof{
		DeviceID: "dev_test", CommandID: commandID, OK: true, Result: result, RollbackPayload: rollback, AuditReceipt: receipt,
	})
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(signedCommandResult{OK: true, Result: result, RollbackPayload: rollback, AuditReceipt: receipt, IdentitySignature: signature})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		encoded, readErr := io.ReadAll(r.Body)
		if readErr != nil {
			http.Error(w, "read body", http.StatusBadRequest)
			return
		}
		var got signedCommandResult
		if json.Unmarshal(encoded, &got) != nil {
			http.Error(w, "decode body", http.StatusBadRequest)
			return
		}
		if verifyErr := identity.VerifyCommandResult(publicKey, got.IdentitySignature, identity.CommandResultProof{
			DeviceID: "dev_test", CommandID: commandID, OK: got.OK, Result: got.Result, RollbackPayload: got.RollbackPayload, AuditReceipt: got.AuditReceipt, Error: got.Error,
		}); verifyErr != nil {
			http.Error(w, verifyErr.Error(), http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	client := authenticatedTestClient(t, server.URL, "token")
	queue, err := NewQueue(filepath.Join(t.TempDir(), "queue"))
	if err != nil {
		t.Fatal(err)
	}
	if err = queue.Enqueue("command_result", commandID, json.RawMessage(body)); err != nil {
		t.Fatal(err)
	}
	if err = queue.Flush(context.Background(), client); err != nil {
		t.Fatal(err)
	}
}

func TestQueueDropsOnlyAuthenticatedProtocolExpiredCommandResult(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if requests.Add(1) == 1 {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusGone)
			_, _ = w.Write([]byte(`{"error":{"code":"command_result_expired","message":"retention elapsed"}}`))
			return
		}
		w.WriteHeader(http.StatusCreated)
	}))
	defer server.Close()
	queue, err := NewQueue(filepath.Join(t.TempDir(), "queue"))
	if err != nil {
		t.Fatal(err)
	}
	if err = queue.Enqueue("command_result", "cmd_old", map[string]any{"ok": true}); err != nil {
		t.Fatal(err)
	}
	if err = queue.Enqueue("report", "", map[string]any{"id": "rpt_new"}); err != nil {
		t.Fatal(err)
	}
	if err = queue.Flush(context.Background(), authenticatedTestClient(t, server.URL, "token")); err != nil {
		t.Fatalf("terminal expired result blocked newer queue item: %v", err)
	}
	files, _, err := queue.files()
	if err != nil || len(files) != 0 || requests.Load() != 2 {
		t.Fatalf("queue files=%v requests=%d err=%v", files, requests.Load(), err)
	}
}

func TestQueueDoesNotDropGenericGoneResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusGone)
		_, _ = w.Write([]byte(`{"error":{"code":"different_code","message":"retry or investigate"}}`))
	}))
	defer server.Close()
	queue, err := NewQueue(filepath.Join(t.TempDir(), "queue"))
	if err != nil {
		t.Fatal(err)
	}
	if err = queue.Enqueue("command_result", "cmd_unknown", map[string]any{"ok": true}); err != nil {
		t.Fatal(err)
	}
	if err = queue.Flush(context.Background(), authenticatedTestClient(t, server.URL, "token")); err == nil {
		t.Fatal("generic 410 was silently discarded")
	}
	files, _, err := queue.files()
	if err != nil || len(files) != 1 {
		t.Fatalf("generic 410 queue files=%v err=%v", files, err)
	}
}
