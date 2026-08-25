package httpapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/witkitlab/witshield/internal/domain"
	"github.com/witkitlab/witshield/internal/store"
)

func TestNotificationWorkerDrainsDurableBurstWithoutDropping(t *testing.T) {
	x := newTestAPI(t)
	received := make(chan string, 16)
	webhook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var event domain.NotificationEvent
		if !decodeJSONForTest(r, &event) {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		received <- event.ID
		w.WriteHeader(http.StatusNoContent)
	}))
	defer webhook.Close()
	secret, err := x.api.vault.Encrypt("0123456789abcdef")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	if err = x.store.PutNotificationSettings(context.Background(), store.StoredNotificationSettings{
		Settings:               domain.NotificationSettings{WebhookEnabled: true, WebhookURL: webhook.URL, UpdatedAt: now},
		EncryptedWebhookSecret: secret,
	}); err != nil {
		t.Fatal(err)
	}
	const total = 12
	for index := 0; index < total; index++ {
		x.api.notify(domain.NotificationEvent{ID: fmt.Sprintf("ntf_burst_%02d", index), Type: "burst", OccurredAt: now})
	}

	workerCtx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- x.api.RunNotificationWorker(workerCtx) }()
	seen := map[string]bool{}
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	for len(seen) < total {
		select {
		case id := <-received:
			seen[id] = true
		case <-deadline.C:
			t.Fatalf("durable worker delivered %d/%d burst events", len(seen), total)
		}
	}
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("notification worker did not stop")
	}
}

func decodeJSONForTest(r *http.Request, out any) bool {
	decoder := json.NewDecoder(r.Body)
	return decoder.Decode(out) == nil
}
