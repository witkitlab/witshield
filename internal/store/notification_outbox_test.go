package store

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/witkitlab/witshield/internal/domain"
)

func TestNotificationOutboxPersistsAndLeasesChannelsIndependently(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "outbox.sqlite")
	s, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 26, 10, 0, 0, 0, time.UTC)
	settings := StoredNotificationSettings{Settings: domain.NotificationSettings{
		WebhookEnabled: true, WebhookURL: "https://alerts.example.test/secret/path?token=secret",
		SMTPEnabled: true, SMTPHost: "smtp.example.test", SMTPPort: 587,
		SMTPFrom: "sender@example.test", SMTPTo: []string{"admin@example.test"}, UpdatedAt: now,
	}}
	if err = s.PutNotificationSettings(ctx, settings); err != nil {
		t.Fatal(err)
	}
	event := domain.NotificationEvent{ID: "ntf_persistent", Type: "action_failure", Title: "failed", OccurredAt: now}
	if count, enqueueErr := s.EnqueueNotification(ctx, event, now); enqueueErr != nil || count != 2 {
		t.Fatalf("enqueue count=%d err=%v", count, enqueueErr)
	}
	if count, enqueueErr := s.EnqueueNotification(ctx, event, now); enqueueErr != nil || count != 0 {
		t.Fatalf("duplicate enqueue count=%d err=%v", count, enqueueErr)
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	webhook, err := s.ClaimNotificationDelivery(ctx, domain.NotificationWebhook, now, time.Minute)
	if err != nil || webhook.Event.ID != event.ID || webhook.Attempts != 1 {
		t.Fatalf("persisted webhook=%#v err=%v", webhook, err)
	}
	if _, err = s.ClaimNotificationDelivery(ctx, domain.NotificationWebhook, now.Add(30*time.Second), time.Minute); !errors.Is(err, ErrNotFound) {
		t.Fatalf("active lease was concurrently reclaimed: %v", err)
	}
	smtp, err := s.ClaimNotificationDelivery(ctx, domain.NotificationSMTP, now, time.Minute)
	if err != nil || smtp.Event.ID != event.ID || smtp.Attempts != 1 {
		t.Fatalf("independent SMTP lease=%#v err=%v", smtp, err)
	}
}

func TestNotificationOutboxFencesExpiredWorkersAndBoundsRetries(t *testing.T) {
	ctx := context.Background()
	s, err := Open(ctx, filepath.Join(t.TempDir(), "outbox.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	now := time.Date(2026, 8, 26, 10, 0, 0, 0, time.UTC)
	if err = s.PutNotificationSettings(ctx, StoredNotificationSettings{Settings: domain.NotificationSettings{WebhookEnabled: true, UpdatedAt: now}}); err != nil {
		t.Fatal(err)
	}
	if _, err = s.EnqueueNotification(ctx, domain.NotificationEvent{ID: "ntf_retry", Type: "test", OccurredAt: now}, now); err != nil {
		t.Fatal(err)
	}
	first, err := s.ClaimNotificationDelivery(ctx, domain.NotificationWebhook, now, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	second, err := s.ClaimNotificationDelivery(ctx, domain.NotificationWebhook, now.Add(time.Minute), time.Minute)
	if err != nil || second.Attempts != 2 {
		t.Fatalf("expired lease was not recovered: %#v err=%v", second, err)
	}
	if err = s.CompleteNotificationDelivery(ctx, first, true, now, now.Add(time.Minute), 3, ""); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale worker overwrote current lease: %v", err)
	}
	retryAt := now.Add(2 * time.Minute)
	if err = s.CompleteNotificationDelivery(ctx, second, false, retryAt, now.Add(time.Minute), 3, "webhook transport failed"); err != nil {
		t.Fatal(err)
	}
	if _, err = s.ClaimNotificationDelivery(ctx, domain.NotificationWebhook, retryAt.Add(-time.Nanosecond), time.Minute); !errors.Is(err, ErrNotFound) {
		t.Fatalf("delivery became due before retry deadline: %v", err)
	}
	third, err := s.ClaimNotificationDelivery(ctx, domain.NotificationWebhook, retryAt, time.Minute)
	if err != nil || third.Attempts != 3 {
		t.Fatalf("third attempt=%#v err=%v", third, err)
	}
	if err = s.CompleteNotificationDelivery(ctx, third, false, retryAt.Add(time.Hour), retryAt, 3, "webhook transport failed"); err != nil {
		t.Fatal(err)
	}
	if _, err = s.ClaimNotificationDelivery(ctx, domain.NotificationWebhook, retryAt.Add(24*time.Hour), time.Minute); !errors.Is(err, ErrNotFound) {
		t.Fatalf("terminal failure was retried beyond bound: %v", err)
	}
	var status string
	var attempts int
	if err = s.db.QueryRowContext(ctx, `SELECT status,attempts FROM notification_outbox WHERE event_id=?`, "ntf_retry").Scan(&status, &attempts); err != nil {
		t.Fatal(err)
	}
	if status != notificationFailed || attempts != 3 {
		t.Fatalf("terminal row status=%q attempts=%d", status, attempts)
	}
}

func TestDisablingNotificationChannelCancelsPendingReplay(t *testing.T) {
	ctx := context.Background()
	s, err := Open(ctx, filepath.Join(t.TempDir(), "outbox.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	now := time.Date(2026, 8, 26, 10, 0, 0, 0, time.UTC)
	if err = s.PutNotificationSettings(ctx, StoredNotificationSettings{Settings: domain.NotificationSettings{WebhookEnabled: true, UpdatedAt: now}}); err != nil {
		t.Fatal(err)
	}
	if _, err = s.EnqueueNotification(ctx, domain.NotificationEvent{ID: "ntf_disable", OccurredAt: now}, now); err != nil {
		t.Fatal(err)
	}
	if err = s.PutNotificationSettings(ctx, StoredNotificationSettings{Settings: domain.NotificationSettings{WebhookEnabled: false, UpdatedAt: now.Add(time.Minute)}}); err != nil {
		t.Fatal(err)
	}
	if err = s.PutNotificationSettings(ctx, StoredNotificationSettings{Settings: domain.NotificationSettings{WebhookEnabled: true, UpdatedAt: now.Add(2 * time.Minute)}}); err != nil {
		t.Fatal(err)
	}
	if _, err = s.ClaimNotificationDelivery(ctx, domain.NotificationWebhook, now.Add(24*time.Hour), time.Minute); !errors.Is(err, ErrNotFound) {
		t.Fatalf("disabled notification replayed after re-enable: %v", err)
	}
}

func TestFullNotificationBacklogCannotRollbackReport(t *testing.T) {
	s, deviceID, now := openReportCommandTestStore(t)
	ctx := context.Background()
	if err := s.PutNotificationSettings(ctx, StoredNotificationSettings{Settings: domain.NotificationSettings{WebhookEnabled: true, UpdatedAt: now}}); err != nil {
		t.Fatal(err)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	statement, err := tx.PrepareContext(ctx, `INSERT INTO notification_outbox(id,event_id,channel,event,settings_version,status,attempts,next_attempt_at,created_at,updated_at) VALUES(?,?,?,?,?,?,0,?,?,?)`)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < maxPendingNotificationsPerChannel; i++ {
		id := fmt.Sprintf("ntd_backlog_%04d", i)
		if _, err = statement.ExecContext(ctx, id, "evt_backlog_"+id, string(domain.NotificationWebhook), `{}`, timeText(now), notificationPending, timeText(now), timeText(now), timeText(now)); err != nil {
			_ = statement.Close()
			_ = tx.Rollback()
			t.Fatal(err)
		}
	}
	if err = statement.Close(); err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}

	report := domain.Report{ID: "rpt_backlog", DeviceID: deviceID, StartedAt: now, CompletedAt: now.Add(time.Minute), Score: 100, Summary: []byte(`{}`)}
	event := domain.NotificationEvent{ID: "report:rpt_backlog", Type: "report_completed", DeviceID: deviceID, OccurredAt: report.CompletedAt}
	created, queued, err := s.SaveReportWithNotification(ctx, report, event, report.CompletedAt)
	if err != nil || !created || queued != 0 {
		t.Fatalf("core report transaction depended on full notification channel: created=%v queued=%d err=%v", created, queued, err)
	}
	if _, err = s.Report(ctx, report.ID); err != nil {
		t.Fatalf("report was rolled back with notification backlog: %v", err)
	}
	var status, lastError string
	if err = s.db.QueryRowContext(ctx, `SELECT status,last_error FROM notification_outbox WHERE event_id=? AND channel=?`, event.ID, string(domain.NotificationWebhook)).Scan(&status, &lastError); err != nil {
		t.Fatal(err)
	}
	if status != notificationFailed || lastError == "" {
		t.Fatalf("dropped notification was not retained as terminal audit: status=%q error=%q", status, lastError)
	}
}
