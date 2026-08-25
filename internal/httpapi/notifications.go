package httpapi

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/witkitlab/witshield/internal/domain"
	"github.com/witkitlab/witshield/internal/ids"
	"github.com/witkitlab/witshield/internal/notification"
	"github.com/witkitlab/witshield/internal/store"
)

type notificationInput struct {
	WebhookEnabled     bool     `json:"webhookEnabled"`
	WebhookURL         string   `json:"webhookUrl"`
	WebhookSecret      *string  `json:"webhookSecret,omitempty"`
	ClearWebhookSecret bool     `json:"clearWebhookSecret,omitempty"`
	SMTPEnabled        bool     `json:"smtpEnabled"`
	SMTPHost           string   `json:"smtpHost"`
	SMTPPort           int      `json:"smtpPort"`
	SMTPUsername       string   `json:"smtpUsername"`
	SMTPPassword       *string  `json:"smtpPassword,omitempty"`
	ClearSMTPPassword  bool     `json:"clearSmtpPassword,omitempty"`
	SMTPFrom           string   `json:"smtpFrom"`
	SMTPTo             []string `json:"smtpTo"`
}

func (s *Server) getNotificationSettings(w http.ResponseWriter, r *http.Request) {
	x, err := s.store.NotificationSettings(r.Context())
	if errors.Is(err, store.ErrNotFound) {
		writeJSON(w, 200, map[string]any{"configured": false, "webhookEnabled": false, "smtpEnabled": false})
		return
	}
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, 200, x.Settings)
}
func (s *Server) putNotificationSettings(w http.ResponseWriter, r *http.Request) {
	var in notificationInput
	if !decodeJSON(w, r, &in) {
		return
	}
	if (in.WebhookSecret != nil && in.ClearWebhookSecret) || (in.SMTPPassword != nil && in.ClearSMTPPassword) {
		writeError(w, 400, "conflicting_secret_update", "secret and clear flag cannot be combined")
		return
	}
	old, err := s.store.NotificationSettings(r.Context())
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		s.fail(w, err)
		return
	}
	webhookSecret := old.EncryptedWebhookSecret
	smtpPassword := old.EncryptedSMTPPassword
	if in.ClearWebhookSecret {
		webhookSecret = ""
	} else if in.WebhookSecret != nil {
		var err error
		webhookSecret, err = s.vault.Encrypt(strings.TrimSpace(*in.WebhookSecret))
		if err != nil {
			s.fail(w, err)
			return
		}
	}
	if in.ClearSMTPPassword {
		smtpPassword = ""
	} else if in.SMTPPassword != nil {
		var err error
		smtpPassword, err = s.vault.Encrypt(*in.SMTPPassword)
		if err != nil {
			s.fail(w, err)
			return
		}
	}
	settings := domain.NotificationSettings{WebhookEnabled: in.WebhookEnabled, WebhookURL: strings.TrimSpace(in.WebhookURL), WebhookSecretConfigured: webhookSecret != "", SMTPEnabled: in.SMTPEnabled, SMTPHost: strings.TrimSpace(in.SMTPHost), SMTPPort: in.SMTPPort, SMTPUsername: in.SMTPUsername, SMTPPasswordConfigured: smtpPassword != "", SMTPFrom: in.SMTPFrom, SMTPTo: in.SMTPTo, UpdatedAt: s.now().UTC()}
	plainWebhook, err := s.vault.Decrypt(webhookSecret)
	if err != nil {
		s.fail(w, errors.New("decrypt stored webhook credential"))
		return
	}
	plainSMTP, err := s.vault.Decrypt(smtpPassword)
	if err != nil {
		s.fail(w, errors.New("decrypt stored SMTP credential"))
		return
	}
	if _, err := notification.New(notification.Config{Settings: settings, WebhookSecret: plainWebhook, SMTPPassword: plainSMTP}); err != nil {
		writeError(w, 400, "invalid_notification_settings", err.Error())
		return
	}
	stored := store.StoredNotificationSettings{Settings: settings, EncryptedWebhookSecret: webhookSecret, EncryptedSMTPPassword: smtpPassword}
	if err := s.store.PutNotificationSettings(r.Context(), stored); err != nil {
		s.fail(w, err)
		return
	}
	s.wakeNotificationWorkers()
	writeJSON(w, 200, settings)
}
func (s *Server) notificationSender(ctx context.Context) (*notification.Sender, time.Time, error) {
	stored, err := s.store.NotificationSettings(ctx)
	if err != nil {
		return nil, time.Time{}, err
	}
	webhook, err := s.vault.Decrypt(stored.EncryptedWebhookSecret)
	if err != nil {
		return nil, time.Time{}, err
	}
	smtpPassword, err := s.vault.Decrypt(stored.EncryptedSMTPPassword)
	if err != nil {
		return nil, time.Time{}, err
	}
	sender, err := notification.New(notification.Config{Settings: stored.Settings, WebhookSecret: webhook, SMTPPassword: smtpPassword})
	return sender, stored.Settings.UpdatedAt, err
}
func (s *Server) testNotification(w http.ResponseWriter, r *http.Request) {
	sender, _, err := s.notificationSender(r.Context())
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, 409, "notifications_not_configured", "notification settings are not configured")
		return
	}
	if err != nil {
		s.fail(w, err)
		return
	}
	if !sender.Enabled() {
		writeError(w, 409, "notification_channels_disabled", "enable a notification channel before testing")
		return
	}
	ctx, cancel := contextWithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	event := domain.NotificationEvent{ID: ids.New("ntf"), Type: "test", Severity: domain.SeverityInfo, Title: "WitShield notification test", Message: "Your WitShield notification channel is configured correctly.", OccurredAt: s.now().UTC()}
	if err = sender.Send(ctx, event); err != nil {
		writeError(w, 502, "notification_delivery_failed", err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}
func (s *Server) notify(event domain.NotificationEvent) {
	if event.ID == "" {
		event.ID = ids.New("ntf")
	}
	if event.OccurredAt.IsZero() {
		event.OccurredAt = s.now().UTC()
	}
	if s.notifyObserver != nil {
		s.notifyObserver(event)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	queued, err := s.store.EnqueueNotification(ctx, event, s.now().UTC())
	if err != nil {
		s.log.Error("persist notification to outbox", "type", event.Type, "error", "notification persistence failed")
		return
	}
	if queued > 0 {
		s.wakeNotificationWorkers()
	}
}

// notificationCommitted publishes a notification already inserted into the
// transactional outbox by the same Store transaction as its business event.
// It must not enqueue a second copy.
func (s *Server) notificationCommitted(event *domain.NotificationEvent, queued int) {
	if event == nil {
		return
	}
	if s.notifyObserver != nil {
		s.notifyObserver(*event)
	}
	if queued > 0 {
		s.wakeNotificationWorkers()
	}
}
