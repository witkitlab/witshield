package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"

	"github.com/witkitlab/witshield/internal/domain"
)

type StoredNotificationSettings struct {
	Settings               domain.NotificationSettings
	EncryptedWebhookSecret string
	EncryptedSMTPPassword  string
}

func (s *Store) PutNotificationSettings(ctx context.Context, x StoredNotificationSettings) error {
	to, _ := json.Marshal(x.Settings.SMTPTo)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `INSERT INTO notification_settings(singleton,webhook_enabled,webhook_url,encrypted_webhook_secret,smtp_enabled,smtp_host,smtp_port,smtp_username,encrypted_smtp_password,smtp_from,smtp_to,updated_at) VALUES(1,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(singleton) DO UPDATE SET webhook_enabled=excluded.webhook_enabled,webhook_url=excluded.webhook_url,encrypted_webhook_secret=excluded.encrypted_webhook_secret,smtp_enabled=excluded.smtp_enabled,smtp_host=excluded.smtp_host,smtp_port=excluded.smtp_port,smtp_username=excluded.smtp_username,encrypted_smtp_password=excluded.encrypted_smtp_password,smtp_from=excluded.smtp_from,smtp_to=excluded.smtp_to,updated_at=excluded.updated_at`, x.Settings.WebhookEnabled, x.Settings.WebhookURL, x.EncryptedWebhookSecret, x.Settings.SMTPEnabled, x.Settings.SMTPHost, x.Settings.SMTPPort, x.Settings.SMTPUsername, x.EncryptedSMTPPassword, x.Settings.SMTPFrom, string(to), timeText(x.Settings.UpdatedAt)); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `UPDATE notification_outbox SET status=?,last_error=?,updated_at=? WHERE status=? AND settings_version<>?`, notificationCanceled, "channel configuration changed before delivery", timeText(x.Settings.UpdatedAt), notificationPending, timeText(x.Settings.UpdatedAt)); err != nil {
		return err
	}
	return tx.Commit()
}
func (s *Store) NotificationSettings(ctx context.Context) (StoredNotificationSettings, error) {
	var x StoredNotificationSettings
	var to, updated string
	err := s.db.QueryRowContext(ctx, `SELECT webhook_enabled,webhook_url,encrypted_webhook_secret,smtp_enabled,smtp_host,smtp_port,smtp_username,encrypted_smtp_password,smtp_from,smtp_to,updated_at FROM notification_settings WHERE singleton=1`).Scan(&x.Settings.WebhookEnabled, &x.Settings.WebhookURL, &x.EncryptedWebhookSecret, &x.Settings.SMTPEnabled, &x.Settings.SMTPHost, &x.Settings.SMTPPort, &x.Settings.SMTPUsername, &x.EncryptedSMTPPassword, &x.Settings.SMTPFrom, &to, &updated)
	if errors.Is(err, sql.ErrNoRows) {
		return x, ErrNotFound
	}
	if err != nil {
		return x, err
	}
	if err = json.Unmarshal([]byte(to), &x.Settings.SMTPTo); err != nil {
		return x, err
	}
	x.Settings.UpdatedAt, err = parseTime(updated)
	x.Settings.WebhookSecretConfigured = x.EncryptedWebhookSecret != ""
	x.Settings.SMTPPasswordConfigured = x.EncryptedSMTPPassword != ""
	return x, err
}
