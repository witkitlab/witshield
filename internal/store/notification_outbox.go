package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/witkitlab/witshield/internal/domain"
	"github.com/witkitlab/witshield/internal/ids"
)

const (
	notificationPending                = "pending"
	notificationInflight               = "inflight"
	notificationDelivered              = "delivered"
	notificationFailed                 = "failed"
	notificationCanceled               = "canceled"
	maxPendingNotificationsPerChannel  = 5_000
	maxTerminalNotificationsPerChannel = 10_000
)

// NotificationDelivery is one channel-specific attempt from the durable
// notification outbox. LeaseUntil is part of the completion token: a worker
// whose lease has expired cannot overwrite a newer worker's result.
type NotificationDelivery struct {
	ID                string
	EventID           string
	Channel           domain.NotificationChannel
	Event             domain.NotificationEvent
	Attempts          int
	LeaseUntil        time.Time
	CreatedAt         time.Time
	SettingsUpdatedAt time.Time
}

// EnqueueNotification atomically snapshots the set of channels enabled at the
// time the event occurs. The payload is persisted once per channel so webhook
// and SMTP delivery, retry, and failure states remain independent.
func (s *Store) EnqueueNotification(ctx context.Context, event domain.NotificationEvent, now time.Time) (int, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	count, err := enqueueNotificationTx(ctx, tx, event, now)
	if err != nil {
		return 0, err
	}
	return count, tx.Commit()
}

func enqueueNotificationTx(ctx context.Context, tx *sql.Tx, event domain.NotificationEvent, now time.Time) (int, error) {
	if strings.TrimSpace(event.ID) == "" {
		return 0, errors.New("notification event ID is required")
	}
	payload, err := json.Marshal(event)
	if err != nil {
		return 0, err
	}
	if len(payload) > 16*1024 {
		return 0, errors.New("notification event is too large")
	}
	var webhookEnabled, smtpEnabled bool
	var settingsVersion string
	if err = tx.QueryRowContext(ctx, `SELECT webhook_enabled,smtp_enabled,updated_at FROM notification_settings WHERE singleton=1`).Scan(&webhookEnabled, &smtpEnabled, &settingsVersion); errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	} else if err != nil {
		return 0, err
	}
	created := timeText(now)
	count := 0
	for channel, enabled := range map[domain.NotificationChannel]bool{
		domain.NotificationWebhook: webhookEnabled,
		domain.NotificationSMTP:    smtpEnabled,
	} {
		if !enabled {
			continue
		}
		if _, execErr := tx.ExecContext(ctx, `DELETE FROM notification_outbox WHERE id IN (
			SELECT id FROM notification_outbox WHERE channel=? AND status IN (?,?,?) ORDER BY updated_at DESC,id DESC LIMIT -1 OFFSET ?
		)`, string(channel), notificationDelivered, notificationFailed, notificationCanceled, maxTerminalNotificationsPerChannel); execErr != nil {
			return 0, execErr
		}
		var pending int
		if queryErr := tx.QueryRowContext(ctx, `SELECT count(*) FROM notification_outbox WHERE channel=? AND status IN (?,?)`, string(channel), notificationPending, notificationInflight).Scan(&pending); queryErr != nil {
			return 0, queryErr
		}
		if pending >= maxPendingNotificationsPerChannel && event.Type == "report_completed" && event.DeviceID != "" {
			toDelete := pending - maxPendingNotificationsPerChannel + 1
			if _, execErr := tx.ExecContext(ctx, `DELETE FROM notification_outbox WHERE id IN (
				SELECT id FROM notification_outbox WHERE channel=? AND status=? AND json_extract(event,'$.type')='report_completed' AND json_extract(event,'$.deviceId')=? ORDER BY created_at,id LIMIT ?
			)`, string(channel), notificationPending, event.DeviceID, toDelete); execErr != nil {
				return 0, execErr
			}
			if queryErr := tx.QueryRowContext(ctx, `SELECT count(*) FROM notification_outbox WHERE channel=? AND status IN (?,?)`, string(channel), notificationPending, notificationInflight).Scan(&pending); queryErr != nil {
				return 0, queryErr
			}
		}
		if pending >= maxPendingNotificationsPerChannel {
			// Notification delivery must never become a reverse dependency of the
			// report, action-result, or automatic-defense transaction. Preserve a
			// bounded terminal audit row and drop only this delivery when a failed
			// channel has filled its live backlog.
			if _, execErr := tx.ExecContext(ctx, `INSERT OR IGNORE INTO notification_outbox(id,event_id,channel,event,settings_version,status,attempts,next_attempt_at,last_error,created_at,updated_at) VALUES(?,?,?,?,?,?,0,?,?,?,?)`, ids.New("ntd"), event.ID, string(channel), string(payload), settingsVersion, notificationFailed, created, "delivery dropped because notification backlog capacity was reached", created, created); execErr != nil {
				return 0, execErr
			}
			continue
		}
		result, execErr := tx.ExecContext(ctx, `INSERT OR IGNORE INTO notification_outbox(id,event_id,channel,event,settings_version,status,attempts,next_attempt_at,created_at,updated_at) VALUES(?,?,?,?,?,?,0,?,?,?)`, ids.New("ntd"), event.ID, string(channel), string(payload), settingsVersion, notificationPending, created, created, created)
		if execErr != nil {
			return 0, execErr
		}
		if affected, rowsErr := result.RowsAffected(); rowsErr != nil {
			return 0, rowsErr
		} else {
			count += int(affected)
		}
	}
	return count, nil
}

// ClaimNotificationDelivery leases the oldest due item for one channel. A
// crashed worker's item becomes claimable again only after its lease expires.
func (s *Store) ClaimNotificationDelivery(ctx context.Context, channel domain.NotificationChannel, now time.Time, lease time.Duration) (NotificationDelivery, error) {
	var delivery NotificationDelivery
	if channel != domain.NotificationWebhook && channel != domain.NotificationSMTP {
		return delivery, errors.New("invalid notification channel")
	}
	if lease <= 0 {
		return delivery, errors.New("notification lease must be positive")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return delivery, err
	}
	defer tx.Rollback()
	var rawEvent, created, settingsVersion string
	nowText := timeText(now)
	err = tx.QueryRowContext(ctx, `SELECT id,event_id,event,settings_version,attempts,created_at FROM notification_outbox WHERE channel=? AND ((status=? AND next_attempt_at<=?) OR (status=? AND lease_until IS NOT NULL AND lease_until<=?)) ORDER BY next_attempt_at,created_at,id LIMIT 1`, string(channel), notificationPending, nowText, notificationInflight, nowText).Scan(&delivery.ID, &delivery.EventID, &rawEvent, &settingsVersion, &delivery.Attempts, &created)
	if errors.Is(err, sql.ErrNoRows) {
		return delivery, ErrNotFound
	}
	if err != nil {
		return delivery, err
	}
	delivery.Channel = channel
	if err = json.Unmarshal([]byte(rawEvent), &delivery.Event); err != nil {
		return delivery, err
	}
	if delivery.CreatedAt, err = parseTime(created); err != nil {
		return delivery, err
	}
	if delivery.SettingsUpdatedAt, err = parseTime(settingsVersion); err != nil {
		return delivery, err
	}
	delivery.Attempts++
	delivery.LeaseUntil = now.Add(lease).UTC()
	result, err := tx.ExecContext(ctx, `UPDATE notification_outbox SET status=?,attempts=?,lease_until=?,updated_at=? WHERE id=? AND ((status=? AND next_attempt_at<=?) OR (status=? AND lease_until IS NOT NULL AND lease_until<=?))`, notificationInflight, delivery.Attempts, timeText(delivery.LeaseUntil), nowText, delivery.ID, notificationPending, nowText, notificationInflight, nowText)
	if err != nil {
		return delivery, err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return delivery, err
	}
	if affected != 1 {
		return delivery, ErrConflict
	}
	return delivery, tx.Commit()
}

// CompleteNotificationDelivery records one leased attempt. Failed attempts are
// rescheduled until maxAttempts, after which the row remains as a terminal
// audit record. lastError must already be public/sanitized by the caller.
func (s *Store) CompleteNotificationDelivery(ctx context.Context, delivery NotificationDelivery, delivered bool, retryAt, now time.Time, maxAttempts int, lastError string) error {
	if maxAttempts < 1 {
		return errors.New("notification max attempts must be positive")
	}
	if len(lastError) > 512 {
		lastError = lastError[:512]
	}
	status := notificationDelivered
	nextAttempt := timeText(now)
	var deliveredAt any = timeText(now)
	if !delivered {
		deliveredAt = nil
		status = notificationPending
		nextAttempt = timeText(retryAt)
		if delivery.Attempts >= maxAttempts {
			status = notificationFailed
		}
	}
	result, err := s.db.ExecContext(ctx, `UPDATE notification_outbox SET status=?,next_attempt_at=?,lease_until=NULL,last_error=?,updated_at=?,delivered_at=? WHERE id=? AND status=? AND attempts=? AND lease_until=?`, status, nextAttempt, lastError, timeText(now), deliveredAt, delivery.ID, notificationInflight, delivery.Attempts, timeText(delivery.LeaseUntil))
	if err != nil {
		return err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if affected != 1 {
		return ErrConflict
	}
	return nil
}

// CancelNotificationDelivery terminates a currently leased item when its
// administrator-disabled channel can no longer be delivered.
func (s *Store) CancelNotificationDelivery(ctx context.Context, delivery NotificationDelivery, reason string, now time.Time) error {
	if len(reason) > 512 {
		reason = reason[:512]
	}
	result, err := s.db.ExecContext(ctx, `UPDATE notification_outbox SET status=?,lease_until=NULL,last_error=?,updated_at=? WHERE id=? AND status=? AND attempts=? AND lease_until=?`, notificationCanceled, reason, timeText(now), delivery.ID, notificationInflight, delivery.Attempts, timeText(delivery.LeaseUntil))
	if err != nil {
		return err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if affected != 1 {
		return ErrConflict
	}
	return nil
}

// ReleaseNotificationDelivery returns a lease without consuming an attempt.
// It is used only when the Controller itself is shutting down, rather than
// when a remote channel actually failed.
func (s *Store) ReleaseNotificationDelivery(ctx context.Context, delivery NotificationDelivery, now time.Time) error {
	result, err := s.db.ExecContext(ctx, `UPDATE notification_outbox SET status=?,attempts=attempts-1,next_attempt_at=?,lease_until=NULL,updated_at=? WHERE id=? AND status=? AND attempts=? AND lease_until=?`, notificationPending, timeText(now), timeText(now), delivery.ID, notificationInflight, delivery.Attempts, timeText(delivery.LeaseUntil))
	if err != nil {
		return err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if affected != 1 {
		return ErrConflict
	}
	return nil
}

// CancelPendingNotificationChannel ensures disabling a channel does not later
// replay its queued notifications if the channel is re-enabled.
func (s *Store) CancelPendingNotificationChannel(ctx context.Context, channel domain.NotificationChannel, reason string, now time.Time) error {
	if channel != domain.NotificationWebhook && channel != domain.NotificationSMTP {
		return errors.New("invalid notification channel")
	}
	if len(reason) > 512 {
		reason = reason[:512]
	}
	_, err := s.db.ExecContext(ctx, `UPDATE notification_outbox SET status=?,last_error=?,updated_at=? WHERE channel=? AND status=?`, notificationCanceled, reason, timeText(now), string(channel), notificationPending)
	return err
}

func (s *Store) PruneNotificationOutbox(ctx context.Context, terminalBefore time.Time) (int64, error) {
	result, err := s.db.ExecContext(ctx, `DELETE FROM notification_outbox WHERE status IN (?,?,?) AND updated_at<?`, notificationDelivered, notificationFailed, notificationCanceled, timeText(terminalBefore))
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}
