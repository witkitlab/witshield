package httpapi

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/witkitlab/witshield/internal/domain"
	"github.com/witkitlab/witshield/internal/notification"
	"github.com/witkitlab/witshield/internal/store"
)

const (
	notificationMaxAttempts       = 6
	notificationDeliveryLease     = time.Minute
	notificationAttemptTimeout    = 25 * time.Second
	notificationIdlePoll          = 5 * time.Second
	notificationTerminalRetention = 30 * 24 * time.Hour
)

// RunNotificationWorker drains the durable outbox until ctx is canceled.
// Webhook and SMTP own separate workers, wakeups, time budgets, and retry
// state, so an unavailable channel cannot delay a healthy one.
func (s *Server) RunNotificationWorker(ctx context.Context) error {
	var wg sync.WaitGroup
	for _, item := range []struct {
		channel domain.NotificationChannel
		wake    <-chan struct{}
	}{
		{channel: domain.NotificationWebhook, wake: s.notifyWebhookWake},
		{channel: domain.NotificationSMTP, wake: s.notifySMTPWake},
	} {
		wg.Add(1)
		go func(channel domain.NotificationChannel, wake <-chan struct{}) {
			defer wg.Done()
			s.runNotificationChannel(ctx, channel, wake)
		}(item.channel, item.wake)
	}
	pruneTicker := time.NewTicker(6 * time.Hour)
	defer pruneTicker.Stop()
	for {
		select {
		case <-ctx.Done():
			wg.Wait()
			return ctx.Err()
		case <-pruneTicker.C:
			pruneCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
			_, err := s.store.PruneNotificationOutbox(pruneCtx, s.now().UTC().Add(-notificationTerminalRetention))
			cancel()
			if err != nil && !errors.Is(err, context.Canceled) {
				s.log.Error("prune notification outbox", "error", "notification outbox maintenance failed")
			}
		}
	}
}

func (s *Server) runNotificationChannel(ctx context.Context, channel domain.NotificationChannel, wake <-chan struct{}) {
	for ctx.Err() == nil {
		now := s.now().UTC()
		delivery, err := s.store.ClaimNotificationDelivery(ctx, channel, now, notificationDeliveryLease)
		if errors.Is(err, store.ErrNotFound) {
			s.MarkWorkerHealth("notification_"+string(channel), nil)
			if !waitForNotificationWork(ctx, wake) {
				return
			}
			continue
		}
		if err != nil {
			s.MarkWorkerHealth("notification_"+string(channel), err)
			s.log.Error("claim notification outbox delivery", "channel", channel, "error", "notification outbox unavailable")
			if !waitForNotificationWork(ctx, wake) {
				return
			}
			continue
		}
		s.MarkWorkerHealth("notification_"+string(channel), nil)
		s.deliverNotification(ctx, delivery)
	}
}

func (s *Server) deliverNotification(workerCtx context.Context, delivery store.NotificationDelivery) {
	attemptCtx, cancel := context.WithTimeout(workerCtx, notificationAttemptTimeout)
	sender, settingsUpdatedAt, err := s.notificationSender(attemptCtx)
	if err == nil && !settingsUpdatedAt.Equal(delivery.SettingsUpdatedAt) {
		err = notification.ErrChannelDisabled
	}
	if err == nil {
		err = sender.SendChannel(attemptCtx, delivery.Channel, delivery.Event)
	}
	cancel()
	now := s.now().UTC()
	recordCtx, recordCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer recordCancel()
	if workerCtx.Err() != nil {
		if releaseErr := s.store.ReleaseNotificationDelivery(recordCtx, delivery, now); releaseErr != nil && !errors.Is(releaseErr, store.ErrConflict) {
			s.log.Error("release notification outbox delivery", "channel", delivery.Channel, "error", "notification outbox update failed")
		}
		return
	}
	if errors.Is(err, notification.ErrChannelDisabled) || errors.Is(err, store.ErrNotFound) {
		if completeErr := s.store.CancelNotificationDelivery(recordCtx, delivery, "channel disabled by administrator", now); completeErr != nil && !errors.Is(completeErr, store.ErrConflict) {
			s.log.Error("cancel notification outbox delivery", "channel", delivery.Channel, "error", "notification outbox update failed")
		}
		return
	}
	if err == nil {
		if completeErr := s.store.CompleteNotificationDelivery(recordCtx, delivery, true, now, now, notificationMaxAttempts, ""); completeErr != nil && !errors.Is(completeErr, store.ErrConflict) {
			s.log.Error("complete notification outbox delivery", "channel", delivery.Channel, "error", "notification outbox update failed")
		}
		return
	}
	publicError := "notification configuration unavailable"
	if sender != nil {
		// notification.Sender guarantees that delivery errors contain only a
		// fixed channel/stage/status classification, never endpoint or peer text.
		publicError = err.Error()
	}
	retryAt := now.Add(notificationRetryDelay(delivery.Attempts))
	maxAttempts := notificationMaxAttempts
	if sender != nil && !notification.IsRetryable(err) {
		maxAttempts = delivery.Attempts
	}
	if completeErr := s.store.CompleteNotificationDelivery(recordCtx, delivery, false, retryAt, now, maxAttempts, publicError); completeErr != nil && !errors.Is(completeErr, store.ErrConflict) {
		s.log.Error("reschedule notification outbox delivery", "channel", delivery.Channel, "error", "notification outbox update failed")
		return
	}
	s.log.Warn("notification delivery attempt failed", "channel", delivery.Channel, "eventType", delivery.Event.Type, "attempt", delivery.Attempts, "error", publicError)
}

func notificationRetryDelay(attempt int) time.Duration {
	delays := [...]time.Duration{5 * time.Second, 30 * time.Second, 2 * time.Minute, 10 * time.Minute, 30 * time.Minute}
	if attempt < 1 {
		return delays[0]
	}
	if attempt > len(delays) {
		return delays[len(delays)-1]
	}
	return delays[attempt-1]
}

func waitForNotificationWork(ctx context.Context, wake <-chan struct{}) bool {
	timer := time.NewTimer(notificationIdlePoll)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-wake:
		return true
	case <-timer.C:
		return true
	}
}

func (s *Server) wakeNotificationWorkers() {
	for _, wake := range []chan struct{}{s.notifyWebhookWake, s.notifySMTPWake} {
		select {
		case wake <- struct{}{}:
		default:
		}
	}
}
