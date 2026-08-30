package scheduler

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"time"

	"github.com/witkitlab/witshield/internal/domain"
	"github.com/witkitlab/witshield/internal/ids"
	"github.com/witkitlab/witshield/internal/store"
)

type Store interface {
	DueSchedules(context.Context, time.Time, int) ([]domain.Schedule, error)
	MarkScheduleRun(context.Context, string, time.Time, time.Time, time.Time) error
	EnqueueCommand(context.Context, domain.DeviceCommand) error
}
type Scheduler struct {
	store    Store
	interval time.Duration
	log      *slog.Logger
	now      func() time.Time
	observer func(error)
}

func New(st Store, log *slog.Logger) *Scheduler {
	if log == nil {
		log = slog.Default()
	}
	return &Scheduler{store: st, interval: 15 * time.Second, log: log, now: time.Now}
}
func (s *Scheduler) SetObserver(observer func(error)) { s.observer = observer }
func (s *Scheduler) Run(ctx context.Context) error {
	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()
	for {
		err := s.Tick(ctx)
		if s.observer != nil {
			s.observer(err)
		}
		if err != nil {
			s.log.Error("schedule tick failed", "error", err)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}
func (s *Scheduler) Tick(ctx context.Context) error {
	now := s.now().UTC()
	due, err := s.store.DueSchedules(ctx, now, 100)
	if err != nil {
		return err
	}
	var errs []error
	for _, x := range due {
		payload, _ := json.Marshal(map[string]any{"scheduleId": x.ID, "requestedAt": now})
		cmd := domain.DeviceCommand{ID: ids.New("cmd"), DeviceID: x.DeviceID, Type: domain.CommandScan, Payload: payload, CreatedAt: now}
		if err = s.store.EnqueueCommand(ctx, cmd); err != nil {
			errs = append(errs, err)
			continue
		}
		next := x.NextRunAt
		for !next.After(now) {
			next = next.Add(x.Interval)
		}
		if err = s.store.MarkScheduleRun(ctx, x.ID, x.NextRunAt, now, next); err != nil && !errors.Is(err, store.ErrConflict) {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}
