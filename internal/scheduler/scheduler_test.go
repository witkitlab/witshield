package scheduler

import (
	"context"
	"github.com/witkitlab/witshield/internal/domain"
	"testing"
	"time"
)

type fakeStore struct {
	due      []domain.Schedule
	commands []domain.DeviceCommand
	next     time.Time
}

func (f *fakeStore) DueSchedules(context.Context, time.Time, int) ([]domain.Schedule, error) {
	return f.due, nil
}
func (f *fakeStore) MarkScheduleRun(_ context.Context, _ string, _ time.Time, _ time.Time, next time.Time) error {
	f.next = next
	return nil
}
func (f *fakeStore) EnqueueCommand(_ context.Context, c domain.DeviceCommand) error {
	f.commands = append(f.commands, c)
	return nil
}
func TestTick(t *testing.T) {
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	f := &fakeStore{due: []domain.Schedule{{ID: "s", DeviceID: "d", Kind: domain.ScheduleScan, Interval: time.Hour, NextRunAt: now.Add(-2 * time.Hour)}}}
	s := New(f, nil)
	s.now = func() time.Time { return now }
	if err := s.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(f.commands) != 1 || f.commands[0].Type != domain.CommandScan {
		t.Fatalf("%#v", f.commands)
	}
	if !f.next.After(now) {
		t.Fatal("next run is not in future")
	}
}
