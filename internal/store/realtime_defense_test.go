package store

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/witkitlab/witshield/internal/domain"
)

func TestAIInvestigationBudgetProtectsCriticalReserve(t *testing.T) {
	s, _, now := openReportCommandTestStore(t)
	policy := domain.AIInvestigationPolicy{Profile: domain.InvestigationBalanced, DailyTokenBudget: 1000, EmergencyReserveTokens: 500,
		ShareNetworkIndicators: true, ShareAccountNames: true, UpdatedAt: now}
	if err := s.PutAIInvestigationPolicy(context.Background(), policy); err != nil {
		t.Fatal(err)
	}
	if _, lane, err := s.ReserveAIInvestigationBudget(context.Background(), domain.SeverityHigh, 900, now); err != nil || lane != "regular" {
		t.Fatalf("regular reservation: lane=%q err=%v", lane, err)
	}
	if _, _, err := s.ReserveAIInvestigationBudget(context.Background(), domain.SeverityHigh, 200, now); !errors.Is(err, ErrAIBudgetExhausted) {
		t.Fatalf("non-critical request consumed reserve: %v", err)
	}
	usage, lane, err := s.ReserveAIInvestigationBudget(context.Background(), domain.SeverityCritical, 200, now)
	if err != nil || lane != "emergency" || usage.EmergencyTokensUsed != 200 {
		t.Fatalf("critical reserve unavailable: usage=%#v lane=%q err=%v", usage, lane, err)
	}
}

func TestSensorHealthTransitionCreatesOneCoverageIncident(t *testing.T) {
	s, deviceID, now := openReportCommandTestStore(t)
	active := domain.SensorHealth{SensorID: "process", Name: "高风险进程", Mode: "procfs", State: domain.SensorActive, CadenceSeconds: 10}
	if err := s.PutSensorHealth(context.Background(), deviceID, []domain.SensorHealth{active}, now); err != nil {
		t.Fatal(err)
	}
	failed := active
	failed.State, failed.Error = domain.SensorUnavailable, "permission denied"
	if err := s.PutSensorHealth(context.Background(), deviceID, []domain.SensorHealth{failed}, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := s.PutSensorHealth(context.Background(), deviceID, []domain.SensorHealth{failed}, now.Add(2*time.Minute)); err != nil {
		t.Fatal(err)
	}
	incidents, err := s.ListIncidents(context.Background(), deviceID, nil, 10)
	if err != nil || len(incidents) != 1 || incidents[0].Category != "sensor_health" || incidents[0].SignalCount != 1 {
		t.Fatalf("sensor transition was noisy or absent: incidents=%#v err=%v", incidents, err)
	}
	if err = s.PutSensorHealth(context.Background(), deviceID, []domain.SensorHealth{active}, now.Add(3*time.Minute)); err != nil {
		t.Fatal(err)
	}
	incidents, _ = s.ListIncidents(context.Background(), deviceID, nil, 10)
	if len(incidents) != 1 || incidents[0].Status != domain.IncidentMonitoring || incidents[0].SignalCount != 2 {
		t.Fatalf("sensor restoration did not advance the case: %#v", incidents)
	}
}
