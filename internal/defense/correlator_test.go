package defense

import (
	"github.com/witkitlab/witshield/internal/domain"
	"testing"
	"time"
)

func policy() domain.DefensePolicy {
	return domain.DefensePolicy{Enabled: true, AutoBan: true, FailureThreshold: 5, Window: time.Minute, BanDuration: 15 * time.Minute, MaxBansPerHour: 2, Allowlist: []string{"10.0.0.0/8"}}
}
func TestEvaluate(t *testing.T) {
	now := time.Now()
	x := Evaluate(policy(), "203.0.113.4", 5, 0, false, now)
	if !x.ShouldBan || !x.Matched || x.ExpiresAt == nil {
		t.Fatalf("%#v", x)
	}
	x = Evaluate(policy(), "10.1.2.3", 99, 0, false, now)
	if x.ShouldBan || x.Reason != "source is allowlisted" {
		t.Fatalf("%#v", x)
	}
}
func TestSafetyStops(t *testing.T) {
	p := policy()
	p.EmergencyStop = true
	if x := Evaluate(p, "203.0.113.1", 99, 0, false, time.Now()); x.ShouldBan {
		t.Fatal("ban during emergency stop")
	}
	p.EmergencyStop = false
	if x := Evaluate(p, "203.0.113.1", 99, 2, false, time.Now()); x.ShouldBan {
		t.Fatal("ban above rate limit")
	}
}
func TestSimulation(t *testing.T) {
	p := policy()
	p.AutoBan = false
	x := Evaluate(p, "203.0.113.1", 5, 0, false, time.Now())
	if !x.Matched || !x.Simulated || x.ShouldBan {
		t.Fatalf("%#v", x)
	}
}
