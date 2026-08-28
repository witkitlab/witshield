package store

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/witkitlab/witshield/internal/domain"
)

func TestRuntimeSignalsCreateGenericIncidentsWithoutAutomaticMutation(t *testing.T) {
	s, deviceID, now := openReportCommandTestStore(t)
	event := domain.SecurityEvent{ID: "evt_container_1", DeviceID: deviceID, Type: "container_runtime_anomaly", OccurredAt: now, Payload: json.RawMessage(`{"container":"api"}`)}
	outcome, err := s.ProcessSecurityEvent(context.Background(), event, false, now)
	if err != nil {
		t.Fatal(err)
	}
	if !outcome.Inserted || outcome.ActionID != "" || outcome.CommandID != "" {
		t.Fatalf("generic signal unexpectedly mutated the host: %#v", outcome)
	}
	items, err := s.ListIncidents(context.Background(), deviceID, nil, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 || items[0].Category != "container_runtime" || items[0].Status != domain.IncidentOpen || items[0].SignalCount != 1 {
		t.Fatalf("generic incident projection is incomplete: %#v", items)
	}
	replayed, err := s.ProcessSecurityEvent(context.Background(), event, false, now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if replayed.Inserted {
		t.Fatal("replayed event created a duplicate signal")
	}
	items, _ = s.ListIncidents(context.Background(), deviceID, nil, 10)
	if items[0].SignalCount != 1 {
		t.Fatalf("replay inflated incident count: %#v", items[0])
	}
}

func TestSSHNoiseIsPromotedOnlyAfterDeterministicThreshold(t *testing.T) {
	s, deviceID, now := openReportCommandTestStore(t)
	putTestDefensePolicy(t, s, deviceID, now, false, 3, 5*time.Minute)
	processTestEvent(t, s, deviceID, "evt_below_one", "8.8.8.8", now)
	processTestEvent(t, s, deviceID, "evt_below_two", "8.8.8.8", now.Add(time.Second))
	incidents, err := s.ListIncidents(context.Background(), deviceID, nil, 10)
	if err != nil || len(incidents) != 0 {
		t.Fatalf("below-threshold authentication noise became an incident: %#v err=%v", incidents, err)
	}
	outcome := processTestEvent(t, s, deviceID, "evt_threshold", "8.8.8.8", now.Add(2*time.Second))
	if !outcome.Decision.Matched {
		t.Fatal("deterministic SSH threshold did not match")
	}
	incidents, err = s.ListIncidents(context.Background(), deviceID, nil, 10)
	if err != nil || len(incidents) != 1 || incidents[0].SignalCount != 1 {
		t.Fatalf("threshold match did not create one bounded incident: %#v err=%v", incidents, err)
	}
	signals, err := s.ListIncidentSignals(context.Background(), incidents[0].ID, 10)
	if err != nil || len(signals) != 1 || !strings.Contains(string(signals[0].Payload), `"failureCount":3`) {
		t.Fatalf("promoted signal lacks correlation evidence: %#v err=%v", signals, err)
	}
}

func TestScannerFindingsCorrelateIntoOneDurableIncident(t *testing.T) {
	s, deviceID, now := openReportCommandTestStore(t)
	makeReport := func(id string, completed time.Time, severity domain.Severity) domain.Report {
		return domain.Report{ID: id, DeviceID: deviceID, StartedAt: completed.Add(-time.Minute), CompletedAt: completed, Score: 70,
			Summary: json.RawMessage(`{"checkErrors":[]}`), Findings: []domain.Finding{{ID: "fnd_" + id, Fingerprint: "stable-risk", Category: "permissions", Severity: severity, Title: "Sensitive file permissions changed", Description: "mode is unsafe", Evidence: "mode 0666", Status: domain.FindingOpen}}}
	}
	if err := s.SaveReport(context.Background(), makeReport("rpt_one", now, domain.SeverityMedium), now); err != nil {
		t.Fatal(err)
	}
	if err := s.SaveReport(context.Background(), makeReport("rpt_two", now.Add(time.Hour), domain.SeverityHigh), now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	items, err := s.ListIncidents(context.Background(), deviceID, nil, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 || items[0].SignalCount != 2 || items[0].Severity != domain.SeverityHigh {
		t.Fatalf("finding correlation did not preserve one escalating case: %#v", items)
	}
	signals, err := s.ListIncidentSignals(context.Background(), items[0].ID, 10)
	if err != nil || len(signals) != 2 {
		t.Fatalf("incident evidence is incomplete: signals=%#v err=%v", signals, err)
	}
}

func TestLegacySSHPolicySynchronizesCapabilityGrant(t *testing.T) {
	s, deviceID, now := openReportCommandTestStore(t)
	policy := domain.DefensePolicy{DeviceID: deviceID, Enabled: true, AutoBan: true, FailureThreshold: 10, Window: 5 * time.Minute, BanDuration: 15 * time.Minute, MaxBansPerHour: 7, Allowlist: []string{"203.0.113.8"}, UpdatedAt: now}
	if _, err := s.PutDefensePolicyAndCancelQueued(context.Background(), policy); err != nil {
		t.Fatal(err)
	}
	grants, err := s.ListPolicyGrants(context.Background(), deviceID, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(grants) < 1 || grants[0].Capability != "network.auth_bruteforce" || grants[0].Mode != domain.AutonomyAutoLowRisk || !grants[0].Enabled || grants[0].MaxActionsPerHour != 7 {
		t.Fatalf("legacy policy and capability grant drifted: %#v", grants)
	}
}

func TestInvestigationLifecycleCreatesAuditableResponsePlan(t *testing.T) {
	s, deviceID, now := openReportCommandTestStore(t)
	if _, err := s.ProcessSecurityEvent(context.Background(), domain.SecurityEvent{ID: "evt_file", DeviceID: deviceID, Type: "file_integrity_changed", OccurredAt: now}, false, now); err != nil {
		t.Fatal(err)
	}
	incidents, _ := s.ListIncidents(context.Background(), deviceID, nil, 10)
	investigation, err := s.CreateInvestigation(context.Background(), incidents[0].ID, "test", "test-model", now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	investigation.Status, investigation.Hypothesis, investigation.Conclusion, investigation.Confidence = domain.InvestigationCompleted, "configuration drift", "A protected file changed and needs review.", 80
	plan := &domain.ResponsePlan{Title: "Review and restore permissions", Rationale: "The deterministic signal identifies a supported target.", Risk: "medium", RequiresApproval: true,
		Steps: []domain.ResponseStep{{ID: "step_test", ActionType: "file_permission_repair", Title: "Restore mode", Rationale: "Return to the approved mode.", Parameters: json.RawMessage(`{"path":"/etc/witshield/test","mode":"600"}`), Risk: "medium", RequiresApproval: true}}}
	if err = s.CompleteInvestigation(context.Background(), investigation, plan, now.Add(2*time.Minute)); err != nil {
		t.Fatal(err)
	}
	incident, err := s.Incident(context.Background(), incidents[0].ID)
	if err != nil || incident.Status != domain.IncidentAwaitingApproval {
		t.Fatalf("incident did not advance to approval: %#v err=%v", incident, err)
	}
	plans, err := s.ListResponsePlans(context.Background(), incident.ID, 10)
	if err != nil || len(plans) != 1 || len(plans[0].Steps) != 1 {
		t.Fatalf("response plan was not retained: %#v err=%v", plans, err)
	}
	timeline, err := s.ListIncidentTimeline(context.Background(), incident.ID, 20)
	if err != nil || len(timeline) < 3 {
		t.Fatalf("investigation timeline is incomplete: %#v err=%v", timeline, err)
	}
}

func TestNewSignalReopensMonitoredIncidentForContinuousInvestigation(t *testing.T) {
	s, deviceID, now := openReportCommandTestStore(t)
	first := domain.SecurityEvent{ID: "evt_monitor_one", DeviceID: deviceID, Type: "service_definition_changed", OccurredAt: now, Payload: json.RawMessage(`{"path":"/etc/systemd/system/api.service"}`)}
	if _, err := s.ProcessSecurityEvent(context.Background(), first, false, now); err != nil {
		t.Fatal(err)
	}
	incidents, _ := s.ListIncidents(context.Background(), deviceID, nil, 10)
	investigation, err := s.CreateInvestigation(context.Background(), incidents[0].ID, "test", "test-model", now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	investigation.Status, investigation.Hypothesis, investigation.Conclusion, investigation.Confidence = domain.InvestigationCompleted, "service changed", "change recorded", 75
	if err = s.CompleteInvestigation(context.Background(), investigation, nil, now.Add(2*time.Minute)); err != nil {
		t.Fatal(err)
	}
	second := first
	second.ID, second.OccurredAt = "evt_monitor_two", now.Add(3*time.Minute)
	if _, err = s.ProcessSecurityEvent(context.Background(), second, false, now.Add(3*time.Minute)); err != nil {
		t.Fatal(err)
	}
	incident, err := s.Incident(context.Background(), incidents[0].ID)
	if err != nil || incident.Status != domain.IncidentOpen || incident.SignalCount != 2 {
		t.Fatalf("new evidence did not reopen the monitored incident: %#v err=%v", incident, err)
	}
}

func TestStaleInvestigationIsRecoveredAfterControllerRestart(t *testing.T) {
	s, deviceID, now := openReportCommandTestStore(t)
	if _, err := s.ProcessSecurityEvent(context.Background(), domain.SecurityEvent{ID: "evt_stale", DeviceID: deviceID, Type: "file_integrity_changed", OccurredAt: now}, false, now); err != nil {
		t.Fatal(err)
	}
	incidents, _ := s.ListIncidents(context.Background(), deviceID, nil, 10)
	if _, err := s.CreateInvestigation(context.Background(), incidents[0].ID, "test", "test-model", now); err != nil {
		t.Fatal(err)
	}
	recovered, err := s.RecoverStaleInvestigations(context.Background(), now.Add(time.Minute), now.Add(2*time.Minute))
	if err != nil || recovered != 1 {
		t.Fatalf("recovered=%d err=%v", recovered, err)
	}
	incident, err := s.Incident(context.Background(), incidents[0].ID)
	if err != nil || incident.Status != domain.IncidentOpen {
		t.Fatalf("stale incident was not reopened: %#v err=%v", incident, err)
	}
	investigations, err := s.ListInvestigations(context.Background(), incident.ID, 10)
	if err != nil || len(investigations) != 1 || investigations[0].Status != domain.InvestigationFailed {
		t.Fatalf("stale investigation was not failed: %#v err=%v", investigations, err)
	}
}

func TestPolicyGrantRejectsCrossCapabilityOrDuplicateActions(t *testing.T) {
	s, deviceID, now := openReportCommandTestStore(t)
	grant := domain.PolicyGrant{DeviceID: deviceID, Capability: "file.integrity", Enabled: true, Mode: domain.AutonomyAssist, MaxActionsPerHour: 5, UpdatedAt: now}
	grant.AllowedActionTypes = []string{"package_security_upgrade"}
	if err := s.PutPolicyGrant(context.Background(), grant); err == nil {
		t.Fatal("cross-capability action type was accepted")
	}
	grant.AllowedActionTypes = []string{"file_permission_repair", "file_permission_repair"}
	if err := s.PutPolicyGrant(context.Background(), grant); err == nil {
		t.Fatal("duplicate action type was accepted")
	}
	grant.AllowedActionTypes = []string{"file_permission_repair"}
	if err := s.PutPolicyGrant(context.Background(), grant); err != nil {
		t.Fatalf("valid capability grant rejected: %v", err)
	}
}

func TestResponsePlanStepCreatesExactlyOneActionAndTracksVerifiedOutcome(t *testing.T) {
	s, deviceID, now := openReportCommandTestStore(t)
	if _, err := s.ProcessSecurityEvent(context.Background(), domain.SecurityEvent{ID: "evt_plan", DeviceID: deviceID, Type: "file_integrity_changed", OccurredAt: now}, false, now); err != nil {
		t.Fatal(err)
	}
	incidents, _ := s.ListIncidents(context.Background(), deviceID, nil, 10)
	investigation, err := s.CreateInvestigation(context.Background(), incidents[0].ID, "test", "test-model", now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	investigation.Status, investigation.Hypothesis, investigation.Conclusion, investigation.Confidence = domain.InvestigationCompleted, "drift", "permission drift", 90
	params := json.RawMessage(`{"path":"/etc/witshield/test","mode":"600"}`)
	plan := &domain.ResponsePlan{Title: "repair", Rationale: "restore", Risk: "medium", RequiresApproval: true, Steps: []domain.ResponseStep{{ID: "step_one", ActionType: "file_permission_repair", Title: "repair", Rationale: "restore", Parameters: params, Risk: "medium", RequiresApproval: true}}}
	if err = s.CompleteInvestigation(context.Background(), investigation, plan, now.Add(2*time.Minute)); err != nil {
		t.Fatal(err)
	}
	action := domain.Action{ID: "act_from_plan", DeviceID: deviceID, Type: "file_permission_repair", Parameters: params, Preview: json.RawMessage(`{"summary":"repair"}`), Status: domain.ActionDraft, CreatedAt: now.Add(3 * time.Minute), UpdatedAt: now.Add(3 * time.Minute)}
	if err = s.CreateActionFromResponsePlan(context.Background(), plan.ID, "step_one", action, "nonce-hash", "admin", 5); err != nil {
		t.Fatal(err)
	}
	duplicate := action
	duplicate.ID = "act_duplicate"
	if err = s.CreateActionFromResponsePlan(context.Background(), plan.ID, "step_one", duplicate, "other-hash", "admin", 5); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate response step action err=%v", err)
	}
	storedPlan, err := s.ResponsePlan(context.Background(), plan.ID)
	if err != nil || storedPlan.Status != domain.ResponsePlanApproved || storedPlan.Steps[0].ActionID != action.ID {
		t.Fatalf("prepared plan=%#v err=%v", storedPlan, err)
	}
	tx, err := s.db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(`UPDATE actions SET status=? WHERE id=?`, string(domain.ActionSucceeded), action.ID); err != nil {
		t.Fatal(err)
	}
	if err = syncResponsePlanForActionTx(context.Background(), tx, action.ID, now.Add(4*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
	storedPlan, _ = s.ResponsePlan(context.Background(), plan.ID)
	incident, _ := s.Incident(context.Background(), incidents[0].ID)
	if storedPlan.Status != domain.ResponsePlanCompleted || incident.Status != domain.IncidentMonitoring {
		t.Fatalf("verified response was not projected: plan=%s incident=%s", storedPlan.Status, incident.Status)
	}
}
