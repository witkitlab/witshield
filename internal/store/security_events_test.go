package store

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/witkitlab/witshield/internal/domain"
)

func putTestDefensePolicy(t *testing.T, s *Store, deviceID string, now time.Time, autoBan bool, threshold int, window time.Duration) {
	t.Helper()
	if err := s.PutDefensePolicy(context.Background(), domain.DefensePolicy{
		DeviceID: deviceID, Enabled: true, AutoBan: autoBan,
		FailureThreshold: threshold, Window: window, BanDuration: 15 * time.Minute,
		MaxBansPerHour: 10, Allowlist: []string{"1.1.1.10"}, UpdatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
}

func processTestEvent(t *testing.T, s *Store, deviceID, id, source string, now time.Time) SecurityEventProcessOutcome {
	t.Helper()
	out, err := s.ProcessSecurityEvent(context.Background(), domain.SecurityEvent{
		ID: id, DeviceID: deviceID, Type: "ssh_auth_failure", SourceIP: source, OccurredAt: now,
	}, false, now)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestSecurityCorrelationSurvivesUnrelatedAuditRetention(t *testing.T) {
	s, deviceID, now := openReportCommandTestStore(t)
	putTestDefensePolicy(t, s, deviceID, now, false, 3, 5*time.Minute)
	processTestEvent(t, s, deviceID, "evt_target_1", "8.8.8.8", now)
	processTestEvent(t, s, deviceID, "evt_target_2", "8.8.8.8", now.Add(time.Second))

	// Force the two target audit rows out of the bounded 2,000-row history with
	// unrelated sources. Correlation uses its own bounded per-source projection.
	for i := 0; i < maxSecurityEventsPerDevice+1; i++ {
		source := fmt.Sprintf("11.%d.%d.1", i/256, i%256)
		processTestEvent(t, s, deviceID, fmt.Sprintf("evt_noise_%04d", i), source, now.Add(2*time.Second))
	}
	out := processTestEvent(t, s, deviceID, "evt_target_3", "8.8.8.8", now.Add(3*time.Second))
	if !out.Decision.Matched || !out.Decision.Simulated || !out.Recorded {
		t.Fatalf("retained correlation did not match: %#v", out)
	}
}

func TestSaturatedSecurityCorrelationRetainsCurrentSourceAndRecordsDegradedHealth(t *testing.T) {
	s, deviceID, now := openReportCommandTestStore(t)
	putTestDefensePolicy(t, s, deviceID, now, false, 3, 5*time.Minute)
	tx, err := s.db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	encodedTimes := fmt.Sprintf(`[%d,%d]`, now.Add(-2*time.Second).UnixMilli(), now.Add(-time.Second).UnixMilli())
	for i := 0; i < maxSecurityEventWindowsPerDevice; i++ {
		if _, err = tx.ExecContext(context.Background(), `INSERT INTO security_event_windows(device_id,type,source_ip,window_seconds,window_started_at,last_seen_at,event_count,event_times,window_ends_at) VALUES(?,?,?,?,?,?,?,?,?)`,
			deviceID, "ssh_auth_failure", fmt.Sprintf("source-%04d", i), 300, timeText(now.Add(-2*time.Second)), timeText(now), 2, encodedTimes, timeText(now.Add(5*time.Minute))); err != nil {
			_ = tx.Rollback()
			t.Fatal(err)
		}
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}

	const source = "8.8.8.99"
	processTestEvent(t, s, deviceID, "evt_capacity_current_1", source, now)
	processTestEvent(t, s, deviceID, "evt_capacity_current_2", source, now.Add(time.Second))
	out := processTestEvent(t, s, deviceID, "evt_capacity_current_3", source, now.Add(2*time.Second))
	if !out.Decision.Matched || !out.Decision.Simulated || !out.Recorded {
		t.Fatalf("saturated table silently disabled current-source defense: %#v", out)
	}
	var retained, currentCount int
	if err = s.db.QueryRowContext(context.Background(), `SELECT count(*) FROM security_event_windows WHERE device_id=?`, deviceID).Scan(&retained); err != nil {
		t.Fatal(err)
	}
	if err = s.db.QueryRowContext(context.Background(), `SELECT event_count FROM security_event_windows WHERE device_id=? AND type='ssh_auth_failure' AND source_ip=?`, deviceID, source).Scan(&currentCount); err != nil {
		t.Fatal(err)
	}
	if retained != maxSecurityEventWindowsPerDevice || currentCount != 3 {
		t.Fatalf("bounded saturated projection lost the current source: retained=%d current=%d", retained, currentCount)
	}
	health, err := s.ListSecurityEvents(context.Background(), deviceID, SecurityEventTypeCorrelationCapacityDegraded, nil, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(health.Items) != 1 || health.Items[0].ID != correlationCapacityEventID {
		t.Fatalf("capacity degradation was silent: %#v", health.Items)
	}
	var payload map[string]any
	if err = json.Unmarshal(health.Items[0].Payload, &payload); err != nil || payload["severity"] != "critical" || payload["status"] != "degraded" || payload["automaticActionEligible"] != false {
		t.Fatalf("degraded health signal is incomplete: payload=%s err=%v", health.Items[0].Payload, err)
	}
}

func TestSecurityCorrelationSlidingWindowNeverCountsStaleFailures(t *testing.T) {
	s, deviceID, now := openReportCommandTestStore(t)
	putTestDefensePolicy(t, s, deviceID, now, false, 3, 10*time.Second)
	processTestEvent(t, s, deviceID, "evt_window_1", "8.8.4.4", now)
	processTestEvent(t, s, deviceID, "evt_window_2", "8.8.4.4", now.Add(9*time.Second))
	out := processTestEvent(t, s, deviceID, "evt_window_3", "8.8.4.4", now.Add(10*time.Second+time.Millisecond))
	if out.Decision.Matched {
		t.Fatalf("stale fixed-window event caused an automatic-defense match: %#v", out.Decision)
	}
}

func TestSecurityCorrelationMatchesBurstAcrossEpochBoundary(t *testing.T) {
	s, deviceID, now := openReportCommandTestStore(t)
	putTestDefensePolicy(t, s, deviceID, now, false, 3, 10*time.Second)
	processTestEvent(t, s, deviceID, "evt_boundary_1", "8.8.4.6", now.Add(9*time.Second))
	processTestEvent(t, s, deviceID, "evt_boundary_2", "8.8.4.6", now.Add(10*time.Second))
	out := processTestEvent(t, s, deviceID, "evt_boundary_3", "8.8.4.6", now.Add(11*time.Second))
	if !out.Decision.Matched || !out.Decision.Simulated {
		t.Fatalf("sliding-window burst was split at an epoch boundary: %#v", out.Decision)
	}
}

func TestDelayedDeliveryUsesOccurrenceTimeForCorrelation(t *testing.T) {
	s, deviceID, now := openReportCommandTestStore(t)
	putTestDefensePolicy(t, s, deviceID, now, false, 3, 10*time.Minute)
	if _, err := s.ProcessSecurityEvent(context.Background(), domain.SecurityEvent{ID: "evt_delayed_1", DeviceID: deviceID, Type: "ssh_auth_failure", SourceIP: "8.8.4.5", OccurredAt: now}, false, now.Add(9*time.Minute)); err != nil {
		t.Fatal(err)
	}
	processTestEvent(t, s, deviceID, "evt_delayed_2", "8.8.4.5", now.Add(9*time.Minute))
	out := processTestEvent(t, s, deviceID, "evt_delayed_3", "8.8.4.5", now.Add(18*time.Minute))
	if out.Decision.Matched {
		t.Fatalf("events spanning two policy windows matched after delayed delivery: %#v", out.Decision)
	}
}

func TestEquivalentIPv6SourcesShareOneCorrelationWindow(t *testing.T) {
	s, deviceID, now := openReportCommandTestStore(t)
	putTestDefensePolicy(t, s, deviceID, now, false, 3, 5*time.Minute)
	processTestEvent(t, s, deviceID, "evt_ipv6_1", "2001:4860:4860:0:0:0:0:8888", now)
	processTestEvent(t, s, deviceID, "evt_ipv6_2", "2001:4860:4860::8888", now.Add(time.Second))
	out := processTestEvent(t, s, deviceID, "evt_ipv6_3", "2001:4860:4860:0::8888", now.Add(2*time.Second))
	if !out.Decision.Matched || !out.Decision.Simulated {
		t.Fatalf("equivalent IPv6 spellings bypassed correlation: %#v", out.Decision)
	}
}

func TestProtectedAutomaticBanTargetIsRecordedOnlyAsSimulation(t *testing.T) {
	s, deviceID, now := openReportCommandTestStore(t)
	putTestDefensePolicy(t, s, deviceID, now, true, 3, 5*time.Minute)
	processTestEvent(t, s, deviceID, "evt_private_1", "10.0.0.5", now)
	processTestEvent(t, s, deviceID, "evt_private_2", "10.0.0.5", now.Add(time.Second))
	out := processTestEvent(t, s, deviceID, "evt_private_3", "10.0.0.5", now.Add(2*time.Second))
	if !out.Decision.Matched || out.Decision.ShouldBan || !out.Decision.Simulated || !out.Recorded || out.ActionID != "" || out.CommandID != "" {
		t.Fatalf("protected target escaped simulation-only path: %#v", out)
	}
	var actual int
	if err := s.db.QueryRowContext(context.Background(), `SELECT count(*) FROM temporary_bans WHERE device_id=? AND simulated=0`, deviceID).Scan(&actual); err != nil {
		t.Fatal(err)
	}
	if actual != 0 {
		t.Fatalf("protected target consumed actual ban budget: %d", actual)
	}
}

func TestSecurityEventIDsAreScopedPerDevice(t *testing.T) {
	s, firstDevice, now := openReportCommandTestStore(t)
	const secondDevice = "dev_second"
	if _, err := s.db.ExecContext(context.Background(), `INSERT INTO devices(id,name,hostname,os,arch,agent_version,identity_key,status,enrolled_at,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)`, secondDevice, "second", "host2", "linux", "amd64", "test", "", string(domain.DeviceOffline), timeText(now), timeText(now), timeText(now)); err != nil {
		t.Fatal(err)
	}
	first := processTestEvent(t, s, firstDevice, "evt_shared", "8.8.8.8", now)
	second := processTestEvent(t, s, secondDevice, "evt_shared", "8.8.4.4", now)
	if !first.Inserted || !second.Inserted {
		t.Fatalf("cross-device event ID collision: first=%#v second=%#v", first, second)
	}
}

func TestListSecurityEventsUsesStableBoundedKeysetPagination(t *testing.T) {
	s, firstDevice, now := openReportCommandTestStore(t)
	const secondDevice = "dev_security_page_second"
	if _, err := s.db.ExecContext(context.Background(), `INSERT INTO devices(id,name,hostname,os,arch,agent_version,identity_key,status,enrolled_at,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)`, secondDevice, "second", "host2", "linux", "amd64", "test", "", string(domain.DeviceOffline), timeText(now), timeText(now), timeText(now)); err != nil {
		t.Fatal(err)
	}
	events := []domain.SecurityEvent{
		{ID: "evt_same", DeviceID: firstDevice, Type: "ssh_auth_failure_untrusted", SourceIP: "8.8.8.8", OccurredAt: now, Payload: []byte(`{"trust":"unverified"}`)},
		{ID: "evt_same", DeviceID: secondDevice, Type: "ssh_auth_failure_untrusted", SourceIP: "1.1.1.1", OccurredAt: now, Payload: []byte(`{"trust":"unverified"}`)},
		{ID: "evt_newer", DeviceID: firstDevice, Type: "ssh_auth_log_line_oversized_untrusted", OccurredAt: now.Add(time.Second), Payload: []byte(`{"reason":"discarded"}`)},
		{ID: "evt_older", DeviceID: firstDevice, Type: "ssh_auth_failure", SourceIP: "9.9.9.9", OccurredAt: now.Add(-time.Second)},
		{ID: "evt_oldest", DeviceID: secondDevice, Type: "ssh_auth_failure", SourceIP: "4.4.4.4", OccurredAt: now.Add(-2 * time.Second)},
	}
	for _, event := range events {
		inserted, err := s.AddSecurityEvent(context.Background(), event)
		if err != nil || !inserted {
			t.Fatalf("insert %s/%s: inserted=%v err=%v", event.DeviceID, event.ID, inserted, err)
		}
	}

	var cursor *SecurityEventCursor
	seen := map[string]bool{}
	var ordered []string
	for {
		page, err := s.ListSecurityEvents(context.Background(), "", "", cursor, 2)
		if err != nil {
			t.Fatal(err)
		}
		if len(page.Items) == 0 || len(page.Items) > 2 {
			t.Fatalf("unbounded or empty intermediate page: %#v", page)
		}
		for _, event := range page.Items {
			key := event.DeviceID + "/" + event.ID
			if seen[key] {
				t.Fatalf("duplicate event across keyset pages: %s", key)
			}
			seen[key] = true
			ordered = append(ordered, key)
		}
		if page.NextCursor == nil {
			break
		}
		cursor = page.NextCursor
	}
	if len(ordered) != len(events) || !strings.HasSuffix(ordered[0], "/evt_newer") || !strings.HasSuffix(ordered[len(ordered)-1], "/evt_oldest") {
		t.Fatalf("unexpected paginated order: %v", ordered)
	}
	filtered, err := s.ListSecurityEvents(context.Background(), firstDevice, "ssh_auth_failure_untrusted", nil, 1000)
	if err != nil {
		t.Fatal(err)
	}
	if len(filtered.Items) != 1 || filtered.NextCursor != nil || filtered.Items[0].DeviceID != firstDevice {
		t.Fatalf("filters or store-side limit normalization failed: %#v", filtered)
	}
}
