package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/witkitlab/witshield/internal/action"
	"github.com/witkitlab/witshield/internal/defense"
	"github.com/witkitlab/witshield/internal/domain"
	"github.com/witkitlab/witshield/internal/ids"
)

const maxSecurityEventsPerDevice = 2_000
const maxActiveSimulationsPerDevice = 1_000
const maxSecurityEventWindowsPerDevice = 2_000
const maxDefenseSimulationsPerHour = 100

const SecurityEventTypeCorrelationCapacityDegraded = "defense_correlation_capacity_degraded"

const correlationCapacityEventID = "evt_defense_correlation_capacity"

const maxSecurityEventsPageSize = 100

type SecurityEventCursor struct {
	OccurredAt time.Time
	DeviceID   string
	ID         string
}

type SecurityEventPage struct {
	Items      []domain.SecurityEvent
	NextCursor *SecurityEventCursor
}

type SecurityEventProcessOutcome struct {
	Inserted           bool
	Recorded           bool
	Decision           defense.Evaluation
	ActionID           string
	CommandID          string
	BanID              string
	Notification       *domain.NotificationEvent
	NotificationQueued int
}

// ListSecurityEvents returns a stable, keyset-paginated administrative audit
// view. The database retains a bounded number of events per device, while the
// API additionally caps every response to prevent an accidental full-history
// read as the fleet grows.
func (s *Store) ListSecurityEvents(ctx context.Context, deviceID, eventType string, before *SecurityEventCursor, limit int) (SecurityEventPage, error) {
	if limit <= 0 || limit > maxSecurityEventsPageSize {
		limit = 50
	}
	query := `SELECT id,device_id,type,source_ip,occurred_at,payload FROM security_events WHERE 1=1`
	args := []any{}
	if deviceID != "" {
		query += ` AND device_id=?`
		args = append(args, deviceID)
	}
	if eventType != "" {
		query += ` AND type=?`
		args = append(args, eventType)
	}
	if before != nil {
		query += ` AND (occurred_at<? OR (occurred_at=? AND device_id<?) OR (occurred_at=? AND device_id=? AND id<?))`
		occurred := timeText(before.OccurredAt)
		args = append(args, occurred, occurred, before.DeviceID, occurred, before.DeviceID, before.ID)
	}
	query += ` ORDER BY occurred_at DESC,device_id DESC,id DESC LIMIT ?`
	args = append(args, limit+1)
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return SecurityEventPage{}, err
	}
	defer rows.Close()
	items := make([]domain.SecurityEvent, 0, limit+1)
	for rows.Next() {
		var item domain.SecurityEvent
		var occurred, payload string
		if err = rows.Scan(&item.ID, &item.DeviceID, &item.Type, &item.SourceIP, &occurred, &payload); err != nil {
			return SecurityEventPage{}, err
		}
		item.OccurredAt, err = parseTime(occurred)
		if err != nil {
			return SecurityEventPage{}, err
		}
		item.Payload = json.RawMessage(payload)
		items = append(items, item)
	}
	if err = rows.Err(); err != nil {
		return SecurityEventPage{}, err
	}
	page := SecurityEventPage{Items: items}
	if len(items) > limit {
		page.Items = items[:limit]
		last := page.Items[len(page.Items)-1]
		page.NextCursor = &SecurityEventCursor{OccurredAt: last.OccurredAt, DeviceID: last.DeviceID, ID: last.ID}
	}
	return page, nil
}

// ProcessSecurityEvent commits event de-duplication and any policy-authorized
// action in one transaction. A retry after a lost response therefore observes
// the already committed event/action pair; it can never leave an event stored
// but permanently skip its automatic-defense decision.
func (s *Store) ProcessSecurityEvent(ctx context.Context, event domain.SecurityEvent, observerOnly bool, now time.Time) (SecurityEventProcessOutcome, error) {
	var out SecurityEventProcessOutcome
	if len(event.Payload) == 0 {
		event.Payload = json.RawMessage(`{}`)
	}
	parsedSource, sourceErr := netip.ParseAddr(strings.TrimSpace(event.SourceIP))
	if sourceErr == nil && parsedSource.Zone() == "" {
		event.SourceIP = parsedSource.Unmap().String()
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return out, err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO security_events(id,device_id,type,source_ip,occurred_at,payload) VALUES(?,?,?,?,?,?)`, event.ID, event.DeviceID, event.Type, event.SourceIP, timeText(event.OccurredAt), string(event.Payload))
	if err != nil {
		return out, err
	}
	inserted, err := result.RowsAffected()
	if err != nil {
		return out, err
	}
	if inserted == 0 {
		return out, tx.Commit()
	}
	out.Inserted = true
	signal, correlationKey := signalFromSecurityEvent(event, now)
	if _, _, err = s.upsertSignalIncidentTx(ctx, tx, signal, correlationKey); err != nil {
		return out, err
	}
	if _, err = tx.ExecContext(ctx, `DELETE FROM security_events WHERE device_id=? AND id IN (
		SELECT id FROM security_events WHERE device_id=? ORDER BY occurred_at DESC,rowid DESC LIMIT -1 OFFSET ?
	)`, event.DeviceID, event.DeviceID, maxSecurityEventsPerDevice); err != nil {
		return out, err
	}
	if event.Type != "ssh_auth_failure" || sourceErr != nil || parsedSource.Zone() != "" {
		return out, tx.Commit()
	}
	policy, err := defensePolicyTx(ctx, tx, event.DeviceID, now)
	if err != nil {
		return out, err
	}
	var failureCount, recentAttempts, active int
	if !event.OccurredAt.Before(now.Add(-policy.Window)) {
		failureCount, err = incrementSecurityEventWindowTx(ctx, tx, event.DeviceID, event.Type, event.SourceIP, policy.Window, event.OccurredAt, now)
		if err != nil {
			return out, err
		}
	}
	if err = tx.QueryRowContext(ctx, `SELECT count(*) FROM temporary_bans WHERE device_id=? AND simulated=0 AND created_at>=?`, event.DeviceID, timeText(now.Add(-time.Hour))).Scan(&recentAttempts); err != nil {
		return out, err
	}
	if err = tx.QueryRowContext(ctx, `SELECT count(*) FROM temporary_bans WHERE device_id=? AND source_ip=? AND (status='pending' OR (status IN ('active','indeterminate') AND expires_at>?))`, event.DeviceID, event.SourceIP, timeText(now)).Scan(&active); err != nil {
		return out, err
	}
	out.Decision = defense.Evaluate(policy, event.SourceIP, failureCount, recentAttempts, active > 0, now)
	if !out.Decision.Matched || out.Decision.ExpiresAt == nil {
		return out, tx.Commit()
	}
	if _, targetErr := action.ValidateTemporaryIPBanTarget(event.SourceIP); targetErr != nil && out.Decision.ShouldBan {
		out.Decision.ShouldBan = false
		out.Decision.Simulated = true
		out.Decision.Reason += "; target is protected from automatic firewall changes"
	}
	if observerOnly && out.Decision.ShouldBan {
		out.Decision.ShouldBan = false
		out.Decision.Simulated = true
		out.Decision.Reason += "; observer-only device recorded a simulation"
	}
	ban := domain.TemporaryBan{ID: ids.New("ban"), DeviceID: event.DeviceID, SourceIP: event.SourceIP, Reason: out.Decision.Reason, ExpiresAt: *out.Decision.ExpiresAt, CreatedAt: now.UTC(), Simulated: out.Decision.Simulated}
	if out.Decision.Simulated {
		var existing, activeSimulations, recentSimulations int
		if err = tx.QueryRowContext(ctx, `SELECT count(*) FROM temporary_bans WHERE device_id=? AND source_ip=? AND simulated=1 AND status='simulated' AND expires_at>?`, event.DeviceID, event.SourceIP, timeText(now)).Scan(&existing); err != nil {
			return out, err
		}
		if existing > 0 {
			return out, tx.Commit()
		}
		if err = tx.QueryRowContext(ctx, `SELECT count(*) FROM temporary_bans WHERE device_id=? AND simulated=1 AND created_at>=?`, event.DeviceID, timeText(now.Add(-time.Hour))).Scan(&recentSimulations); err != nil {
			return out, err
		}
		if recentSimulations >= maxDefenseSimulationsPerHour {
			out.Decision.Reason += "; simulation audit rate limit reached"
			out.Decision.ExpiresAt = nil
			return out, tx.Commit()
		}
		if err = tx.QueryRowContext(ctx, `SELECT count(*) FROM temporary_bans WHERE device_id=? AND simulated=1 AND status='simulated' AND expires_at>?`, event.DeviceID, timeText(now)).Scan(&activeSimulations); err != nil {
			return out, err
		}
		if activeSimulations >= maxActiveSimulationsPerDevice {
			out.Decision.Reason += "; simulation retention limit reached"
			out.Decision.ExpiresAt = nil
			return out, tx.Commit()
		}
		if _, err = tx.ExecContext(ctx, `INSERT INTO temporary_bans(id,device_id,action_id,source_ip,reason,expires_at,created_at,simulated,status) VALUES(?,?,?,?,?,?,?,?,?)`, ban.ID, ban.DeviceID, "", ban.SourceIP, ban.Reason, timeText(ban.ExpiresAt), timeText(ban.CreatedAt), true, "simulated"); err != nil {
			return out, err
		}
		out.Recorded, out.BanID = true, ban.ID
		notificationEvent := domain.NotificationEvent{ID: "defense:" + ban.ID, Type: "defense_event", Severity: domain.SeverityHigh, DeviceID: event.DeviceID, Title: "SSH brute-force policy matched", Message: fmt.Sprintf("Source %s matched the SSH defense policy. %s", event.SourceIP, out.Decision.Reason), OccurredAt: now.UTC()}
		out.NotificationQueued, err = enqueueNotificationTx(ctx, tx, notificationEvent, now)
		if err != nil {
			return SecurityEventProcessOutcome{}, err
		}
		out.Notification = &notificationEvent
		if err = tx.Commit(); err != nil {
			return SecurityEventProcessOutcome{}, err
		}
		return out, nil
	}
	if !out.Decision.ShouldBan {
		return out, tx.Commit()
	}
	cooldown := policy.Window
	if cooldown > 5*time.Minute {
		cooldown = 5 * time.Minute
	}
	var recentSourceAttempts int
	if err = tx.QueryRowContext(ctx, `SELECT count(*) FROM temporary_bans WHERE device_id=? AND source_ip=? AND simulated=0 AND created_at>=?`, event.DeviceID, event.SourceIP, timeText(now.Add(-cooldown))).Scan(&recentSourceAttempts); err != nil {
		return out, err
	}
	if recentSourceAttempts > 0 {
		out.Decision.ShouldBan = false
		out.Decision.ExpiresAt = nil
		out.Decision.Reason = "source is in automatic-action retry cooldown"
		return out, tx.Commit()
	}
	params, _ := json.Marshal(action.TemporaryIPBanParams{Address: event.SourceIP, TTLSeconds: int(policy.BanDuration / time.Second), CurrentAdminIP: policyAdminIP(policy.Allowlist), Reason: "WitShield SSH brute-force policy"})
	actionID, commandID := ids.New("act"), ids.New("cmd")
	preview, _ := json.Marshal(map[string]any{"summary": "SSH brute-force policy authorized a temporary IP ban", "sourceIp": event.SourceIP, "ttlSeconds": int(policy.BanDuration / time.Second), "triggerCount": failureCount})
	approvedAt := now.UTC()
	policyAction := domain.Action{ID: actionID, DeviceID: event.DeviceID, Type: string(action.TypeTemporaryIPBan), Parameters: params, Preview: preview, Status: domain.ActionApproved, ApprovedBy: "policy:ssh_bruteforce", ApprovedAt: &approvedAt, CreatedAt: approvedAt, UpdatedAt: approvedAt}
	payload, _ := json.Marshal(map[string]any{"actionId": actionID, "type": action.TypeTemporaryIPBan, "parameters": json.RawMessage(params), "policyAuthorized": true})
	command := domain.DeviceCommand{ID: commandID, DeviceID: event.DeviceID, Type: domain.CommandExecuteAction, Payload: payload, CreatedAt: approvedAt}
	ban.ActionID, ban.Simulated = actionID, false
	if err = insertPolicyActionAndEnqueue(ctx, tx, policyAction, command, ban, "policy:ssh_bruteforce"); err != nil {
		return out, err
	}
	out.Recorded, out.ActionID, out.CommandID, out.BanID = true, actionID, commandID, ban.ID
	notificationEvent := domain.NotificationEvent{ID: "defense:" + ban.ID, Type: "defense_event", Severity: domain.SeverityHigh, DeviceID: event.DeviceID, Title: "SSH brute-force policy matched", Message: fmt.Sprintf("Source %s matched the SSH defense policy. %s", event.SourceIP, out.Decision.Reason), OccurredAt: now.UTC()}
	out.NotificationQueued, err = enqueueNotificationTx(ctx, tx, notificationEvent, now)
	if err != nil {
		return SecurityEventProcessOutcome{}, err
	}
	out.Notification = &notificationEvent
	if err = tx.Commit(); err != nil {
		return SecurityEventProcessOutcome{}, err
	}
	return out, nil
}

// incrementSecurityEventWindowTx maintains an exact, bounded sliding window per
// source. Unlike the audit-event retention table, correlation for one noisy
// source cannot be displaced by unrelated addresses. Signed occurrence times
// are pruned against Controller time so delayed and out-of-order delivery can
// neither combine stale failures nor evade a burst around a fixed boundary.
func incrementSecurityEventWindowTx(ctx context.Context, tx *sql.Tx, deviceID, eventType, sourceIP string, window time.Duration, occurredAt, now time.Time) (int, error) {
	windowSeconds := int64(window / time.Second)
	if _, err := tx.ExecContext(ctx, `DELETE FROM security_event_windows WHERE device_id=? AND window_ends_at<>'' AND window_ends_at<=?`, deviceID, timeText(now)); err != nil {
		return 0, err
	}
	var storedWindow int64
	var encodedTimes string
	err := tx.QueryRowContext(ctx, `SELECT window_seconds,event_times FROM security_event_windows WHERE device_id=? AND type=? AND source_ip=?`, deviceID, eventType, sourceIP).Scan(&storedWindow, &encodedTimes)
	var samples []int64
	if err == nil && storedWindow == windowSeconds {
		if err = json.Unmarshal([]byte(encodedTimes), &samples); err != nil {
			return 0, err
		}
	} else if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return 0, err
	}
	cutoff := now.Add(-window).UnixMilli()
	kept := samples[:0]
	for _, sample := range samples {
		if sample >= cutoff {
			kept = append(kept, sample)
		}
	}
	kept = append(kept, occurredAt.UTC().UnixMilli())
	sort.Slice(kept, func(i, j int) bool { return kept[i] < kept[j] })
	if len(kept) > defense.MaxFailureThreshold {
		kept = append([]int64(nil), kept[len(kept)-defense.MaxFailureThreshold:]...)
	}
	encoded, err := json.Marshal(kept)
	if err != nil {
		return 0, err
	}
	startedAt := occurredAt.UTC()
	endsAt := occurredAt.UTC().Add(window)
	if len(kept) > 0 {
		startedAt = time.UnixMilli(kept[0]).UTC()
		endsAt = time.UnixMilli(kept[len(kept)-1]).UTC().Add(window)
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO security_event_windows(device_id,type,source_ip,window_seconds,window_started_at,last_seen_at,event_count,event_times,window_ends_at) VALUES(?,?,?,?,?,?,?,?,?)
		ON CONFLICT(device_id,type,source_ip) DO UPDATE SET window_seconds=excluded.window_seconds,window_started_at=excluded.window_started_at,last_seen_at=excluded.last_seen_at,event_count=excluded.event_count,event_times=excluded.event_times,window_ends_at=excluded.window_ends_at`, deviceID, eventType, sourceIP, windowSeconds, timeText(startedAt), timeText(now), len(kept), string(encoded), timeText(endsAt)); err != nil {
		return 0, err
	}
	var windowCount int
	if err = tx.QueryRowContext(ctx, `SELECT count(*) FROM security_event_windows WHERE device_id=?`, deviceID).Scan(&windowCount); err != nil {
		return 0, err
	}
	if windowCount >= maxSecurityEventWindowsPerDevice {
		if err = recordCorrelationCapacityDegradedTx(ctx, tx, deviceID, windowCount, now); err != nil {
			return 0, err
		}
	}
	// The source currently being evaluated is reserved before pruning. Without
	// this exclusion, 2,000 near-threshold rows can cause every first event from
	// a new source to be immediately evicted, silently disabling correlation for
	// that source forever.
	if _, err = tx.ExecContext(ctx, `DELETE FROM security_event_windows WHERE device_id=? AND rowid IN (
		SELECT rowid FROM security_event_windows
		WHERE device_id=? AND NOT (type=? AND source_ip=?)
		ORDER BY event_count DESC,last_seen_at DESC,rowid DESC LIMIT -1 OFFSET ?
	)`, deviceID, deviceID, eventType, sourceIP, maxSecurityEventWindowsPerDevice-1); err != nil {
		return 0, err
	}
	return len(kept), nil
}

func recordCorrelationCapacityDegradedTx(ctx context.Context, tx *sql.Tx, deviceID string, observedWindows int, now time.Time) error {
	payload, err := json.Marshal(map[string]any{
		"status":                  "degraded",
		"severity":                "critical",
		"automaticActionEligible": false,
		"capacity":                maxSecurityEventWindowsPerDevice,
		"observedWindows":         observedWindows,
		"reason":                  "SSH source-correlation capacity was reached; lower-priority historical source windows may be evicted while the currently observed source remains protected",
	})
	if err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO security_events(id,device_id,type,source_ip,occurred_at,payload) VALUES(?,?,?,?,?,?)
		ON CONFLICT(device_id,id) DO UPDATE SET type=excluded.type,source_ip=excluded.source_ip,occurred_at=excluded.occurred_at,payload=excluded.payload`,
		correlationCapacityEventID, deviceID, SecurityEventTypeCorrelationCapacityDegraded, "", timeText(now), string(payload)); err != nil {
		return err
	}
	// Keep the health signal inside the same 2,000-row audit bound, reserving a
	// slot for it instead of allowing the next noisy event to erase it.
	_, err = tx.ExecContext(ctx, `DELETE FROM security_events WHERE device_id=? AND id<>? AND id IN (
		SELECT id FROM security_events WHERE device_id=? AND id<>? ORDER BY occurred_at DESC,rowid DESC LIMIT -1 OFFSET ?
	)`, deviceID, correlationCapacityEventID, deviceID, correlationCapacityEventID, maxSecurityEventsPerDevice-1)
	return err
}

func defensePolicyTx(ctx context.Context, tx *sql.Tx, deviceID string, now time.Time) (domain.DefensePolicy, error) {
	var policy domain.DefensePolicy
	var windowSeconds, banSeconds int64
	var allowlist, updated string
	err := tx.QueryRowContext(ctx, `SELECT device_id,enabled,emergency_stop,auto_ban,failure_threshold,window_seconds,ban_duration_seconds,max_bans_per_hour,allowlist,updated_at FROM defense_policies WHERE device_id=?`, deviceID).Scan(&policy.DeviceID, &policy.Enabled, &policy.EmergencyStop, &policy.AutoBan, &policy.FailureThreshold, &windowSeconds, &banSeconds, &policy.MaxBansPerHour, &allowlist, &updated)
	if errors.Is(err, sql.ErrNoRows) {
		return defaultPolicy(deviceID, now), nil
	}
	if err != nil {
		return policy, err
	}
	policy.Window = time.Duration(windowSeconds) * time.Second
	policy.WindowText = policy.Window.String()
	policy.BanDuration = time.Duration(banSeconds) * time.Second
	policy.BanDurationText = policy.BanDuration.String()
	if err = json.Unmarshal([]byte(allowlist), &policy.Allowlist); err != nil {
		return policy, err
	}
	policy.UpdatedAt, err = parseTime(updated)
	return policy, err
}

func policyAdminIP(entries []string) string {
	for _, entry := range entries {
		if ip := net.ParseIP(entry); ip != nil && !ip.IsLoopback() && !ip.IsUnspecified() {
			return ip.String()
		}
		if _, network, err := net.ParseCIDR(entry); err == nil && !network.IP.IsLoopback() && !network.IP.IsUnspecified() {
			return network.IP.String()
		}
	}
	return "127.0.0.1"
}
