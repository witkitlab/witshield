package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/witkitlab/witshield/internal/domain"
	"github.com/witkitlab/witshield/internal/ids"
)

const (
	maxSignalsPerDevice          = 10_000
	maxIncidentsPerDevice        = 2_000
	maxActiveIncidentsPerDevice  = 1_000
	maxTimelineEventsPerIncident = 2_000
)

var supportedPolicyCapabilities = map[string]struct{}{
	"network.auth_bruteforce":   {},
	"identity.persistence":      {},
	"workload.runtime":          {},
	"file.integrity":            {},
	"vulnerability.remediation": {},
}

var allowedPolicyActions = map[string]map[string]struct{}{
	"network.auth_bruteforce":   {"temporary_ip_ban": {}},
	"identity.persistence":      {"ssh_password_hardening": {}},
	"workload.runtime":          {},
	"file.integrity":            {"file_permission_repair": {}},
	"vulnerability.remediation": {"package_security_upgrade": {}},
}

func signalFromSecurityEvent(event domain.SecurityEvent, now time.Time) (domain.Signal, string) {
	category, severity, trust, title := "system", domain.SeverityLow, "verified", "服务器安全事件"
	subject := strings.TrimSpace(event.SourceIP)
	var metadata struct {
		Path string `json:"path"`
	}
	_ = json.Unmarshal(event.Payload, &metadata)
	if subject == "" {
		subject = strings.TrimSpace(metadata.Path)
	}
	switch event.Type {
	case "ssh_auth_failure":
		category, severity, title = "identity_access", domain.SeverityMedium, "SSH 登录失败活动"
	case "ssh_auth_failure_untrusted":
		category, severity, trust, title = "identity_access", domain.SeverityLow, "unverified", "未验证的 SSH 登录线索"
	case "ssh_auth_log_line_oversized_untrusted":
		category, severity, trust, title = "sensor_health", domain.SeverityLow, "unverified", "认证日志输入超过安全解析上限"
	case SecurityEventTypeCorrelationCapacityDegraded:
		category, severity, title = "sensor_health", domain.SeverityHigh, "安全事件关联容量保护已触发"
	case "identity_state_changed":
		category, severity, title = "identity_persistence", domain.SeverityHigh, "账号或权限边界发生变化"
	case "file_integrity_changed":
		category, severity, title = "file_integrity", domain.SeverityHigh, "关键安全配置发生变化"
	case "schedule_definition_changed":
		category, severity, title = "persistence", domain.SeverityHigh, "计划任务定义发生变化"
	case "service_definition_changed":
		category, severity, title = "workload_runtime", domain.SeverityMedium, "系统服务定义发生变化"
	case "container_configuration_changed":
		category, severity, title = "container_runtime", domain.SeverityMedium, "容器运行时配置发生变化"
	default:
		if strings.Contains(event.Type, "container") {
			category, title = "container_runtime", "容器运行时安全事件"
		} else if strings.Contains(event.Type, "process") || strings.Contains(event.Type, "service") {
			category, title = "workload_runtime", "进程或服务安全事件"
		} else if strings.Contains(event.Type, "file") {
			category, title = "file_integrity", "文件完整性安全事件"
		} else if strings.Contains(event.Type, "network") {
			category, title = "network", "网络安全事件"
		}
	}
	if subject == "" {
		subject = event.Type
	}
	return domain.Signal{
		ID: "event:" + event.ID, DeviceID: event.DeviceID, Type: event.Type,
		Category: category, Severity: severity, Trust: trust, Subject: subject,
		Summary: title, Source: "runtime_sensor", SourceRef: event.ID,
		Payload: event.Payload, OccurredAt: event.OccurredAt.UTC(), IngestedAt: now.UTC(),
	}, "event:" + event.Type + ":" + subject
}

func signalFromFinding(report domain.Report, finding domain.Finding, now time.Time) (domain.Signal, string) {
	payload, _ := json.Marshal(map[string]any{
		"findingId": finding.ID, "reportId": report.ID, "fingerprint": finding.Fingerprint,
		"description": finding.Description, "evidence": finding.Evidence, "remediation": finding.Remediation,
	})
	return domain.Signal{
		ID: "finding:" + report.ID + ":" + finding.Fingerprint, DeviceID: report.DeviceID,
		Type: "scanner_finding", Category: finding.Category, Severity: finding.Severity,
		Trust: "verified", Subject: finding.Fingerprint, Summary: finding.Title,
		Source: "deterministic_scanner", SourceRef: finding.ID, Payload: payload,
		OccurredAt: report.CompletedAt.UTC(), IngestedAt: now.UTC(),
	}, "finding:" + finding.Fingerprint
}

func severityRank(value domain.Severity) int {
	switch value {
	case domain.SeverityCritical:
		return 5
	case domain.SeverityHigh:
		return 4
	case domain.SeverityMedium:
		return 3
	case domain.SeverityLow:
		return 2
	default:
		return 1
	}
}

func (s *Store) upsertSignalIncidentTx(ctx context.Context, tx *sql.Tx, signal domain.Signal, correlationKey string) (domain.Incident, bool, error) {
	var out domain.Incident
	if signal.ID == "" || signal.DeviceID == "" || correlationKey == "" || len(signal.ID) > 512 || len(correlationKey) > 1024 || len(signal.Payload) > 64*1024 {
		return out, false, errors.New("signal identity, correlation key, or payload is invalid")
	}
	if len(signal.Payload) == 0 {
		signal.Payload = json.RawMessage(`{}`)
	}
	result, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO signals(
		id,device_id,type,category,severity,trust,subject,summary,source,source_ref,payload,occurred_at,ingested_at
	) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)`, signal.ID, signal.DeviceID, signal.Type, signal.Category, string(signal.Severity), signal.Trust,
		signal.Subject, signal.Summary, signal.Source, signal.SourceRef, string(signal.Payload), timeText(signal.OccurredAt), timeText(signal.IngestedAt))
	if err != nil {
		return out, false, err
	}
	inserted, err := result.RowsAffected()
	if err != nil || inserted == 0 {
		return out, false, err
	}
	if _, err = tx.ExecContext(ctx, `DELETE FROM signals WHERE device_id=? AND rowid IN (
		SELECT rowid FROM signals WHERE device_id=? ORDER BY occurred_at DESC,rowid DESC LIMIT -1 OFFSET ?
	)`, signal.DeviceID, signal.DeviceID, maxSignalsPerDevice); err != nil {
		return out, false, err
	}
	var incidentID string
	err = tx.QueryRowContext(ctx, `SELECT id FROM incidents WHERE device_id=? AND correlation_key=?
		AND status IN ('open','investigating','awaiting_approval','responding','monitoring') LIMIT 1`, signal.DeviceID, correlationKey).Scan(&incidentID)
	created := false
	if errors.Is(err, sql.ErrNoRows) {
		var active int
		if err = tx.QueryRowContext(ctx, `SELECT count(*) FROM incidents WHERE device_id=? AND status IN ('open','investigating','awaiting_approval','responding','monitoring')`, signal.DeviceID).Scan(&active); err != nil {
			return out, false, err
		}
		if active >= maxActiveIncidentsPerDevice {
			correlationKey = "system:active_incident_capacity"
			err = tx.QueryRowContext(ctx, `SELECT id FROM incidents WHERE device_id=? AND correlation_key=?
				AND status IN ('open','investigating','awaiting_approval','responding','monitoring') LIMIT 1`, signal.DeviceID, correlationKey).Scan(&incidentID)
			if err == nil {
				created = false
				goto incidentReady
			}
			if !errors.Is(err, sql.ErrNoRows) {
				return out, false, err
			}
		}
		incidentID, created = ids.New("inc"), true
		title, summary, category, severity := signal.Summary, signal.Summary, signal.Category, signal.Severity
		if correlationKey == "system:active_incident_capacity" {
			title, summary, category, severity = "活动事件容量保护已触发", "新的安全信号已汇总到容量保护事件；请先处置现有事件。", "sensor_health", domain.SeverityHigh
		}
		if _, err = tx.ExecContext(ctx, `INSERT INTO incidents(
			id,device_id,correlation_key,category,severity,status,title,summary,signal_count,
			first_seen_at,last_seen_at,created_at,updated_at
		) VALUES(?,?,?,?,?,?,?,?,1,?,?,?,?)`, incidentID, signal.DeviceID, correlationKey, category, string(severity),
			string(domain.IncidentOpen), title, summary, timeText(signal.OccurredAt), timeText(signal.OccurredAt),
			timeText(signal.IngestedAt), timeText(signal.IngestedAt)); err != nil {
			return out, false, err
		}
		if _, err = tx.ExecContext(ctx, `INSERT INTO incident_timeline(incident_id,actor,type,summary,details,created_at)
			VALUES(?,?,?,?,?,?)`, incidentID, signal.Source, "incident_opened", "检测到新的安全事件", `{}`, timeText(signal.IngestedAt)); err != nil {
			return out, false, err
		}
	} else if err != nil {
		return out, false, err
	}
incidentReady:
	if !created {
		if _, err = tx.ExecContext(ctx, `UPDATE incidents SET
			status=CASE WHEN status='monitoring' THEN 'open' ELSE status END,
			severity=CASE
				WHEN CASE severity WHEN 'critical' THEN 5 WHEN 'high' THEN 4 WHEN 'medium' THEN 3 WHEN 'low' THEN 2 ELSE 1 END < ? THEN ?
				ELSE severity END,
			signal_count=signal_count+1,last_seen_at=CASE WHEN last_seen_at<? THEN ? ELSE last_seen_at END,
			summary=?,updated_at=? WHERE id=?`, severityRank(signal.Severity), string(signal.Severity), timeText(signal.OccurredAt),
			timeText(signal.OccurredAt), signal.Summary, timeText(signal.IngestedAt), incidentID); err != nil {
			return out, false, err
		}
	}
	if _, err = tx.ExecContext(ctx, `INSERT OR IGNORE INTO incident_signals(incident_id,device_id,signal_id,created_at) VALUES(?,?,?,?)`, incidentID, signal.DeviceID, signal.ID, timeText(signal.IngestedAt)); err != nil {
		return out, false, err
	}
	if !created {
		details, _ := json.Marshal(map[string]any{"signalType": signal.Type, "signalId": signal.ID})
		if _, err = tx.ExecContext(ctx, `INSERT INTO incident_timeline(incident_id,actor,type,summary,details,created_at) VALUES(?,?,?,?,?,?)`, incidentID, signal.Source, "signal_added", signal.Summary, string(details), timeText(signal.IngestedAt)); err != nil {
			return out, false, err
		}
	}
	if _, err = tx.ExecContext(ctx, `DELETE FROM incident_timeline WHERE incident_id=? AND id IN (
		SELECT id FROM incident_timeline WHERE incident_id=? ORDER BY created_at DESC,id DESC LIMIT -1 OFFSET ?
	)`, incidentID, incidentID, maxTimelineEventsPerIncident); err != nil {
		return out, false, err
	}
	if _, err = tx.ExecContext(ctx, `DELETE FROM incidents WHERE device_id=? AND status IN ('resolved','dismissed') AND id IN (
		SELECT id FROM incidents WHERE device_id=? AND status IN ('resolved','dismissed') ORDER BY updated_at DESC,rowid DESC LIMIT -1 OFFSET ?
	)`, signal.DeviceID, signal.DeviceID, maxIncidentsPerDevice); err != nil {
		return out, false, err
	}
	out, err = scanIncident(tx.QueryRowContext(ctx, `SELECT `+incidentColumns+` FROM incidents WHERE id=?`, incidentID))
	return out, created, err
}

const incidentColumns = `id,device_id,correlation_key,category,severity,status,title,summary,signal_count,first_seen_at,last_seen_at,last_investigated_at,created_at,updated_at`

func scanIncident(row interface{ Scan(...any) error }) (domain.Incident, error) {
	var item domain.Incident
	var first, last, investigated, created, updated sql.NullString
	err := row.Scan(&item.ID, &item.DeviceID, &item.CorrelationKey, &item.Category, &item.Severity, &item.Status,
		&item.Title, &item.Summary, &item.SignalCount, &first, &last, &investigated, &created, &updated)
	if errors.Is(err, sql.ErrNoRows) {
		return item, ErrNotFound
	}
	if err != nil {
		return item, err
	}
	for _, pair := range []struct {
		source sql.NullString
		target *time.Time
	}{{first, &item.FirstSeenAt}, {last, &item.LastSeenAt}, {created, &item.CreatedAt}, {updated, &item.UpdatedAt}} {
		source, target := pair.source, pair.target
		if !source.Valid {
			return item, errors.New("incident timestamp is missing")
		}
		*target, err = parseTime(source.String)
		if err != nil {
			return item, err
		}
	}
	if investigated.Valid {
		value, parseErr := parseTime(investigated.String)
		if parseErr != nil {
			return item, parseErr
		}
		item.LastInvestigatedAt = &value
	}
	return item, nil
}

func (s *Store) ListIncidents(ctx context.Context, deviceID string, statuses []domain.IncidentStatus, limit int) ([]domain.Incident, error) {
	if limit <= 0 || limit > 200 {
		limit = 100
	}
	if len(statuses) > 7 {
		return nil, errors.New("too many incident status filters")
	}
	var statusFilter [7]string
	for index, status := range statuses {
		statusFilter[index] = string(status)
	}
	includeStatusFilter := 0
	if len(statuses) > 0 {
		includeStatusFilter = 1
	}
	// Keep the SQL shape fixed. Both the device and the bounded status filter
	// remain parameters, avoiding a query-construction path from API input.
	rows, err := s.db.QueryContext(ctx, `SELECT id,device_id,correlation_key,category,severity,status,title,summary,signal_count,first_seen_at,last_seen_at,last_investigated_at,created_at,updated_at
		FROM incidents
		WHERE (?='' OR device_id=?) AND (?=0 OR status IN (?,?,?,?,?,?,?))
		ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END,last_seen_at DESC LIMIT ?`,
		deviceID, deviceID, includeStatusFilter,
		statusFilter[0], statusFilter[1], statusFilter[2], statusFilter[3], statusFilter[4], statusFilter[5], statusFilter[6], limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.Incident
	for rows.Next() {
		item, scanErr := scanIncident(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (s *Store) Incident(ctx context.Context, id string) (domain.Incident, error) {
	return scanIncident(s.db.QueryRowContext(ctx, `SELECT `+incidentColumns+` FROM incidents WHERE id=?`, id))
}

func (s *Store) ListIncidentSignals(ctx context.Context, incidentID string, limit int) ([]domain.Signal, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	rows, err := s.db.QueryContext(ctx, `SELECT s.id,s.device_id,s.type,s.category,s.severity,s.trust,s.subject,s.summary,s.source,s.source_ref,s.payload,s.occurred_at,s.ingested_at
		FROM incident_signals x JOIN signals s ON s.device_id=x.device_id AND s.id=x.signal_id WHERE x.incident_id=? ORDER BY s.occurred_at DESC LIMIT ?`, incidentID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.Signal
	for rows.Next() {
		var item domain.Signal
		var payload, occurred, ingested string
		if err = rows.Scan(&item.ID, &item.DeviceID, &item.Type, &item.Category, &item.Severity, &item.Trust, &item.Subject, &item.Summary, &item.Source, &item.SourceRef, &payload, &occurred, &ingested); err != nil {
			return nil, err
		}
		item.Payload = json.RawMessage(payload)
		if item.OccurredAt, err = parseTime(occurred); err != nil {
			return nil, err
		}
		if item.IngestedAt, err = parseTime(ingested); err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (s *Store) ListIncidentTimeline(ctx context.Context, incidentID string, limit int) ([]domain.IncidentTimelineEvent, error) {
	if limit <= 0 || limit > 500 {
		limit = 200
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id,incident_id,actor,type,summary,details,created_at FROM incident_timeline WHERE incident_id=? ORDER BY created_at,id LIMIT ?`, incidentID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.IncidentTimelineEvent
	for rows.Next() {
		var item domain.IncidentTimelineEvent
		var details, created string
		if err = rows.Scan(&item.ID, &item.IncidentID, &item.Actor, &item.Type, &item.Summary, &details, &created); err != nil {
			return nil, err
		}
		item.Details = json.RawMessage(details)
		if item.CreatedAt, err = parseTime(created); err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func defaultPolicyGrants(deviceID string, now time.Time) []domain.PolicyGrant {
	return []domain.PolicyGrant{
		{DeviceID: deviceID, Capability: "network.auth_bruteforce", Mode: domain.AutonomyObserve, AllowedActionTypes: []string{"temporary_ip_ban"}, MaxActionsPerHour: 10, UpdatedAt: now},
		{DeviceID: deviceID, Capability: "identity.persistence", Mode: domain.AutonomyObserve, AllowedActionTypes: []string{"ssh_password_hardening"}, MaxActionsPerHour: 5, UpdatedAt: now},
		{DeviceID: deviceID, Capability: "workload.runtime", Mode: domain.AutonomyObserve, AllowedActionTypes: []string{}, MaxActionsPerHour: 5, UpdatedAt: now},
		{DeviceID: deviceID, Capability: "file.integrity", Mode: domain.AutonomyObserve, AllowedActionTypes: []string{"file_permission_repair"}, MaxActionsPerHour: 5, UpdatedAt: now},
		{DeviceID: deviceID, Capability: "vulnerability.remediation", Mode: domain.AutonomyObserve, AllowedActionTypes: []string{"package_security_upgrade"}, MaxActionsPerHour: 2, UpdatedAt: now},
	}
}

func (s *Store) ListPolicyGrants(ctx context.Context, deviceID string, now time.Time) ([]domain.PolicyGrant, error) {
	defaults := defaultPolicyGrants(deviceID, now.UTC())
	rows, err := s.db.QueryContext(ctx, `SELECT device_id,capability,enabled,mode,allowed_action_types,max_actions_per_hour,emergency_stop,updated_at FROM policy_grants WHERE device_id=?`, deviceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	byCapability := make(map[string]domain.PolicyGrant)
	for rows.Next() {
		var item domain.PolicyGrant
		var allowed, updated string
		if err = rows.Scan(&item.DeviceID, &item.Capability, &item.Enabled, &item.Mode, &allowed, &item.MaxActionsPerHour, &item.EmergencyStop, &updated); err != nil {
			return nil, err
		}
		if err = json.Unmarshal([]byte(allowed), &item.AllowedActionTypes); err != nil {
			return nil, err
		}
		if item.UpdatedAt, err = parseTime(updated); err != nil {
			return nil, err
		}
		byCapability[item.Capability] = item
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	out := make([]domain.PolicyGrant, 0, len(defaults))
	for _, fallback := range defaults {
		if stored, ok := byCapability[fallback.Capability]; ok {
			out = append(out, stored)
		} else {
			out = append(out, fallback)
		}
	}
	return out, nil
}

func (s *Store) PutPolicyGrant(ctx context.Context, item domain.PolicyGrant) error {
	if item.DeviceID == "" || len(item.Capability) == 0 || len(item.Capability) > 128 || item.MaxActionsPerHour < 1 || item.MaxActionsPerHour > 1000 {
		return errors.New("policy grant is invalid")
	}
	if _, ok := supportedPolicyCapabilities[item.Capability]; !ok {
		return errors.New("unsupported policy capability")
	}
	switch item.Mode {
	case domain.AutonomyObserve, domain.AutonomyAssist, domain.AutonomyAutoLowRisk, domain.AutonomyEnhanced:
	default:
		return errors.New("unsupported autonomy mode")
	}
	if len(item.AllowedActionTypes) > 32 {
		return errors.New("too many allowed action types")
	}
	allowed := allowedPolicyActions[item.Capability]
	seen := make(map[string]struct{}, len(item.AllowedActionTypes))
	for _, actionType := range item.AllowedActionTypes {
		if _, supported := allowed[actionType]; !supported {
			return errors.New("unsupported action type for policy capability")
		}
		if _, duplicate := seen[actionType]; duplicate {
			return errors.New("duplicate action type in policy capability")
		}
		seen[actionType] = struct{}{}
	}
	encoded, err := json.Marshal(item.AllowedActionTypes)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO policy_grants(device_id,capability,enabled,mode,allowed_action_types,max_actions_per_hour,emergency_stop,updated_at)
		VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(device_id,capability) DO UPDATE SET enabled=excluded.enabled,mode=excluded.mode,
		allowed_action_types=excluded.allowed_action_types,max_actions_per_hour=excluded.max_actions_per_hour,emergency_stop=excluded.emergency_stop,updated_at=excluded.updated_at`,
		item.DeviceID, item.Capability, item.Enabled, string(item.Mode), string(encoded), item.MaxActionsPerHour, item.EmergencyStop, timeText(item.UpdatedAt))
	return err
}

func (s *Store) SetIncidentStatus(ctx context.Context, incidentID string, status domain.IncidentStatus, actor, summary string, now time.Time) error {
	switch status {
	case domain.IncidentOpen, domain.IncidentInvestigating, domain.IncidentAwaitingApproval, domain.IncidentResponding, domain.IncidentMonitoring, domain.IncidentResolved, domain.IncidentDismissed:
	default:
		return errors.New("invalid incident status")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `UPDATE incidents SET status=?,updated_at=? WHERE id=?`, string(status), timeText(now), incidentID)
	if err != nil {
		return err
	}
	if changed, _ := result.RowsAffected(); changed != 1 {
		return ErrNotFound
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO incident_timeline(incident_id,actor,type,summary,details,created_at) VALUES(?,?,?,?,?,?)`, incidentID, actor, "status_changed", summary, fmt.Sprintf(`{"status":%q}`, status), timeText(now)); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) CreateInvestigation(ctx context.Context, incidentID, trigger, model string, now time.Time) (domain.Investigation, error) {
	item := domain.Investigation{ID: ids.New("inv"), IncidentID: incidentID, Status: domain.InvestigationRunning, Trigger: trigger, Model: model, CreatedAt: now.UTC(), UpdatedAt: now.UTC()}
	started := now.UTC()
	item.StartedAt = &started
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return item, err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `UPDATE incidents SET status=?,last_investigated_at=?,updated_at=? WHERE id=? AND status IN ('open','monitoring')`, string(domain.IncidentInvestigating), timeText(now), timeText(now), incidentID)
	if err != nil {
		return item, err
	}
	if changed, _ := result.RowsAffected(); changed != 1 {
		return item, ErrConflict
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO investigations(id,incident_id,status,trigger,model,started_at,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)`, item.ID, incidentID, string(item.Status), trigger, model, timeText(started), timeText(now), timeText(now)); err != nil {
		return item, err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO incident_timeline(incident_id,actor,type,summary,details,created_at) VALUES(?,?,?,?,?,?)`, incidentID, "ai:investigator", "investigation_started", "AI 安全工程师开始调查", `{}`, timeText(now)); err != nil {
		return item, err
	}
	return item, tx.Commit()
}

func (s *Store) CompleteInvestigation(ctx context.Context, item domain.Investigation, plan *domain.ResponsePlan, now time.Time) error {
	if item.Status != domain.InvestigationCompleted || item.Confidence < 0 || item.Confidence > 100 || len(item.ToolCalls) > 32 {
		return errors.New("completed investigation is invalid")
	}
	toolCalls, err := json.Marshal(item.ToolCalls)
	if err != nil || len(toolCalls) > 256*1024 {
		return errors.New("investigation tool record is invalid")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	completed := now.UTC()
	result, err := tx.ExecContext(ctx, `UPDATE investigations SET status=?,hypothesis=?,conclusion=?,confidence=?,tool_calls=?,error='',completed_at=?,updated_at=? WHERE id=? AND incident_id=? AND status=?`,
		string(item.Status), item.Hypothesis, item.Conclusion, item.Confidence, string(toolCalls), timeText(completed), timeText(completed), item.ID, item.IncidentID, string(domain.InvestigationRunning))
	if err != nil {
		return err
	}
	if changed, _ := result.RowsAffected(); changed != 1 {
		return ErrConflict
	}
	nextStatus := domain.IncidentMonitoring
	if plan != nil && len(plan.Steps) > 0 {
		steps, marshalErr := json.Marshal(plan.Steps)
		if marshalErr != nil || len(steps) > 256*1024 {
			return errors.New("response plan is invalid")
		}
		if plan.ID == "" {
			plan.ID = ids.New("rsp")
		}
		plan.IncidentID, plan.InvestigationID = item.IncidentID, item.ID
		plan.Status, plan.CreatedAt, plan.UpdatedAt = domain.ResponsePlanProposed, completed, completed
		if _, err = tx.ExecContext(ctx, `INSERT INTO response_plans(id,incident_id,investigation_id,title,rationale,risk,status,requires_approval,steps,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)`,
			plan.ID, plan.IncidentID, plan.InvestigationID, plan.Title, plan.Rationale, plan.Risk, string(plan.Status), plan.RequiresApproval, string(steps), timeText(completed), timeText(completed)); err != nil {
			return err
		}
		nextStatus = domain.IncidentAwaitingApproval
	}
	if _, err = tx.ExecContext(ctx, `UPDATE incidents SET status=?,summary=?,last_investigated_at=?,updated_at=? WHERE id=?`, string(nextStatus), item.Conclusion, timeText(completed), timeText(completed), item.IncidentID); err != nil {
		return err
	}
	details, _ := json.Marshal(map[string]any{"confidence": item.Confidence, "responsePlanCreated": plan != nil && len(plan.Steps) > 0})
	if _, err = tx.ExecContext(ctx, `INSERT INTO incident_timeline(incident_id,actor,type,summary,details,created_at) VALUES(?,?,?,?,?,?)`, item.IncidentID, "ai:investigator", "investigation_completed", "AI 安全工程师完成调查", string(details), timeText(completed)); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) FailInvestigation(ctx context.Context, item domain.Investigation, failure string, now time.Time) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `UPDATE investigations SET status=?,error=?,completed_at=?,updated_at=? WHERE id=? AND incident_id=? AND status=?`, string(domain.InvestigationFailed), failure, timeText(now), timeText(now), item.ID, item.IncidentID, string(domain.InvestigationRunning))
	if err != nil {
		return err
	}
	if changed, _ := result.RowsAffected(); changed != 1 {
		return ErrConflict
	}
	if _, err = tx.ExecContext(ctx, `UPDATE incidents SET status=?,updated_at=? WHERE id=? AND status=?`, string(domain.IncidentOpen), timeText(now), item.IncidentID, string(domain.IncidentInvestigating)); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO incident_timeline(incident_id,actor,type,summary,details,created_at) VALUES(?,?,?,?,?,?)`, item.IncidentID, "ai:investigator", "investigation_failed", "AI 调查失败，事件保持打开", `{}`, timeText(now)); err != nil {
		return err
	}
	return tx.Commit()
}

// RecoverStaleInvestigations releases incidents left in-flight by a Controller
// crash. A live model call is bounded to 35 seconds, so two minutes is a safe
// lease boundary and prevents an Incident from remaining uninvestigable forever.
func (s *Store) RecoverStaleInvestigations(ctx context.Context, cutoff, now time.Time) (int, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	rows, err := tx.QueryContext(ctx, `SELECT id,incident_id FROM investigations WHERE status=? AND updated_at<=? ORDER BY updated_at LIMIT 100`, string(domain.InvestigationRunning), timeText(cutoff))
	if err != nil {
		return 0, err
	}
	type stale struct{ investigationID, incidentID string }
	var items []stale
	for rows.Next() {
		var item stale
		if err = rows.Scan(&item.investigationID, &item.incidentID); err != nil {
			if closeErr := rows.Close(); closeErr != nil {
				return 0, errors.Join(err, closeErr)
			}
			return 0, err
		}
		items = append(items, item)
	}
	if err = rows.Close(); err != nil {
		return 0, err
	}
	for _, item := range items {
		result, updateErr := tx.ExecContext(ctx, `UPDATE investigations SET status=?,error=?,completed_at=?,updated_at=? WHERE id=? AND status=?`, string(domain.InvestigationFailed), "Controller restarted or the investigation lease expired", timeText(now), timeText(now), item.investigationID, string(domain.InvestigationRunning))
		if updateErr != nil {
			return 0, updateErr
		}
		if changed, _ := result.RowsAffected(); changed != 1 {
			continue
		}
		if _, err = tx.ExecContext(ctx, `UPDATE incidents SET status=?,updated_at=? WHERE id=? AND status=?`, string(domain.IncidentOpen), timeText(now), item.incidentID, string(domain.IncidentInvestigating)); err != nil {
			return 0, err
		}
		if _, err = tx.ExecContext(ctx, `INSERT INTO incident_timeline(incident_id,actor,type,summary,details,created_at) VALUES(?,?,?,?,?,?)`, item.incidentID, "controller", "investigation_recovered", "上次调查被中断，事件已重新进入队列", `{}`, timeText(now)); err != nil {
			return 0, err
		}
	}
	if err = tx.Commit(); err != nil {
		return 0, err
	}
	return len(items), nil
}

func (s *Store) ListInvestigations(ctx context.Context, incidentID string, limit int) ([]domain.Investigation, error) {
	if limit <= 0 || limit > 100 {
		limit = 20
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id,incident_id,status,trigger,hypothesis,conclusion,confidence,model,tool_calls,error,started_at,completed_at,created_at,updated_at FROM investigations WHERE incident_id=? ORDER BY created_at DESC LIMIT ?`, incidentID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.Investigation
	for rows.Next() {
		var item domain.Investigation
		var calls, started, completed sql.NullString
		var created, updated string
		if err = rows.Scan(&item.ID, &item.IncidentID, &item.Status, &item.Trigger, &item.Hypothesis, &item.Conclusion, &item.Confidence, &item.Model, &calls, &item.Error, &started, &completed, &created, &updated); err != nil {
			return nil, err
		}
		if calls.Valid && calls.String != "" {
			if err = json.Unmarshal([]byte(calls.String), &item.ToolCalls); err != nil {
				return nil, err
			}
		}
		if started.Valid {
			value, parseErr := parseTime(started.String)
			if parseErr != nil {
				return nil, parseErr
			}
			item.StartedAt = &value
		}
		if completed.Valid {
			value, parseErr := parseTime(completed.String)
			if parseErr != nil {
				return nil, parseErr
			}
			item.CompletedAt = &value
		}
		if item.CreatedAt, err = parseTime(created); err != nil {
			return nil, err
		}
		if item.UpdatedAt, err = parseTime(updated); err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (s *Store) ListResponsePlans(ctx context.Context, incidentID string, limit int) ([]domain.ResponsePlan, error) {
	if limit <= 0 || limit > 100 {
		limit = 20
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id,incident_id,investigation_id,title,rationale,risk,status,requires_approval,steps,created_at,updated_at FROM response_plans WHERE incident_id=? ORDER BY created_at DESC LIMIT ?`, incidentID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.ResponsePlan
	for rows.Next() {
		var item domain.ResponsePlan
		var steps, created, updated string
		if err = rows.Scan(&item.ID, &item.IncidentID, &item.InvestigationID, &item.Title, &item.Rationale, &item.Risk, &item.Status, &item.RequiresApproval, &steps, &created, &updated); err != nil {
			return nil, err
		}
		if err = json.Unmarshal([]byte(steps), &item.Steps); err != nil {
			return nil, err
		}
		if item.CreatedAt, err = parseTime(created); err != nil {
			return nil, err
		}
		if item.UpdatedAt, err = parseTime(updated); err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func scanResponsePlan(row interface{ Scan(...any) error }) (domain.ResponsePlan, error) {
	var item domain.ResponsePlan
	var steps, created, updated string
	err := row.Scan(&item.ID, &item.IncidentID, &item.InvestigationID, &item.Title, &item.Rationale, &item.Risk, &item.Status, &item.RequiresApproval, &steps, &created, &updated)
	if errors.Is(err, sql.ErrNoRows) {
		return item, ErrNotFound
	}
	if err != nil {
		return item, err
	}
	if err = json.Unmarshal([]byte(steps), &item.Steps); err != nil {
		return item, err
	}
	if item.CreatedAt, err = parseTime(created); err != nil {
		return item, err
	}
	if item.UpdatedAt, err = parseTime(updated); err != nil {
		return item, err
	}
	return item, nil
}

func (s *Store) ResponsePlan(ctx context.Context, id string) (domain.ResponsePlan, error) {
	return scanResponsePlan(s.db.QueryRowContext(ctx, `SELECT id,incident_id,investigation_id,title,rationale,risk,status,requires_approval,steps,created_at,updated_at FROM response_plans WHERE id=?`, id))
}

// CreateActionFromResponsePlan binds exactly one AI-proposed, Controller-
// validated typed step to one draft action. The step reservation, action,
// approval nonce hash and audit records commit atomically, so retries cannot
// produce two privileged actions for the same proposal.
func (s *Store) CreateActionFromResponsePlan(ctx context.Context, planID, stepID string, action domain.Action, nonceHash, actor string, maxActionsPerHour int) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var incidentID, deviceID, status, encodedSteps string
	if err = tx.QueryRowContext(ctx, `SELECT p.incident_id,i.device_id,p.status,p.steps FROM response_plans p JOIN incidents i ON i.id=p.incident_id WHERE p.id=?`, planID).Scan(&incidentID, &deviceID, &status, &encodedSteps); errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	} else if err != nil {
		return err
	}
	if status != string(domain.ResponsePlanProposed) && status != string(domain.ResponsePlanApproved) {
		return ErrConflict
	}
	var steps []domain.ResponseStep
	if err = json.Unmarshal([]byte(encodedSteps), &steps); err != nil {
		return err
	}
	stepIndex := -1
	for index := range steps {
		if steps[index].ID == stepID {
			stepIndex = index
			break
		}
	}
	if stepIndex < 0 || action.DeviceID != deviceID || action.Type != steps[stepIndex].ActionType || string(action.Parameters) != string(steps[stepIndex].Parameters) {
		return ErrConflict
	}
	if previousActionID := steps[stepIndex].ActionID; previousActionID != "" {
		var previousStatus domain.ActionStatus
		if err = tx.QueryRowContext(ctx, `SELECT status FROM actions WHERE id=?`, previousActionID).Scan(&previousStatus); err != nil {
			return ErrConflict
		}
		if previousStatus != domain.ActionCancelled {
			return ErrConflict
		}
		if _, err = tx.ExecContext(ctx, `DELETE FROM response_plan_actions WHERE plan_id=? AND step_id=? AND action_id=?`, planID, stepID, previousActionID); err != nil {
			return err
		}
		steps[stepIndex].ActionID = ""
	}
	if len(action.Parameters) == 0 || len(action.Preview) == 0 || action.Status != domain.ActionDraft {
		return errors.New("response plan action is invalid")
	}
	if maxActionsPerHour < 1 || maxActionsPerHour > 1000 {
		return errors.New("response plan action limit is invalid")
	}
	var recentActions int
	if err = tx.QueryRowContext(ctx, `SELECT count(*) FROM actions WHERE device_id=? AND type=? AND created_at>=?`, action.DeviceID, action.Type, timeText(action.CreatedAt.Add(-time.Hour))).Scan(&recentActions); err != nil {
		return err
	}
	if recentActions >= maxActionsPerHour {
		return ErrConflict
	}
	if err = expireDraftActionsTx(ctx, tx, action.DeviceID, action.CreatedAt); err != nil {
		return err
	}
	if err = ensureUnfinishedActionCapacityTx(ctx, tx, action.DeviceID); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO actions(id,device_id,finding_id,type,parameters,preview,status,approval_nonce_hash,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?)`,
		action.ID, action.DeviceID, action.FindingID, action.Type, string(action.Parameters), string(action.Preview), string(action.Status), nonceHash, timeText(action.CreatedAt), timeText(action.UpdatedAt)); err != nil {
		return mapSQLError(err)
	}
	steps[stepIndex].ActionID = action.ID
	updatedSteps, err := json.Marshal(steps)
	if err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO response_plan_actions(plan_id,step_id,action_id,created_at) VALUES(?,?,?,?)`, planID, stepID, action.ID, timeText(action.CreatedAt)); err != nil {
		return mapSQLError(err)
	}
	if _, err = tx.ExecContext(ctx, `UPDATE response_plans SET status=?,steps=?,updated_at=? WHERE id=?`, string(domain.ResponsePlanApproved), string(updatedSteps), timeText(action.UpdatedAt), planID); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `UPDATE incidents SET status=?,updated_at=? WHERE id=?`, string(domain.IncidentAwaitingApproval), timeText(action.UpdatedAt), incidentID); err != nil {
		return err
	}
	previewDetails, _ := json.Marshal(map[string]any{"responsePlanId": planID, "stepId": stepID, "preview": json.RawMessage(action.Preview)})
	if _, err = tx.ExecContext(ctx, `INSERT INTO action_audit(action_id,actor,event,details,created_at) VALUES(?,?,?,?,?)`, action.ID, actor, "response_plan_step_prepared", string(previewDetails), timeText(action.CreatedAt)); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO incident_timeline(incident_id,actor,type,summary,details,created_at) VALUES(?,?,?,?,?,?)`, incidentID, actor, "response_step_prepared", "管理员正在审查响应计划动作", string(previewDetails), timeText(action.CreatedAt)); err != nil {
		return err
	}
	return tx.Commit()
}

func markIncidentRespondingForActionTx(ctx context.Context, tx *sql.Tx, actionID, actor string, now time.Time) error {
	var incidentID, planID, stepID string
	err := tx.QueryRowContext(ctx, `SELECT p.incident_id,x.plan_id,x.step_id FROM response_plan_actions x JOIN response_plans p ON p.id=x.plan_id WHERE x.action_id=?`, actionID).Scan(&incidentID, &planID, &stepID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `UPDATE response_plans SET status=?,updated_at=? WHERE id=?`, string(domain.ResponsePlanExecuting), timeText(now), planID); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `UPDATE incidents SET status=?,updated_at=? WHERE id=?`, string(domain.IncidentResponding), timeText(now), incidentID); err != nil {
		return err
	}
	details, _ := json.Marshal(map[string]any{"responsePlanId": planID, "stepId": stepID, "actionId": actionID})
	if _, err = tx.ExecContext(ctx, `INSERT INTO incident_timeline(incident_id,actor,type,summary,details,created_at) VALUES(?,?,?,?,?,?)`, incidentID, actor, "response_started", "响应计划动作已批准并开始执行", string(details), timeText(now)); err != nil {
		return err
	}
	return nil
}

func syncResponsePlanForActionTx(ctx context.Context, tx *sql.Tx, actionID string, now time.Time) error {
	var planID, incidentID, currentStatus, encodedSteps string
	err := tx.QueryRowContext(ctx, `SELECT p.id,p.incident_id,p.status,p.steps FROM response_plan_actions x JOIN response_plans p ON p.id=x.plan_id WHERE x.action_id=?`, actionID).Scan(&planID, &incidentID, &currentStatus, &encodedSteps)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	var steps []domain.ResponseStep
	if err = json.Unmarshal([]byte(encodedSteps), &steps); err != nil {
		return err
	}
	statuses := make(map[string]domain.ActionStatus)
	rows, err := tx.QueryContext(ctx, `SELECT x.step_id,a.status FROM response_plan_actions x JOIN actions a ON a.id=x.action_id WHERE x.plan_id=?`, planID)
	if err != nil {
		return err
	}
	for rows.Next() {
		var stepID string
		var status domain.ActionStatus
		if err = rows.Scan(&stepID, &status); err != nil {
			if closeErr := rows.Close(); closeErr != nil {
				return errors.Join(err, closeErr)
			}
			return err
		}
		statuses[stepID] = status
	}
	if err = rows.Close(); err != nil {
		return err
	}
	nextPlan, nextIncident := domain.ResponsePlanApproved, domain.IncidentAwaitingApproval
	allComplete, anyExecuting, anyFailed := len(steps) > 0, false, false
	for _, step := range steps {
		status, prepared := statuses[step.ID]
		if !prepared {
			allComplete = false
			continue
		}
		switch status {
		case domain.ActionSucceeded, domain.ActionRolledBack:
		case domain.ActionFailed, domain.ActionIndeterminate, domain.ActionCancelled:
			allComplete, anyFailed = false, true
		default:
			allComplete, anyExecuting = false, true
		}
	}
	if anyFailed {
		nextPlan, nextIncident = domain.ResponsePlanFailed, domain.IncidentOpen
	} else if allComplete {
		nextPlan, nextIncident = domain.ResponsePlanCompleted, domain.IncidentMonitoring
	} else if anyExecuting {
		nextPlan, nextIncident = domain.ResponsePlanExecuting, domain.IncidentResponding
	}
	if currentStatus == string(nextPlan) {
		return nil
	}
	if _, err = tx.ExecContext(ctx, `UPDATE response_plans SET status=?,updated_at=? WHERE id=?`, string(nextPlan), timeText(now), planID); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `UPDATE incidents SET status=?,updated_at=? WHERE id=?`, string(nextIncident), timeText(now), incidentID); err != nil {
		return err
	}
	summary := map[domain.ResponsePlanStatus]string{
		domain.ResponsePlanApproved:  "响应计划仍有步骤等待批准",
		domain.ResponsePlanExecuting: "响应计划正在执行或验证",
		domain.ResponsePlanCompleted: "响应计划已完成，事件进入持续观察",
		domain.ResponsePlanFailed:    "响应计划未达到可验证的安全终态，需要重新调查",
	}[nextPlan]
	details, _ := json.Marshal(map[string]any{"responsePlanId": planID, "actionId": actionID, "status": nextPlan})
	_, err = tx.ExecContext(ctx, `INSERT INTO incident_timeline(incident_id,actor,type,summary,details,created_at) VALUES(?,?,?,?,?,?)`, incidentID, "controller", "response_state_changed", summary, string(details), timeText(now))
	return err
}
