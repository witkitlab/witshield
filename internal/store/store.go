package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/witkitlab/witshield/internal/domain"
	"github.com/witkitlab/witshield/internal/ids"

	_ "modernc.org/sqlite"
)

var (
	ErrNotFound          = errors.New("not found")
	ErrConflict          = errors.New("conflict")
	ErrUnauthorized      = errors.New("unauthorized")
	ErrTokenExpired      = errors.New("token expired")
	ErrTokenExhausted    = errors.New("token exhausted")
	ErrAIBudgetExhausted = errors.New("AI investigation budget exhausted")
)

type Store struct{ db *sql.DB }

func Open(ctx context.Context, dsn string) (*Store, error) {
	if strings.TrimSpace(dsn) == "" {
		return nil, errors.New("database path is required")
	}
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	db.SetConnMaxLifetime(0)
	for _, pragma := range []string{"PRAGMA foreign_keys = ON", "PRAGMA busy_timeout = 5000", "PRAGMA journal_mode = WAL", "PRAGMA synchronous = NORMAL"} {
		if _, err := db.ExecContext(ctx, pragma); err != nil {
			_ = db.Close()
			return nil, fmt.Errorf("%s: %w", pragma, err)
		}
	}
	s := &Store{db: db}
	if err := s.migrate(ctx); err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) Close() error                   { return s.db.Close() }
func (s *Store) Ping(ctx context.Context) error { return s.db.PingContext(ctx) }

func (s *Store) migrate(ctx context.Context) error {
	const schema = `
CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS admins (
  id TEXT PRIMARY KEY, username TEXT NOT NULL UNIQUE COLLATE NOCASE, password_hash TEXT NOT NULL,
  created_at TEXT NOT NULL, updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
  id TEXT PRIMARY KEY, token_hash TEXT NOT NULL UNIQUE, admin_id TEXT NOT NULL REFERENCES admins(id) ON DELETE CASCADE,
  expires_at TEXT NOT NULL, created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS sessions_expires_idx ON sessions(expires_at);
CREATE TABLE IF NOT EXISTS enrollment_tokens (
  id TEXT PRIMARY KEY, name TEXT NOT NULL, token_hash TEXT NOT NULL UNIQUE, hint TEXT NOT NULL,
  max_uses INTEGER NOT NULL CHECK(max_uses > 0), uses INTEGER NOT NULL DEFAULT 0 CHECK(uses >= 0),
  expires_at TEXT, revoked_at TEXT, created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS devices (
  id TEXT PRIMARY KEY, name TEXT NOT NULL, hostname TEXT NOT NULL, os TEXT NOT NULL, arch TEXT NOT NULL,
  agent_version TEXT NOT NULL, observer_only INTEGER NOT NULL DEFAULT 0,
  identity_key TEXT NOT NULL DEFAULT '', status TEXT NOT NULL,
  last_seen_at TEXT, enrolled_at TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS agent_tokens (
  id TEXT PRIMARY KEY, device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
  token_hash TEXT NOT NULL UNIQUE, created_at TEXT NOT NULL, revoked_at TEXT
);
CREATE INDEX IF NOT EXISTS agent_tokens_device_idx ON agent_tokens(device_id);
CREATE TABLE IF NOT EXISTS agent_request_nonces (
  device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
  nonce TEXT NOT NULL, expires_at TEXT NOT NULL, created_at TEXT NOT NULL,
  PRIMARY KEY(device_id,nonce)
);
CREATE INDEX IF NOT EXISTS agent_request_nonces_expiry_idx ON agent_request_nonces(expires_at);
CREATE INDEX IF NOT EXISTS agent_request_nonces_device_expiry_idx ON agent_request_nonces(device_id,expires_at);
CREATE TABLE IF NOT EXISTS enrollment_identities (
  identity_key TEXT PRIMARY KEY, device_id TEXT NOT NULL UNIQUE REFERENCES devices(id) ON DELETE CASCADE,
  enrollment_token_id TEXT NOT NULL REFERENCES enrollment_tokens(id),
  encrypted_agent_token TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS enrollment_challenges (
  id TEXT PRIMARY KEY, enrollment_token_id TEXT NOT NULL REFERENCES enrollment_tokens(id) ON DELETE CASCADE,
  identity_key TEXT NOT NULL, challenge_hash TEXT NOT NULL, expires_at TEXT NOT NULL,
  used_at TEXT, created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS enrollment_challenges_expiry_idx ON enrollment_challenges(expires_at);
CREATE TABLE IF NOT EXISTS reports (
  id TEXT PRIMARY KEY, device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
  started_at TEXT NOT NULL, completed_at TEXT NOT NULL, score INTEGER NOT NULL CHECK(score BETWEEN 0 AND 100),
  summary TEXT NOT NULL DEFAULT '{}', ingest_digest TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS reports_device_completed_idx ON reports(device_id, completed_at DESC);
CREATE TABLE IF NOT EXISTS findings (
  id TEXT PRIMARY KEY, report_id TEXT NOT NULL REFERENCES reports(id) ON DELETE CASCADE,
  device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE, fingerprint TEXT NOT NULL,
  category TEXT NOT NULL, severity TEXT NOT NULL, title TEXT NOT NULL, description TEXT NOT NULL,
  evidence TEXT NOT NULL DEFAULT '', remediation TEXT NOT NULL DEFAULT '', status TEXT NOT NULL,
  first_seen_at TEXT NOT NULL, last_seen_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS findings_device_status_idx ON findings(device_id, status, severity);
CREATE INDEX IF NOT EXISTS findings_fingerprint_idx ON findings(device_id, fingerprint, last_seen_at DESC);
-- Current risk is a durable projection, not a view over retained report
-- snapshots. Neither id nor report_id references a snapshot: report retention
-- must never erase an unresolved risk from the administrator's view.
CREATE TABLE IF NOT EXISTS current_findings (
  device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE, fingerprint TEXT NOT NULL,
  id TEXT NOT NULL UNIQUE, report_id TEXT NOT NULL, category TEXT NOT NULL, severity TEXT NOT NULL,
  title TEXT NOT NULL, description TEXT NOT NULL, evidence TEXT NOT NULL DEFAULT '',
  remediation TEXT NOT NULL DEFAULT '', status TEXT NOT NULL, first_seen_at TEXT NOT NULL,
  last_seen_at TEXT NOT NULL, updated_at TEXT NOT NULL,
  PRIMARY KEY(device_id, fingerprint)
);
CREATE INDEX IF NOT EXISTS current_findings_device_status_idx ON current_findings(device_id, status, severity);
CREATE TABLE IF NOT EXISTS current_findings_state (
  device_id TEXT PRIMARY KEY REFERENCES devices(id) ON DELETE CASCADE,
  report_id TEXT NOT NULL, completed_at TEXT NOT NULL, updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS schedules (
  id TEXT PRIMARY KEY, device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
  kind TEXT NOT NULL, interval_seconds INTEGER NOT NULL CHECK(interval_seconds >= 60), enabled INTEGER NOT NULL,
  next_run_at TEXT NOT NULL, last_run_at TEXT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS schedules_due_idx ON schedules(enabled, next_run_at);
CREATE TABLE IF NOT EXISTS device_commands (
  id TEXT PRIMARY KEY, device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
  type TEXT NOT NULL, payload TEXT NOT NULL DEFAULT '{}', created_at TEXT NOT NULL,
  claimed_at TEXT, started_at TEXT, completed_at TEXT, result TEXT, error TEXT NOT NULL DEFAULT '',
  completion_digest TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS commands_pending_idx ON device_commands(device_id, completed_at, created_at);
CREATE INDEX IF NOT EXISTS commands_unstarted_action_expiry_idx ON device_commands(created_at)
  WHERE completed_at IS NULL AND started_at IS NULL AND type IN ('execute_action','rollback_action','confirm_action');
CREATE INDEX IF NOT EXISTS commands_device_unstarted_action_expiry_idx ON device_commands(device_id,created_at)
  WHERE completed_at IS NULL AND started_at IS NULL AND type IN ('execute_action','rollback_action','confirm_action');
CREATE INDEX IF NOT EXISTS commands_started_action_expiry_idx ON device_commands(started_at)
  WHERE completed_at IS NULL AND started_at IS NOT NULL AND type IN ('execute_action','rollback_action','confirm_action');
CREATE TABLE IF NOT EXISTS ai_settings (
  singleton INTEGER PRIMARY KEY CHECK(singleton = 1), protocol TEXT NOT NULL, base_url TEXT NOT NULL,
  model TEXT NOT NULL, encrypted_api_key TEXT NOT NULL DEFAULT '', api_key_hint TEXT NOT NULL DEFAULT '',
  encrypted_headers TEXT NOT NULL DEFAULT '', updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS ai_investigation_policy (
  singleton INTEGER PRIMARY KEY CHECK(singleton=1), profile TEXT NOT NULL,
  daily_token_budget INTEGER NOT NULL CHECK(daily_token_budget BETWEEN 1000 AND 2000000),
  emergency_reserve_tokens INTEGER NOT NULL CHECK(emergency_reserve_tokens BETWEEN 0 AND 500000),
  share_network_indicators INTEGER NOT NULL DEFAULT 1,
  share_account_names INTEGER NOT NULL DEFAULT 1, updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS ai_investigation_usage (
  usage_day TEXT PRIMARY KEY, regular_tokens_used INTEGER NOT NULL DEFAULT 0 CHECK(regular_tokens_used >= 0),
  emergency_tokens_used INTEGER NOT NULL DEFAULT 0 CHECK(emergency_tokens_used >= 0),
  investigation_calls INTEGER NOT NULL DEFAULT 0 CHECK(investigation_calls >= 0), updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS sensor_health (
  device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE, sensor_id TEXT NOT NULL,
  name TEXT NOT NULL, mode TEXT NOT NULL, state TEXT NOT NULL, cadence_seconds INTEGER NOT NULL,
  last_success_at TEXT, last_event_at TEXT, event_count INTEGER NOT NULL DEFAULT 0,
  error TEXT NOT NULL DEFAULT '', updated_at TEXT NOT NULL, PRIMARY KEY(device_id,sensor_id)
);
CREATE INDEX IF NOT EXISTS sensor_health_device_state_idx ON sensor_health(device_id,state,updated_at);
CREATE TABLE IF NOT EXISTS notification_settings (
  singleton INTEGER PRIMARY KEY CHECK(singleton=1), webhook_enabled INTEGER NOT NULL DEFAULT 0,
  webhook_url TEXT NOT NULL DEFAULT '', encrypted_webhook_secret TEXT NOT NULL DEFAULT '',
  smtp_enabled INTEGER NOT NULL DEFAULT 0, smtp_host TEXT NOT NULL DEFAULT '', smtp_port INTEGER NOT NULL DEFAULT 587,
  smtp_username TEXT NOT NULL DEFAULT '', encrypted_smtp_password TEXT NOT NULL DEFAULT '',
  smtp_from TEXT NOT NULL DEFAULT '', smtp_to TEXT NOT NULL DEFAULT '[]', updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS notification_outbox (
  id TEXT PRIMARY KEY, event_id TEXT NOT NULL, channel TEXT NOT NULL CHECK(channel IN ('webhook','smtp')),
  event TEXT NOT NULL, settings_version TEXT NOT NULL,
  status TEXT NOT NULL CHECK(status IN ('pending','inflight','delivered','failed','canceled')),
  attempts INTEGER NOT NULL DEFAULT 0 CHECK(attempts >= 0), next_attempt_at TEXT NOT NULL,
  lease_until TEXT, last_error TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL, delivered_at TEXT, UNIQUE(event_id, channel)
);
CREATE INDEX IF NOT EXISTS notification_outbox_due_idx ON notification_outbox(channel,status,next_attempt_at,lease_until,created_at);
CREATE INDEX IF NOT EXISTS notification_outbox_terminal_idx ON notification_outbox(status,updated_at);
CREATE TABLE IF NOT EXISTS actions (
  id TEXT PRIMARY KEY, device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
  finding_id TEXT NOT NULL DEFAULT '', type TEXT NOT NULL, parameters TEXT NOT NULL, preview TEXT NOT NULL,
  status TEXT NOT NULL, approval_nonce_hash TEXT NOT NULL, approved_by TEXT NOT NULL DEFAULT '',
  approved_at TEXT, executed_at TEXT, completed_at TEXT, rollback_payload TEXT, confirm_by TEXT,
  error TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL, updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS actions_device_created_idx ON actions(device_id, created_at DESC);
CREATE TABLE IF NOT EXISTS action_audit (
  id INTEGER PRIMARY KEY AUTOINCREMENT, action_id TEXT NOT NULL REFERENCES actions(id) ON DELETE CASCADE,
  actor TEXT NOT NULL, event TEXT NOT NULL, details TEXT NOT NULL DEFAULT '{}', created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS defense_policies (
  device_id TEXT PRIMARY KEY REFERENCES devices(id) ON DELETE CASCADE, enabled INTEGER NOT NULL DEFAULT 0,
  emergency_stop INTEGER NOT NULL DEFAULT 0, auto_ban INTEGER NOT NULL DEFAULT 0,
  failure_threshold INTEGER NOT NULL DEFAULT 10, window_seconds INTEGER NOT NULL DEFAULT 300,
  ban_duration_seconds INTEGER NOT NULL DEFAULT 900, max_bans_per_hour INTEGER NOT NULL DEFAULT 10,
  allowlist TEXT NOT NULL DEFAULT '[]', updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS security_events (
  id TEXT NOT NULL, device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE, type TEXT NOT NULL,
  source_ip TEXT NOT NULL DEFAULT '', occurred_at TEXT NOT NULL, payload TEXT NOT NULL DEFAULT '{}'
  ,PRIMARY KEY(device_id,id)
);
CREATE INDEX IF NOT EXISTS security_events_correlation_idx ON security_events(device_id, type, source_ip, occurred_at);
CREATE INDEX IF NOT EXISTS security_events_global_list_idx ON security_events(occurred_at DESC,device_id DESC,id DESC);
CREATE INDEX IF NOT EXISTS security_events_device_list_idx ON security_events(device_id,occurred_at DESC,id DESC);
CREATE INDEX IF NOT EXISTS security_events_device_type_list_idx ON security_events(device_id,type,occurred_at DESC,id DESC);
CREATE TABLE IF NOT EXISTS security_event_retention_state (
  device_id TEXT PRIMARY KEY REFERENCES devices(id) ON DELETE CASCADE,
  since_prune INTEGER NOT NULL DEFAULT 0 CHECK(since_prune >= 0),
  window_count INTEGER NOT NULL DEFAULT -1 CHECK(window_count >= -1)
);
CREATE TABLE IF NOT EXISTS security_event_windows (
  device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE, type TEXT NOT NULL,
  source_ip TEXT NOT NULL, window_seconds INTEGER NOT NULL, window_started_at TEXT NOT NULL,
  last_seen_at TEXT NOT NULL, event_count INTEGER NOT NULL CHECK(event_count > 0), event_times TEXT NOT NULL DEFAULT '[]',
  window_ends_at TEXT NOT NULL DEFAULT '',
  PRIMARY KEY(device_id,type,source_ip)
);
CREATE INDEX IF NOT EXISTS security_event_windows_lru_idx ON security_event_windows(device_id,last_seen_at DESC);
CREATE INDEX IF NOT EXISTS security_event_windows_expiry_idx ON security_event_windows(device_id,window_ends_at);
CREATE TABLE IF NOT EXISTS temporary_bans (
  id TEXT PRIMARY KEY, device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
  action_id TEXT NOT NULL DEFAULT '', source_ip TEXT NOT NULL, reason TEXT NOT NULL,
  expires_at TEXT NOT NULL, created_at TEXT NOT NULL, simulated INTEGER NOT NULL DEFAULT 0,
  status TEXT NOT NULL DEFAULT 'active'
);
CREATE INDEX IF NOT EXISTS temporary_bans_active_idx ON temporary_bans(device_id, source_ip, expires_at);
CREATE TABLE IF NOT EXISTS signals (
  id TEXT NOT NULL, device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
  type TEXT NOT NULL, category TEXT NOT NULL, severity TEXT NOT NULL, trust TEXT NOT NULL,
  subject TEXT NOT NULL DEFAULT '', summary TEXT NOT NULL, source TEXT NOT NULL,
  source_ref TEXT NOT NULL DEFAULT '', payload TEXT NOT NULL DEFAULT '{}',
  occurred_at TEXT NOT NULL, ingested_at TEXT NOT NULL,
  PRIMARY KEY(device_id,id)
);
CREATE INDEX IF NOT EXISTS signals_device_time_idx ON signals(device_id,occurred_at DESC,id DESC);
CREATE INDEX IF NOT EXISTS signals_device_category_idx ON signals(device_id,category,occurred_at DESC);
CREATE TABLE IF NOT EXISTS incidents (
  id TEXT PRIMARY KEY, device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
  correlation_key TEXT NOT NULL, category TEXT NOT NULL, severity TEXT NOT NULL,
  status TEXT NOT NULL, title TEXT NOT NULL, summary TEXT NOT NULL,
  signal_count INTEGER NOT NULL DEFAULT 0 CHECK(signal_count >= 0),
  first_seen_at TEXT NOT NULL, last_seen_at TEXT NOT NULL, last_investigated_at TEXT,
  created_at TEXT NOT NULL, updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS incidents_device_status_idx ON incidents(device_id,status,severity,last_seen_at DESC);
CREATE UNIQUE INDEX IF NOT EXISTS incidents_active_correlation_idx ON incidents(device_id,correlation_key)
  WHERE status IN ('open','investigating','awaiting_approval','responding','monitoring');
CREATE TABLE IF NOT EXISTS incident_signals (
  incident_id TEXT NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
  device_id TEXT NOT NULL, signal_id TEXT NOT NULL,
  created_at TEXT NOT NULL,
  PRIMARY KEY(incident_id,device_id,signal_id),
  FOREIGN KEY(device_id,signal_id) REFERENCES signals(device_id,id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS incident_signals_signal_idx ON incident_signals(device_id,signal_id);
CREATE TABLE IF NOT EXISTS investigations (
  id TEXT PRIMARY KEY, incident_id TEXT NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
  status TEXT NOT NULL, trigger TEXT NOT NULL, hypothesis TEXT NOT NULL DEFAULT '',
	observations TEXT NOT NULL DEFAULT '[]', uncertainties TEXT NOT NULL DEFAULT '[]', next_checks TEXT NOT NULL DEFAULT '[]',
  conclusion TEXT NOT NULL DEFAULT '', confidence INTEGER NOT NULL DEFAULT 0 CHECK(confidence BETWEEN 0 AND 100),
  model TEXT NOT NULL DEFAULT '', tool_calls TEXT NOT NULL DEFAULT '[]', error TEXT NOT NULL DEFAULT '',
  started_at TEXT, completed_at TEXT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS investigations_incident_idx ON investigations(incident_id,created_at DESC);
CREATE TABLE IF NOT EXISTS response_plans (
  id TEXT PRIMARY KEY, incident_id TEXT NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
  investigation_id TEXT NOT NULL DEFAULT '', title TEXT NOT NULL, rationale TEXT NOT NULL,
  risk TEXT NOT NULL, status TEXT NOT NULL, requires_approval INTEGER NOT NULL,
  steps TEXT NOT NULL DEFAULT '[]', created_at TEXT NOT NULL, updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS response_plans_incident_idx ON response_plans(incident_id,created_at DESC);
CREATE TABLE IF NOT EXISTS response_plan_actions (
  plan_id TEXT NOT NULL REFERENCES response_plans(id) ON DELETE CASCADE,
  step_id TEXT NOT NULL, action_id TEXT NOT NULL UNIQUE REFERENCES actions(id) ON DELETE RESTRICT,
  created_at TEXT NOT NULL,
  PRIMARY KEY(plan_id,step_id)
);
CREATE TABLE IF NOT EXISTS policy_grants (
  device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE, capability TEXT NOT NULL,
  enabled INTEGER NOT NULL DEFAULT 0, mode TEXT NOT NULL DEFAULT 'observe',
  allowed_action_types TEXT NOT NULL DEFAULT '[]', max_actions_per_hour INTEGER NOT NULL DEFAULT 10,
  emergency_stop INTEGER NOT NULL DEFAULT 0, updated_at TEXT NOT NULL,
  PRIMARY KEY(device_id,capability)
);
CREATE TABLE IF NOT EXISTS incident_timeline (
  id INTEGER PRIMARY KEY AUTOINCREMENT, incident_id TEXT NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
  actor TEXT NOT NULL, type TEXT NOT NULL, summary TEXT NOT NULL,
  details TEXT NOT NULL DEFAULT '{}', created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS incident_timeline_incident_idx ON incident_timeline(incident_id,created_at,id);
INSERT OR IGNORE INTO schema_migrations(version, applied_at) VALUES (1, CURRENT_TIMESTAMP);
`
	if _, err := s.db.ExecContext(ctx, schema); err != nil {
		return fmt.Errorf("migrate database: %w", err)
	}
	// Version 1 development builds did not persist the SSH safety-confirmation
	// deadline. Keep upgrades from those databases safe without making fresh
	// installations depend on a separate migration runner.
	hasConfirmBy, err := s.tableHasColumn(ctx, "actions", "confirm_by")
	if err != nil {
		return fmt.Errorf("inspect action schema: %w", err)
	}
	if !hasConfirmBy {
		if _, err = s.db.ExecContext(ctx, `ALTER TABLE actions ADD COLUMN confirm_by TEXT`); err != nil {
			return fmt.Errorf("add action confirmation deadline: %w", err)
		}
	}
	hasCommandStart, err := s.tableHasColumn(ctx, "device_commands", "started_at")
	if err != nil {
		return fmt.Errorf("inspect device command schema: %w", err)
	}
	if !hasCommandStart {
		if _, err = s.db.ExecContext(ctx, `ALTER TABLE device_commands ADD COLUMN started_at TEXT`); err != nil {
			return fmt.Errorf("add device command start marker: %w", err)
		}
	}
	hasCommandCompletionDigest, err := s.tableHasColumn(ctx, "device_commands", "completion_digest")
	if err != nil {
		return fmt.Errorf("inspect command receipt schema: %w", err)
	}
	if !hasCommandCompletionDigest {
		if _, err = s.db.ExecContext(ctx, `ALTER TABLE device_commands ADD COLUMN completion_digest TEXT NOT NULL DEFAULT ''`); err != nil {
			return fmt.Errorf("add command completion receipt digest: %w", err)
		}
	}
	hasNotificationSettingsVersion, err := s.tableHasColumn(ctx, "notification_outbox", "settings_version")
	if err != nil {
		return fmt.Errorf("inspect notification outbox schema: %w", err)
	}
	if !hasNotificationSettingsVersion {
		if _, err = s.db.ExecContext(ctx, `ALTER TABLE notification_outbox ADD COLUMN settings_version TEXT NOT NULL DEFAULT ''`); err != nil {
			return fmt.Errorf("add notification settings generation: %w", err)
		}
		if _, err = s.db.ExecContext(ctx, `UPDATE notification_outbox SET settings_version=COALESCE((SELECT updated_at FROM notification_settings WHERE singleton=1),'') WHERE settings_version=''`); err != nil {
			return fmt.Errorf("backfill notification settings generation: %w", err)
		}
	}
	hasObserverOnly, err := s.tableHasColumn(ctx, "devices", "observer_only")
	if err != nil {
		return fmt.Errorf("inspect device capability schema: %w", err)
	}
	if !hasObserverOnly {
		if _, err = s.db.ExecContext(ctx, `ALTER TABLE devices ADD COLUMN observer_only INTEGER NOT NULL DEFAULT 0`); err != nil {
			return fmt.Errorf("add observer-only device capability: %w", err)
		}
	}
	hasReportDigest, err := s.tableHasColumn(ctx, "reports", "ingest_digest")
	if err != nil {
		return fmt.Errorf("inspect report receipt schema: %w", err)
	}
	if !hasReportDigest {
		if _, err = s.db.ExecContext(ctx, `ALTER TABLE reports ADD COLUMN ingest_digest TEXT NOT NULL DEFAULT ''`); err != nil {
			return fmt.Errorf("add report ingest receipt: %w", err)
		}
	}
	hasSecurityEventTimes, err := s.tableHasColumn(ctx, "security_event_windows", "event_times")
	if err != nil {
		return fmt.Errorf("inspect security event correlation schema: %w", err)
	}
	if !hasSecurityEventTimes {
		if _, err = s.db.ExecContext(ctx, `ALTER TABLE security_event_windows ADD COLUMN event_times TEXT NOT NULL DEFAULT '[]'`); err != nil {
			return fmt.Errorf("add exact security event correlation samples: %w", err)
		}
	}
	hasSecurityEventWindowEnd, err := s.tableHasColumn(ctx, "security_event_windows", "window_ends_at")
	if err != nil {
		return fmt.Errorf("inspect security event expiry schema: %w", err)
	}
	if !hasSecurityEventWindowEnd {
		if _, err = s.db.ExecContext(ctx, `ALTER TABLE security_event_windows ADD COLUMN window_ends_at TEXT NOT NULL DEFAULT ''`); err != nil {
			return fmt.Errorf("add security event correlation expiry: %w", err)
		}
	}
	if !hasSecurityEventTimes || !hasSecurityEventWindowEnd {
		// Legacy aggregate counts cannot be losslessly converted into exact
		// occurrence samples. Reset them instead of allowing stale high counters
		// to monopolize the bounded correlation table after upgrade.
		if _, err = s.db.ExecContext(ctx, `DELETE FROM security_event_windows`); err != nil {
			return fmt.Errorf("reset legacy security event correlation state: %w", err)
		}
	}
	compositeEventKey, err := s.securityEventsHaveCompositePrimaryKey(ctx)
	if err != nil {
		return fmt.Errorf("inspect security event key schema: %w", err)
	}
	if !compositeEventKey {
		tx, beginErr := s.db.BeginTx(ctx, nil)
		if beginErr != nil {
			return beginErr
		}
		defer tx.Rollback()
		if _, err = tx.ExecContext(ctx, `CREATE TABLE security_events_v2 (
			id TEXT NOT NULL,device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,type TEXT NOT NULL,
			source_ip TEXT NOT NULL DEFAULT '',occurred_at TEXT NOT NULL,payload TEXT NOT NULL DEFAULT '{}',
			PRIMARY KEY(device_id,id)
		)`); err != nil {
			return fmt.Errorf("create composite security event table: %w", err)
		}
		if _, err = tx.ExecContext(ctx, `INSERT OR IGNORE INTO security_events_v2(id,device_id,type,source_ip,occurred_at,payload) SELECT id,device_id,type,source_ip,occurred_at,payload FROM security_events`); err != nil {
			return fmt.Errorf("copy security events: %w", err)
		}
		if _, err = tx.ExecContext(ctx, `DROP TABLE security_events`); err != nil {
			return fmt.Errorf("replace security event table: %w", err)
		}
		if _, err = tx.ExecContext(ctx, `ALTER TABLE security_events_v2 RENAME TO security_events`); err != nil {
			return fmt.Errorf("rename security event table: %w", err)
		}
		if _, err = tx.ExecContext(ctx, `CREATE INDEX security_events_correlation_idx ON security_events(device_id,type,source_ip,occurred_at)`); err != nil {
			return fmt.Errorf("recreate security event index: %w", err)
		}
		if err = tx.Commit(); err != nil {
			return err
		}
	}
	if _, err = s.db.ExecContext(ctx, `
		CREATE INDEX IF NOT EXISTS security_events_global_list_idx ON security_events(occurred_at DESC,device_id DESC,id DESC);
		CREATE INDEX IF NOT EXISTS security_events_device_list_idx ON security_events(device_id,occurred_at DESC,id DESC);
		CREATE INDEX IF NOT EXISTS security_events_device_type_list_idx ON security_events(device_id,type,occurred_at DESC,id DESC);
	`); err != nil {
		return fmt.Errorf("create security event listing indexes: %w", err)
	}
	if err = s.migrateControllerSchedules(ctx); err != nil {
		return err
	}
	if err = s.migrateCurrentFindings(ctx); err != nil {
		return err
	}
	if err = s.migrateCurrentFindingCapacityV4(ctx); err != nil {
		return err
	}
	if err = s.migrateSecurityEngineerV5(ctx); err != nil {
		return err
	}
	if err = s.migrateResponsePlanActionsV6(ctx); err != nil {
		return err
	}
	if err = s.migrateSecurityEventRetentionV7(ctx); err != nil {
		return err
	}
	if err = s.migrateInvestigationEvidenceV8(ctx); err != nil {
		return err
	}
	return s.migrateRealtimeDefenseV9(ctx)
}

func (s *Store) migrateRealtimeDefenseV9(ctx context.Context) error {
	now := timeText(time.Now().UTC())
	_, err := s.db.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS ai_investigation_policy (
			singleton INTEGER PRIMARY KEY CHECK(singleton=1), profile TEXT NOT NULL,
			daily_token_budget INTEGER NOT NULL CHECK(daily_token_budget BETWEEN 1000 AND 2000000),
			emergency_reserve_tokens INTEGER NOT NULL CHECK(emergency_reserve_tokens BETWEEN 0 AND 500000),
			share_network_indicators INTEGER NOT NULL DEFAULT 1,
			share_account_names INTEGER NOT NULL DEFAULT 1, updated_at TEXT NOT NULL
		);
		CREATE TABLE IF NOT EXISTS ai_investigation_usage (
			usage_day TEXT PRIMARY KEY, regular_tokens_used INTEGER NOT NULL DEFAULT 0 CHECK(regular_tokens_used >= 0),
			emergency_tokens_used INTEGER NOT NULL DEFAULT 0 CHECK(emergency_tokens_used >= 0),
			investigation_calls INTEGER NOT NULL DEFAULT 0 CHECK(investigation_calls >= 0), updated_at TEXT NOT NULL
		);
		CREATE TABLE IF NOT EXISTS sensor_health (
			device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE, sensor_id TEXT NOT NULL,
			name TEXT NOT NULL, mode TEXT NOT NULL, state TEXT NOT NULL, cadence_seconds INTEGER NOT NULL,
			last_success_at TEXT, last_event_at TEXT, event_count INTEGER NOT NULL DEFAULT 0,
			error TEXT NOT NULL DEFAULT '', updated_at TEXT NOT NULL, PRIMARY KEY(device_id,sensor_id)
		);
		CREATE INDEX IF NOT EXISTS sensor_health_device_state_idx ON sensor_health(device_id,state,updated_at);
		INSERT OR IGNORE INTO ai_investigation_policy(singleton,profile,daily_token_budget,emergency_reserve_tokens,share_network_indicators,share_account_names,updated_at)
			VALUES(1,'balanced',60000,20000,1,1,?);
		INSERT OR IGNORE INTO schema_migrations(version,applied_at) VALUES(9,?);
	`, now, now)
	return err
}

func (s *Store) migrateInvestigationEvidenceV8(ctx context.Context) error {
	columns := []string{"observations", "uncertainties", "next_checks"}
	for _, column := range columns {
		exists, err := s.tableHasColumn(ctx, "investigations", column)
		if err != nil {
			return fmt.Errorf("inspect investigation evidence schema: %w", err)
		}
		if !exists {
			if _, err = s.db.ExecContext(ctx, `ALTER TABLE investigations ADD COLUMN `+column+` TEXT NOT NULL DEFAULT '[]'`); err != nil {
				return fmt.Errorf("add investigation evidence column %s: %w", column, err)
			}
		}
	}
	_, err := s.db.ExecContext(ctx, `INSERT OR IGNORE INTO schema_migrations(version,applied_at) VALUES(8,?)`, timeText(time.Now().UTC()))
	return err
}

// migrateSecurityEngineerV5 introduces the generic signal/incident/policy
// domain without changing the legacy SSH defense API. The SSH policy is copied
// into the first capability grant so existing installations preserve their
// effective posture while new code moves to capability-scoped authorization.
func (s *Store) migrateSecurityEngineerV5(ctx context.Context) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var applied int
	if err = tx.QueryRowContext(ctx, `SELECT count(*) FROM schema_migrations WHERE version=5`).Scan(&applied); err != nil {
		return err
	}
	if applied != 0 {
		return tx.Commit()
	}
	now := timeText(time.Now().UTC())
	if _, err = tx.ExecContext(ctx, `INSERT OR IGNORE INTO policy_grants(
		device_id,capability,enabled,mode,allowed_action_types,max_actions_per_hour,emergency_stop,updated_at
	) SELECT device_id,'network.auth_bruteforce',enabled,
		CASE WHEN auto_ban=1 THEN 'auto_low_risk' WHEN enabled=1 THEN 'assist' ELSE 'observe' END,
		'["temporary_ip_ban"]',max_bans_per_hour,emergency_stop,updated_at FROM defense_policies`); err != nil {
		return fmt.Errorf("migrate SSH defense capability: %w", err)
	}
	if _, err = tx.ExecContext(ctx, `INSERT OR IGNORE INTO schema_migrations(version,applied_at) VALUES(5,?)`, now); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) migrateResponsePlanActionsV6(ctx context.Context) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var applied int
	if err = tx.QueryRowContext(ctx, `SELECT count(*) FROM schema_migrations WHERE version=6`).Scan(&applied); err != nil {
		return err
	}
	if applied == 0 {
		if _, err = tx.ExecContext(ctx, `INSERT INTO schema_migrations(version,applied_at) VALUES(6,?)`, timeText(time.Now().UTC())); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) migrateSecurityEventRetentionV7(ctx context.Context) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS security_event_retention_state (
		device_id TEXT PRIMARY KEY REFERENCES devices(id) ON DELETE CASCADE,
		since_prune INTEGER NOT NULL DEFAULT 0 CHECK(since_prune >= 0),
		window_count INTEGER NOT NULL DEFAULT -1 CHECK(window_count >= -1)
	)`); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `CREATE INDEX IF NOT EXISTS security_event_windows_expiry_idx ON security_event_windows(device_id,window_ends_at)`); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `INSERT OR IGNORE INTO schema_migrations(version,applied_at) VALUES(7,?)`, timeText(time.Now().UTC())); err != nil {
		return err
	}
	return tx.Commit()
}

// migrateCurrentFindings builds the independent current-risk projection for
// databases created before it existed. Existing snapshot status already
// reflects the old projection rules, so the newest snapshot per fingerprint is
// the safest lossless source available during upgrade.
func (s *Store) migrateCurrentFindings(ctx context.Context) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var applied int
	if err = tx.QueryRowContext(ctx, `SELECT count(*) FROM schema_migrations WHERE version=3`).Scan(&applied); err != nil {
		return err
	}
	if applied != 0 {
		return tx.Commit()
	}
	now := time.Now().UTC()
	if _, err = tx.ExecContext(ctx, `WITH ranked_latest AS (
		SELECT f.*,f.rowid AS source_rowid,
			row_number() OVER (
				PARTITION BY f.device_id,f.fingerprint
				ORDER BY f.last_seen_at DESC,f.rowid DESC
			) AS latest_rank
		FROM findings f
	), latest AS (
		SELECT * FROM ranked_latest WHERE latest_rank=1 AND fingerprint<>?
	), bounded AS (
		SELECT latest.*,
			row_number() OVER (
				PARTITION BY device_id,CASE WHEN status=? THEN 1 ELSE 0 END
				ORDER BY
					CASE WHEN status=? THEN 0 ELSE CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END END,
					last_seen_at DESC,source_rowid DESC
			) AS capacity_rank
		FROM latest
	)
	INSERT OR REPLACE INTO current_findings(
		device_id,fingerprint,id,report_id,category,severity,title,description,evidence,remediation,status,first_seen_at,last_seen_at,updated_at
	)
	SELECT device_id,fingerprint,id,report_id,category,severity,title,description,evidence,remediation,status,first_seen_at,last_seen_at,?
	FROM bounded
	WHERE (status=? AND capacity_rank<=?) OR (status<>? AND capacity_rank<?)`,
		currentFindingCapacityFingerprint,
		string(domain.FindingResolved), string(domain.FindingResolved),
		timeText(now),
		string(domain.FindingResolved), maxResolvedCurrentFindingsPerDevice,
		string(domain.FindingResolved), maxCurrentFindingsPerDevice); err != nil {
		return fmt.Errorf("backfill current findings: %w", err)
	}
	if _, err = tx.ExecContext(ctx, `INSERT OR REPLACE INTO current_findings_state(device_id,report_id,completed_at,updated_at)
	SELECT r.device_id,r.id,r.completed_at,?
	FROM reports r
	WHERE NOT EXISTS (
		SELECT 1 FROM reports newer
		WHERE newer.device_id=r.device_id
		  AND (newer.completed_at>r.completed_at OR (newer.completed_at=r.completed_at AND newer.rowid>r.rowid))
	)`, timeText(now)); err != nil {
		return fmt.Errorf("backfill current finding watermarks: %w", err)
	}
	// A legacy database can contain more current risks than the live projection
	// permits. Bound the one-time migration too: opening an old database must not
	// materialize an attacker-controlled, unbounded projection before the next
	// scan. Keep the highest-priority 1,999 active records above and add the same
	// explicit critical capacity sentinel used by live ingestion.
	if _, err = tx.ExecContext(ctx, `WITH ranked_latest AS (
		SELECT f.*,f.rowid AS source_rowid,
			row_number() OVER (
				PARTITION BY f.device_id,f.fingerprint
				ORDER BY f.last_seen_at DESC,f.rowid DESC
			) AS latest_rank
		FROM findings f
	), active_counts AS (
		SELECT device_id,count(*) AS active_count,min(first_seen_at) AS first_seen_at,max(last_seen_at) AS last_seen_at
		FROM ranked_latest
		WHERE latest_rank=1 AND status<>? AND fingerprint<>?
		GROUP BY device_id HAVING count(*)>=?
	)
	INSERT OR REPLACE INTO current_findings(
		device_id,fingerprint,id,report_id,category,severity,title,description,evidence,remediation,status,first_seen_at,last_seen_at,updated_at
	)
	SELECT c.device_id,?,
		'fnd_migration_'||lower(hex(randomblob(16))),
		(SELECT r.id FROM reports r WHERE r.device_id=c.device_id ORDER BY r.completed_at DESC,r.rowid DESC LIMIT 1),
		'system','critical','Current finding capacity reached',
		printf('The current-risk projection reached its %d-item safety limit; %d lower-priority finding records were omitted. Recent immutable reports remain available for detailed review.',?,c.active_count-(?-1)),
		'','Review recent reports and remove duplicated or unbounded custom findings.',?,
		c.first_seen_at,c.last_seen_at,?
	FROM active_counts c`,
		string(domain.FindingResolved), currentFindingCapacityFingerprint, maxCurrentFindingsPerDevice,
		currentFindingCapacityFingerprint,
		maxCurrentFindingsPerDevice, maxCurrentFindingsPerDevice,
		string(domain.FindingOpen), timeText(now)); err != nil {
		return fmt.Errorf("record migrated current finding capacity: %w", err)
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO schema_migrations(version,applied_at) VALUES(3,?)`, timeText(now)); err != nil {
		return err
	}
	return tx.Commit()
}

// migrateCurrentFindingCapacityV4 applies both row and byte limits to
// projections created by older builds. Version 3 may already be marked as
// applied, so this must remain a distinct migration rather than changing the
// historical v3 backfill and waiting for a future scan to repair it.
func (s *Store) migrateCurrentFindingCapacityV4(ctx context.Context) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var applied int
	if err = tx.QueryRowContext(ctx, `SELECT count(*) FROM schema_migrations WHERE version=4`).Scan(&applied); err != nil {
		return err
	}
	if applied != 0 {
		return tx.Commit()
	}
	now := time.Now().UTC()
	if _, err = tx.ExecContext(ctx, `CREATE TEMP TABLE IF NOT EXISTS witshield_v4_finding_counts(device_id TEXT PRIMARY KEY,before_count INTEGER NOT NULL);
		DELETE FROM witshield_v4_finding_counts;
		INSERT INTO witshield_v4_finding_counts(device_id,before_count)
		SELECT device_id,count(*) FROM current_findings WHERE fingerprint<>? GROUP BY device_id`, currentFindingCapacityFingerprint); err != nil {
		return fmt.Errorf("snapshot legacy current finding capacity: %w", err)
	}
	if _, err = tx.ExecContext(ctx, `DELETE FROM current_findings WHERE rowid IN (
		SELECT rowid FROM (
			SELECT rowid,row_number() OVER (PARTITION BY device_id ORDER BY last_seen_at DESC,rowid DESC) AS retained_rank
			FROM current_findings WHERE status=? AND fingerprint<>?
		) WHERE retained_rank>?
	)`, string(domain.FindingResolved), currentFindingCapacityFingerprint, maxResolvedCurrentFindingsPerDevice); err != nil {
		return fmt.Errorf("bound migrated resolved findings: %w", err)
	}
	if _, err = tx.ExecContext(ctx, `DELETE FROM current_findings WHERE rowid IN (
		SELECT rowid FROM (
			SELECT rowid,row_number() OVER (PARTITION BY device_id ORDER BY
				CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END,
				last_seen_at DESC,rowid DESC) AS retained_rank
			FROM current_findings WHERE status<>? AND fingerprint<>?
		) WHERE retained_rank>=?
	)`, string(domain.FindingResolved), currentFindingCapacityFingerprint, maxCurrentFindingsPerDevice); err != nil {
		return fmt.Errorf("bound migrated active findings: %w", err)
	}
	if _, err = tx.ExecContext(ctx, `WITH ordered AS (
		SELECT rowid,sum(
			length(CAST(fingerprint AS BLOB))+length(CAST(category AS BLOB))+length(CAST(title AS BLOB))+
			length(CAST(description AS BLOB))+length(CAST(evidence AS BLOB))+length(CAST(remediation AS BLOB))+256
		) OVER (PARTITION BY device_id ORDER BY
			CASE WHEN status=? THEN 1 ELSE 0 END,
			CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END,
			last_seen_at DESC,rowid DESC) AS retained_bytes
		FROM current_findings WHERE fingerprint<>?
	)
	DELETE FROM current_findings WHERE rowid IN (SELECT rowid FROM ordered WHERE retained_bytes>?)`, string(domain.FindingResolved), currentFindingCapacityFingerprint, maxCurrentFindingBytesPerDevice); err != nil {
		return fmt.Errorf("bound migrated current finding bytes: %w", err)
	}
	if _, err = tx.ExecContext(ctx, `WITH after_counts AS (
		SELECT device_id,count(*) AS after_count,min(first_seen_at) AS first_seen_at,max(last_seen_at) AS last_seen_at
		FROM current_findings WHERE fingerprint<>? GROUP BY device_id
	), truncated AS (
		SELECT b.device_id,b.before_count,coalesce(a.after_count,0) AS after_count,a.first_seen_at,a.last_seen_at
		FROM witshield_v4_finding_counts b LEFT JOIN after_counts a ON a.device_id=b.device_id
		WHERE b.before_count>coalesce(a.after_count,0)
	)
	INSERT INTO current_findings(device_id,fingerprint,id,report_id,category,severity,title,description,evidence,remediation,status,first_seen_at,last_seen_at,updated_at)
	SELECT t.device_id,?,'fnd_v4_'||lower(hex(randomblob(16))),
		coalesce((SELECT report_id FROM current_findings c WHERE c.device_id=t.device_id ORDER BY last_seen_at DESC,rowid DESC LIMIT 1),(SELECT id FROM reports r WHERE r.device_id=t.device_id ORDER BY completed_at DESC,rowid DESC LIMIT 1)),
		'system','critical','Current finding capacity reached',
		printf('The current-risk projection reached its safety capacity (%d records / %d MiB); %d lower-priority finding records were omitted. Recent retained reports remain available for detailed review.',?,?,t.before_count-t.after_count),
		'','Review recent reports and remove duplicated or unbounded custom findings.',?,
		coalesce(t.first_seen_at,?),coalesce(t.last_seen_at,?),?
	FROM truncated t WHERE true
	ON CONFLICT(device_id,fingerprint) DO UPDATE SET id=excluded.id,report_id=excluded.report_id,category=excluded.category,severity=excluded.severity,title=excluded.title,description=excluded.description,evidence=excluded.evidence,remediation=excluded.remediation,status=excluded.status,last_seen_at=excluded.last_seen_at,updated_at=excluded.updated_at`,
		currentFindingCapacityFingerprint,
		currentFindingCapacityFingerprint, maxCurrentFindingsPerDevice, maxCurrentFindingBytesPerDevice>>20,
		string(domain.FindingOpen), timeText(now), timeText(now), timeText(now)); err != nil {
		return fmt.Errorf("record migrated current finding truncation: %w", err)
	}
	if _, err = tx.ExecContext(ctx, `DROP TABLE witshield_v4_finding_counts; INSERT INTO schema_migrations(version,applied_at) VALUES(4,?)`, timeText(now)); err != nil {
		return err
	}
	return tx.Commit()
}

// migrateControllerSchedules preserves the old Agent's default recurring-scan
// behavior while moving schedule authority to the Controller. It runs once:
// deleting or disabling schedules after migration remains an administrator
// decision and will not be undone on later restarts.
func (s *Store) migrateControllerSchedules(ctx context.Context) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var applied int
	if err = tx.QueryRowContext(ctx, `SELECT count(*) FROM schema_migrations WHERE version=2`).Scan(&applied); err != nil {
		return err
	}
	if applied != 0 {
		return tx.Commit()
	}
	rows, err := tx.QueryContext(ctx, `SELECT id FROM devices d WHERE d.status<>? AND NOT EXISTS (SELECT 1 FROM schedules s WHERE s.device_id=d.id)`, string(domain.DeviceRevoked))
	if err != nil {
		return err
	}
	var deviceIDs []string
	for rows.Next() {
		var deviceID string
		if err = rows.Scan(&deviceID); err != nil {
			rows.Close()
			return err
		}
		deviceIDs = append(deviceIDs, deviceID)
	}
	if err = rows.Close(); err != nil {
		return err
	}
	now := time.Now().UTC()
	for _, deviceID := range deviceIDs {
		if _, err = tx.ExecContext(ctx, `INSERT INTO schedules(id,device_id,kind,interval_seconds,enabled,next_run_at,last_run_at,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?)`, ids.New("sch"), deviceID, string(domain.ScheduleScan), int64(DefaultScanInterval/time.Second), true, timeText(now.Add(DefaultScanInterval)), nil, timeText(now), timeText(now)); err != nil {
			return err
		}
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO schema_migrations(version,applied_at) VALUES(2,?)`, timeText(now)); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) tableHasColumn(ctx context.Context, table, column string) (bool, error) {
	if table != "actions" && table != "device_commands" && table != "notification_outbox" && table != "devices" && table != "reports" && table != "security_event_windows" && table != "investigations" {
		return false, errors.New("unsupported schema inspection table")
	}
	rows, err := s.db.QueryContext(ctx, `PRAGMA table_info(`+table+`)`)
	if err != nil {
		return false, err
	}
	defer rows.Close()
	for rows.Next() {
		var cid int
		var name, typ string
		var notNull, primaryKey int
		var defaultValue any
		if err = rows.Scan(&cid, &name, &typ, &notNull, &defaultValue, &primaryKey); err != nil {
			return false, err
		}
		if name == column {
			return true, nil
		}
	}
	return false, rows.Err()
}

func (s *Store) securityEventsHaveCompositePrimaryKey(ctx context.Context) (bool, error) {
	rows, err := s.db.QueryContext(ctx, `PRAGMA table_info(security_events)`)
	if err != nil {
		return false, err
	}
	defer rows.Close()
	primaryKeyOrder := map[string]int{}
	for rows.Next() {
		var cid, notNull, primaryKey int
		var name, typ string
		var defaultValue any
		if err = rows.Scan(&cid, &name, &typ, &notNull, &defaultValue, &primaryKey); err != nil {
			return false, err
		}
		primaryKeyOrder[name] = primaryKey
	}
	if err = rows.Err(); err != nil {
		return false, err
	}
	return primaryKeyOrder["device_id"] == 1 && primaryKeyOrder["id"] == 2, nil
}

// SQLite compares these values lexically. RFC3339Nano omits trailing fractional
// zeroes, so it is not order-preserving as TEXT. Always write fixed-width UTC.
func timeText(t time.Time) string           { return t.UTC().Format("2006-01-02T15:04:05.000000000Z") }
func parseTime(v string) (time.Time, error) { return time.Parse(time.RFC3339Nano, v) }
func nullableTime(v sql.NullString) (*time.Time, error) {
	if !v.Valid {
		return nil, nil
	}
	t, err := parseTime(v.String)
	if err != nil {
		return nil, err
	}
	return &t, nil
}

func mapSQLError(err error) error {
	if err == nil {
		return nil
	}
	lower := strings.ToLower(err.Error())
	if strings.Contains(lower, "unique constraint") || strings.Contains(lower, "constraint failed") {
		return fmt.Errorf("%w: %v", ErrConflict, err)
	}
	return err
}
