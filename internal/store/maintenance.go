package store

import (
	"context"
	"errors"
	"time"

	"github.com/witkitlab/witshield/internal/domain"
)

const (
	maxTerminalActionsPerDevice      = 2_000
	maxDetailedCommandsPerDevice     = 5_000
	maxCommandTombstonesPerDevice    = 12_000
	maxTerminalBansPerDevice         = 5_000
	maxDetailedCommandBytesPerDevice = 64 << 20
	maxTerminalActionBytesPerDevice  = 64 << 20
)

// Maintain applies time-based state transitions and removes data that is no
// longer useful to the product. It is safe to call repeatedly and is also run
// once at Controller startup so an extended shutdown does not leave stale
// approvals visible after restart.
func (s *Store) Maintain(ctx context.Context, now time.Time) error {
	var errs []error
	if err := s.ExpireStaleActionCommands(ctx, now); err != nil {
		errs = append(errs, err)
	}
	if err := s.ExpireActionConfirmations(ctx, now); err != nil {
		errs = append(errs, err)
	}
	if err := s.ExpireDraftActions(ctx, now); err != nil {
		errs = append(errs, err)
	}
	if _, err := s.db.ExecContext(ctx, `DELETE FROM enrollment_challenges WHERE expires_at<=? OR (used_at IS NOT NULL AND used_at<?)`, timeText(now), timeText(now.Add(-time.Hour))); err != nil {
		errs = append(errs, err)
	}
	// Security events are only accepted for the latest seven days and are used
	// for short correlation windows. Older rows have no operational value.
	if _, err := s.db.ExecContext(ctx, `DELETE FROM security_events WHERE occurred_at<?`, timeText(now.Add(-7*24*time.Hour))); err != nil {
		errs = append(errs, err)
	}
	// Exact per-source correlation samples have no audit value after their own
	// policy window closes. Legacy rows without an end marker receive the
	// maximum 24-hour grace period.
	if _, err := s.db.ExecContext(ctx, `DELETE FROM security_event_windows WHERE (window_ends_at<>'' AND window_ends_at<=?) OR (window_ends_at='' AND last_seen_at<?)`, timeText(now), timeText(now.Add(-24*time.Hour))); err != nil {
		errs = append(errs, err)
	}
	if _, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE expires_at<=?`, timeText(now)); err != nil {
		errs = append(errs, err)
	}
	if _, err := s.db.ExecContext(ctx, `DELETE FROM agent_request_nonces WHERE expires_at<=?`, timeText(now)); err != nil {
		errs = append(errs, err)
	}
	// expires_at is the Controller-owned earliest possible kernel expiry. Once
	// that guaranteed-active horizon passes, clocks/suspend gaps prevent us from
	// claiming the element is gone. Release dedupe but retain an explicit unknown
	// state until a rollback, replacement generation, or later evidence resolves it.
	if _, err := s.db.ExecContext(ctx, `UPDATE temporary_bans SET status='indeterminate' WHERE simulated=0 AND status='active' AND expires_at<=?`, timeText(now)); err != nil {
		errs = append(errs, err)
	}
	if _, err := s.db.ExecContext(ctx, `DELETE FROM temporary_bans WHERE (simulated=1 AND expires_at<?) OR (simulated=0 AND status IN ('failed','cancelled','rolled_back','expired') AND expires_at<?) OR (simulated=0 AND status='indeterminate' AND expires_at<?)`, timeText(now.Add(-24*time.Hour)), timeText(now.Add(-30*24*time.Hour)), timeText(now.Add(-90*24*time.Hour))); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

// Compact performs ranked retention work at startup and on a slow cadence.
// Running these full-history window queries once per minute would monopolize
// SQLite's single connection as the number of devices grows.
func (s *Store) Compact(ctx context.Context, now time.Time) error {
	var errs []error
	if _, err := s.db.ExecContext(ctx, `DELETE FROM temporary_bans WHERE id IN (
		SELECT id FROM (
			SELECT id,row_number() OVER (PARTITION BY device_id ORDER BY created_at DESC,rowid DESC) AS retained_rank
			FROM temporary_bans WHERE simulated=1 OR status IN ('failed','cancelled','rolled_back','expired') OR (status='indeterminate' AND expires_at<=?)
		) WHERE retained_rank>?
	)`, timeText(now), maxTerminalBansPerDevice); err != nil {
		errs = append(errs, err)
	}
	if _, err := s.db.ExecContext(ctx, `WITH audit_sizes AS (
		SELECT action_id,sum(length(CAST(details AS BLOB))+128) AS audit_bytes FROM action_audit GROUP BY action_id
	), terminal AS (
		SELECT a.id,
			row_number() OVER (PARTITION BY a.device_id ORDER BY CASE WHEN a.status='indeterminate' THEN 0 ELSE 1 END,a.updated_at DESC,a.rowid DESC) AS retained_rank,
			sum(length(CAST(a.parameters AS BLOB))+length(CAST(a.preview AS BLOB))+coalesce(length(CAST(a.rollback_payload AS BLOB)),0)+length(CAST(a.error AS BLOB))+coalesce(s.audit_bytes,0)+512)
			OVER (PARTITION BY a.device_id ORDER BY CASE WHEN a.status='indeterminate' THEN 0 ELSE 1 END,a.updated_at DESC,a.rowid DESC) AS retained_bytes
		FROM actions a LEFT JOIN audit_sizes s ON s.action_id=a.id WHERE a.status IN ('succeeded','failed','rolled_back','cancelled','indeterminate')
			AND NOT EXISTS (SELECT 1 FROM temporary_bans b WHERE b.action_id=a.id AND (b.status='pending' OR (b.status IN ('active','indeterminate') AND b.expires_at>?)))
	)
	DELETE FROM actions WHERE id IN (SELECT id FROM terminal WHERE retained_rank>? OR retained_bytes>?)`, timeText(now), maxTerminalActionsPerDevice, maxTerminalActionBytesPerDevice); err != nil {
		errs = append(errs, err)
	}
	// Legacy action completions have no full replay digest and refer to their
	// action only through payload JSON. Action retention may therefore remove
	// the final proof needed to validate an exact replay before the command's
	// own, larger detail window is reached. Remove such completed orphans in the
	// same compaction pass so a delayed Agent queue item receives the endpoint's
	// terminal 410 instead of a permanent 409 at the FIFO head. This also heals
	// databases which already contain an orphan from an older Controller.
	if _, err := s.db.ExecContext(ctx, `DELETE FROM device_commands
	WHERE completed_at IS NOT NULL AND completion_digest=''
	  AND type IN (?,?,?)
	  AND NOT EXISTS (
		SELECT 1 FROM actions a
		WHERE a.id=CASE WHEN json_valid(device_commands.payload) THEN json_extract(device_commands.payload,'$.actionId') ELSE NULL END
		  AND a.device_id=device_commands.device_id
	  )`, string(domain.CommandExecuteAction), string(domain.CommandRollback), string(domain.CommandConfirm)); err != nil {
		errs = append(errs, err)
	}
	if _, err := s.db.ExecContext(ctx, `WITH ranked AS (
		SELECT id,
			row_number() OVER (PARTITION BY device_id ORDER BY completed_at DESC,rowid DESC) AS retained_rank,
			sum(length(CAST(payload AS BLOB))+coalesce(length(CAST(result AS BLOB)),0)+length(CAST(error AS BLOB))+256)
			OVER (PARTITION BY device_id ORDER BY completed_at DESC,rowid DESC) AS retained_bytes
		FROM device_commands WHERE completed_at IS NOT NULL
	)
	UPDATE device_commands SET payload='{}',result=NULL,claimed_at=NULL
	WHERE id IN (SELECT id FROM ranked WHERE retained_rank>? OR retained_bytes>?)
	  AND (completion_digest<>'' OR error IN (?,?))`,
		maxDetailedCommandsPerDevice, maxDetailedCommandBytesPerDevice,
		supersededScanMessage, commandExecutionIndeterminateMessage); err != nil {
		errs = append(errs, err)
	}
	if _, err := s.db.ExecContext(ctx, `WITH ranked AS (
		SELECT id,
			row_number() OVER (PARTITION BY device_id ORDER BY completed_at DESC,rowid DESC) AS retained_rank,
			sum(length(CAST(payload AS BLOB))+coalesce(length(CAST(result AS BLOB)),0)+length(CAST(error AS BLOB))+256)
			OVER (PARTITION BY device_id ORDER BY completed_at DESC,rowid DESC) AS retained_bytes
		FROM device_commands WHERE completed_at IS NOT NULL
	)
	DELETE FROM device_commands WHERE id IN (SELECT id FROM ranked WHERE retained_rank>? OR retained_bytes>?)
	  AND completion_digest='' AND error NOT IN (?,?)`, maxDetailedCommandsPerDevice, maxDetailedCommandBytesPerDevice, supersededScanMessage, commandExecutionIndeterminateMessage); err != nil {
		errs = append(errs, err)
	}
	if _, err := s.db.ExecContext(ctx, `DELETE FROM device_commands WHERE id IN (
		SELECT id FROM (
			SELECT id,row_number() OVER (PARTITION BY device_id ORDER BY completed_at DESC,rowid DESC) AS retained_rank
			FROM device_commands WHERE completed_at IS NOT NULL AND payload='{}' AND result IS NULL
		) WHERE retained_rank>?
	)`, maxCommandTombstonesPerDevice); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}
