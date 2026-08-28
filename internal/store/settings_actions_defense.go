package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/witkitlab/witshield/internal/domain"
	"github.com/witkitlab/witshield/internal/ids"
)

type StoredAISettings struct {
	Settings         domain.AISettings
	EncryptedAPIKey  string
	EncryptedHeaders string
}

func (s *Store) PutAISettings(ctx context.Context, x StoredAISettings) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO ai_settings(singleton,protocol,base_url,model,encrypted_api_key,api_key_hint,encrypted_headers,updated_at) VALUES(1,?,?,?,?,?,?,?) ON CONFLICT(singleton) DO UPDATE SET protocol=excluded.protocol,base_url=excluded.base_url,model=excluded.model,encrypted_api_key=excluded.encrypted_api_key,api_key_hint=excluded.api_key_hint,encrypted_headers=excluded.encrypted_headers,updated_at=excluded.updated_at`, string(x.Settings.Protocol), x.Settings.BaseURL, x.Settings.Model, x.EncryptedAPIKey, x.Settings.APIKeyHint, x.EncryptedHeaders, timeText(x.Settings.UpdatedAt))
	return err
}
func (s *Store) AISettings(ctx context.Context) (StoredAISettings, error) {
	var x StoredAISettings
	var updated string
	err := s.db.QueryRowContext(ctx, `SELECT protocol,base_url,model,encrypted_api_key,api_key_hint,encrypted_headers,updated_at FROM ai_settings WHERE singleton=1`).Scan(&x.Settings.Protocol, &x.Settings.BaseURL, &x.Settings.Model, &x.EncryptedAPIKey, &x.Settings.APIKeyHint, &x.EncryptedHeaders, &updated)
	if errors.Is(err, sql.ErrNoRows) {
		return x, ErrNotFound
	}
	if err != nil {
		return x, err
	}
	x.Settings.UpdatedAt, err = parseTime(updated)
	x.Settings.KeyConfigured = x.EncryptedAPIKey != ""
	return x, err
}

func (s *Store) CreateAction(ctx context.Context, x domain.Action, nonceHash, actor string) error {
	if x.ID == "" {
		x.ID = ids.New("act")
	}
	if len(x.Parameters) == 0 {
		x.Parameters = json.RawMessage(`{}`)
	}
	if len(x.Preview) == 0 {
		x.Preview = json.RawMessage(`{}`)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err = expireDraftActionsTx(ctx, tx, x.DeviceID, x.CreatedAt); err != nil {
		return err
	}
	if err = ensureUnfinishedActionCapacityTx(ctx, tx, x.DeviceID); err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO actions(id,device_id,finding_id,type,parameters,preview,status,approval_nonce_hash,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?)`, x.ID, x.DeviceID, x.FindingID, x.Type, string(x.Parameters), string(x.Preview), string(x.Status), nonceHash, timeText(x.CreatedAt), timeText(x.UpdatedAt))
	if err != nil {
		return mapSQLError(err)
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO action_audit(action_id,actor,event,details,created_at) VALUES(?,?,?,?,?)`, x.ID, actor, "preview_created", string(x.Preview), timeText(x.CreatedAt)); err != nil {
		return err
	}
	return tx.Commit()
}

func scanAction(row interface{ Scan(...any) error }) (domain.Action, string, error) {
	var x domain.Action
	var params, preview string
	var nonce string
	var approved, executed, completed, confirmBy sql.NullString
	var rollback sql.NullString
	var created, updated string
	err := row.Scan(&x.ID, &x.DeviceID, &x.FindingID, &x.Type, &params, &preview, &x.Status, &nonce, &x.ApprovedBy, &approved, &executed, &completed, &rollback, &confirmBy, &x.Error, &created, &updated)
	if errors.Is(err, sql.ErrNoRows) {
		return x, "", ErrNotFound
	}
	if err != nil {
		return x, "", err
	}
	x.Parameters = json.RawMessage(params)
	x.Preview = json.RawMessage(preview)
	x.ApprovedAt, err = nullableTime(approved)
	if err != nil {
		return x, "", err
	}
	x.ExecutedAt, err = nullableTime(executed)
	if err != nil {
		return x, "", err
	}
	x.CompletedAt, err = nullableTime(completed)
	if err != nil {
		return x, "", err
	}
	if rollback.Valid {
		x.RollbackPayload = json.RawMessage(rollback.String)
	}
	x.ConfirmBy, err = nullableTime(confirmBy)
	if err != nil {
		return x, "", err
	}
	x.CreatedAt, err = parseTime(created)
	if err != nil {
		return x, "", err
	}
	x.UpdatedAt, err = parseTime(updated)
	return x, nonce, err
}

const actionColumns = `id,device_id,finding_id,type,parameters,preview,status,approval_nonce_hash,approved_by,approved_at,executed_at,completed_at,rollback_payload,confirm_by,error,created_at,updated_at`

func (s *Store) Action(ctx context.Context, id string) (domain.Action, string, error) {
	return scanAction(s.db.QueryRowContext(ctx, `SELECT `+actionColumns+` FROM actions WHERE id=?`, id))
}
func (s *Store) ListActions(ctx context.Context, deviceID string, limit int) ([]domain.Action, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	q := `SELECT ` + actionColumns + ` FROM actions`
	args := []any{}
	if deviceID != "" {
		q += ` WHERE device_id=?`
		args = append(args, deviceID)
	}
	q += ` ORDER BY created_at DESC LIMIT ?`
	args = append(args, limit)
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.Action
	for rows.Next() {
		x, _, e := scanAction(rows)
		if e != nil {
			return nil, e
		}
		out = append(out, x)
	}
	return out, rows.Err()
}

const actionApprovalTTL = 10 * time.Minute
const maxUnfinishedActionsPerDevice = 200

func expireDraftActionsTx(ctx context.Context, tx *sql.Tx, deviceID string, now time.Time) error {
	where := `status=? AND created_at<?`
	args := []any{string(domain.ActionDraft), timeText(now.Add(-actionApprovalTTL))}
	if deviceID != "" {
		where += ` AND device_id=?`
		args = append(args, deviceID)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO action_audit(action_id,actor,event,details,created_at)
		SELECT id,'controller','approval_expired','{}',? FROM actions WHERE `+where, append([]any{timeText(now)}, args...)...); err != nil {
		return err
	}
	updateArgs := []any{string(domain.ActionCancelled), timeText(now), "action approval expired before confirmation", timeText(now)}
	updateArgs = append(updateArgs, args...)
	_, err := tx.ExecContext(ctx, `UPDATE actions SET status=?,completed_at=?,error=?,updated_at=? WHERE `+where, updateArgs...)
	return err
}

func ensureUnfinishedActionCapacityTx(ctx context.Context, tx *sql.Tx, deviceID string) error {
	var unfinished int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM actions WHERE device_id=? AND status NOT IN (?,?,?,?,?)`, deviceID,
		string(domain.ActionSucceeded), string(domain.ActionFailed), string(domain.ActionRolledBack), string(domain.ActionCancelled), string(domain.ActionIndeterminate)).Scan(&unfinished); err != nil {
		return err
	}
	if unfinished >= maxUnfinishedActionsPerDevice {
		return ErrConflict
	}
	return nil
}

func (s *Store) ExpireDraftActions(ctx context.Context, now time.Time) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err = expireDraftActionsTx(ctx, tx, "", now); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) ApproveAction(ctx context.Context, id, nonceHash, adminID string, now time.Time) (domain.Action, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return domain.Action{}, err
	}
	defer tx.Rollback()
	res, err := tx.ExecContext(ctx, `UPDATE actions SET status=?,approved_by=?,approved_at=?,updated_at=? WHERE id=? AND status=? AND approval_nonce_hash=? AND created_at>=?`, string(domain.ActionApproved), adminID, timeText(now), timeText(now), id, string(domain.ActionDraft), nonceHash, timeText(now.Add(-actionApprovalTTL)))
	if err != nil {
		return domain.Action{}, err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return domain.Action{}, ErrConflict
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO action_audit(action_id,actor,event,created_at) VALUES(?,?,?,?)`, id, adminID, "approved", timeText(now)); err != nil {
		return domain.Action{}, err
	}
	if err = tx.Commit(); err != nil {
		return domain.Action{}, err
	}
	x, _, err := s.Action(ctx, id)
	return x, err
}

func (s *Store) ApproveActionAndEnqueue(ctx context.Context, id, nonceHash, adminID string, cmd domain.DeviceCommand, now time.Time) (domain.Action, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return domain.Action{}, err
	}
	defer tx.Rollback()
	res, err := tx.ExecContext(ctx, `UPDATE actions SET status=?,approved_by=?,approved_at=?,updated_at=? WHERE id=? AND status=? AND approval_nonce_hash=? AND created_at>=?`, string(domain.ActionApproved), adminID, timeText(now), timeText(now), id, string(domain.ActionDraft), nonceHash, timeText(now.Add(-actionApprovalTTL)))
	if err != nil {
		return domain.Action{}, err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return domain.Action{}, ErrConflict
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO device_commands(id,device_id,type,payload,created_at) VALUES(?,?,?,?,?)`, cmd.ID, cmd.DeviceID, string(cmd.Type), string(cmd.Payload), timeText(cmd.CreatedAt)); err != nil {
		return domain.Action{}, err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO action_audit(action_id,actor,event,details,created_at) VALUES(?,?,?,?,?)`, id, adminID, "approved_and_queued", `{}`, timeText(now)); err != nil {
		return domain.Action{}, err
	}
	if err = markIncidentRespondingForActionTx(ctx, tx, id, adminID, now); err != nil {
		return domain.Action{}, err
	}
	if err = tx.Commit(); err != nil {
		return domain.Action{}, err
	}
	x, _, err := s.Action(ctx, id)
	return x, err
}
func (s *Store) MarkActionExecuting(ctx context.Context, id string, now time.Time) error {
	return s.transitionAction(ctx, id, domain.ActionApproved, domain.ActionExecuting, "agent", "execution_started", nil, "", now)
}
func (s *Store) CompleteAction(ctx context.Context, id string, ok bool, result, rollback json.RawMessage, errorText string, now time.Time) error {
	status := domain.ActionFailed
	if ok {
		status = domain.ActionSucceeded
	}
	details := result
	if len(details) == 0 {
		details = json.RawMessage(`{}`)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	res, err := tx.ExecContext(ctx, `UPDATE actions SET status=?,completed_at=?,rollback_payload=?,error=?,updated_at=? WHERE id=? AND status IN (?,?)`, string(status), timeText(now), nullableJSON(rollback), errorText, timeText(now), id, string(domain.ActionExecuting), string(domain.ActionApproved))
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrConflict
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO action_audit(action_id,actor,event,details,created_at) VALUES(?,?,?,?,?)`, id, "agent", string(status), string(details), timeText(now)); err != nil {
		return err
	}
	return tx.Commit()
}
func nullableJSON(v json.RawMessage) any {
	if len(v) == 0 {
		return nil
	}
	return string(v)
}
func (s *Store) RequestRollback(ctx context.Context, id, adminID string, now time.Time) error {
	return s.transitionAction(ctx, id, domain.ActionSucceeded, domain.ActionRollingBack, adminID, "rollback_requested", nil, "", now)
}
func (s *Store) RequestRollbackAndEnqueue(ctx context.Context, id, adminID string, cmd domain.DeviceCommand, now time.Time) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err = ensureUnfinishedActionCapacityTx(ctx, tx, cmd.DeviceID); err != nil {
		return err
	}
	res, err := tx.ExecContext(ctx, `UPDATE actions SET status=?,updated_at=? WHERE id=? AND rollback_payload IS NOT NULL AND status IN (?,?,?,?)`, string(domain.ActionRollingBack), timeText(now), id, string(domain.ActionSucceeded), string(domain.ActionAwaitingConfirmation), string(domain.ActionFailed), string(domain.ActionIndeterminate))
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrConflict
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO device_commands(id,device_id,type,payload,created_at) VALUES(?,?,?,?,?)`, cmd.ID, cmd.DeviceID, string(cmd.Type), string(cmd.Payload), timeText(cmd.CreatedAt)); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO action_audit(action_id,actor,event,details,created_at) VALUES(?,?,?,?,?)`, id, adminID, "rollback_requested", `{}`, timeText(now)); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) RequestConfirmationAndEnqueue(ctx context.Context, id, adminID string, cmd domain.DeviceCommand, now time.Time) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	res, err := tx.ExecContext(ctx, `UPDATE actions SET status=?,updated_at=? WHERE id=? AND status=? AND rollback_payload IS NOT NULL AND confirm_by>?`, string(domain.ActionConfirming), timeText(now), id, string(domain.ActionAwaitingConfirmation), timeText(now))
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return ErrConflict
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO device_commands(id,device_id,type,payload,created_at) VALUES(?,?,?,?,?)`, cmd.ID, cmd.DeviceID, string(cmd.Type), string(cmd.Payload), timeText(cmd.CreatedAt)); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO action_audit(action_id,actor,event,details,created_at) VALUES(?,?,?,?,?)`, id, adminID, "confirmation_requested", `{}`, timeText(now)); err != nil {
		return err
	}
	return tx.Commit()
}

// ExpireActionConfirmations records that the administrator did not confirm a
// safety-window action. The root helper owns the durable rollback timer; the
// Controller deliberately says "triggered" rather than claiming the rollback
// succeeded without a device receipt.
func (s *Store) ExpireActionConfirmations(ctx context.Context, now time.Time) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	rows, err := tx.QueryContext(ctx, `SELECT id FROM actions WHERE status=? AND confirm_by IS NOT NULL AND confirm_by<=?`, string(domain.ActionAwaitingConfirmation), timeText(now))
	if err != nil {
		return err
	}
	var ids []string
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil {
			rows.Close()
			return err
		}
		ids = append(ids, id)
	}
	if err = rows.Close(); err != nil {
		return err
	}
	const message = "confirmation window expired; the helper safety rollback was triggered"
	for _, id := range ids {
		res, updateErr := tx.ExecContext(ctx, `UPDATE actions SET status=?,completed_at=?,error=?,updated_at=? WHERE id=? AND status=?`, string(domain.ActionCancelled), timeText(now), message, timeText(now), id, string(domain.ActionAwaitingConfirmation))
		if updateErr != nil {
			return updateErr
		}
		if n, _ := res.RowsAffected(); n == 1 {
			if _, err = tx.ExecContext(ctx, `INSERT INTO action_audit(action_id,actor,event,details,created_at) VALUES(?,?,?,?,?)`, id, "controller", "confirmation_expired_safety_rollback_triggered", `{}`, timeText(now)); err != nil {
				return err
			}
		}
	}
	return tx.Commit()
}
func (s *Store) CompleteRollback(ctx context.Context, id string, ok bool, details json.RawMessage, errorText string, now time.Time) error {
	status := domain.ActionFailed
	if ok {
		status = domain.ActionRolledBack
	}
	return s.transitionAction(ctx, id, domain.ActionRollingBack, status, "agent", string(status), details, errorText, now)
}
func (s *Store) transitionAction(ctx context.Context, id string, from, to domain.ActionStatus, actor, event string, details json.RawMessage, errorText string, now time.Time) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	res, err := tx.ExecContext(ctx, `UPDATE actions SET status=?,error=?,updated_at=? WHERE id=? AND status=?`, string(to), errorText, timeText(now), id, string(from))
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrConflict
	}
	if len(details) == 0 {
		details = json.RawMessage(`{}`)
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO action_audit(action_id,actor,event,details,created_at) VALUES(?,?,?,?,?)`, id, actor, event, string(details), timeText(now)); err != nil {
		return err
	}
	return tx.Commit()
}
func (s *Store) ActionAudit(ctx context.Context, actionID string, limit int) ([]domain.ActionAudit, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	q := `SELECT id,action_id,actor,event,details,created_at FROM action_audit`
	args := []any{}
	if actionID != "" {
		q += ` WHERE action_id=?`
		args = append(args, actionID)
	}
	q += ` ORDER BY id DESC LIMIT ?`
	args = append(args, limit)
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.ActionAudit
	for rows.Next() {
		var x domain.ActionAudit
		var details, created string
		if err = rows.Scan(&x.ID, &x.ActionID, &x.Actor, &x.Event, &details, &created); err != nil {
			return nil, err
		}
		x.Details = json.RawMessage(details)
		x.CreatedAt, err = parseTime(created)
		if err != nil {
			return nil, err
		}
		out = append(out, x)
	}
	return out, rows.Err()
}

func defaultPolicy(deviceID string, now time.Time) domain.DefensePolicy {
	return domain.DefensePolicy{DeviceID: deviceID, FailureThreshold: 10, Window: 5 * time.Minute, WindowText: "5m", BanDuration: 15 * time.Minute, BanDurationText: "15m", MaxBansPerHour: 10, Allowlist: []string{}, UpdatedAt: now.UTC()}
}
func (s *Store) DefensePolicy(ctx context.Context, deviceID string, now time.Time) (domain.DefensePolicy, error) {
	var x domain.DefensePolicy
	var window, ban int64
	var allow, updated string
	err := s.db.QueryRowContext(ctx, `SELECT device_id,enabled,emergency_stop,auto_ban,failure_threshold,window_seconds,ban_duration_seconds,max_bans_per_hour,allowlist,updated_at FROM defense_policies WHERE device_id=?`, deviceID).Scan(&x.DeviceID, &x.Enabled, &x.EmergencyStop, &x.AutoBan, &x.FailureThreshold, &window, &ban, &x.MaxBansPerHour, &allow, &updated)
	if errors.Is(err, sql.ErrNoRows) {
		if err = s.RequireDevice(ctx, deviceID); err != nil {
			return x, err
		}
		return defaultPolicy(deviceID, now), nil
	}
	if err != nil {
		return x, err
	}
	x.Window = time.Duration(window) * time.Second
	x.WindowText = x.Window.String()
	x.BanDuration = time.Duration(ban) * time.Second
	x.BanDurationText = x.BanDuration.String()
	if err = json.Unmarshal([]byte(allow), &x.Allowlist); err != nil {
		return x, err
	}
	x.UpdatedAt, err = parseTime(updated)
	return x, err
}
func (s *Store) PutDefensePolicy(ctx context.Context, x domain.DefensePolicy) error {
	allow, _ := json.Marshal(x.Allowlist)
	_, err := s.db.ExecContext(ctx, `INSERT INTO defense_policies(device_id,enabled,emergency_stop,auto_ban,failure_threshold,window_seconds,ban_duration_seconds,max_bans_per_hour,allowlist,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?) ON CONFLICT(device_id) DO UPDATE SET enabled=excluded.enabled,emergency_stop=excluded.emergency_stop,auto_ban=excluded.auto_ban,failure_threshold=excluded.failure_threshold,window_seconds=excluded.window_seconds,ban_duration_seconds=excluded.ban_duration_seconds,max_bans_per_hour=excluded.max_bans_per_hour,allowlist=excluded.allowlist,updated_at=excluded.updated_at`, x.DeviceID, x.Enabled, x.EmergencyStop, x.AutoBan, x.FailureThreshold, int64(x.Window/time.Second), int64(x.BanDuration/time.Second), x.MaxBansPerHour, string(allow), timeText(x.UpdatedAt))
	return err
}

// PutDefensePolicyAndCancelQueued persists the switch and, when emergency stop
// is active, atomically cancels every policy action which has not crossed the
// Agent's StartActionCommand execution gate.
func (s *Store) PutDefensePolicyAndCancelQueued(ctx context.Context, x domain.DefensePolicy) (int, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	allow, _ := json.Marshal(x.Allowlist)
	if _, err = tx.ExecContext(ctx, `INSERT INTO defense_policies(device_id,enabled,emergency_stop,auto_ban,failure_threshold,window_seconds,ban_duration_seconds,max_bans_per_hour,allowlist,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?) ON CONFLICT(device_id) DO UPDATE SET enabled=excluded.enabled,emergency_stop=excluded.emergency_stop,auto_ban=excluded.auto_ban,failure_threshold=excluded.failure_threshold,window_seconds=excluded.window_seconds,ban_duration_seconds=excluded.ban_duration_seconds,max_bans_per_hour=excluded.max_bans_per_hour,allowlist=excluded.allowlist,updated_at=excluded.updated_at`, x.DeviceID, x.Enabled, x.EmergencyStop, x.AutoBan, x.FailureThreshold, int64(x.Window/time.Second), int64(x.BanDuration/time.Second), x.MaxBansPerHour, string(allow), timeText(x.UpdatedAt)); err != nil {
		return 0, err
	}
	mode := domain.AutonomyObserve
	if x.Enabled {
		mode = domain.AutonomyAssist
	}
	if x.Enabled && x.AutoBan {
		mode = domain.AutonomyAutoLowRisk
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO policy_grants(device_id,capability,enabled,mode,allowed_action_types,max_actions_per_hour,emergency_stop,updated_at)
		VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(device_id,capability) DO UPDATE SET enabled=excluded.enabled,mode=excluded.mode,
		allowed_action_types=excluded.allowed_action_types,max_actions_per_hour=excluded.max_actions_per_hour,emergency_stop=excluded.emergency_stop,updated_at=excluded.updated_at`,
		x.DeviceID, "network.auth_bruteforce", x.Enabled, string(mode), `["temporary_ip_ban"]`, x.MaxBansPerHour, x.EmergencyStop, timeText(x.UpdatedAt)); err != nil {
		return 0, err
	}
	if !x.EmergencyStop {
		return 0, tx.Commit()
	}
	rows, err := tx.QueryContext(ctx, `SELECT c.id,a.id FROM device_commands c JOIN actions a ON a.id=json_extract(c.payload,'$.actionId') WHERE c.device_id=? AND c.completed_at IS NULL AND c.type=? AND a.approved_by='policy:ssh_bruteforce' AND a.status=?`, x.DeviceID, string(domain.CommandExecuteAction), string(domain.ActionApproved))
	if err != nil {
		return 0, err
	}
	type queued struct{ commandID, actionID string }
	var items []queued
	for rows.Next() {
		var item queued
		if err = rows.Scan(&item.commandID, &item.actionID); err != nil {
			rows.Close()
			return 0, err
		}
		items = append(items, item)
	}
	if err = rows.Close(); err != nil {
		return 0, err
	}
	const message = "cancelled by automatic-defense emergency stop"
	for _, item := range items {
		if _, err = tx.ExecContext(ctx, `UPDATE device_commands SET completed_at=?,result='{"ok":false}',error=? WHERE id=? AND completed_at IS NULL`, timeText(x.UpdatedAt), message, item.commandID); err != nil {
			return 0, err
		}
		if _, err = tx.ExecContext(ctx, `UPDATE actions SET status=?,completed_at=?,error=?,updated_at=? WHERE id=? AND status=?`, string(domain.ActionCancelled), timeText(x.UpdatedAt), message, timeText(x.UpdatedAt), item.actionID, string(domain.ActionApproved)); err != nil {
			return 0, err
		}
		if _, err = tx.ExecContext(ctx, `UPDATE temporary_bans SET status='cancelled' WHERE action_id=? AND status='pending'`, item.actionID); err != nil {
			return 0, err
		}
		if _, err = tx.ExecContext(ctx, `INSERT INTO action_audit(action_id,actor,event,details,created_at) VALUES(?,?,?,?,?)`, item.actionID, "controller", "cancelled_by_emergency_stop", `{}`, timeText(x.UpdatedAt)); err != nil {
			return 0, err
		}
	}
	if err = tx.Commit(); err != nil {
		return 0, err
	}
	return len(items), nil
}
func (s *Store) AddSecurityEvent(ctx context.Context, e domain.SecurityEvent) (bool, error) {
	if e.ID == "" {
		e.ID = ids.New("evt")
	}
	if len(e.Payload) == 0 {
		e.Payload = json.RawMessage(`{}`)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO security_events(id,device_id,type,source_ip,occurred_at,payload) VALUES(?,?,?,?,?,?)`, e.ID, e.DeviceID, e.Type, e.SourceIP, timeText(e.OccurredAt), string(e.Payload))
	if err != nil {
		return false, err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return false, err
	}
	if n == 1 {
		err = pruneSecurityEventsTx(ctx, tx, e.DeviceID)
	}
	if err != nil {
		return false, err
	}
	if err = tx.Commit(); err != nil {
		return false, err
	}
	return n == 1, nil
}
func (s *Store) CountSecurityEvents(ctx context.Context, deviceID, eventType, sourceIP string, since time.Time) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT count(*) FROM security_events WHERE device_id=? AND type=? AND source_ip=? AND occurred_at>=?`, deviceID, eventType, sourceIP, timeText(since)).Scan(&n)
	return n, err
}
func (s *Store) AddTemporaryBan(ctx context.Context, x domain.TemporaryBan) error {
	if x.ID == "" {
		x.ID = ids.New("ban")
	}
	if x.Status == "" {
		if x.Simulated {
			x.Status = "simulated"
		} else {
			x.Status = "active"
		}
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO temporary_bans(id,device_id,action_id,source_ip,reason,expires_at,created_at,simulated,status) VALUES(?,?,?,?,?,?,?,?,?)`, x.ID, x.DeviceID, x.ActionID, x.SourceIP, x.Reason, timeText(x.ExpiresAt), timeText(x.CreatedAt), x.Simulated, x.Status)
	return err
}
func (s *Store) CountRecentBans(ctx context.Context, deviceID string, since time.Time) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT count(*) FROM temporary_bans WHERE device_id=? AND created_at>=? AND simulated=0`, deviceID, timeText(since)).Scan(&n)
	return n, err
}
func (s *Store) ActiveBan(ctx context.Context, deviceID, sourceIP string, now time.Time) (domain.TemporaryBan, error) {
	var x domain.TemporaryBan
	var expires, created string
	err := s.db.QueryRowContext(ctx, `SELECT id,device_id,action_id,source_ip,reason,expires_at,created_at,simulated,status FROM temporary_bans WHERE device_id=? AND source_ip=? AND (status='pending' OR (status IN ('active','indeterminate') AND expires_at>?)) ORDER BY expires_at DESC LIMIT 1`, deviceID, sourceIP, timeText(now)).Scan(&x.ID, &x.DeviceID, &x.ActionID, &x.SourceIP, &x.Reason, &expires, &created, &x.Simulated, &x.Status)
	if errors.Is(err, sql.ErrNoRows) {
		return x, ErrNotFound
	}
	if err != nil {
		return x, err
	}
	x.ExpiresAt, err = parseTime(expires)
	if err != nil {
		return x, err
	}
	x.CreatedAt, err = parseTime(created)
	return x, err
}
