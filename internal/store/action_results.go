package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"github.com/witkitlab/witshield/internal/action"
	"github.com/witkitlab/witshield/internal/domain"
)

var (
	ErrPolicyStopped  = errors.New("automatic defense is stopped")
	ErrBanAlreadyLive = errors.New("a ban is already pending or active for this source")
	ErrBanRateLimited = errors.New("automatic ban rate limit reached")
)

func (s *Store) CreatePolicyActionAndEnqueue(ctx context.Context, x domain.Action, cmd domain.DeviceCommand, ban domain.TemporaryBan, policyActor string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err = insertPolicyActionAndEnqueue(ctx, tx, x, cmd, ban, policyActor); err != nil {
		return err
	}
	return tx.Commit()
}

// CreatePolicyActionAndEnqueueLimited makes the policy decision durable in one
// transaction. This prevents concurrent/batched events from bypassing either
// the per-source de-duplication or the hourly action budget.
func (s *Store) CreatePolicyActionAndEnqueueLimited(ctx context.Context, x domain.Action, cmd domain.DeviceCommand, ban domain.TemporaryBan, policyActor string, maxPerHour int, since time.Time) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var enabled, emergencyStop, autoBan bool
	var storedMax int
	err = tx.QueryRowContext(ctx, `SELECT enabled,emergency_stop,auto_ban,max_bans_per_hour FROM defense_policies WHERE device_id=?`, x.DeviceID).Scan(&enabled, &emergencyStop, &autoBan, &storedMax)
	if errors.Is(err, sql.ErrNoRows) || !enabled || emergencyStop || !autoBan {
		return ErrPolicyStopped
	}
	if err != nil {
		return err
	}
	if storedMax < maxPerHour || maxPerHour <= 0 {
		maxPerHour = storedMax
	}
	var alreadyLive int
	if err = tx.QueryRowContext(ctx, `SELECT count(*) FROM temporary_bans WHERE device_id=? AND source_ip=? AND (status='pending' OR (status IN ('active','indeterminate') AND expires_at>?))`, x.DeviceID, ban.SourceIP, timeText(x.CreatedAt)).Scan(&alreadyLive); err != nil {
		return err
	}
	if alreadyLive > 0 {
		return ErrBanAlreadyLive
	}
	var recent int
	if err = tx.QueryRowContext(ctx, `SELECT count(*) FROM temporary_bans WHERE device_id=? AND created_at>=? AND simulated=0`, x.DeviceID, timeText(since)).Scan(&recent); err != nil {
		return err
	}
	if recent >= maxPerHour {
		return ErrBanRateLimited
	}
	if err = insertPolicyActionAndEnqueue(ctx, tx, x, cmd, ban, policyActor); err != nil {
		return err
	}
	return tx.Commit()
}

func insertPolicyActionAndEnqueue(ctx context.Context, tx *sql.Tx, x domain.Action, cmd domain.DeviceCommand, ban domain.TemporaryBan, policyActor string) error {
	if err := insertPolicyActionAndCommand(ctx, tx, x, cmd, policyActor); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO temporary_bans(id,device_id,action_id,source_ip,reason,expires_at,created_at,simulated,status) VALUES(?,?,?,?,?,?,?,?,?)`, ban.ID, ban.DeviceID, x.ID, ban.SourceIP, ban.Reason, timeText(ban.ExpiresAt), timeText(ban.CreatedAt), false, "pending"); err != nil {
		return err
	}
	return nil
}

func insertPolicyActionAndCommand(ctx context.Context, tx *sql.Tx, x domain.Action, cmd domain.DeviceCommand, policyActor string) error {
	if err := expireDraftActionsTx(ctx, tx, x.DeviceID, x.CreatedAt); err != nil {
		return err
	}
	if err := ensureUnfinishedActionCapacityTx(ctx, tx, x.DeviceID); err != nil {
		return err
	}
	if len(x.Preview) == 0 {
		x.Preview = json.RawMessage(`{}`)
	}
	if len(x.Parameters) == 0 {
		x.Parameters = json.RawMessage(`{}`)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO actions(id,device_id,finding_id,type,parameters,preview,status,approval_nonce_hash,approved_by,approved_at,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`, x.ID, x.DeviceID, x.FindingID, x.Type, string(x.Parameters), string(x.Preview), string(domain.ActionApproved), "", policyActor, timeText(approvedAt(x)), timeText(x.CreatedAt), timeText(x.UpdatedAt)); err != nil {
		return mapSQLError(err)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO action_audit(action_id,actor,event,details,created_at) VALUES(?,?,?,?,?)`, x.ID, policyActor, "policy_preauthorized_and_queued", string(x.Preview), timeText(x.CreatedAt)); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO device_commands(id,device_id,type,payload,created_at) VALUES(?,?,?,?,?)`, cmd.ID, cmd.DeviceID, string(cmd.Type), string(cmd.Payload), timeText(cmd.CreatedAt)); err != nil {
		return err
	}
	return nil
}

// ApprovedAtValue avoids storing a null approval time for policy-authorized actions.
func approvedAt(x domain.Action) time.Time {
	if x.ApprovedAt != nil {
		return *x.ApprovedAt
	}
	return x.CreatedAt
}

// StartActionCommand is the final authorization gate immediately before the
// Agent crosses into the privileged helper. Policy-created actions are denied
// if emergency stop won the transaction race; once this method succeeds the
// action is explicitly executing rather than merely queued.
func (s *Store) StartActionCommand(ctx context.Context, deviceID, commandID string, now time.Time) (bool, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	var commandType, payload, createdText string
	var started, completed sql.NullString
	if err = tx.QueryRowContext(ctx, `SELECT type,payload,created_at,started_at,completed_at FROM device_commands WHERE id=? AND device_id=?`, commandID, deviceID).Scan(&commandType, &payload, &createdText, &started, &completed); errors.Is(err, sql.ErrNoRows) {
		return false, ErrNotFound
	} else if err != nil {
		return false, err
	}
	if completed.Valid {
		return false, tx.Commit()
	}
	if commandType != string(domain.CommandExecuteAction) && commandType != string(domain.CommandRollback) && commandType != string(domain.CommandConfirm) {
		return false, ErrConflict
	}
	var meta struct {
		ActionID         string          `json:"actionId"`
		PolicyAuthorized bool            `json:"policyAuthorized"`
		Type             action.Type     `json:"type"`
		Parameters       json.RawMessage `json:"parameters"`
	}
	if json.Unmarshal([]byte(payload), &meta) != nil || meta.ActionID == "" {
		return false, errors.New("action command payload is invalid")
	}
	var observerOnly bool
	if err = tx.QueryRowContext(ctx, `SELECT observer_only FROM devices WHERE id=?`, deviceID).Scan(&observerOnly); err != nil {
		return false, err
	}
	if observerOnly {
		const message = "action command cancelled because the device is read-only observer mode"
		if _, err = tx.ExecContext(ctx, `UPDATE device_commands SET completed_at=?,result='{"ok":false}',error=? WHERE id=? AND completed_at IS NULL`, timeText(now), message, commandID); err != nil {
			return false, err
		}
		if _, err = tx.ExecContext(ctx, `UPDATE actions SET status=?,completed_at=?,error=?,updated_at=? WHERE id=? AND device_id=? AND status IN (?,?,?)`, string(domain.ActionCancelled), timeText(now), message, timeText(now), meta.ActionID, deviceID, string(domain.ActionApproved), string(domain.ActionRollingBack), string(domain.ActionConfirming)); err != nil {
			return false, err
		}
		if _, err = tx.ExecContext(ctx, `UPDATE temporary_bans SET status='cancelled' WHERE action_id=? AND status='pending'`, meta.ActionID); err != nil {
			return false, err
		}
		if _, err = tx.ExecContext(ctx, `INSERT INTO action_audit(action_id,actor,event,details,created_at) VALUES(?,?,?,?,?)`, meta.ActionID, "controller", "observer_mode_cancelled", `{}`, timeText(now)); err != nil {
			return false, err
		}
		return false, tx.Commit()
	}
	if started.Valid {
		return true, tx.Commit()
	}
	createdAt, parseErr := parseTime(createdText)
	if parseErr != nil || createdAt.After(now.Add(5*time.Minute)) || now.Sub(createdAt) > domain.ActionCommandTTL {
		const message = "action command expired before privileged execution"
		if _, err = tx.ExecContext(ctx, `UPDATE device_commands SET completed_at=?,result='{"ok":false}',error=? WHERE id=? AND completed_at IS NULL`, timeText(now), message, commandID); err != nil {
			return false, err
		}
		if _, err = tx.ExecContext(ctx, `UPDATE actions SET status=?,completed_at=?,error=?,updated_at=? WHERE id=? AND device_id=? AND status IN (?,?,?)`, string(domain.ActionCancelled), timeText(now), message, timeText(now), meta.ActionID, deviceID, string(domain.ActionApproved), string(domain.ActionRollingBack), string(domain.ActionConfirming)); err != nil {
			return false, err
		}
		if _, err = tx.ExecContext(ctx, `UPDATE temporary_bans SET status='cancelled' WHERE action_id=? AND status='pending'`, meta.ActionID); err != nil {
			return false, err
		}
		if _, err = tx.ExecContext(ctx, `INSERT INTO action_audit(action_id,actor,event,details,created_at) VALUES(?,?,?,?,?)`, meta.ActionID, "controller", "command_expired_before_execution", `{}`, timeText(now)); err != nil {
			return false, err
		}
		return false, tx.Commit()
	}
	if commandType == string(domain.CommandExecuteAction) && meta.PolicyAuthorized && meta.Type == action.TypeTemporaryIPBan {
		var enabled, emergencyStop, autoBan bool
		err = tx.QueryRowContext(ctx, `SELECT enabled,emergency_stop,auto_ban FROM defense_policies WHERE device_id=?`, deviceID).Scan(&enabled, &emergencyStop, &autoBan)
		if errors.Is(err, sql.ErrNoRows) || !enabled || emergencyStop || !autoBan {
			const message = "automatic defense command cancelled before execution"
			if _, err = tx.ExecContext(ctx, `UPDATE device_commands SET completed_at=?,result='{"ok":false}',error=? WHERE id=? AND completed_at IS NULL`, timeText(now), message, commandID); err != nil {
				return false, err
			}
			if _, err = tx.ExecContext(ctx, `UPDATE actions SET status=?,completed_at=?,error=?,updated_at=? WHERE id=? AND device_id=? AND status=?`, string(domain.ActionCancelled), timeText(now), message, timeText(now), meta.ActionID, deviceID, string(domain.ActionApproved)); err != nil {
				return false, err
			}
			if _, err = tx.ExecContext(ctx, `UPDATE temporary_bans SET status='cancelled' WHERE action_id=? AND status='pending'`, meta.ActionID); err != nil {
				return false, err
			}
			if _, err = tx.ExecContext(ctx, `INSERT INTO action_audit(action_id,actor,event,details,created_at) VALUES(?,?,?,?,?)`, meta.ActionID, "controller", "policy_command_cancelled_before_execution", `{}`, timeText(now)); err != nil {
				return false, err
			}
			return false, tx.Commit()
		}
		if err != nil {
			return false, err
		}
	} else if commandType == string(domain.CommandExecuteAction) && meta.PolicyAuthorized {
		capability := ""
		if meta.Type == action.TypeTemporaryProcessSuspend {
			capability = "workload.runtime"
		}
		var enabled, emergencyStop bool
		var mode, allowedJSON string
		if capability == "" {
			err = sql.ErrNoRows
		} else {
			err = tx.QueryRowContext(ctx, `SELECT enabled,emergency_stop,mode,allowed_action_types FROM policy_grants WHERE device_id=? AND capability=?`, deviceID, capability).Scan(&enabled, &emergencyStop, &mode, &allowedJSON)
		}
		var allowed []string
		if err == nil {
			err = json.Unmarshal([]byte(allowedJSON), &allowed)
		}
		authorized := enabled && !emergencyStop && mode == string(domain.AutonomyEnhanced)
		if authorized {
			authorized = false
			for _, actionType := range allowed {
				if actionType == string(meta.Type) {
					authorized = true
					break
				}
			}
		}
		if err != nil || !authorized {
			const message = "pre-authorized action cancelled because its policy grant is no longer active"
			if _, updateErr := tx.ExecContext(ctx, `UPDATE device_commands SET completed_at=?,result='{"ok":false}',error=? WHERE id=? AND completed_at IS NULL`, timeText(now), message, commandID); updateErr != nil {
				return false, updateErr
			}
			if _, updateErr := tx.ExecContext(ctx, `UPDATE actions SET status=?,completed_at=?,error=?,updated_at=? WHERE id=? AND device_id=? AND status=?`, string(domain.ActionCancelled), timeText(now), message, timeText(now), meta.ActionID, deviceID, string(domain.ActionApproved)); updateErr != nil {
				return false, updateErr
			}
			if _, updateErr := tx.ExecContext(ctx, `INSERT INTO action_audit(action_id,actor,event,details,created_at) VALUES(?,?,?,?,?)`, meta.ActionID, "controller", "policy_command_cancelled_before_execution", `{}`, timeText(now)); updateErr != nil {
				return false, updateErr
			}
			return false, tx.Commit()
		}
	}
	if commandType == string(domain.CommandExecuteAction) {
		res, updateErr := tx.ExecContext(ctx, `UPDATE actions SET status=?,executed_at=COALESCE(executed_at,?),updated_at=? WHERE id=? AND device_id=? AND status=?`, string(domain.ActionExecuting), timeText(now), timeText(now), meta.ActionID, deviceID, string(domain.ActionApproved))
		if updateErr != nil {
			return false, updateErr
		}
		if n, _ := res.RowsAffected(); n == 1 {
			if _, err = tx.ExecContext(ctx, `INSERT INTO action_audit(action_id,actor,event,details,created_at) VALUES(?,?,?,?,?)`, meta.ActionID, "agent", "execution_started", `{}`, timeText(now)); err != nil {
				return false, err
			}
		} else {
			var status domain.ActionStatus
			if err = tx.QueryRowContext(ctx, `SELECT status FROM actions WHERE id=? AND device_id=?`, meta.ActionID, deviceID).Scan(&status); err != nil || status != domain.ActionExecuting {
				if err == nil {
					err = ErrConflict
				}
				return false, err
			}
		}
		if meta.Type == action.TypeTemporaryIPBan {
			var params action.TemporaryIPBanParams
			if json.Unmarshal(meta.Parameters, &params) != nil || params.TTLSeconds < 1 {
				return false, errors.New("temporary ban action parameters are invalid")
			}
			horizon := now.UTC().Add(time.Duration(params.TTLSeconds) * time.Second)
			if _, err = tx.ExecContext(ctx, `UPDATE temporary_bans SET expires_at=CASE WHEN expires_at<? THEN ? ELSE expires_at END WHERE action_id=? AND status='pending'`, timeText(horizon), timeText(horizon), meta.ActionID); err != nil {
				return false, err
			}
		}
	} else {
		expected := domain.ActionRollingBack
		if commandType == string(domain.CommandConfirm) {
			expected = domain.ActionConfirming
		}
		var status domain.ActionStatus
		if err = tx.QueryRowContext(ctx, `SELECT status FROM actions WHERE id=? AND device_id=?`, meta.ActionID, deviceID).Scan(&status); err != nil {
			return false, err
		}
		if status != expected {
			return false, ErrConflict
		}
	}
	res, err := tx.ExecContext(ctx, `UPDATE device_commands SET started_at=? WHERE id=? AND device_id=? AND started_at IS NULL AND completed_at IS NULL`, timeText(now), commandID, deviceID)
	if err != nil {
		return false, err
	}
	if count, _ := res.RowsAffected(); count != 1 {
		return false, ErrConflict
	}
	if err = tx.Commit(); err != nil {
		return false, err
	}
	return true, nil
}

// CompleteCommandAndAction atomically stores the idempotent device receipt and
// transitions its associated action/temporary-ban projection.
type commandActionMeta struct {
	ActionID   string          `json:"actionId"`
	Type       action.Type     `json:"type"`
	Parameters json.RawMessage `json:"parameters"`
}

type helperReceiptStep struct {
	Operation  action.Operation `json:"operation"`
	StartedAt  time.Time        `json:"startedAt"`
	FinishedAt time.Time        `json:"finishedAt"`
	Success    bool             `json:"success"`
	Result     *struct {
		Details map[string]any `json:"details"`
	} `json:"result"`
}

type helperReceiptProjection struct {
	ActionID            string              `json:"actionId"`
	Type                action.Type         `json:"type"`
	Operation           action.Operation    `json:"operation"`
	ParametersDigest    string              `json:"parametersDigest"`
	StartedAt           time.Time           `json:"startedAt"`
	FinishedAt          time.Time           `json:"finishedAt"`
	Success             bool                `json:"success"`
	Indeterminate       bool                `json:"indeterminate"`
	RollbackStateDigest string              `json:"rollbackStateDigest"`
	ConfirmBy           *time.Time          `json:"confirmBy"`
	Steps               []helperReceiptStep `json:"steps"`
}

type storedHelperReceiptStep struct {
	Operation           action.Operation `json:"operation"`
	StartedAt           time.Time        `json:"startedAt,omitempty"`
	FinishedAt          time.Time        `json:"finishedAt,omitempty"`
	Success             bool             `json:"success"`
	ConfirmationPending *bool            `json:"confirmationPending,omitempty"`
}

type storedHelperReceipt struct {
	ActionID            string                    `json:"actionId"`
	Type                action.Type               `json:"type"`
	Operation           action.Operation          `json:"operation"`
	ParametersDigest    string                    `json:"parametersDigest"`
	StartedAt           time.Time                 `json:"startedAt,omitempty"`
	FinishedAt          time.Time                 `json:"finishedAt,omitempty"`
	Success             bool                      `json:"success"`
	Indeterminate       bool                      `json:"indeterminate,omitempty"`
	RollbackStateDigest string                    `json:"rollbackStateDigest,omitempty"`
	ConfirmBy           *time.Time                `json:"confirmBy,omitempty"`
	Steps               []storedHelperReceiptStep `json:"steps,omitempty"`
}

// CommandCompletionOutcome exposes the effective result after Controller-side
// receipt validation. A device may claim success while the Controller rejects a
// missing or mismatched privileged-helper receipt; callers must notify from this
// outcome rather than from the untrusted request body.
type CommandCompletionOutcome struct {
	OK                 bool
	Error              string
	NewlyCompleted     bool
	Notification       *domain.NotificationEvent
	NotificationQueued int
}

func (s *Store) CompleteCommandAndAction(ctx context.Context, deviceID, commandID string, ok bool, result, rollback, audit json.RawMessage, errorText string, now time.Time) error {
	_, err := s.CompleteCommandAndActionWithOutcome(ctx, deviceID, commandID, ok, result, rollback, audit, errorText, now)
	return err
}

func (s *Store) CompleteCommandAndActionWithOutcome(ctx context.Context, deviceID, commandID string, ok bool, result, rollback, audit json.RawMessage, errorText string, now time.Time) (outcome CommandCompletionOutcome, err error) {
	submittedOK := ok
	outcome.OK = ok
	outcome.Error = errorText
	if len(result) == 0 {
		result = json.RawMessage(`{}`)
	}
	completionDigest, err := commandCompletionDigest(deviceID, commandID, ok, result, rollback, audit, errorText)
	if err != nil {
		return outcome, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return outcome, err
	}
	defer tx.Rollback()
	var commandType string
	var payload string
	var started, completed, oldResult sql.NullString
	var oldError, oldCompletionDigest string
	err = tx.QueryRowContext(ctx, `SELECT type,payload,started_at,completed_at,result,error,completion_digest FROM device_commands WHERE id=? AND device_id=?`, commandID, deviceID).Scan(&commandType, &payload, &started, &completed, &oldResult, &oldError, &oldCompletionDigest)
	if errors.Is(err, sql.ErrNoRows) {
		return outcome, ErrNotFound
	}
	if err != nil {
		return outcome, err
	}
	if completed.Valid && oldCompletionDigest != "" {
		if oldCompletionDigest == completionDigest {
			var persisted struct {
				OK bool `json:"ok"`
			}
			if oldResult.Valid {
				_ = json.Unmarshal([]byte(oldResult.String), &persisted)
			}
			outcome.OK = persisted.OK
			outcome.Error = oldError
			return outcome, nil
		}
		// New-format rows bind every signed result field, including rollback
		// state and audit receipt. Never fall back to the legacy partial JSON
		// comparison for a different digest.
		return outcome, ErrConflict
	}
	if completed.Valid && oldError == commandExecutionIndeterminateMessage {
		// The operation crossed the privileged boundary, but the Controller
		// timed out without a signed result. Never retry or retroactively claim a
		// verified outcome: acknowledge a later authentic queue item as a no-op
		// and leave the explicit manual-verification state intact.
		outcome.OK = false
		outcome.Error = oldError
		return outcome, nil
	}
	isActionCommand := commandType == string(domain.CommandExecuteAction) || commandType == string(domain.CommandRollback) || commandType == string(domain.CommandConfirm)
	var meta commandActionMeta
	var receipt helperReceiptProjection
	expectedOperation := action.OperationExecute
	if isActionCommand {
		if json.Unmarshal([]byte(payload), &meta) != nil || meta.ActionID == "" {
			return outcome, errors.New("action command payload is invalid")
		}
		if !started.Valid {
			return outcome, ErrConflict
		}
		if commandType == string(domain.CommandRollback) {
			expectedOperation = action.OperationRollback
		} else if commandType == string(domain.CommandConfirm) {
			expectedOperation = action.OperationConfirm
		}
	}
	receiptMatches := false
	if isActionCommand && len(audit) > 0 && json.Unmarshal(audit, &receipt) == nil {
		receiptMatches = receipt.ActionID == meta.ActionID && receipt.Type == meta.Type && receipt.Operation == expectedOperation && receipt.ParametersDigest == action.ParametersDigest(meta.Parameters)
	}
	if ok && isActionCommand {
		if !receiptMatches || !receipt.Success || receipt.Indeterminate || !validSuccessfulReceiptSteps(receipt.Steps, commandType) {
			ok = false
			errorText = "privileged helper receipt was missing or did not match the approved action"
		}
	}
	if ok && commandType == string(domain.CommandExecuteAction) && (!validRollbackState(rollback) || receipt.RollbackStateDigest != digestRollbackState(rollback)) {
		ok = false
		errorText = "privileged helper receipt lacked a matching durable rollback state"
	}
	if ok && isActionCommand && commandType != string(domain.CommandExecuteAction) && len(rollback) != 0 {
		// Rollback and confirmation commands consume the rollback state carried
		// in their command payload; they must never return a second state blob.
		// Besides narrowing the signed protocol, this makes the rollback field
		// exactly reconstructable for legacy completion rows.
		ok = false
		errorText = "only an action execution may return durable rollback state"
	}
	if ok && receipt.ConfirmBy != nil && (meta.Type != action.TypeSSHPasswordHardening || commandType != string(domain.CommandExecuteAction)) {
		ok = false
		errorText = "only an SSH hardening execution may request a safety confirmation window"
	}
	if ok && meta.Type == action.TypeSSHPasswordHardening && commandType == string(domain.CommandExecuteAction) {
		confirmationPending, found := receiptConfirmationPending(receipt.Steps)
		if !found {
			ok = false
			errorText = "SSH helper receipt did not prove whether the configuration changed"
		} else if confirmationPending && receipt.ConfirmBy == nil {
			ok = false
			errorText = "SSH change lacked a matching durable rollback state or safety confirmation deadline"
		} else if !confirmationPending && receipt.ConfirmBy != nil {
			ok = false
			errorText = "SSH receipt requested confirmation even though verification reported no pending change"
		}
	}
	if ok && receipt.ConfirmBy != nil && !(completed.Valid && oldCompletionDigest == "") && (!receipt.ConfirmBy.After(now) || !receipt.ConfirmBy.Before(now.Add(15*time.Minute))) {
		ok = false
		errorText = "SSH safety confirmation deadline was invalid or already elapsed"
	}
	indeterminate := isActionCommand && !submittedOK && errorText == action.ExecutionIndeterminateMessage
	if indeterminate {
		// This exact error is bound by the Agent's device-identity signature and
		// is emitted only after bytes may have reached the privileged Helper. The
		// absence of a receipt is therefore an unknown outcome, not proof that the
		// requested change failed.
		ok = false
		errorText = commandExecutionIndeterminateMessage
	}
	trustedSuccessfulReceipt := !completed.Valid && !submittedOK && !indeterminate && errorText == action.ReceiptPersistenceFailureMessage && isActionCommand && receiptMatches && receipt.Success && !receipt.Indeterminate && validSuccessfulReceiptSteps(receipt.Steps, commandType) && validRecoveredSuccessfulResult(meta, receipt, commandType, rollback, now)
	trustedExecuteIndeterminateWithState := !completed.Valid && !submittedOK && !indeterminate && commandType == string(domain.CommandExecuteAction) && receiptMatches && !receipt.Success && receipt.Indeterminate && validRollbackState(rollback) && receipt.RollbackStateDigest == digestRollbackState(rollback) && validExecuteReceiptWithRecoverableState(receipt)
	trustedExecuteIndeterminateWithoutState := !completed.Valid && !submittedOK && !indeterminate && commandType == string(domain.CommandExecuteAction) && receiptMatches && !receipt.Success && receipt.Indeterminate && len(rollback) == 0 && receipt.RollbackStateDigest == "" && validExecuteReceiptWithUnavailableState(receipt)
	trustedExecuteIndeterminate := trustedExecuteIndeterminateWithState || trustedExecuteIndeterminateWithoutState
	trustedRollbackIndeterminate := !completed.Valid && !submittedOK && !indeterminate && commandType == string(domain.CommandRollback) && receiptMatches && !receipt.Success && receipt.Indeterminate && len(rollback) == 0 && receipt.RollbackStateDigest == "" && validFailedRollbackReceipt(receipt)
	trustedConfirmIndeterminate := !completed.Valid && !submittedOK && !indeterminate && commandType == string(domain.CommandConfirm) && receiptMatches && !receipt.Success && receipt.Indeterminate && len(rollback) == 0 && receipt.RollbackStateDigest == "" && validFailedConfirmReceipt(receipt)
	if trustedSuccessfulReceipt {
		// The Helper completed every typed step and returned the exact durable
		// result, but could not save its local replay cache. The signed response
		// still proves the host outcome to the Controller, so projecting execute,
		// rollback, or confirmation as failed would be false. Keep the cache error
		// as an audit warning while deriving the effective outcome from the receipt.
		ok = true
	}
	if trustedExecuteIndeterminate {
		// Apply is proven, Verify failed, and the automatic Rollback also failed.
		// The change may still be present, but its intended final state is not
		// proven. Preserve the sealed state for an explicit administrator retry and
		// project the action and any temporary ban as indeterminate.
		indeterminate = true
		ok = false
	}
	if trustedRollbackIndeterminate {
		indeterminate = true
		ok = false
	}
	if trustedConfirmIndeterminate {
		indeterminate = true
		ok = false
	}
	trustedRollbackState := (trustedSuccessfulReceipt && commandType == string(domain.CommandExecuteAction)) || trustedExecuteIndeterminateWithState
	outcome.OK = ok
	outcome.Error = errorText
	storedAudit := json.RawMessage(nil)
	if isActionCommand {
		storedAudit = sanitizeHelperReceipt(receipt)
	}
	if !ok && !trustedRollbackState {
		// Only a matching Helper receipt can make failure-side rollback bytes
		// Controller-trusted. This deliberately preserves state when Apply was
		// proven but both Verify and automatic Rollback failed; all other failure
		// payloads remain attacker-controlled and are discarded.
		rollback = nil
	}
	storedResult := map[string]any{"ok": ok, "result": result, "auditReceipt": storedAudit}
	if indeterminate {
		storedResult["indeterminate"] = true
	}
	stored, _ := json.Marshal(storedResult)
	if completed.Valid {
		// Scan requests are intentionally coalesced while a device is offline. A
		// previous Agent process may still submit the receipt for a scan that the
		// Controller has superseded; accept and discard that late receipt so it
		// cannot permanently block the Agent's durable outbound queue.
		if commandType == string(domain.CommandScan) && oldError == supersededScanMessage {
			return outcome, nil
		}
		if isActionCommand && oldCompletionDigest == "" {
			legacyStored, marshalErr := json.Marshal(map[string]any{"ok": ok, "result": result, "auditReceipt": audit})
			if marshalErr != nil {
				return outcome, marshalErr
			}
			if !ok {
				// Legacy failure rows did not preserve the submitted rollback field,
				// so never install a digest that would claim knowledge we do not have.
				// A real execute failure may still carry sealed state after Apply
				// succeeded and Verify failed. Since the legacy row cannot prove which
				// rollback bytes were returned, deliberately ignore that one field and
				// acknowledge only an exact raw result/audit/error replay. This is a
				// terminal no-op: it neither trusts the state nor repeats side effects.
				if oldResult.Valid && oldResult.String == string(legacyStored) && oldError == errorText {
					return outcome, nil
				}
				return outcome, ErrConflict
			}
			if ok {
				// Before completion_digest existed, action commands retained the raw
				// helper receipt in the command result. Construct that exact historical
				// representation only after today's receipt validation has derived the
				// effective outcome. The successful receipt cryptographically binds an
				// execution's rollback bytes; rollback/confirm results are valid only
				// when that field is absent. This lets us safely install the full-tuple
				// digest without re-running action side effects.
				rollbackMatches, matchErr := legacyActionRollbackMatchesTx(ctx, tx, meta.ActionID, commandType, rollback, receipt.ConfirmBy)
				if matchErr != nil {
					return outcome, matchErr
				}
				if oldResult.Valid && oldResult.String == string(legacyStored) && oldError == errorText && rollbackMatches {
					updateResult, updateErr := tx.ExecContext(ctx, `UPDATE device_commands SET completion_digest=? WHERE id=? AND device_id=? AND completed_at IS NOT NULL AND completion_digest=''`, completionDigest, commandID, deviceID)
					if updateErr != nil {
						return outcome, updateErr
					}
					if changed, _ := updateResult.RowsAffected(); changed != 1 {
						return outcome, ErrConflict
					}
					if commitErr := tx.Commit(); commitErr != nil {
						return outcome, commitErr
					}
					return outcome, nil
				}
			}
			return outcome, ErrConflict
		}
		if oldResult.Valid && oldResult.String == string(stored) && oldError == errorText {
			return outcome, nil
		}
		return outcome, ErrConflict
	}
	if _, err = tx.ExecContext(ctx, `UPDATE device_commands SET completed_at=?,result=?,error=?,completion_digest=? WHERE id=? AND device_id=? AND completed_at IS NULL`, timeText(now), string(stored), errorText, completionDigest, commandID, deviceID); err != nil {
		return outcome, err
	}
	if !isActionCommand {
		err = tx.Commit()
		outcome.NewlyCompleted = err == nil
		return outcome, err
	}
	details := storedAudit
	if len(details) == 0 {
		details = result
	}
	if len(details) == 0 {
		details = json.RawMessage(`{}`)
	}
	banExpiryTimingUncertain := false
	if commandType == string(domain.CommandExecuteAction) {
		status := domain.ActionFailed
		if indeterminate {
			status = domain.ActionIndeterminate
		} else if ok {
			status = domain.ActionSucceeded
		}
		var completedAt, confirmBy any = timeText(now), nil
		if ok && receipt.ConfirmBy != nil {
			status = domain.ActionAwaitingConfirmation
			completedAt = nil
			confirmBy = timeText(*receipt.ConfirmBy)
		}
		res, err := tx.ExecContext(ctx, `UPDATE actions SET status=?,executed_at=COALESCE(executed_at,?),completed_at=?,rollback_payload=?,confirm_by=?,error=?,updated_at=? WHERE id=? AND device_id=? AND status=?`, string(status), timeText(now), completedAt, nullableJSON(rollback), confirmBy, errorText, timeText(now), meta.ActionID, deviceID, string(domain.ActionExecuting))
		if err != nil {
			return outcome, err
		}
		if n, _ := res.RowsAffected(); n != 1 {
			return outcome, ErrConflict
		}
		banStatus := "failed"
		if indeterminate {
			banStatus = "indeterminate"
		} else if ok {
			banStatus = "active"
		}
		if (ok || indeterminate) && meta.Type == action.TypeTemporaryIPBan {
			var params action.TemporaryIPBanParams
			if err = json.Unmarshal(meta.Parameters, &params); err != nil || params.TTLSeconds < 1 {
				return outcome, errors.New("temporary ban action parameters are invalid")
			}
			commandStartedAt, parseErr := parseTime(started.String)
			if parseErr != nil {
				return outcome, errors.New("action command start time is invalid")
			}
			// The Controller and Agent do not share a trusted clock, and a host may
			// sleep after final authorization. commandStartedAt+TTL is therefore the
			// earliest possible kernel expiry, not the exact expiry. It gives us a
			// guaranteed dedupe horizon without ever restarting TTL from a delayed
			// result upload. Beyond it, preserve an honest unknown projection and let
			// a new generation atomically refresh the nftables element if necessary.
			expiresAt := commandStartedAt.UTC().Add(time.Duration(params.TTLSeconds) * time.Second)
			if !expiresAt.After(now) {
				banStatus = "indeterminate"
				banExpiryTimingUncertain = true
			}
			if _, err = tx.ExecContext(ctx, `UPDATE temporary_bans SET status=?,expires_at=? WHERE action_id=? AND status='pending'`, banStatus, timeText(expiresAt), meta.ActionID); err != nil {
				return outcome, err
			}
		} else if _, err = tx.ExecContext(ctx, `UPDATE temporary_bans SET status=? WHERE action_id=? AND status='pending'`, banStatus, meta.ActionID); err != nil {
			return outcome, err
		}
		if _, err = tx.ExecContext(ctx, `INSERT INTO action_audit(action_id,actor,event,details,created_at) VALUES(?,?,?,?,?)`, meta.ActionID, "agent", string(status), string(details), timeText(now)); err != nil {
			return outcome, err
		}
	} else if commandType == string(domain.CommandRollback) {
		status := domain.ActionFailed
		if indeterminate {
			status = domain.ActionIndeterminate
		} else if ok {
			status = domain.ActionRolledBack
		}
		res, err := tx.ExecContext(ctx, `UPDATE actions SET status=?,completed_at=?,error=?,updated_at=? WHERE id=? AND device_id=? AND status=?`, string(status), timeText(now), errorText, timeText(now), meta.ActionID, deviceID, string(domain.ActionRollingBack))
		if err != nil {
			return outcome, err
		}
		if n, _ := res.RowsAffected(); n != 1 {
			return outcome, ErrConflict
		}
		if ok {
			_, err = tx.ExecContext(ctx, `UPDATE temporary_bans SET status='rolled_back' WHERE action_id=? AND status IN ('active','indeterminate')`, meta.ActionID)
			if err != nil {
				return outcome, err
			}
		} else if indeterminate {
			if _, err = tx.ExecContext(ctx, `UPDATE temporary_bans SET status='indeterminate' WHERE action_id=? AND status IN ('pending','active','indeterminate')`, meta.ActionID); err != nil {
				return outcome, err
			}
		}
		if _, err = tx.ExecContext(ctx, `INSERT INTO action_audit(action_id,actor,event,details,created_at) VALUES(?,?,?,?,?)`, meta.ActionID, "agent", string(status), string(details), timeText(now)); err != nil {
			return outcome, err
		}
	} else {
		status := domain.ActionFailed
		if indeterminate {
			status = domain.ActionIndeterminate
		} else if ok {
			status = domain.ActionSucceeded
		}
		res, err := tx.ExecContext(ctx, `UPDATE actions SET status=?,completed_at=?,error=?,updated_at=? WHERE id=? AND device_id=? AND status=?`, string(status), timeText(now), errorText, timeText(now), meta.ActionID, deviceID, string(domain.ActionConfirming))
		if err != nil {
			return outcome, err
		}
		if n, _ := res.RowsAffected(); n != 1 {
			return outcome, ErrConflict
		}
		event := "confirmation_failed"
		if ok {
			event = "confirmed"
		}
		if _, err = tx.ExecContext(ctx, `INSERT INTO action_audit(action_id,actor,event,details,created_at) VALUES(?,?,?,?,?)`, meta.ActionID, "agent", event, string(details), timeText(now)); err != nil {
			return outcome, err
		}
	}
	if trustedSuccessfulReceipt {
		warning, _ := json.Marshal(map[string]any{"message": errorText, "manualVerificationRequired": false, "operation": expectedOperation})
		if _, err = tx.ExecContext(ctx, `INSERT INTO action_audit(action_id,actor,event,details,created_at) VALUES(?,?,?,?,?)`, meta.ActionID, "controller", "helper_receipt_persistence_warning", string(warning), timeText(now)); err != nil {
			return outcome, err
		}
	}
	if banExpiryTimingUncertain {
		warning, _ := json.Marshal(map[string]any{"message": "temporary ban result arrived after the Controller's guaranteed-active horizon; kernel TTL was not restarted and the current host state is unknown", "manualVerificationRequired": true})
		if _, err = tx.ExecContext(ctx, `INSERT INTO action_audit(action_id,actor,event,details,created_at) VALUES(?,?,?,?,?)`, meta.ActionID, "controller", "temporary_ban_expiry_indeterminate", string(warning), timeText(now)); err != nil {
			return outcome, err
		}
	}
	if !ok {
		message := errorText
		if len(message) > 1000 {
			message = message[:1000]
		}
		notificationEvent := domain.NotificationEvent{ID: "action-failure:" + commandID, Type: "action_failure", Severity: domain.SeverityHigh, DeviceID: deviceID, Title: "A security action failed", Message: message, OccurredAt: now.UTC()}
		if indeterminate {
			notificationEvent.ID = "action-indeterminate:" + commandID
			notificationEvent.Type = "action_indeterminate"
			notificationEvent.Title = "A security action needs manual verification"
		}
		outcome.NotificationQueued, err = enqueueNotificationTx(ctx, tx, notificationEvent, now)
		if err != nil {
			return outcome, err
		}
		outcome.Notification = &notificationEvent
	}
	if err = syncResponsePlanForActionTx(ctx, tx, meta.ActionID, now); err != nil {
		return outcome, err
	}
	err = tx.Commit()
	outcome.NewlyCompleted = err == nil
	return outcome, err
}

// validRecoveredSuccessfulResult applies the success-side semantic checks that
// normally run only when the Agent submits ok=true. A receipt-cache write error
// makes the outer response false even though the embedded Helper receipt may
// prove a successful execution, so that recovery path must repeat these checks
// before it can derive success.
func validRecoveredSuccessfulResult(meta commandActionMeta, receipt helperReceiptProjection, commandType string, rollback json.RawMessage, now time.Time) bool {
	if commandType != string(domain.CommandExecuteAction) {
		return len(rollback) == 0 && receipt.ConfirmBy == nil
	}
	if !validRollbackState(rollback) || receipt.RollbackStateDigest != digestRollbackState(rollback) {
		return false
	}
	if receipt.ConfirmBy != nil && meta.Type != action.TypeSSHPasswordHardening {
		return false
	}
	if meta.Type == action.TypeSSHPasswordHardening {
		confirmationPending, found := receiptConfirmationPending(receipt.Steps)
		if !found || confirmationPending != (receipt.ConfirmBy != nil) {
			return false
		}
	}
	return receipt.ConfirmBy == nil || (receipt.ConfirmBy.After(now) && receipt.ConfirmBy.Before(now.Add(15*time.Minute)))
}

func legacyActionRollbackMatchesTx(ctx context.Context, tx *sql.Tx, actionID, commandType string, rollback json.RawMessage, receiptConfirmBy *time.Time) (bool, error) {
	if commandType != string(domain.CommandExecuteAction) {
		return len(rollback) == 0, nil
	}
	var persisted, persistedConfirmBy sql.NullString
	if err := tx.QueryRowContext(ctx, `SELECT rollback_payload,confirm_by FROM actions WHERE id=?`, actionID).Scan(&persisted, &persistedConfirmBy); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false, nil
		}
		return false, err
	}
	confirmMatches := !persistedConfirmBy.Valid && receiptConfirmBy == nil
	if persistedConfirmBy.Valid && receiptConfirmBy != nil {
		confirmMatches = persistedConfirmBy.String == timeText(*receiptConfirmBy)
	}
	return persisted.Valid && persisted.String == string(rollback) && confirmMatches, nil
}

func commandCompletionDigest(deviceID, commandID string, ok bool, result, rollback, audit json.RawMessage, errorText string) (string, error) {
	payload, err := json.Marshal(struct {
		DeviceID  string          `json:"deviceId"`
		CommandID string          `json:"commandId"`
		OK        bool            `json:"ok"`
		Result    json.RawMessage `json:"result"`
		Rollback  json.RawMessage `json:"rollback"`
		Audit     json.RawMessage `json:"audit"`
		Error     string          `json:"error"`
	}{DeviceID: deviceID, CommandID: commandID, OK: ok, Result: result, Rollback: rollback, Audit: audit, Error: errorText})
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(payload)
	return hex.EncodeToString(digest[:]), nil
}

func receiptConfirmationPending(steps []helperReceiptStep) (bool, bool) {
	for _, step := range steps {
		if step.Operation != action.OperationVerify || !step.Success || step.Result == nil {
			continue
		}
		value, ok := step.Result.Details["confirmationPending"].(bool)
		return value, ok
	}
	return false, false
}

func validRollbackState(value json.RawMessage) bool {
	if len(value) == 0 || !json.Valid(value) {
		return false
	}
	var object map[string]json.RawMessage
	return json.Unmarshal(value, &object) == nil && len(object) > 0
}

func digestRollbackState(value json.RawMessage) string {
	digest := sha256.Sum256(value)
	return "sha256:" + hex.EncodeToString(digest[:])
}

func sanitizeHelperReceipt(receipt helperReceiptProjection) json.RawMessage {
	stored := storedHelperReceipt{
		ActionID: receipt.ActionID, Type: receipt.Type, Operation: receipt.Operation,
		ParametersDigest: receipt.ParametersDigest, StartedAt: receipt.StartedAt, FinishedAt: receipt.FinishedAt, Success: receipt.Success, Indeterminate: receipt.Indeterminate,
		RollbackStateDigest: receipt.RollbackStateDigest, ConfirmBy: receipt.ConfirmBy,
	}
	for index, step := range receipt.Steps {
		if index >= 5 {
			break
		}
		item := storedHelperReceiptStep{Operation: step.Operation, StartedAt: step.StartedAt, FinishedAt: step.FinishedAt, Success: step.Success}
		if step.Operation == action.OperationVerify && step.Success && step.Result != nil {
			if pending, ok := step.Result.Details["confirmationPending"].(bool); ok {
				value := pending
				item.ConfirmationPending = &value
			}
		}
		stored.Steps = append(stored.Steps, item)
	}
	encoded, _ := json.Marshal(stored)
	return encoded
}

func validSuccessfulReceiptSteps(steps []helperReceiptStep, commandType string) bool {
	expected := []action.Operation{action.OperationPrecheck, action.OperationPreview, action.OperationApply, action.OperationVerify}
	if commandType == string(domain.CommandRollback) {
		expected = []action.Operation{action.OperationRollback}
	} else if commandType == string(domain.CommandConfirm) {
		expected = []action.Operation{action.OperationConfirm}
	}
	if len(steps) != len(expected) {
		return false
	}
	for index, operation := range expected {
		if steps[index].Operation != operation || !steps[index].Success || steps[index].Result == nil {
			return false
		}
	}
	return true
}

// validExecuteReceiptWithRecoverableState accepts the two failure envelopes in
// which retaining the sealed Apply state is both necessary and safe:
//   - execution itself succeeded, but the Helper could not durably cache its
//     final response; or
//   - Apply succeeded and both Verify and the automatic Rollback failed.
//
// A successful automatic rollback intentionally does not qualify: replaying a
// rollback after the host was already restored can itself be unsafe.
func validExecuteReceiptWithRecoverableState(receipt helperReceiptProjection) bool {
	if receipt.Success {
		return validSuccessfulReceiptSteps(receipt.Steps, string(domain.CommandExecuteAction))
	}
	verifyRollbackFailure := []struct {
		operation action.Operation
		success   bool
	}{
		{action.OperationPrecheck, true},
		{action.OperationPreview, true},
		{action.OperationApply, true},
		{action.OperationVerify, false},
		{action.OperationRollback, false},
	}
	applyRollbackFailure := []struct {
		operation action.Operation
		success   bool
	}{
		{action.OperationPrecheck, true},
		{action.OperationPreview, true},
		{action.OperationApply, false},
		{action.OperationRollback, false},
	}
	expected := verifyRollbackFailure
	if len(receipt.Steps) == len(applyRollbackFailure) {
		expected = applyRollbackFailure
	}
	if len(receipt.Steps) != len(expected) {
		return false
	}
	for index, want := range expected {
		step := receipt.Steps[index]
		if step.Operation != want.operation || step.Success != want.success {
			return false
		}
		if want.success && step.Result == nil {
			return false
		}
	}
	return true
}

func validExecuteReceiptWithUnavailableState(receipt helperReceiptProjection) bool {
	if receipt.Success || len(receipt.Steps) != 3 {
		return false
	}
	expected := []struct {
		operation action.Operation
		success   bool
	}{
		{action.OperationPrecheck, true},
		{action.OperationPreview, true},
		{action.OperationApply, false},
	}
	for index, want := range expected {
		step := receipt.Steps[index]
		if step.Operation != want.operation || step.Success != want.success {
			return false
		}
		if want.success && step.Result == nil {
			return false
		}
	}
	return true
}

func validFailedRollbackReceipt(receipt helperReceiptProjection) bool {
	return !receipt.Success && len(receipt.Steps) == 1 && receipt.Steps[0].Operation == action.OperationRollback && !receipt.Steps[0].Success
}

func validFailedConfirmReceipt(receipt helperReceiptProjection) bool {
	return !receipt.Success && len(receipt.Steps) == 1 && receipt.Steps[0].Operation == action.OperationConfirm && !receipt.Steps[0].Success
}
