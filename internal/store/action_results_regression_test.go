package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/witkitlab/witshield/internal/action"
	"github.com/witkitlab/witshield/internal/domain"
)

func seedStartedAction(t *testing.T, s *Store, deviceID, actionID, commandID string, actionType action.Type, commandType domain.CommandType, parameters json.RawMessage, now time.Time) {
	t.Helper()
	ctx := context.Background()
	payload, err := json.Marshal(map[string]any{
		"actionId": actionID, "type": actionType, "parameters": parameters,
	})
	if err != nil {
		t.Fatal(err)
	}
	status := domain.ActionExecuting
	if commandType == domain.CommandRollback {
		status = domain.ActionRollingBack
	} else if commandType == domain.CommandConfirm {
		status = domain.ActionConfirming
	}
	if _, err = s.db.ExecContext(ctx, `INSERT INTO actions(id,device_id,finding_id,type,parameters,preview,status,approval_nonce_hash,approved_by,approved_at,executed_at,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)`, actionID, deviceID, "", string(actionType), string(parameters), `{}`, string(status), "", "admin", timeText(now), timeText(now), timeText(now), timeText(now)); err != nil {
		t.Fatal(err)
	}
	if _, err = s.db.ExecContext(ctx, `INSERT INTO device_commands(id,device_id,type,payload,created_at,claimed_at,started_at) VALUES(?,?,?,?,?,?,?)`, commandID, deviceID, string(commandType), string(payload), timeText(now), timeText(now), timeText(now)); err != nil {
		t.Fatal(err)
	}
}

func seedStartedExecuteAction(t *testing.T, s *Store, deviceID, actionID, commandID string, parameters json.RawMessage, now time.Time) {
	t.Helper()
	seedStartedAction(t, s, deviceID, actionID, commandID, action.TypePackageSecurityUpgrade, domain.CommandExecuteAction, parameters, now)
}

func TestInterruptedHelperExecutionBecomesIndeterminate(t *testing.T) {
	s, deviceID, now := openReportCommandTestStore(t)
	ctx := context.Background()
	const actionID = "act_interrupted_helper"
	const commandID = "cmd_interrupted_helper"
	parameters := json.RawMessage(`{"packages":["openssl"]}`)
	seedStartedExecuteAction(t, s, deviceID, actionID, commandID, parameters, now)

	outcome, err := s.CompleteCommandAndActionWithOutcome(ctx, deviceID, commandID, false, nil, nil, nil, action.ExecutionIndeterminateMessage, now.Add(time.Minute))
	if err != nil || outcome.OK || outcome.Error != commandExecutionIndeterminateMessage {
		t.Fatalf("outcome=%#v err=%v", outcome, err)
	}
	var status domain.ActionStatus
	var commandError, storedResult string
	var rollback sql.NullString
	if err = s.db.QueryRowContext(ctx, `SELECT a.status,a.rollback_payload,c.error,c.result FROM actions a JOIN device_commands c ON c.id=? WHERE a.id=?`, commandID, actionID).Scan(&status, &rollback, &commandError, &storedResult); err != nil {
		t.Fatal(err)
	}
	if status != domain.ActionIndeterminate || rollback.Valid || commandError != commandExecutionIndeterminateMessage || !strings.Contains(storedResult, `"indeterminate":true`) {
		t.Fatalf("status=%s rollback=%v commandError=%q result=%s", status, rollback.Valid, commandError, storedResult)
	}
	if outcome.Notification == nil || outcome.Notification.Type != "action_indeterminate" || !strings.Contains(outcome.Notification.Title, "manual verification") {
		t.Fatalf("indeterminate notification=%#v", outcome.Notification)
	}
	if _, err = s.CompleteCommandAndActionWithOutcome(ctx, deviceID, commandID, false, nil, nil, nil, action.ExecutionIndeterminateMessage, now.Add(2*time.Minute)); err != nil {
		t.Fatalf("exact indeterminate replay failed: %v", err)
	}
}

func TestFailedExecuteRetainsOnlyProvenRecoverableState(t *testing.T) {
	parameters := json.RawMessage(`{"packages":["openssl"]}`)
	rollback := json.RawMessage(`{"version":1,"sealed":"package-snapshot"}`)
	tests := []struct {
		name             string
		receiptSuccess   bool
		verifySuccess    bool
		rollbackStep     *bool
		wantRollback     bool
		wantOK           bool
		wantStatus       domain.ActionStatus
		wantNotification string
	}{
		{name: "verification and automatic rollback failed", rollbackStep: boolPointer(false), wantRollback: true, wantStatus: domain.ActionIndeterminate, wantNotification: "action_indeterminate"},
		{name: "automatic rollback succeeded", rollbackStep: boolPointer(true), wantRollback: false, wantStatus: domain.ActionFailed, wantNotification: "action_failure"},
		{name: "final receipt persistence failed", receiptSuccess: true, verifySuccess: true, wantRollback: true, wantOK: true, wantStatus: domain.ActionSucceeded},
	}
	for index, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			s, deviceID, now := openReportCommandTestStore(t)
			ctx := context.Background()
			actionID := "act_failed_state_" + string(rune('a'+index))
			commandID := "cmd_failed_state_" + string(rune('a'+index))
			seedStartedExecuteAction(t, s, deviceID, actionID, commandID, parameters, now)

			steps := []map[string]any{
				{"operation": action.OperationPrecheck, "success": true, "result": map[string]any{"details": map[string]any{}}},
				{"operation": action.OperationPreview, "success": true, "result": map[string]any{"details": map[string]any{}}},
				{"operation": action.OperationApply, "success": true, "result": map[string]any{"details": map[string]any{}}},
			}
			if test.verifySuccess {
				steps = append(steps, map[string]any{"operation": action.OperationVerify, "success": true, "result": map[string]any{"details": map[string]any{}}})
			} else {
				steps = append(steps, map[string]any{"operation": action.OperationVerify, "success": false})
			}
			if test.rollbackStep != nil {
				step := map[string]any{"operation": action.OperationRollback, "success": *test.rollbackStep}
				if *test.rollbackStep {
					step["result"] = map[string]any{"details": map[string]any{}}
				}
				steps = append(steps, step)
			}
			audit, marshalErr := json.Marshal(map[string]any{
				"actionId": actionID, "type": action.TypePackageSecurityUpgrade, "operation": action.OperationExecute,
				"parametersDigest": action.ParametersDigest(parameters), "success": test.receiptSuccess,
				"rollbackStateDigest": digestRollbackState(rollback), "steps": steps,
			})
			if marshalErr != nil {
				t.Fatal(marshalErr)
			}
			if test.wantStatus == domain.ActionIndeterminate {
				var receipt map[string]any
				_ = json.Unmarshal(audit, &receipt)
				receipt["indeterminate"] = true
				audit, _ = json.Marshal(receipt)
			}
			failureText := "helper execution failed"
			if test.receiptSuccess {
				failureText = action.ReceiptPersistenceFailureMessage
			}
			outcome, completeErr := s.CompleteCommandAndActionWithOutcome(ctx, deviceID, commandID, false, nil, rollback, audit, failureText, now.Add(time.Minute))
			if completeErr != nil || outcome.OK != test.wantOK {
				t.Fatalf("outcome=%#v err=%v", outcome, completeErr)
			}
			stored, _, queryErr := s.Action(ctx, actionID)
			if queryErr != nil {
				t.Fatal(queryErr)
			}
			if got := len(stored.RollbackPayload) > 0; got != test.wantRollback {
				t.Fatalf("rollback retained=%v want=%v payload=%s", got, test.wantRollback, stored.RollbackPayload)
			}
			if stored.Status != test.wantStatus {
				t.Fatalf("status=%s want=%s", stored.Status, test.wantStatus)
			}
			if test.wantNotification == "" {
				if outcome.Notification != nil {
					t.Fatalf("unexpected notification=%#v", outcome.Notification)
				}
			} else if outcome.Notification == nil || outcome.Notification.Type != test.wantNotification {
				t.Fatalf("notification=%#v want type=%s", outcome.Notification, test.wantNotification)
			}
			if test.wantRollback {
				commandPayload, _ := json.Marshal(map[string]any{"actionId": actionID, "type": action.TypePackageSecurityUpgrade, "parameters": parameters, "rollbackPayload": rollback})
				command := domain.DeviceCommand{ID: commandID + "_rollback", DeviceID: deviceID, Type: domain.CommandRollback, Payload: commandPayload, CreatedAt: now.Add(2 * time.Minute)}
				if requestErr := s.RequestRollbackAndEnqueue(ctx, actionID, "admin", command, now.Add(2*time.Minute)); requestErr != nil {
					t.Fatalf("proven recovery state could not be rolled back: %v", requestErr)
				}
			}
		})
	}
}

func TestApplyFailureProjectionDistinguishesRecoveryFromUnknownState(t *testing.T) {
	parameters := json.RawMessage(`{"packages":["openssl"]}`)
	rollback := json.RawMessage(`{"version":1,"sealed":"pre-apply-state"}`)
	tests := []struct {
		name          string
		rollbackStep  *bool
		unusableState bool
		wantStatus    domain.ActionStatus
		wantRollback  bool
		wantNotice    string
	}{
		{name: "automatic rollback proves original state", rollbackStep: boolPointer(true), wantStatus: domain.ActionFailed, wantNotice: "action_failure"},
		{name: "automatic rollback failure preserves manual recovery", rollbackStep: boolPointer(false), wantStatus: domain.ActionIndeterminate, wantRollback: true, wantNotice: "action_indeterminate"},
		{name: "unusable recovery state remains explicitly unknown", unusableState: true, wantStatus: domain.ActionIndeterminate, wantNotice: "action_indeterminate"},
	}
	for index, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			s, deviceID, now := openReportCommandTestStore(t)
			ctx := context.Background()
			actionID := "act_apply_projection_" + string(rune('a'+index))
			commandID := "cmd_apply_projection_" + string(rune('a'+index))
			seedStartedExecuteAction(t, s, deviceID, actionID, commandID, parameters, now)
			steps := []map[string]any{
				{"operation": action.OperationPrecheck, "success": true, "result": map[string]any{"details": map[string]any{}}},
				{"operation": action.OperationPreview, "success": true, "result": map[string]any{"details": map[string]any{}}},
				{"operation": action.OperationApply, "success": false},
			}
			if test.rollbackStep != nil {
				step := map[string]any{"operation": action.OperationRollback, "success": *test.rollbackStep}
				if *test.rollbackStep {
					step["result"] = map[string]any{"details": map[string]any{}}
				}
				steps = append(steps, step)
			}
			receipt := map[string]any{
				"actionId": actionID, "type": action.TypePackageSecurityUpgrade, "operation": action.OperationExecute,
				"parametersDigest": action.ParametersDigest(parameters), "success": false,
				"indeterminate": test.wantStatus == domain.ActionIndeterminate, "steps": steps,
			}
			submittedRollback := json.RawMessage(nil)
			if test.wantRollback {
				submittedRollback = rollback
				receipt["rollbackStateDigest"] = digestRollbackState(rollback)
			}
			if test.unusableState {
				delete(receipt, "rollbackStateDigest")
			}
			audit, _ := json.Marshal(receipt)
			outcome, err := s.CompleteCommandAndActionWithOutcome(ctx, deviceID, commandID, false, nil, submittedRollback, audit, "apply failed", now.Add(time.Minute))
			if err != nil || outcome.Notification == nil || outcome.Notification.Type != test.wantNotice {
				t.Fatalf("outcome=%#v err=%v", outcome, err)
			}
			stored, _, err := s.Action(ctx, actionID)
			if err != nil || stored.Status != test.wantStatus || (len(stored.RollbackPayload) > 0) != test.wantRollback {
				t.Fatalf("action=%#v err=%v", stored, err)
			}
		})
	}
}

func TestTemporaryBanReceiptOutcomesStayTruthfulAndBlockDuplicates(t *testing.T) {
	parameters := json.RawMessage(`{"address":"203.0.113.42","ttlSeconds":300}`)
	rollback := json.RawMessage(`{"version":1,"sealed":"nft-state"}`)
	tests := []struct {
		name           string
		receiptSuccess bool
		verifySuccess  bool
		wantOK         bool
		wantAction     domain.ActionStatus
		wantBan        string
	}{
		{name: "successful execution with receipt cache warning", receiptSuccess: true, verifySuccess: true, wantOK: true, wantAction: domain.ActionSucceeded, wantBan: "active"},
		{name: "apply and automatic rollback failure", wantAction: domain.ActionIndeterminate, wantBan: "indeterminate"},
	}
	for index, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			s, deviceID, now := openReportCommandTestStore(t)
			ctx := context.Background()
			actionID := "act_ban_receipt_" + string(rune('a'+index))
			commandID := "cmd_ban_receipt_" + string(rune('a'+index))
			seedStartedAction(t, s, deviceID, actionID, commandID, action.TypeTemporaryIPBan, domain.CommandExecuteAction, parameters, now)
			if _, err := s.db.ExecContext(ctx, `INSERT INTO temporary_bans(id,device_id,action_id,source_ip,reason,expires_at,created_at,simulated,status) VALUES(?,?,?,?,?,?,?,?,?)`, "ban_receipt_"+string(rune('a'+index)), deviceID, actionID, "203.0.113.42", "test", timeText(now.Add(5*time.Minute)), timeText(now), false, "pending"); err != nil {
				t.Fatal(err)
			}

			receiptStarted := now.Add(5 * time.Second)
			steps := []map[string]any{
				{"operation": action.OperationPrecheck, "startedAt": receiptStarted, "finishedAt": receiptStarted.Add(time.Second), "success": true, "result": map[string]any{"details": map[string]any{}}},
				{"operation": action.OperationPreview, "startedAt": receiptStarted.Add(time.Second), "finishedAt": receiptStarted.Add(2 * time.Second), "success": true, "result": map[string]any{"details": map[string]any{}}},
				{"operation": action.OperationApply, "startedAt": receiptStarted.Add(2 * time.Second), "finishedAt": receiptStarted.Add(3 * time.Second), "success": true, "result": map[string]any{"details": map[string]any{}}},
			}
			if test.verifySuccess {
				steps = append(steps, map[string]any{"operation": action.OperationVerify, "startedAt": receiptStarted.Add(3 * time.Second), "finishedAt": receiptStarted.Add(4 * time.Second), "success": true, "result": map[string]any{"details": map[string]any{}}})
			} else {
				steps = append(steps,
					map[string]any{"operation": action.OperationVerify, "startedAt": receiptStarted.Add(3 * time.Second), "finishedAt": receiptStarted.Add(4 * time.Second), "success": false},
					map[string]any{"operation": action.OperationRollback, "startedAt": receiptStarted.Add(4 * time.Second), "finishedAt": receiptStarted.Add(5 * time.Second), "success": false},
				)
			}
			audit, _ := json.Marshal(map[string]any{
				"actionId": actionID, "type": action.TypeTemporaryIPBan, "operation": action.OperationExecute,
				"parametersDigest": action.ParametersDigest(parameters), "success": test.receiptSuccess,
				"indeterminate":       test.wantAction == domain.ActionIndeterminate,
				"rollbackStateDigest": digestRollbackState(rollback), "startedAt": receiptStarted,
				"finishedAt": receiptStarted.Add(time.Duration(len(steps)) * time.Second), "steps": steps,
			})
			failureText := "helper execution failed"
			if test.receiptSuccess {
				failureText = action.ReceiptPersistenceFailureMessage
			}
			outcome, err := s.CompleteCommandAndActionWithOutcome(ctx, deviceID, commandID, false, nil, rollback, audit, failureText, now.Add(time.Minute))
			if err != nil || outcome.OK != test.wantOK {
				t.Fatalf("outcome=%#v err=%v", outcome, err)
			}
			var actionStatus domain.ActionStatus
			var banStatus, expires string
			if err = s.db.QueryRowContext(ctx, `SELECT a.status,b.status,b.expires_at FROM actions a JOIN temporary_bans b ON b.action_id=a.id WHERE a.id=?`, actionID).Scan(&actionStatus, &banStatus, &expires); err != nil {
				t.Fatal(err)
			}
			// Controller start + TTL is the earliest possible kernel expiry and the
			// guaranteed dedupe horizon. Upload completion never restarts it.
			expectedExpiry := now.Add(5 * time.Minute)
			if actionStatus != test.wantAction || banStatus != test.wantBan || expires != timeText(expectedExpiry) {
				t.Fatalf("action=%s ban=%s expires=%s", actionStatus, banStatus, expires)
			}
			live, err := s.ActiveBan(ctx, deviceID, "203.0.113.42", now.Add(2*time.Minute))
			if err != nil || live.Status != test.wantBan {
				t.Fatalf("ActiveBan=%#v err=%v", live, err)
			}
			if test.wantAction == domain.ActionIndeterminate {
				commandPayload, _ := json.Marshal(map[string]any{"actionId": actionID, "type": action.TypeTemporaryIPBan, "parameters": parameters, "rollbackPayload": rollback})
				command := domain.DeviceCommand{ID: commandID + "_retry_rollback", DeviceID: deviceID, Type: domain.CommandRollback, Payload: commandPayload, CreatedAt: now.Add(2 * time.Minute)}
				if err = s.RequestRollbackAndEnqueue(ctx, actionID, "admin", command, now.Add(2*time.Minute)); err != nil {
					t.Fatalf("manual rollback retry from indeterminate state: %v", err)
				}
			}
		})
	}
}

func TestTemporaryBanDelayedResultCannotRestartKernelTTL(t *testing.T) {
	s, deviceID, commandStartedAt := openReportCommandTestStore(t)
	ctx := context.Background()
	const actionID = "act_ban_delayed_result"
	const commandID = "cmd_ban_delayed_result"
	parameters := json.RawMessage(`{"address":"203.0.113.43","ttlSeconds":60}`)
	rollback := json.RawMessage(`{"version":1,"sealed":"nft-state"}`)
	seedStartedAction(t, s, deviceID, actionID, commandID, action.TypeTemporaryIPBan, domain.CommandExecuteAction, parameters, commandStartedAt)
	if _, err := s.db.ExecContext(ctx, `INSERT INTO temporary_bans(id,device_id,action_id,source_ip,reason,expires_at,created_at,simulated,status) VALUES(?,?,?,?,?,?,?,?,?)`, "ban_delayed_result", deviceID, actionID, "203.0.113.43", "test", timeText(commandStartedAt.Add(time.Minute)), timeText(commandStartedAt), false, "pending"); err != nil {
		t.Fatal(err)
	}
	receiptStarted := commandStartedAt.Add(time.Second)
	step := func(operation action.Operation, start, finish time.Duration) map[string]any {
		return map[string]any{"operation": operation, "startedAt": receiptStarted.Add(start), "finishedAt": receiptStarted.Add(finish), "success": true, "result": map[string]any{"details": map[string]any{}}}
	}
	audit, _ := json.Marshal(map[string]any{
		"actionId": actionID, "type": action.TypeTemporaryIPBan, "operation": action.OperationExecute,
		"parametersDigest": action.ParametersDigest(parameters), "success": true,
		"rollbackStateDigest": digestRollbackState(rollback), "startedAt": receiptStarted, "finishedAt": receiptStarted.Add(4 * time.Second),
		"steps": []map[string]any{
			step(action.OperationPrecheck, 0, 500*time.Millisecond),
			step(action.OperationPreview, 500*time.Millisecond, time.Second),
			step(action.OperationApply, time.Second, 2*time.Second),
			step(action.OperationVerify, 2*time.Second, 3*time.Second),
		},
	})
	uploadedAt := commandStartedAt.Add(5 * time.Minute)
	outcome, err := s.CompleteCommandAndActionWithOutcome(ctx, deviceID, commandID, true, nil, rollback, audit, "", uploadedAt)
	if err != nil || !outcome.OK {
		t.Fatalf("outcome=%#v err=%v", outcome, err)
	}
	var status, expires string
	if err = s.db.QueryRowContext(ctx, `SELECT status,expires_at FROM temporary_bans WHERE action_id=?`, actionID).Scan(&status, &expires); err != nil {
		t.Fatal(err)
	}
	expectedExpiry := commandStartedAt.Add(time.Minute)
	if status != "indeterminate" || expires != timeText(expectedExpiry) || !expectedExpiry.Before(uploadedAt) {
		t.Fatalf("status=%s expires=%s want indeterminate after horizon %s before upload %s", status, expires, timeText(expectedExpiry), timeText(uploadedAt))
	}
	if _, err = s.ActiveBan(ctx, deviceID, "203.0.113.43", uploadedAt); !errors.Is(err, ErrNotFound) {
		t.Fatalf("delayed receipt restarted a dead ban: %v", err)
	}
}

func TestTemporaryBanHorizonStartsWhenPrivilegedExecutionStarts(t *testing.T) {
	tests := []struct {
		name            string
		ttl             time.Duration
		transition      func(context.Context, *Store, string, time.Time) error
		transitionAfter time.Duration
		probeAfter      time.Duration
	}{
		{
			name: "device revocation",
			ttl:  10 * time.Minute,
			transition: func(ctx context.Context, s *Store, deviceID string, at time.Time) error {
				return s.RevokeDevice(ctx, deviceID, at)
			},
			transitionAfter: time.Minute,
			probeAfter:      2 * time.Minute,
		},
		{
			name: "execution timeout",
			ttl:  3 * time.Hour,
			transition: func(ctx context.Context, s *Store, _ string, at time.Time) error {
				return s.ExpireStaleActionCommands(ctx, at)
			},
			transitionAfter: domain.ActionExecutionTimeout + time.Minute,
			probeAfter:      2*time.Hour + 56*time.Minute,
		},
	}
	for index, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			s, deviceID, createdAt := openReportCommandTestStore(t)
			ctx := context.Background()
			actionID := "act_delayed_start_" + string(rune('a'+index))
			commandID := "cmd_delayed_start_" + string(rune('a'+index))
			banID := "ban_delayed_start_" + string(rune('a'+index))
			startAt := createdAt.Add(9 * time.Minute)
			parameters, _ := json.Marshal(action.TemporaryIPBanParams{Address: "8.8.8.8", TTLSeconds: int(test.ttl / time.Second)})
			payload, _ := json.Marshal(map[string]any{
				"actionId": actionID, "type": action.TypeTemporaryIPBan, "parameters": json.RawMessage(parameters),
			})
			if _, err := s.db.ExecContext(ctx, `INSERT INTO actions(id,device_id,finding_id,type,parameters,preview,status,approval_nonce_hash,approved_by,approved_at,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`, actionID, deviceID, "", string(action.TypeTemporaryIPBan), string(parameters), `{}`, string(domain.ActionApproved), "", "admin", timeText(createdAt), timeText(createdAt), timeText(createdAt)); err != nil {
				t.Fatal(err)
			}
			if _, err := s.db.ExecContext(ctx, `INSERT INTO device_commands(id,device_id,type,payload,created_at,claimed_at) VALUES(?,?,?,?,?,?)`, commandID, deviceID, string(domain.CommandExecuteAction), string(payload), timeText(createdAt), timeText(startAt)); err != nil {
				t.Fatal(err)
			}
			initialExpiry := createdAt.Add(test.ttl)
			if _, err := s.db.ExecContext(ctx, `INSERT INTO temporary_bans(id,device_id,action_id,source_ip,reason,expires_at,created_at,simulated,status) VALUES(?,?,?,?,?,?,?,?,?)`, banID, deviceID, actionID, "8.8.8.8", "test", timeText(initialExpiry), timeText(createdAt), false, "pending"); err != nil {
				t.Fatal(err)
			}
			if authorized, err := s.StartActionCommand(ctx, deviceID, commandID, startAt); err != nil || !authorized {
				t.Fatalf("start authorized=%v err=%v", authorized, err)
			}
			expectedExpiry := startAt.Add(test.ttl)
			var storedExpiry string
			if err := s.db.QueryRowContext(ctx, `SELECT expires_at FROM temporary_bans WHERE id=?`, banID).Scan(&storedExpiry); err != nil || storedExpiry != timeText(expectedExpiry) {
				t.Fatalf("start horizon=%s want=%s err=%v", storedExpiry, timeText(expectedExpiry), err)
			}
			if err := test.transition(ctx, s, deviceID, startAt.Add(test.transitionAfter)); err != nil {
				t.Fatal(err)
			}
			probeAt := startAt.Add(test.probeAfter)
			if !probeAt.After(initialExpiry) || !probeAt.Before(expectedExpiry) {
				t.Fatalf("test probe %s does not distinguish old %s from new %s horizon", probeAt, initialExpiry, expectedExpiry)
			}
			live, err := s.ActiveBan(ctx, deviceID, "8.8.8.8", probeAt)
			if err != nil || live.Status != "indeterminate" || !live.ExpiresAt.Equal(expectedExpiry) {
				t.Fatalf("ActiveBan=%#v err=%v", live, err)
			}
		})
	}
}

func TestRollbackAndConfirmationCacheWarningsUseProvenHelperOutcome(t *testing.T) {
	tests := []struct {
		name        string
		actionType  action.Type
		commandType domain.CommandType
		parameters  json.RawMessage
		wantStatus  domain.ActionStatus
		withBan     bool
	}{
		{name: "rollback", actionType: action.TypeTemporaryIPBan, commandType: domain.CommandRollback, parameters: json.RawMessage(`{"address":"198.51.100.29","ttlSeconds":300}`), wantStatus: domain.ActionRolledBack, withBan: true},
		{name: "confirmation", actionType: action.TypeSSHPasswordHardening, commandType: domain.CommandConfirm, parameters: json.RawMessage(`{"rollbackAfterSeconds":300}`), wantStatus: domain.ActionSucceeded},
	}
	for index, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			s, deviceID, now := openReportCommandTestStore(t)
			ctx := context.Background()
			actionID := "act_cache_warning_" + string(rune('a'+index))
			commandID := "cmd_cache_warning_" + string(rune('a'+index))
			seedStartedAction(t, s, deviceID, actionID, commandID, test.actionType, test.commandType, test.parameters, now)
			if _, err := s.db.ExecContext(ctx, `UPDATE actions SET rollback_payload=? WHERE id=?`, `{"version":1,"sealed":"state"}`, actionID); err != nil {
				t.Fatal(err)
			}
			if test.withBan {
				if _, err := s.db.ExecContext(ctx, `INSERT INTO temporary_bans(id,device_id,action_id,source_ip,reason,expires_at,created_at,simulated,status) VALUES(?,?,?,?,?,?,?,?,?)`, "ban_cache_warning", deviceID, actionID, "198.51.100.29", "test", timeText(now.Add(5*time.Minute)), timeText(now), false, "active"); err != nil {
					t.Fatal(err)
				}
			}
			operation := action.OperationRollback
			if test.commandType == domain.CommandConfirm {
				operation = action.OperationConfirm
			}
			audit, _ := json.Marshal(map[string]any{
				"actionId": actionID, "type": test.actionType, "operation": operation,
				"parametersDigest": action.ParametersDigest(test.parameters), "success": true,
				"steps": []map[string]any{{"operation": operation, "success": true, "result": map[string]any{"details": map[string]any{}}}},
			})
			const cacheWarning = action.ReceiptPersistenceFailureMessage
			outcome, err := s.CompleteCommandAndActionWithOutcome(ctx, deviceID, commandID, false, nil, nil, audit, cacheWarning, now.Add(time.Minute))
			if err != nil || !outcome.OK || outcome.Notification != nil {
				t.Fatalf("outcome=%#v err=%v", outcome, err)
			}
			stored, _, err := s.Action(ctx, actionID)
			if err != nil || stored.Status != test.wantStatus || stored.Error != cacheWarning {
				t.Fatalf("action=%#v err=%v", stored, err)
			}
			var warnings int
			if err = s.db.QueryRowContext(ctx, `SELECT count(*) FROM action_audit WHERE action_id=? AND event='helper_receipt_persistence_warning'`, actionID).Scan(&warnings); err != nil || warnings != 1 {
				t.Fatalf("warning audits=%d err=%v", warnings, err)
			}
			if test.withBan {
				var banStatus string
				if err = s.db.QueryRowContext(ctx, `SELECT status FROM temporary_bans WHERE action_id=?`, actionID).Scan(&banStatus); err != nil || banStatus != "rolled_back" {
					t.Fatalf("ban=%s err=%v", banStatus, err)
				}
			}
			replayed, replayErr := s.CompleteCommandAndActionWithOutcome(ctx, deviceID, commandID, false, nil, nil, audit, cacheWarning, now.Add(2*time.Minute))
			if replayErr != nil || !replayed.OK || replayed.NewlyCompleted {
				t.Fatalf("replay=%#v err=%v", replayed, replayErr)
			}
		})
	}
}

func TestIndeterminateRollbackMovesActiveBanToUnknown(t *testing.T) {
	s, deviceID, now := openReportCommandTestStore(t)
	ctx := context.Background()
	const actionID = "act_rollback_unknown"
	const commandID = "cmd_rollback_unknown"
	parameters := json.RawMessage(`{"address":"198.51.100.17","ttlSeconds":300}`)
	rollback := json.RawMessage(`{"version":1,"sealed":"nft-state"}`)
	commandPayload, _ := json.Marshal(map[string]any{"actionId": actionID, "type": action.TypeTemporaryIPBan, "parameters": parameters, "rollbackPayload": rollback})
	if _, err := s.db.ExecContext(ctx, `INSERT INTO actions(id,device_id,finding_id,type,parameters,preview,status,rollback_payload,approval_nonce_hash,approved_by,approved_at,executed_at,completed_at,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, actionID, deviceID, "", string(action.TypeTemporaryIPBan), string(parameters), `{}`, string(domain.ActionSucceeded), string(rollback), "", "admin", timeText(now), timeText(now), timeText(now), timeText(now), timeText(now)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.ExecContext(ctx, `INSERT INTO temporary_bans(id,device_id,action_id,source_ip,reason,expires_at,created_at,simulated,status) VALUES(?,?,?,?,?,?,?,?,?)`, "ban_rollback_unknown", deviceID, actionID, "198.51.100.17", "test", timeText(now.Add(5*time.Minute)), timeText(now), false, "active"); err != nil {
		t.Fatal(err)
	}
	command := domain.DeviceCommand{ID: commandID, DeviceID: deviceID, Type: domain.CommandRollback, Payload: commandPayload, CreatedAt: now.Add(time.Minute)}
	if err := s.RequestRollbackAndEnqueue(ctx, actionID, "admin", command, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if authorized, err := s.StartActionCommand(ctx, deviceID, commandID, now.Add(2*time.Minute)); err != nil || !authorized {
		t.Fatalf("start rollback authorized=%v err=%v", authorized, err)
	}
	outcome, err := s.CompleteCommandAndActionWithOutcome(ctx, deviceID, commandID, false, nil, nil, nil, action.ExecutionIndeterminateMessage, now.Add(3*time.Minute))
	if err != nil || outcome.Notification == nil || outcome.Notification.Type != "action_indeterminate" {
		t.Fatalf("outcome=%#v err=%v", outcome, err)
	}
	var actionStatus domain.ActionStatus
	var banStatus string
	if err = s.db.QueryRowContext(ctx, `SELECT a.status,b.status FROM actions a JOIN temporary_bans b ON b.action_id=a.id WHERE a.id=?`, actionID).Scan(&actionStatus, &banStatus); err != nil {
		t.Fatal(err)
	}
	if actionStatus != domain.ActionIndeterminate || banStatus != "indeterminate" {
		t.Fatalf("action=%s ban=%s", actionStatus, banStatus)
	}
	if live, liveErr := s.ActiveBan(ctx, deviceID, "198.51.100.17", now.Add(4*time.Minute)); liveErr != nil || live.Status != "indeterminate" {
		t.Fatalf("ActiveBan=%#v err=%v", live, liveErr)
	}
}

func TestFailedRollbackReceiptMovesActiveBanToUnknown(t *testing.T) {
	s, deviceID, now := openReportCommandTestStore(t)
	ctx := context.Background()
	const actionID = "act_rollback_receipt_unknown"
	const commandID = "cmd_rollback_receipt_unknown"
	parameters := json.RawMessage(`{"address":"8.8.8.8","ttlSeconds":300}`)
	rollback := json.RawMessage(`{"version":1,"sealed":"nft-state"}`)
	seedStartedAction(t, s, deviceID, actionID, commandID, action.TypeTemporaryIPBan, domain.CommandRollback, parameters, now)
	if _, err := s.db.ExecContext(ctx, `UPDATE actions SET rollback_payload=? WHERE id=?`, string(rollback), actionID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.ExecContext(ctx, `INSERT INTO temporary_bans(id,device_id,action_id,source_ip,reason,expires_at,created_at,simulated,status) VALUES(?,?,?,?,?,?,?,?,?)`, "ban_rollback_receipt_unknown", deviceID, actionID, "8.8.8.8", "test", timeText(now.Add(5*time.Minute)), timeText(now), false, "active"); err != nil {
		t.Fatal(err)
	}
	audit, _ := json.Marshal(map[string]any{
		"actionId": actionID, "type": action.TypeTemporaryIPBan, "operation": action.OperationRollback,
		"parametersDigest": action.ParametersDigest(parameters), "success": false, "indeterminate": true,
		"steps": []map[string]any{{"operation": action.OperationRollback, "success": false}},
	})
	outcome, err := s.CompleteCommandAndActionWithOutcome(ctx, deviceID, commandID, false, nil, nil, audit, "rollback response was not conclusive", now.Add(time.Minute))
	if err != nil || outcome.Notification == nil || outcome.Notification.Type != "action_indeterminate" {
		t.Fatalf("outcome=%#v err=%v", outcome, err)
	}
	stored, _, err := s.Action(ctx, actionID)
	if err != nil || stored.Status != domain.ActionIndeterminate || string(stored.RollbackPayload) != string(rollback) {
		t.Fatalf("action=%#v err=%v", stored, err)
	}
	var banStatus string
	if err := s.db.QueryRowContext(ctx, `SELECT status FROM temporary_bans WHERE action_id=?`, actionID).Scan(&banStatus); err != nil || banStatus != "indeterminate" {
		t.Fatalf("ban=%s err=%v", banStatus, err)
	}
}

func TestFailedConfirmReceiptRetainsRecoveryStateAndBecomesUnknown(t *testing.T) {
	s, deviceID, now := openReportCommandTestStore(t)
	ctx := context.Background()
	const actionID = "act_confirm_receipt_unknown"
	const commandID = "cmd_confirm_receipt_unknown"
	parameters := json.RawMessage(`{"rollbackAfterSeconds":300}`)
	rollback := json.RawMessage(`{"version":1,"sealed":"ssh-state"}`)
	seedStartedAction(t, s, deviceID, actionID, commandID, action.TypeSSHPasswordHardening, domain.CommandConfirm, parameters, now)
	if _, err := s.db.ExecContext(ctx, `UPDATE actions SET rollback_payload=? WHERE id=?`, string(rollback), actionID); err != nil {
		t.Fatal(err)
	}
	audit, _ := json.Marshal(map[string]any{
		"actionId": actionID, "type": action.TypeSSHPasswordHardening, "operation": action.OperationConfirm,
		"parametersDigest": action.ParametersDigest(parameters), "success": false, "indeterminate": true,
		"steps": []map[string]any{{"operation": action.OperationConfirm, "success": false}},
	})
	outcome, err := s.CompleteCommandAndActionWithOutcome(ctx, deviceID, commandID, false, nil, nil, audit, "confirmation response was not conclusive", now.Add(time.Minute))
	if err != nil || outcome.Notification == nil || outcome.Notification.Type != "action_indeterminate" {
		t.Fatalf("outcome=%#v err=%v", outcome, err)
	}
	stored, _, err := s.Action(ctx, actionID)
	if err != nil || stored.Status != domain.ActionIndeterminate || string(stored.RollbackPayload) != string(rollback) {
		t.Fatalf("action=%#v err=%v", stored, err)
	}
}

func TestTimeoutAndDeviceRevocationMakeStartedRollbackBanIndeterminate(t *testing.T) {
	tests := []struct {
		name       string
		transition func(context.Context, *Store, string, time.Time) error
	}{
		{
			name: "execution timeout",
			transition: func(ctx context.Context, s *Store, _ string, now time.Time) error {
				return s.ExpireStaleActionCommands(ctx, now)
			},
		},
		{
			name: "device revocation",
			transition: func(ctx context.Context, s *Store, deviceID string, now time.Time) error {
				return s.RevokeDevice(ctx, deviceID, now)
			},
		},
	}
	for index, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			s, deviceID, now := openReportCommandTestStore(t)
			ctx := context.Background()
			actionID := "act_started_rollback_" + string(rune('a'+index))
			commandID := "cmd_started_rollback_" + string(rune('a'+index))
			parameters := json.RawMessage(`{"address":"192.0.2.81","ttlSeconds":900}`)
			startedAt := now.Add(-domain.ActionExecutionTimeout - time.Minute)
			seedStartedAction(t, s, deviceID, actionID, commandID, action.TypeTemporaryIPBan, domain.CommandRollback, parameters, startedAt)
			if _, err := s.db.ExecContext(ctx, `UPDATE actions SET rollback_payload=? WHERE id=?`, `{"version":1,"sealed":"state"}`, actionID); err != nil {
				t.Fatal(err)
			}
			if _, err := s.db.ExecContext(ctx, `INSERT INTO temporary_bans(id,device_id,action_id,source_ip,reason,expires_at,created_at,simulated,status) VALUES(?,?,?,?,?,?,?,?,?)`, "ban_started_rollback_"+string(rune('a'+index)), deviceID, actionID, "192.0.2.81", "test", timeText(now.Add(time.Hour)), timeText(startedAt), false, "active"); err != nil {
				t.Fatal(err)
			}
			if err := test.transition(ctx, s, deviceID, now); err != nil {
				t.Fatal(err)
			}
			var actionStatus domain.ActionStatus
			var banStatus string
			if err := s.db.QueryRowContext(ctx, `SELECT a.status,b.status FROM actions a JOIN temporary_bans b ON b.action_id=a.id WHERE a.id=?`, actionID).Scan(&actionStatus, &banStatus); err != nil {
				t.Fatal(err)
			}
			if actionStatus != domain.ActionIndeterminate || banStatus != "indeterminate" {
				t.Fatalf("action=%s ban=%s", actionStatus, banStatus)
			}
		})
	}
}

func boolPointer(value bool) *bool { return &value }
