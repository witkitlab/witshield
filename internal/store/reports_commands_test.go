package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/witkitlab/witshield/internal/action"
	"github.com/witkitlab/witshield/internal/domain"
)

func openReportCommandTestStore(t *testing.T) (*Store, string, time.Time) {
	t.Helper()
	ctx := context.Background()
	s, err := Open(ctx, filepath.Join(t.TempDir(), "store.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	now := time.Date(2026, 8, 26, 8, 0, 0, 0, time.UTC)
	const deviceID = "dev_test"
	_, err = s.db.ExecContext(ctx, `INSERT INTO devices(id,name,hostname,os,arch,agent_version,identity_key,status,enrolled_at,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)`, deviceID, "test", "host", "linux", "amd64", "test", "", string(domain.DeviceOffline), timeText(now), timeText(now), timeText(now))
	if err != nil {
		t.Fatal(err)
	}
	return s, deviceID, now
}

func TestSaveReportPreservesFindingsForUnavailableCheckCategories(t *testing.T) {
	s, deviceID, now := openReportCommandTestStore(t)
	ctx := context.Background()
	first := domain.Report{
		ID: "rpt_first", DeviceID: deviceID, StartedAt: now, CompletedAt: now.Add(time.Minute), Score: 50,
		Summary: json.RawMessage(`{"checkErrors":[]}`),
		Findings: []domain.Finding{
			{ID: "fnd_ssh", Fingerprint: "fingerprint-ssh", Category: "ssh", Severity: domain.SeverityHigh, Title: "SSH risk", Status: domain.FindingOpen},
			{ID: "fnd_network", Fingerprint: "fingerprint-network", Category: "network", Severity: domain.SeverityMedium, Title: "Network risk", Status: domain.FindingOpen},
			{ID: "fnd_updates", Fingerprint: "fingerprint-updates", Category: "updates", Severity: domain.SeverityMedium, Title: "Update risk", Status: domain.FindingOpen},
		},
	}
	if err := s.SaveReport(ctx, first, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	second := domain.Report{
		ID: "rpt_second", DeviceID: deviceID, StartedAt: now.Add(2 * time.Minute), CompletedAt: now.Add(3 * time.Minute), Score: 71,
		Summary: json.RawMessage(`{"checkErrors":["ssh_configuration: permission denied","firewall: operation not permitted"]}`),
	}
	if err := s.SaveReport(ctx, second, now.Add(3*time.Minute)); err != nil {
		t.Fatal(err)
	}
	findings, err := s.ListFindings(ctx, FindingFilter{DeviceID: deviceID, Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	statuses := map[string]domain.FindingStatus{}
	for _, finding := range findings {
		statuses[finding.Category] = finding.Status
	}
	if statuses["ssh"] != domain.FindingOpen || statuses["network"] != domain.FindingOpen {
		t.Fatalf("unavailable categories were falsely resolved: %#v", statuses)
	}
	if statuses["updates"] != domain.FindingResolved {
		t.Fatalf("successfully checked absent category did not resolve: %#v", statuses)
	}
	third := domain.Report{ID: "rpt_third", DeviceID: deviceID, StartedAt: now.Add(4 * time.Minute), CompletedAt: now.Add(5 * time.Minute), Score: 100, Summary: json.RawMessage(`{"checkErrors":[]}`)}
	if err = s.SaveReport(ctx, third, now.Add(5*time.Minute)); err != nil {
		t.Fatal(err)
	}
	findings, err = s.ListFindings(ctx, FindingFilter{DeviceID: deviceID, Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	for _, finding := range findings {
		if finding.Status != domain.FindingResolved {
			t.Fatalf("a later complete scan did not resolve absent finding: %#v", finding)
		}
	}
}

func TestSaveReportUnknownUnavailableCheckConservativelyPreservesFindings(t *testing.T) {
	s, deviceID, now := openReportCommandTestStore(t)
	ctx := context.Background()
	first := domain.Report{ID: "rpt_old", DeviceID: deviceID, StartedAt: now, CompletedAt: now.Add(time.Minute), Score: 90, Summary: json.RawMessage(`{}`), Findings: []domain.Finding{{ID: "fnd_old", Fingerprint: "fingerprint-old", Category: "custom", Severity: domain.SeverityLow, Title: "custom risk", Status: domain.FindingOpen}}}
	if err := s.SaveReport(ctx, first, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	second := domain.Report{ID: "rpt_new", DeviceID: deviceID, StartedAt: now.Add(2 * time.Minute), CompletedAt: now.Add(3 * time.Minute), Score: 0, Summary: json.RawMessage(`{"checkErrors":["future_check: unavailable"]}`)}
	if err := s.SaveReport(ctx, second, now.Add(3*time.Minute)); err != nil {
		t.Fatal(err)
	}
	findings, err := s.ListFindings(ctx, FindingFilter{DeviceID: deviceID, Limit: 10})
	if err != nil || len(findings) != 1 || findings[0].Status != domain.FindingOpen {
		t.Fatalf("unknown unavailable check must not assert resolution: findings=%#v err=%v", findings, err)
	}
}

func TestUnavailableReportCanExplicitlyResolveFindingWithoutMutatingSnapshot(t *testing.T) {
	s, deviceID, now := openReportCommandTestStore(t)
	ctx := context.Background()
	first := domain.Report{
		ID: "rpt_explicit_open", DeviceID: deviceID, StartedAt: now,
		CompletedAt: now.Add(time.Minute), Score: 50, Summary: json.RawMessage(`{"checkErrors":[]}`),
		Findings: []domain.Finding{{ID: "fnd_explicit_open", Fingerprint: "fingerprint-explicit-resolution", Category: "ssh", Severity: domain.SeverityHigh, Title: "SSH risk", Status: domain.FindingOpen}},
	}
	if err := s.SaveReport(ctx, first, first.CompletedAt); err != nil {
		t.Fatal(err)
	}
	second := domain.Report{
		ID: "rpt_explicit_resolved", DeviceID: deviceID, StartedAt: now.Add(2 * time.Minute),
		CompletedAt: now.Add(3 * time.Minute), Score: 100,
		Summary:  json.RawMessage(`{"checkErrors":["ssh_configuration: partial result"]}`),
		Findings: []domain.Finding{{ID: "fnd_explicit_resolved", Fingerprint: "fingerprint-explicit-resolution", Category: "ssh", Severity: domain.SeverityHigh, Title: "SSH risk", Status: domain.FindingResolved}},
	}
	if err := s.SaveReport(ctx, second, second.CompletedAt); err != nil {
		t.Fatal(err)
	}
	current, err := s.ListFindings(ctx, FindingFilter{DeviceID: deviceID, Limit: 10})
	if err != nil || len(current) != 1 || current[0].Status != domain.FindingResolved || current[0].ID != "fnd_explicit_resolved" {
		t.Fatalf("explicit resolution did not advance projection: findings=%#v err=%v", current, err)
	}
	historical, err := s.Report(ctx, first.ID)
	if err != nil || len(historical.Findings) != 1 || historical.Findings[0].Status != domain.FindingOpen {
		t.Fatalf("projection update mutated immutable report snapshot: report=%#v err=%v", historical, err)
	}
}

func TestReportRetentionCannotEraseCurrentFindingDuringUnavailableScans(t *testing.T) {
	s, deviceID, now := openReportCommandTestStore(t)
	ctx := context.Background()
	first := domain.Report{
		ID: "rpt_retention_origin", DeviceID: deviceID, StartedAt: now,
		CompletedAt: now.Add(time.Minute), Score: 50, Summary: json.RawMessage(`{"checkErrors":[]}`),
		Findings: []domain.Finding{{
			ID: "fnd_retention_origin", Fingerprint: "fingerprint-retention-open", Category: "ssh",
			Severity: domain.SeverityHigh, Title: "SSH risk", Status: domain.FindingOpen,
		}},
	}
	if err := s.SaveReport(ctx, first, first.CompletedAt); err != nil {
		t.Fatal(err)
	}
	for index := 0; index < maxReportsPerDevice+1; index++ {
		completed := now.Add(time.Duration(index+2) * time.Minute)
		report := domain.Report{
			ID: fmt.Sprintf("rpt_unavailable_%03d", index), DeviceID: deviceID,
			StartedAt: completed.Add(-time.Second), CompletedAt: completed, Score: 0,
			Summary: json.RawMessage(`{"checkErrors":["ssh_configuration: unavailable"]}`),
		}
		if err := s.SaveReport(ctx, report, completed); err != nil {
			t.Fatalf("save unavailable report %d: %v", index, err)
		}
	}
	if _, err := s.Report(ctx, first.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("origin report should have been retained out of snapshot history: %v", err)
	}
	findings, err := s.ListFindings(ctx, FindingFilter{DeviceID: deviceID, Limit: 10})
	if err != nil || len(findings) != 1 || findings[0].Status != domain.FindingOpen {
		t.Fatalf("retention silently erased an unresolved unavailable finding: findings=%#v err=%v", findings, err)
	}
	completed := now.Add(time.Duration(maxReportsPerDevice+3) * time.Minute)
	if err = s.SaveReport(ctx, domain.Report{
		ID: "rpt_retention_resolved", DeviceID: deviceID, StartedAt: completed.Add(-time.Second),
		CompletedAt: completed, Score: 100, Summary: json.RawMessage(`{"checkErrors":[]}`),
	}, completed); err != nil {
		t.Fatal(err)
	}
	findings, err = s.ListFindings(ctx, FindingFilter{DeviceID: deviceID, Limit: 10})
	if err != nil || len(findings) != 1 || findings[0].Status != domain.FindingResolved {
		t.Fatalf("complete report did not explicitly resolve projected risk: findings=%#v err=%v", findings, err)
	}
}

func TestCurrentFindingProjectionIsBoundedAndKeepsIncompleteWarning(t *testing.T) {
	s, deviceID, now := openReportCommandTestStore(t)
	ctx := context.Background()
	for reportIndex := 0; reportIndex < 3; reportIndex++ {
		findings := make([]domain.Finding, 1000)
		for findingIndex := range findings {
			sequence := reportIndex*1000 + findingIndex
			findings[findingIndex] = domain.Finding{
				ID: fmt.Sprintf("fnd_capacity_%04d", sequence), Fingerprint: fmt.Sprintf("fingerprint-capacity-%08d", sequence),
				Category: "ssh", Severity: domain.SeverityLow, Title: "Capacity test risk", Status: domain.FindingOpen,
			}
		}
		completed := now.Add(time.Duration(reportIndex+1) * time.Minute)
		report := domain.Report{ID: fmt.Sprintf("rpt_capacity_%d", reportIndex), DeviceID: deviceID, StartedAt: completed.Add(-time.Second), CompletedAt: completed, Score: 0, Summary: json.RawMessage(`{"checkErrors":["future_check: unavailable"]}`), Findings: findings}
		if err := s.SaveReport(ctx, report, completed); err != nil {
			t.Fatal(err)
		}
	}
	var total, warnings int
	if err := s.db.QueryRowContext(ctx, `SELECT count(*),sum(CASE WHEN fingerprint=? AND status=? THEN 1 ELSE 0 END) FROM current_findings WHERE device_id=?`, currentFindingCapacityFingerprint, string(domain.FindingOpen), deviceID).Scan(&total, &warnings); err != nil {
		t.Fatal(err)
	}
	if total > maxCurrentFindingsPerDevice || warnings != 1 {
		t.Fatalf("projection bound/warning missing: total=%d warnings=%d", total, warnings)
	}
	visible, err := s.ListFindings(ctx, FindingFilter{DeviceID: deviceID, Status: domain.FindingOpen, Limit: 100})
	if err != nil || len(visible) == 0 || visible[0].Fingerprint != currentFindingCapacityFingerprint {
		t.Fatalf("default finding page hid capacity warning: first=%#v err=%v", visible, err)
	}

	// A partial scan cannot prove that omitted SSH risks disappeared, so the
	// capacity warning must remain open.
	partial := domain.Report{ID: "rpt_capacity_partial", DeviceID: deviceID, StartedAt: now.Add(4 * time.Minute), CompletedAt: now.Add(5 * time.Minute), Score: 0, Summary: json.RawMessage(`{"checkErrors":["ssh_configuration: unavailable"]}`)}
	if err := s.SaveReport(ctx, partial, partial.CompletedAt); err != nil {
		t.Fatal(err)
	}
	if err := s.db.QueryRowContext(ctx, `SELECT count(*) FROM current_findings WHERE device_id=? AND fingerprint=? AND status=?`, deviceID, currentFindingCapacityFingerprint, string(domain.FindingOpen)).Scan(&warnings); err != nil {
		t.Fatal(err)
	}
	if warnings != 1 {
		t.Fatal("partial scan cleared the projection-capacity warning")
	}

	complete := domain.Report{ID: "rpt_capacity_complete", DeviceID: deviceID, StartedAt: now.Add(6 * time.Minute), CompletedAt: now.Add(7 * time.Minute), Score: 100, Summary: json.RawMessage(`{"checkErrors":[]}`)}
	if err := s.SaveReport(ctx, complete, complete.CompletedAt); err != nil {
		t.Fatal(err)
	}
	if err := s.db.QueryRowContext(ctx, `SELECT count(*) FROM current_findings WHERE device_id=?`, deviceID).Scan(&total); err != nil {
		t.Fatal(err)
	}
	if total > maxResolvedCurrentFindingsPerDevice {
		t.Fatalf("resolved projection retention is unbounded: %d", total)
	}
}

func TestStartedActionCommandIsNeverExpiredByDeliveryTTL(t *testing.T) {
	s, deviceID, now := openReportCommandTestStore(t)
	ctx := context.Background()
	created := now.Add(-2 * domain.ActionCommandTTL)
	if _, err := s.db.ExecContext(ctx, `INSERT INTO actions(id,device_id,finding_id,type,parameters,preview,status,approval_nonce_hash,approved_by,approved_at,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`, "act_started", deviceID, "", "package_security_upgrade", `{}`, `{}`, string(domain.ActionExecuting), "", "admin", timeText(created), timeText(created), timeText(created)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.ExecContext(ctx, `INSERT INTO device_commands(id,device_id,type,payload,created_at,claimed_at,started_at) VALUES(?,?,?,?,?,?,?)`, "cmd_started", deviceID, string(domain.CommandExecuteAction), `{"actionId":"act_started"}`, timeText(created), timeText(created), timeText(created)); err != nil {
		t.Fatal(err)
	}
	if err := s.ExpireStaleActionCommands(ctx, now); err != nil {
		t.Fatal(err)
	}
	var completed sql.NullString
	var status domain.ActionStatus
	if err := s.db.QueryRowContext(ctx, `SELECT c.completed_at,a.status FROM device_commands c JOIN actions a ON a.id='act_started' WHERE c.id='cmd_started'`).Scan(&completed, &status); err != nil {
		t.Fatal(err)
	}
	if completed.Valid || status != domain.ActionExecuting {
		t.Fatalf("started action was expired by delivery TTL: completed=%v status=%s", completed.Valid, status)
	}
}

func TestStartedActionWithoutReceiptBecomesIndeterminateAndLateReceiptIsNoOp(t *testing.T) {
	s, deviceID, now := openReportCommandTestStore(t)
	ctx := context.Background()
	started := now.Add(-domain.ActionExecutionTimeout - time.Minute)
	if _, err := s.db.ExecContext(ctx, `INSERT INTO actions(id,device_id,finding_id,type,parameters,preview,status,approval_nonce_hash,approved_by,approved_at,executed_at,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)`, "act_indeterminate", deviceID, "", string(action.TypeTemporaryIPBan), `{"address":"8.8.8.8","ttlSeconds":300}`, `{}`, string(domain.ActionExecuting), "", "admin", timeText(started), timeText(started), timeText(started), timeText(started)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.ExecContext(ctx, `INSERT INTO temporary_bans(id,device_id,action_id,source_ip,reason,expires_at,created_at,simulated,status) VALUES(?,?,?,?,?,?,?,?,?)`, "ban_indeterminate", deviceID, "act_indeterminate", "8.8.8.8", "test", timeText(now.Add(time.Hour)), timeText(started), false, "pending"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.ExecContext(ctx, `INSERT INTO device_commands(id,device_id,type,payload,created_at,claimed_at,started_at) VALUES(?,?,?,?,?,?,?)`, "cmd_indeterminate", deviceID, string(domain.CommandExecuteAction), `{"actionId":"act_indeterminate","type":"temporary_ip_ban","parameters":{"address":"8.8.8.8","ttlSeconds":300}}`, timeText(started), timeText(started), timeText(started)); err != nil {
		t.Fatal(err)
	}
	if err := s.ExpireStaleActionCommands(ctx, now); err != nil {
		t.Fatal(err)
	}
	var completed sql.NullString
	var actionStatus domain.ActionStatus
	var banStatus, commandError string
	if err := s.db.QueryRowContext(ctx, `SELECT c.completed_at,c.error,a.status,b.status FROM device_commands c JOIN actions a ON a.id='act_indeterminate' JOIN temporary_bans b ON b.action_id=a.id WHERE c.id='cmd_indeterminate'`).Scan(&completed, &commandError, &actionStatus, &banStatus); err != nil {
		t.Fatal(err)
	}
	if !completed.Valid || commandError != commandExecutionIndeterminateMessage || actionStatus != domain.ActionIndeterminate || banStatus != "indeterminate" {
		t.Fatalf("started timeout state completed=%v error=%q action=%s ban=%s", completed.Valid, commandError, actionStatus, banStatus)
	}
	if err := s.CompleteCommandAndAction(ctx, deviceID, "cmd_indeterminate", true, json.RawMessage(`{"late":true}`), json.RawMessage(`{"state":true}`), json.RawMessage(`{"signed":"elsewhere"}`), "", now.Add(time.Minute)); err != nil {
		t.Fatalf("late authentic queue receipt was not acknowledged: %v", err)
	}
	if err := s.db.QueryRowContext(ctx, `SELECT status FROM actions WHERE id='act_indeterminate'`).Scan(&actionStatus); err != nil || actionStatus != domain.ActionIndeterminate {
		t.Fatalf("late receipt rewrote indeterminate state: status=%s err=%v", actionStatus, err)
	}
}

func TestRevokeDeviceCancelsQueuedWorkAndMarksStartedActionIndeterminate(t *testing.T) {
	s, deviceID, now := openReportCommandTestStore(t)
	ctx := context.Background()
	insertAction := func(id string, status domain.ActionStatus) {
		t.Helper()
		if _, err := s.db.ExecContext(ctx, `INSERT INTO actions(id,device_id,finding_id,type,parameters,preview,status,approval_nonce_hash,approved_by,approved_at,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`, id, deviceID, "", string(action.TypePackageSecurityUpgrade), `{"packages":["openssl"]}`, `{}`, string(status), "", "admin", timeText(now), timeText(now), timeText(now)); err != nil {
			t.Fatal(err)
		}
	}
	insertAction("act_revoke_queued", domain.ActionApproved)
	insertAction("act_revoke_started", domain.ActionExecuting)
	if _, err := s.db.ExecContext(ctx, `INSERT INTO device_commands(id,device_id,type,payload,created_at) VALUES(?,?,?,?,?)`, "cmd_revoke_queued", deviceID, string(domain.CommandExecuteAction), `{"actionId":"act_revoke_queued"}`, timeText(now)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.ExecContext(ctx, `INSERT INTO device_commands(id,device_id,type,payload,created_at,started_at) VALUES(?,?,?,?,?,?)`, "cmd_revoke_started", deviceID, string(domain.CommandExecuteAction), `{"actionId":"act_revoke_started"}`, timeText(now), timeText(now)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.ExecContext(ctx, `INSERT INTO device_commands(id,device_id,type,payload,created_at) VALUES(?,?,?,?,?)`, "cmd_revoke_scan", deviceID, string(domain.CommandScan), `{}`, timeText(now)); err != nil {
		t.Fatal(err)
	}
	if err := s.RevokeDevice(ctx, deviceID, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	var queuedStatus, startedStatus domain.ActionStatus
	if err := s.db.QueryRowContext(ctx, `SELECT status FROM actions WHERE id='act_revoke_queued'`).Scan(&queuedStatus); err != nil {
		t.Fatal(err)
	}
	if err := s.db.QueryRowContext(ctx, `SELECT status FROM actions WHERE id='act_revoke_started'`).Scan(&startedStatus); err != nil {
		t.Fatal(err)
	}
	if queuedStatus != domain.ActionCancelled || startedStatus != domain.ActionIndeterminate {
		t.Fatalf("revocation action states queued=%s started=%s", queuedStatus, startedStatus)
	}
	var unfinished int
	if err := s.db.QueryRowContext(ctx, `SELECT count(*) FROM device_commands WHERE device_id=? AND completed_at IS NULL`, deviceID).Scan(&unfinished); err != nil || unfinished != 0 {
		t.Fatalf("revocation left unfinished commands=%d err=%v", unfinished, err)
	}
}

func TestCurrentFindingsMigrationBackfillsSnapshotsAndWatermark(t *testing.T) {
	ctx := context.Background()
	databasePath := filepath.Join(t.TempDir(), "current-findings-migration.sqlite")
	s, err := Open(ctx, databasePath)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 26, 8, 0, 0, 0, time.UTC)
	const deviceID = "dev_current_migration"
	if _, err = s.db.ExecContext(ctx, `INSERT INTO devices(id,name,hostname,os,arch,agent_version,identity_key,status,enrolled_at,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)`, deviceID, "test", "host", "linux", "amd64", "test", "", string(domain.DeviceOffline), timeText(now), timeText(now), timeText(now)); err != nil {
		t.Fatal(err)
	}
	report := domain.Report{
		ID: "rpt_current_migration", DeviceID: deviceID, StartedAt: now,
		CompletedAt: now.Add(time.Minute), Score: 60, Summary: json.RawMessage(`{"checkErrors":[]}`),
		Findings: []domain.Finding{{ID: "fnd_current_migration", Fingerprint: "fingerprint-current-migration", Category: "ssh", Severity: domain.SeverityHigh, Title: "SSH risk"}},
	}
	if err = s.SaveReport(ctx, report, report.CompletedAt); err != nil {
		t.Fatal(err)
	}
	if _, err = s.db.ExecContext(ctx, `DELETE FROM current_findings; DELETE FROM current_findings_state; DELETE FROM schema_migrations WHERE version=3`); err != nil {
		t.Fatal(err)
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = Open(ctx, databasePath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	findings, err := s.ListFindings(ctx, FindingFilter{DeviceID: deviceID, Limit: 10})
	if err != nil || len(findings) != 1 || findings[0].ID != "fnd_current_migration" {
		t.Fatalf("migration did not backfill current finding: findings=%#v err=%v", findings, err)
	}
	var watermarkReport string
	if err = s.db.QueryRowContext(ctx, `SELECT report_id FROM current_findings_state WHERE device_id=?`, deviceID).Scan(&watermarkReport); err != nil || watermarkReport != report.ID {
		t.Fatalf("migration did not backfill projection watermark: report=%q err=%v", watermarkReport, err)
	}
}

func TestCurrentFindingsMigrationIsBoundedAndKeepsCriticalCapacityEvidence(t *testing.T) {
	ctx := context.Background()
	databasePath := filepath.Join(t.TempDir(), "current-findings-capacity-migration.sqlite")
	s, err := Open(ctx, databasePath)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 26, 8, 0, 0, 0, time.UTC)
	const deviceID = "dev_capacity_migration"
	if _, err = s.db.ExecContext(ctx, `INSERT INTO devices(id,name,hostname,os,arch,agent_version,identity_key,status,enrolled_at,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)`, deviceID, "test", "host", "linux", "amd64", "test", "", string(domain.DeviceOffline), timeText(now), timeText(now), timeText(now)); err != nil {
		t.Fatal(err)
	}
	if _, err = s.db.ExecContext(ctx, `INSERT INTO reports(id,device_id,started_at,completed_at,score,summary,ingest_digest,created_at) VALUES(?,?,?,?,?,?,?,?)`, "rpt_capacity_migration", deviceID, timeText(now), timeText(now.Add(time.Minute)), 20, `{}`, "", timeText(now)); err != nil {
		t.Fatal(err)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	stmt, err := tx.PrepareContext(ctx, `INSERT INTO findings(id,report_id,device_id,fingerprint,category,severity,title,description,evidence,remediation,status,first_seen_at,last_seen_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)`)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < maxCurrentFindingsPerDevice+50; i++ {
		severity := domain.SeverityLow
		if i == maxCurrentFindingsPerDevice+49 {
			severity = domain.SeverityCritical
		}
		id := fmt.Sprintf("fnd_capacity_migration_%04d", i)
		if _, err = stmt.ExecContext(ctx, id, "rpt_capacity_migration", deviceID, "fingerprint-"+id, "test", string(severity), "risk", "", "", "", string(domain.FindingOpen), timeText(now), timeText(now)); err != nil {
			_ = stmt.Close()
			_ = tx.Rollback()
			t.Fatal(err)
		}
	}
	if err = stmt.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err = tx.ExecContext(ctx, `DELETE FROM current_findings; DELETE FROM current_findings_state; DELETE FROM schema_migrations WHERE version=3`); err != nil {
		_ = tx.Rollback()
		t.Fatal(err)
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = Open(ctx, databasePath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	var total int
	if err = s.db.QueryRowContext(ctx, `SELECT count(*) FROM current_findings WHERE device_id=?`, deviceID).Scan(&total); err != nil {
		t.Fatal(err)
	}
	if total != maxCurrentFindingsPerDevice {
		t.Fatalf("migration projection count=%d want=%d", total, maxCurrentFindingsPerDevice)
	}
	visible, err := s.ListFindings(ctx, FindingFilter{DeviceID: deviceID, Status: domain.FindingOpen, Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	if len(visible) != 100 || visible[0].Fingerprint != currentFindingCapacityFingerprint {
		t.Fatalf("capacity sentinel is not the first visible risk: %#v", visible)
	}
	criticalID := fmt.Sprintf("fnd_capacity_migration_%04d", maxCurrentFindingsPerDevice+49)
	if visible[1].ID != criticalID || visible[1].Severity != domain.SeverityCritical {
		t.Fatalf("late critical risk was hidden by migration ordering: %#v", visible[1])
	}
}

func TestCurrentFindingCapacityV4BoundsExistingVersion3ProjectionByBytes(t *testing.T) {
	ctx := context.Background()
	databasePath := filepath.Join(t.TempDir(), "current-findings-v4.sqlite")
	s, err := Open(ctx, databasePath)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 26, 8, 0, 0, 0, time.UTC)
	const deviceID = "dev_current_v4"
	if _, err = s.db.ExecContext(ctx, `INSERT INTO devices(id,name,hostname,os,arch,agent_version,identity_key,status,enrolled_at,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)`, deviceID, "test", "host", "linux", "amd64", "test", "", string(domain.DeviceOffline), timeText(now), timeText(now), timeText(now)); err != nil {
		t.Fatal(err)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	stmt, err := tx.PrepareContext(ctx, `INSERT INTO current_findings(device_id,fingerprint,id,report_id,category,severity,title,description,evidence,remediation,status,first_seen_at,last_seen_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)`)
	if err != nil {
		t.Fatal(err)
	}
	largeEvidence := strings.Repeat("证据", 6_000)
	for i := 0; i < 300; i++ {
		id := fmt.Sprintf("fnd_v4_%03d", i)
		if _, err = stmt.ExecContext(ctx, deviceID, "fingerprint-"+id, id, "rpt_legacy_v3", "test", string(domain.SeverityLow), "legacy risk", "", largeEvidence, "", string(domain.FindingOpen), timeText(now), timeText(now), timeText(now)); err != nil {
			_ = stmt.Close()
			_ = tx.Rollback()
			t.Fatal(err)
		}
	}
	_ = stmt.Close()
	if _, err = tx.ExecContext(ctx, `DELETE FROM schema_migrations WHERE version=4`); err != nil {
		_ = tx.Rollback()
		t.Fatal(err)
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = Open(ctx, databasePath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	var retained, warning int
	var retainedBytes int64
	if err = s.db.QueryRowContext(ctx, `SELECT count(*),coalesce(sum(length(CAST(fingerprint AS BLOB))+length(CAST(category AS BLOB))+length(CAST(title AS BLOB))+length(CAST(description AS BLOB))+length(CAST(evidence AS BLOB))+length(CAST(remediation AS BLOB))+256),0),sum(CASE WHEN fingerprint=? THEN 1 ELSE 0 END) FROM current_findings WHERE device_id=?`, currentFindingCapacityFingerprint, deviceID).Scan(&retained, &retainedBytes, &warning); err != nil {
		t.Fatal(err)
	}
	if retained >= 300 || retainedBytes > maxCurrentFindingBytesPerDevice+64*1024 || warning != 1 {
		t.Fatalf("v4 byte migration retained=%d bytes=%d warning=%d", retained, retainedBytes, warning)
	}
}

func TestLateReportCannotReopenFindingResolvedByNewerScan(t *testing.T) {
	s, deviceID, now := openReportCommandTestStore(t)
	ctx := context.Background()
	finding := func(id string) domain.Finding {
		return domain.Finding{ID: id, Fingerprint: "fingerprint-late-order", Category: "ssh", Severity: domain.SeverityHigh, Title: "SSH risk", Status: domain.FindingOpen}
	}
	t0 := domain.Report{ID: "rpt_t0", DeviceID: deviceID, StartedAt: now, CompletedAt: now.Add(time.Minute), Score: 50, Summary: json.RawMessage(`{"checkErrors":[]}`), Findings: []domain.Finding{finding("fnd_t0")}}
	if err := s.SaveReport(ctx, t0, t0.CompletedAt); err != nil {
		t.Fatal(err)
	}
	t2 := domain.Report{ID: "rpt_t2", DeviceID: deviceID, StartedAt: now.Add(4 * time.Minute), CompletedAt: now.Add(5 * time.Minute), Score: 100, Summary: json.RawMessage(`{"checkErrors":[]}`)}
	if err := s.SaveReport(ctx, t2, t2.CompletedAt); err != nil {
		t.Fatal(err)
	}
	t1 := domain.Report{ID: "rpt_t1", DeviceID: deviceID, StartedAt: now.Add(2 * time.Minute), CompletedAt: now.Add(3 * time.Minute), Score: 50, Summary: json.RawMessage(`{"checkErrors":[]}`), Findings: []domain.Finding{finding("fnd_t1")}}
	if err := s.SaveReport(ctx, t1, now.Add(6*time.Minute)); err != nil {
		t.Fatal(err)
	}
	findings, err := s.ListFindings(ctx, FindingFilter{DeviceID: deviceID, Limit: 10})
	if err != nil || len(findings) != 1 || findings[0].Status != domain.FindingResolved {
		t.Fatalf("late historical snapshot reopened current risk: findings=%#v err=%v", findings, err)
	}
}

func TestSaveReportRetryIsIdempotentButConflictingPayloadIsRejected(t *testing.T) {
	s, deviceID, now := openReportCommandTestStore(t)
	report := domain.Report{ID: "rpt_retry", DeviceID: deviceID, StartedAt: now, CompletedAt: now.Add(time.Minute), Score: 90, Summary: json.RawMessage(`{"checkErrors":[]}`), Findings: []domain.Finding{{Fingerprint: "fingerprint-report-retry", Category: "ssh", Severity: domain.SeverityLow, Title: "retry"}}}
	created, err := s.SaveReportWithOutcome(context.Background(), report, report.CompletedAt)
	if err != nil || !created {
		t.Fatalf("first save created=%v err=%v", created, err)
	}
	created, err = s.SaveReportWithOutcome(context.Background(), report, report.CompletedAt.Add(time.Minute))
	if err != nil || created {
		t.Fatalf("exact retry created=%v err=%v", created, err)
	}
	report.Score = 10
	if _, err = s.SaveReportWithOutcome(context.Background(), report, report.CompletedAt.Add(2*time.Minute)); !errors.Is(err, ErrConflict) {
		t.Fatalf("conflicting report replay was accepted: %v", err)
	}
}

func TestLegacyReportReplayBackfillsDigestOnlyAfterStablePayloadMatch(t *testing.T) {
	s, deviceID, now := openReportCommandTestStore(t)
	ctx := context.Background()
	report := domain.Report{
		ID: "rpt_legacy_retry", DeviceID: deviceID, StartedAt: now, CompletedAt: now.Add(time.Minute), Score: 83,
		Summary: json.RawMessage(`{"checks":2,"checkErrors":[]}`),
		Findings: []domain.Finding{
			{ReportID: "rpt_legacy_retry", DeviceID: deviceID, Fingerprint: "fingerprint-legacy-retry-one", Category: "ssh", Severity: domain.SeverityHigh, Title: "SSH setting", Description: "description one", Evidence: "evidence one", Remediation: "fix one", Status: domain.FindingOpen},
			{ReportID: "rpt_legacy_retry", DeviceID: deviceID, Fingerprint: "fingerprint-legacy-retry-two", Category: "updates", Severity: domain.SeverityLow, Title: "Package update", Description: "description two", Evidence: "evidence two", Remediation: "fix two", Status: domain.FindingOpen},
		},
	}
	if err := s.SaveReport(ctx, report, now.Add(2*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.ExecContext(ctx, `UPDATE reports SET ingest_digest='' WHERE id=?`, report.ID); err != nil {
		t.Fatal(err)
	}

	copyReport := func() domain.Report {
		value := report
		value.Findings = append([]domain.Finding(nil), report.Findings...)
		return value
	}
	conflicts := []struct {
		name   string
		mutate func(*domain.Report)
	}{
		{name: "report field", mutate: func(value *domain.Report) { value.Score-- }},
		{name: "summary bytes", mutate: func(value *domain.Report) { value.Summary = json.RawMessage(`{"checks":1,"checkErrors":[]}`) }},
		{name: "finding field", mutate: func(value *domain.Report) { value.Findings[0].Evidence = "different evidence" }},
		{name: "non-canonical finding report id", mutate: func(value *domain.Report) { value.Findings[0].ReportID = "rpt_other" }},
		{name: "wrong finding device", mutate: func(value *domain.Report) { value.Findings[0].DeviceID = "dev_other" }},
		{name: "finding order", mutate: func(value *domain.Report) {
			value.Findings[0], value.Findings[1] = value.Findings[1], value.Findings[0]
		}},
		{name: "unrecoverable observation time", mutate: func(value *domain.Report) { value.Findings[0].FirstSeenAt = now }},
	}
	for _, test := range conflicts {
		t.Run(test.name, func(t *testing.T) {
			changed := copyReport()
			test.mutate(&changed)
			if _, err := s.SaveReportWithOutcome(ctx, changed, now.Add(3*time.Minute)); !errors.Is(err, ErrConflict) {
				t.Fatalf("legacy conflict was accepted: %v", err)
			}
			var digest string
			if err := s.db.QueryRowContext(ctx, `SELECT ingest_digest FROM reports WHERE id=?`, report.ID).Scan(&digest); err != nil || digest != "" {
				t.Fatalf("conflict changed legacy digest: digest=%q err=%v", digest, err)
			}
		})
	}

	created, err := s.SaveReportWithOutcome(ctx, report, now.Add(4*time.Minute))
	if err != nil || created {
		t.Fatalf("exact legacy replay was not idempotent: created=%v err=%v", created, err)
	}
	wantDigest, err := reportIngestDigest(report)
	if err != nil {
		t.Fatal(err)
	}
	var digest string
	if err = s.db.QueryRowContext(ctx, `SELECT ingest_digest FROM reports WHERE id=?`, report.ID).Scan(&digest); err != nil || digest != wantDigest {
		t.Fatalf("legacy digest was not backfilled: got=%q want=%q err=%v", digest, wantDigest, err)
	}
	changed := copyReport()
	changed.Findings[1].Title = "changed after upgrade"
	if _, err = s.SaveReportWithOutcome(ctx, changed, now.Add(5*time.Minute)); !errors.Is(err, ErrConflict) {
		t.Fatalf("post-upgrade conflicting report was accepted: %v", err)
	}
	var storedScore int
	var storedSummary string
	if err = s.db.QueryRowContext(ctx, `SELECT score,summary FROM reports WHERE id=?`, report.ID).Scan(&storedScore, &storedSummary); err != nil || storedScore != report.Score || storedSummary != string(report.Summary) {
		t.Fatalf("legacy report was overwritten: score=%d summary=%q err=%v", storedScore, storedSummary, err)
	}
}

func TestLegacyRawActionReceiptReplayBackfillsFullTupleDigest(t *testing.T) {
	s, deviceID, now := openReportCommandTestStore(t)
	ctx := context.Background()
	const actionID = "act_legacy_receipt"
	const commandID = "cmd_legacy_receipt"
	parameters := json.RawMessage(`{"packages":["openssl"]}`)
	commandPayload, err := json.Marshal(map[string]any{"actionId": actionID, "type": action.TypePackageSecurityUpgrade, "parameters": parameters})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.db.ExecContext(ctx, `INSERT INTO actions(id,device_id,finding_id,type,parameters,preview,status,approval_nonce_hash,approved_by,approved_at,executed_at,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)`, actionID, deviceID, "", string(action.TypePackageSecurityUpgrade), string(parameters), `{}`, string(domain.ActionExecuting), "", "admin", timeText(now), timeText(now), timeText(now), timeText(now)); err != nil {
		t.Fatal(err)
	}
	if _, err = s.db.ExecContext(ctx, `INSERT INTO device_commands(id,device_id,type,payload,created_at,claimed_at,started_at) VALUES(?,?,?,?,?,?,?)`, commandID, deviceID, string(domain.CommandExecuteAction), string(commandPayload), timeText(now), timeText(now), timeText(now)); err != nil {
		t.Fatal(err)
	}
	result := json.RawMessage(`{"summary":"upgraded"}`)
	rollback := json.RawMessage(`{"packages":{"openssl":"old-version"}}`)
	auditBytes, err := json.Marshal(map[string]any{
		"actionId": actionID, "type": action.TypePackageSecurityUpgrade, "operation": action.OperationExecute,
		"parametersDigest": action.ParametersDigest(parameters), "success": true,
		"rollbackStateDigest": digestRollbackState(rollback), "legacyMetadata": map[string]any{"helperVersion": "legacy"},
		"steps": []map[string]any{
			{"operation": action.OperationPrecheck, "success": true, "result": map[string]any{"details": map[string]any{"stage": "precheck"}}},
			{"operation": action.OperationPreview, "success": true, "result": map[string]any{"details": map[string]any{"stage": "preview"}}},
			{"operation": action.OperationApply, "success": true, "result": map[string]any{"details": map[string]any{"stage": "apply"}}},
			{"operation": action.OperationVerify, "success": true, "result": map[string]any{"details": map[string]any{"stage": "verify"}}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	audit := json.RawMessage(auditBytes)
	initialOutcome, err := s.CompleteCommandAndActionWithOutcome(ctx, deviceID, commandID, true, result, rollback, audit, "", now.Add(time.Minute))
	if err != nil || !initialOutcome.OK {
		t.Fatalf("seed valid completion failed: outcome=%#v err=%v", initialOutcome, err)
	}
	legacyStored, err := json.Marshal(map[string]any{"ok": true, "result": result, "auditReceipt": audit})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.db.ExecContext(ctx, `UPDATE device_commands SET result=?,completion_digest='' WHERE id=?`, string(legacyStored), commandID); err != nil {
		t.Fatal(err)
	}
	var auditRowsBefore int
	if err = s.db.QueryRowContext(ctx, `SELECT count(*) FROM action_audit WHERE action_id=?`, actionID).Scan(&auditRowsBefore); err != nil {
		t.Fatal(err)
	}

	changedAudit := append(json.RawMessage(nil), audit...)
	var auditObject map[string]any
	if err = json.Unmarshal(changedAudit, &auditObject); err != nil {
		t.Fatal(err)
	}
	auditObject["legacyMetadata"] = map[string]any{"helperVersion": "changed"}
	changedAudit, err = json.Marshal(auditObject)
	if err != nil {
		t.Fatal(err)
	}
	attempts := []struct {
		name     string
		ok       bool
		result   json.RawMessage
		rollback json.RawMessage
		audit    json.RawMessage
		error    string
	}{
		{name: "result", ok: true, result: json.RawMessage(`{"summary":"different"}`), rollback: rollback, audit: audit},
		{name: "rollback", ok: true, result: result, rollback: json.RawMessage(`{"packages":{"openssl":"different"}}`), audit: audit},
		{name: "audit", ok: true, result: result, rollback: rollback, audit: changedAudit},
		{name: "error", ok: true, result: result, rollback: rollback, audit: audit, error: "different error"},
		{name: "ok", ok: false, result: result, rollback: rollback, audit: audit},
	}
	for _, attempt := range attempts {
		t.Run(attempt.name, func(t *testing.T) {
			if _, completeErr := s.CompleteCommandAndActionWithOutcome(ctx, deviceID, commandID, attempt.ok, attempt.result, attempt.rollback, attempt.audit, attempt.error, now.Add(2*time.Minute)); !errors.Is(completeErr, ErrConflict) {
				t.Fatalf("changed %s crossed legacy replay guard: %v", attempt.name, completeErr)
			}
			var digest string
			if queryErr := s.db.QueryRowContext(ctx, `SELECT completion_digest FROM device_commands WHERE id=?`, commandID).Scan(&digest); queryErr != nil || digest != "" {
				t.Fatalf("changed replay installed digest: digest=%q err=%v", digest, queryErr)
			}
		})
	}
	var persistedResult, persistedRollback, persistedError, persistedDigest string
	if err = s.db.QueryRowContext(ctx, `SELECT c.result,a.rollback_payload,c.error,c.completion_digest FROM device_commands c JOIN actions a ON a.id=? WHERE c.id=?`, actionID, commandID).Scan(&persistedResult, &persistedRollback, &persistedError, &persistedDigest); err != nil {
		t.Fatal(err)
	}
	if persistedResult != string(legacyStored) || persistedRollback != string(rollback) || persistedError != "" || persistedDigest != "" {
		t.Fatalf("legacy fixture drifted: resultEqual=%v rollbackEqual=%v error=%q digest=%q", persistedResult == string(legacyStored), persistedRollback == string(rollback), persistedError, persistedDigest)
	}
	checkTx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	rollbackMatches, err := legacyActionRollbackMatchesTx(ctx, checkTx, actionID, string(domain.CommandExecuteAction), rollback, nil)
	_ = checkTx.Rollback()
	if err != nil || !rollbackMatches {
		t.Fatalf("legacy rollback proof failed before replay: matches=%v err=%v", rollbackMatches, err)
	}

	outcome, err := s.CompleteCommandAndActionWithOutcome(ctx, deviceID, commandID, true, result, rollback, audit, "", now.Add(3*time.Minute))
	if err != nil || outcome.NewlyCompleted || !outcome.OK {
		t.Fatalf("exact legacy action replay failed: outcome=%#v err=%v", outcome, err)
	}
	wantDigest, err := commandCompletionDigest(deviceID, commandID, true, result, rollback, audit, "")
	if err != nil {
		t.Fatal(err)
	}
	var digest string
	if err = s.db.QueryRowContext(ctx, `SELECT completion_digest FROM device_commands WHERE id=?`, commandID).Scan(&digest); err != nil || digest != wantDigest {
		t.Fatalf("legacy completion digest was not backfilled: got=%q want=%q err=%v", digest, wantDigest, err)
	}
	var auditRowsAfter int
	if err = s.db.QueryRowContext(ctx, `SELECT count(*) FROM action_audit WHERE action_id=?`, actionID).Scan(&auditRowsAfter); err != nil || auditRowsAfter != auditRowsBefore {
		t.Fatalf("legacy replay repeated action side effects: before=%d after=%d err=%v", auditRowsBefore, auditRowsAfter, err)
	}
}

func TestLegacySSHReceiptReplayAfterExpiredConfirmationDeadline(t *testing.T) {
	s, deviceID, now := openReportCommandTestStore(t)
	ctx := context.Background()
	const actionID = "act_legacy_ssh_deadline"
	const commandID = "cmd_legacy_ssh_deadline"
	parameters := json.RawMessage(`{"rollbackAfterSeconds":300}`)
	commandPayload, err := json.Marshal(map[string]any{"actionId": actionID, "type": action.TypeSSHPasswordHardening, "parameters": parameters})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.db.ExecContext(ctx, `INSERT INTO actions(id,device_id,finding_id,type,parameters,preview,status,approval_nonce_hash,approved_by,approved_at,executed_at,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)`, actionID, deviceID, "", string(action.TypeSSHPasswordHardening), string(parameters), `{}`, string(domain.ActionExecuting), "", "admin", timeText(now), timeText(now), timeText(now), timeText(now)); err != nil {
		t.Fatal(err)
	}
	if _, err = s.db.ExecContext(ctx, `INSERT INTO device_commands(id,device_id,type,payload,created_at,claimed_at,started_at) VALUES(?,?,?,?,?,?,?)`, commandID, deviceID, string(domain.CommandExecuteAction), string(commandPayload), timeText(now), timeText(now), timeText(now)); err != nil {
		t.Fatal(err)
	}
	result := json.RawMessage(`{"summary":"ssh hardened"}`)
	rollback := json.RawMessage(`{"config":"original"}`)
	confirmBy := now.Add(5 * time.Minute).UTC()
	makeAudit := func(deadline time.Time) json.RawMessage {
		value, marshalErr := json.Marshal(map[string]any{
			"actionId": actionID, "type": action.TypeSSHPasswordHardening, "operation": action.OperationExecute,
			"parametersDigest": action.ParametersDigest(parameters), "success": true,
			"rollbackStateDigest": digestRollbackState(rollback), "confirmBy": deadline,
			"steps": []map[string]any{
				{"operation": action.OperationPrecheck, "success": true, "result": map[string]any{"details": map[string]any{}}},
				{"operation": action.OperationPreview, "success": true, "result": map[string]any{"details": map[string]any{}}},
				{"operation": action.OperationApply, "success": true, "result": map[string]any{"details": map[string]any{}}},
				{"operation": action.OperationVerify, "success": true, "result": map[string]any{"details": map[string]any{"confirmationPending": true}}},
			},
		})
		if marshalErr != nil {
			t.Fatal(marshalErr)
		}
		return value
	}
	audit := makeAudit(confirmBy)
	if outcome, completeErr := s.CompleteCommandAndActionWithOutcome(ctx, deviceID, commandID, true, result, rollback, audit, "", now.Add(time.Minute)); completeErr != nil || !outcome.OK {
		t.Fatalf("seed SSH completion failed: outcome=%#v err=%v", outcome, completeErr)
	}
	legacyStored, err := json.Marshal(map[string]any{"ok": true, "result": result, "auditReceipt": audit})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.db.ExecContext(ctx, `UPDATE device_commands SET result=?,completion_digest='' WHERE id=?`, string(legacyStored), commandID); err != nil {
		t.Fatal(err)
	}
	// Model a Controller that ran confirmation expiry while the Agent was still
	// blocked on the lost HTTP response. The helper deadline is historical now,
	// but the exact signed receipt still must be acknowledged once.
	if err = s.ExpireActionConfirmations(ctx, now.Add(10*time.Minute)); err != nil {
		t.Fatal(err)
	}
	changedAudit := makeAudit(confirmBy.Add(time.Minute))
	if _, err = s.CompleteCommandAndActionWithOutcome(ctx, deviceID, commandID, true, result, rollback, changedAudit, "", now.Add(30*time.Minute)); !errors.Is(err, ErrConflict) {
		t.Fatalf("changed legacy SSH deadline was accepted: %v", err)
	}
	outcome, err := s.CompleteCommandAndActionWithOutcome(ctx, deviceID, commandID, true, result, rollback, audit, "", now.Add(30*time.Minute))
	if err != nil || !outcome.OK || outcome.NewlyCompleted {
		t.Fatalf("expired legacy SSH receipt did not unblock replay: outcome=%#v err=%v", outcome, err)
	}
	wantDigest, err := commandCompletionDigest(deviceID, commandID, true, result, rollback, audit, "")
	if err != nil {
		t.Fatal(err)
	}
	var digest, status string
	if err = s.db.QueryRowContext(ctx, `SELECT c.completion_digest,a.status FROM device_commands c JOIN actions a ON a.id=? WHERE c.id=?`, actionID, commandID).Scan(&digest, &status); err != nil || digest != wantDigest || status != string(domain.ActionCancelled) {
		t.Fatalf("legacy SSH replay changed terminal safety state: digest=%q status=%q err=%v", digest, status, err)
	}
}

func TestLegacyFailedActionExactReplayUnblocksWithoutClaimingDigest(t *testing.T) {
	s, deviceID, now := openReportCommandTestStore(t)
	ctx := context.Background()
	const actionID = "act_legacy_failure"
	const commandID = "cmd_legacy_failure"
	parameters := json.RawMessage(`{"packages":["openssl"]}`)
	payload, err := json.Marshal(map[string]any{"actionId": actionID, "type": action.TypePackageSecurityUpgrade, "parameters": parameters})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.db.ExecContext(ctx, `INSERT INTO actions(id,device_id,finding_id,type,parameters,preview,status,approval_nonce_hash,approved_by,approved_at,executed_at,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)`, actionID, deviceID, "", string(action.TypePackageSecurityUpgrade), string(parameters), `{}`, string(domain.ActionExecuting), "", "admin", timeText(now), timeText(now), timeText(now), timeText(now)); err != nil {
		t.Fatal(err)
	}
	if _, err = s.db.ExecContext(ctx, `INSERT INTO device_commands(id,device_id,type,payload,created_at,claimed_at,started_at) VALUES(?,?,?,?,?,?,?)`, commandID, deviceID, string(domain.CommandExecuteAction), string(payload), timeText(now), timeText(now), timeText(now)); err != nil {
		t.Fatal(err)
	}
	result := json.RawMessage(`{"partial":"none"}`)
	audit := json.RawMessage(`{"legacyFailureReceipt":"package manager unavailable"}`)
	// A genuine Execute can fail after Apply succeeded and Verify failed. The
	// helper then returns the sealed Apply state even though OK is false.
	rollback := json.RawMessage(`{"version":1,"actionId":"act_legacy_failure","sealed":"apply-succeeded-before-verify-failed"}`)
	const failure = "package manager unavailable"
	if outcome, completeErr := s.CompleteCommandAndActionWithOutcome(ctx, deviceID, commandID, false, result, rollback, audit, failure, now.Add(time.Minute)); completeErr != nil || outcome.OK {
		t.Fatalf("seed failure completion failed: outcome=%#v err=%v", outcome, completeErr)
	}
	legacyStored, err := json.Marshal(map[string]any{"ok": false, "result": result, "auditReceipt": audit})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.db.ExecContext(ctx, `UPDATE device_commands SET result=?,completion_digest='' WHERE id=?`, string(legacyStored), commandID); err != nil {
		t.Fatal(err)
	}
	var auditRowsBefore int
	if err = s.db.QueryRowContext(ctx, `SELECT count(*) FROM action_audit WHERE action_id=?`, actionID).Scan(&auditRowsBefore); err != nil {
		t.Fatal(err)
	}
	attempts := []struct {
		name   string
		result json.RawMessage
		audit  json.RawMessage
		error  string
	}{
		{name: "result", result: json.RawMessage(`{"partial":"changed"}`), audit: audit, error: failure},
		{name: "audit", result: result, audit: json.RawMessage(`{"legacyFailureReceipt":"changed"}`), error: failure},
		{name: "error", result: result, audit: audit, error: "changed"},
	}
	for _, attempt := range attempts {
		t.Run(attempt.name, func(t *testing.T) {
			if _, replayErr := s.CompleteCommandAndActionWithOutcome(ctx, deviceID, commandID, false, attempt.result, rollback, attempt.audit, attempt.error, now.Add(2*time.Minute)); !errors.Is(replayErr, ErrConflict) {
				t.Fatalf("changed legacy failure was accepted: %v", replayErr)
			}
		})
	}
	outcome, err := s.CompleteCommandAndActionWithOutcome(ctx, deviceID, commandID, false, result, rollback, audit, failure, now.Add(3*time.Minute))
	if err != nil || outcome.OK || outcome.NewlyCompleted || outcome.Error != failure {
		t.Fatalf("exact legacy failure did not unblock replay: outcome=%#v err=%v", outcome, err)
	}
	var digest, status string
	var auditRowsAfter int
	if err = s.db.QueryRowContext(ctx, `SELECT c.completion_digest,a.status FROM device_commands c JOIN actions a ON a.id=? WHERE c.id=?`, actionID, commandID).Scan(&digest, &status); err != nil || digest != "" || status != string(domain.ActionFailed) {
		t.Fatalf("legacy failure acknowledgement changed durable state: digest=%q status=%q err=%v", digest, status, err)
	}
	if err = s.db.QueryRowContext(ctx, `SELECT count(*) FROM action_audit WHERE action_id=?`, actionID).Scan(&auditRowsAfter); err != nil || auditRowsAfter != auditRowsBefore {
		t.Fatalf("legacy failure replay repeated side effects: before=%d after=%d err=%v", auditRowsBefore, auditRowsAfter, err)
	}
}

func TestCommandCompactionKeepsReplayTombstoneAndFullDigest(t *testing.T) {
	s, deviceID, now := openReportCommandTestStore(t)
	ctx := context.Background()
	const commandID = "cmd_tombstone_oldest"
	if _, err := s.db.ExecContext(ctx, `INSERT INTO device_commands(id,device_id,type,payload,created_at) VALUES(?,?,?,?,?)`, commandID, deviceID, string(domain.CommandScan), `{"scan":true}`, timeText(now)); err != nil {
		t.Fatal(err)
	}
	result := json.RawMessage(`{"score":90}`)
	if err := s.CompleteCommandAndAction(ctx, deviceID, commandID, true, result, nil, nil, "", now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.ExecContext(ctx, `WITH RECURSIVE seq(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM seq WHERE x<=?)
		INSERT INTO device_commands(id,device_id,type,payload,created_at,completed_at,result,error,completion_digest)
		SELECT printf('cmd_newer_%05d',x),?,?,'{}',?,?,?,'','digest-'||x FROM seq`, maxDetailedCommandsPerDevice, deviceID, string(domain.CommandScan), timeText(now.Add(2*time.Minute)), timeText(now.Add(2*time.Minute)), `{"ok":true}`); err != nil {
		t.Fatal(err)
	}
	if err := s.Compact(ctx, now.Add(3*time.Minute)); err != nil {
		t.Fatal(err)
	}
	var payload string
	var storedResult sql.NullString
	if err := s.db.QueryRowContext(ctx, `SELECT payload,result FROM device_commands WHERE id=?`, commandID).Scan(&payload, &storedResult); err != nil {
		t.Fatalf("old command identity was deleted: %v", err)
	}
	if payload != `{}` || storedResult.Valid {
		t.Fatalf("old command was not compacted to a tombstone: payload=%q result=%v", payload, storedResult.Valid)
	}
	if err := s.CompleteCommandAndAction(ctx, deviceID, commandID, true, result, nil, nil, "", now.Add(4*time.Minute)); err != nil {
		t.Fatalf("exact queued result could not cross tombstone: %v", err)
	}
	if err := s.CompleteCommandAndAction(ctx, deviceID, commandID, true, json.RawMessage(`{"score":1}`), nil, nil, "", now.Add(4*time.Minute)); !errors.Is(err, ErrConflict) {
		t.Fatalf("different result crossed tombstone: %v", err)
	}
}

func TestCompactionRemovesLegacyActionCommandWhenActionRetentionDropsItsProof(t *testing.T) {
	s, deviceID, now := openReportCommandTestStore(t)
	ctx := context.Background()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	for index := 0; index <= maxTerminalActionsPerDevice; index++ {
		actionID := fmt.Sprintf("act_compact_legacy_%04d", index)
		commandID := fmt.Sprintf("cmd_compact_legacy_%04d", index)
		created := now.Add(time.Duration(index) * time.Second)
		if _, err = tx.ExecContext(ctx, `INSERT INTO actions(id,device_id,finding_id,type,parameters,preview,status,approval_nonce_hash,approved_by,approved_at,executed_at,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)`, actionID, deviceID, "", string(action.TypePackageSecurityUpgrade), `{}`, `{}`, string(domain.ActionSucceeded), "", "admin", timeText(created), timeText(created), timeText(created), timeText(created)); err != nil {
			t.Fatal(err)
		}
		payload := fmt.Sprintf(`{"actionId":%q,"type":"package_security_upgrade","parameters":{}}`, actionID)
		if _, err = tx.ExecContext(ctx, `INSERT INTO device_commands(id,device_id,type,payload,result,error,completion_digest,created_at,claimed_at,started_at,completed_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)`, commandID, deviceID, string(domain.CommandExecuteAction), payload, `{"ok":true,"result":{},"auditReceipt":{}}`, "", "", timeText(created), timeText(created), timeText(created), timeText(created)); err != nil {
			t.Fatal(err)
		}
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if err = s.Compact(ctx, now.Add(2*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err = s.Command(ctx, deviceID, "cmd_compact_legacy_0000"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("orphaned legacy command was retained and can poison FIFO replay: %v", err)
	}
	if _, err = s.Command(ctx, deviceID, fmt.Sprintf("cmd_compact_legacy_%04d", maxTerminalActionsPerDevice)); err != nil {
		t.Fatalf("newest retained action command was removed: %v", err)
	}
}

func TestUnfinishedActionCapacityIsBoundedPerDevice(t *testing.T) {
	s, deviceID, now := openReportCommandTestStore(t)
	ctx := context.Background()
	if _, err := s.db.ExecContext(ctx, `WITH RECURSIVE seq(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM seq WHERE x<?)
		INSERT INTO actions(id,device_id,finding_id,type,parameters,preview,status,approval_nonce_hash,approved_by,approved_at,created_at,updated_at)
		SELECT printf('act_pending_%03d',x),?,'',?,'{}','{}',?,'','admin',?,?,? FROM seq`, maxUnfinishedActionsPerDevice, deviceID, string(action.TypePackageSecurityUpgrade), string(domain.ActionApproved), timeText(now), timeText(now), timeText(now)); err != nil {
		t.Fatal(err)
	}
	next := domain.Action{ID: "act_over_capacity", DeviceID: deviceID, Type: string(action.TypePackageSecurityUpgrade), Parameters: json.RawMessage(`{}`), Preview: json.RawMessage(`{}`), Status: domain.ActionDraft, CreatedAt: now, UpdatedAt: now}
	if err := s.CreateAction(ctx, next, "nonce", "admin"); !errors.Is(err, ErrConflict) {
		t.Fatalf("unfinished action capacity was bypassed: %v", err)
	}
	if _, err := s.db.ExecContext(ctx, `UPDATE actions SET status=? WHERE id='act_pending_001'`, string(domain.ActionFailed)); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateAction(ctx, next, "nonce", "admin"); err != nil {
		t.Fatalf("released unfinished capacity was not reusable: %v", err)
	}
}

func TestOfflineScanCommandsAreCoalescedToNewest(t *testing.T) {
	s, deviceID, now := openReportCommandTestStore(t)
	ctx := context.Background()
	old := domain.DeviceCommand{ID: "cmd_old", DeviceID: deviceID, Type: domain.CommandScan, Payload: json.RawMessage(`{"sequence":1}`), CreatedAt: now}
	latest := domain.DeviceCommand{ID: "cmd_latest", DeviceID: deviceID, Type: domain.CommandScan, Payload: json.RawMessage(`{"sequence":2}`), CreatedAt: now.Add(time.Hour)}
	if err := s.EnqueueCommand(ctx, old); err != nil {
		t.Fatal(err)
	}
	if err := s.EnqueueCommand(ctx, latest); err != nil {
		t.Fatal(err)
	}
	storedOld, err := s.Command(ctx, deviceID, old.ID)
	if err != nil || storedOld.CompletedAt == nil || storedOld.Error != supersededScanMessage {
		t.Fatalf("old scan was not durably superseded: %#v err=%v", storedOld, err)
	}
	commands, err := s.ClaimCommands(ctx, deviceID, 10, now.Add(2*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if len(commands) != 1 || commands[0].ID != latest.ID {
		t.Fatalf("reconnect did not receive only the latest scan: %#v", commands)
	}
	if err = s.CompleteCommandAndAction(ctx, deviceID, old.ID, true, json.RawMessage(`{"late":true}`), nil, nil, "", now.Add(2*time.Hour)); err != nil {
		t.Fatalf("late receipt for a superseded scan blocked the Agent queue: %v", err)
	}
}

func TestClaimCommandsCollapsesLegacyScanBacklog(t *testing.T) {
	s, deviceID, now := openReportCommandTestStore(t)
	ctx := context.Background()
	for index, id := range []string{"legacy_one", "legacy_two", "legacy_latest"} {
		created := now.Add(time.Duration(index) * time.Hour)
		claimed := any(nil)
		if id == "legacy_latest" {
			claimed = timeText(now)
		}
		if _, err := s.db.ExecContext(ctx, `INSERT INTO device_commands(id,device_id,type,payload,created_at,claimed_at) VALUES(?,?,?,?,?,?)`, id, deviceID, string(domain.CommandScan), `{}`, timeText(created), claimed); err != nil {
			t.Fatal(err)
		}
	}
	commands, err := s.ClaimCommands(ctx, deviceID, 10, now.Add(3*time.Hour+time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if len(commands) != 1 || commands[0].ID != "legacy_latest" {
		t.Fatalf("legacy backlog was not collapsed to newest: %#v", commands)
	}
	for _, id := range []string{"legacy_one", "legacy_two"} {
		command, err := s.Command(ctx, deviceID, id)
		if err != nil || command.CompletedAt == nil || command.Error != supersededScanMessage {
			t.Fatalf("legacy command %s was not superseded: %#v err=%v", id, command, err)
		}
	}
}

func TestEnrollmentCreatesControllerOwnedScheduleFromLegacyHint(t *testing.T) {
	s, _, now := openReportCommandTestStore(t)
	ctx := context.Background()
	token := domain.EnrollmentToken{ID: "enr_schedule", Name: "schedule", Hint: "hint", MaxUses: 1, ExpiresAt: timePointer(now.Add(time.Hour)), CreatedAt: now}
	if err := s.CreateEnrollmentToken(ctx, token, "enrollment-hash"); err != nil {
		t.Fatal(err)
	}
	device, err := s.EnrollDevice(ctx, "enrollment-hash", "agent-hash", EnrollInput{Name: "scheduled", Hostname: "host", OS: "linux", Arch: "amd64", AgentVersion: "test", ScanInterval: 7 * 24 * time.Hour}, now)
	if err != nil {
		t.Fatal(err)
	}
	schedules, err := s.ListSchedules(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var found *domain.Schedule
	for index := range schedules {
		if schedules[index].DeviceID == device.ID {
			found = &schedules[index]
			break
		}
	}
	if found == nil || !found.Enabled || found.Kind != domain.ScheduleScan || found.Interval != 7*24*time.Hour || !found.NextRunAt.Equal(now.Add(7*24*time.Hour)) {
		t.Fatalf("authoritative enrollment schedule mismatch: %#v", found)
	}
}

func TestScheduleMigrationSeedsExistingDeviceOnlyOnce(t *testing.T) {
	ctx := context.Background()
	databasePath := filepath.Join(t.TempDir(), "migration.sqlite")
	s, err := Open(ctx, databasePath)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 26, 8, 0, 0, 0, time.UTC)
	_, err = s.db.ExecContext(ctx, `INSERT INTO devices(id,name,hostname,os,arch,agent_version,identity_key,status,enrolled_at,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)`, "dev_existing", "existing", "host", "linux", "amd64", "old", "", string(domain.DeviceOffline), timeText(now), timeText(now), timeText(now))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.db.ExecContext(ctx, `DELETE FROM schema_migrations WHERE version=2`); err != nil {
		t.Fatal(err)
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = Open(ctx, databasePath)
	if err != nil {
		t.Fatal(err)
	}
	schedules, err := s.ListSchedules(ctx)
	if err != nil || len(schedules) != 1 || schedules[0].DeviceID != "dev_existing" || schedules[0].Interval != DefaultScanInterval {
		t.Fatalf("existing device schedule was not migrated: schedules=%#v err=%v", schedules, err)
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = Open(ctx, databasePath)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	schedules, err = s.ListSchedules(ctx)
	if err != nil || len(schedules) != 1 {
		t.Fatalf("schedule migration was not idempotent: schedules=%#v err=%v", schedules, err)
	}
}

func timePointer(value time.Time) *time.Time { return &value }
