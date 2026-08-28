package httpapi

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/witkitlab/witshield/internal/action"
	"github.com/witkitlab/witshield/internal/defense"
	"github.com/witkitlab/witshield/internal/domain"
	"github.com/witkitlab/witshield/internal/identity"
	"github.com/witkitlab/witshield/internal/ids"
	"github.com/witkitlab/witshield/internal/secret"
	"github.com/witkitlab/witshield/internal/store"
)

var packageName = regexp.MustCompile(`^[a-z0-9][a-z0-9+.-]{0,127}(?::[a-z0-9][a-z0-9-]{0,31})?$`)
var agentIdentifier = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$`)
var findingCategory = regexp.MustCompile(`^[a-z][a-z0-9_.-]{0,63}$`)

type agentReportSummary struct {
	Checks          *int      `json:"checks"`
	CompletedChecks *int      `json:"completedChecks"`
	CoveragePercent *int      `json:"coveragePercent"`
	FindingCount    *int      `json:"findingCount"`
	CheckErrors     *[]string `json:"checkErrors"`
	Mode            *string   `json:"mode"`
}

func validAgentReportSummary(raw json.RawMessage, score, findings int) bool {
	var summary agentReportSummary
	if len(raw) == 0 || json.Unmarshal(raw, &summary) != nil || summary.Checks == nil || summary.CompletedChecks == nil || summary.CoveragePercent == nil || summary.FindingCount == nil || summary.CheckErrors == nil || summary.Mode == nil {
		return false
	}
	checks, completed, coverage := *summary.Checks, *summary.CompletedChecks, *summary.CoveragePercent
	if checks < 0 || checks > 10_000 || completed < 0 || completed > checks || coverage < 0 || coverage > 100 || *summary.FindingCount != findings || score > coverage || (*summary.Mode != "native" && *summary.Mode != "observer") {
		return false
	}
	expectedCoverage := 100
	if checks > 0 {
		expectedCoverage = completed * 100 / checks
	}
	if coverage != expectedCoverage || len(*summary.CheckErrors) != checks-completed {
		return false
	}
	for _, checkError := range *summary.CheckErrors {
		if checkError == "" || len(checkError) > 4_000 {
			return false
		}
	}
	return true
}

func strictRaw(raw json.RawMessage, dst any) error {
	if len(raw) == 0 || len(raw) > 64*1024 {
		return errors.New("parameters must be 1-65536 bytes")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return errors.New("parameters do not match the action schema")
	}
	if err := dec.Decode(&struct{}{}); errors.Is(err, io.EOF) {
		return nil
	}
	return errors.New("parameters must contain one valid JSON object")
}
func validateAction(actionType string, raw json.RawMessage) (map[string]any, error) {
	switch action.Type(actionType) {
	case action.TypePackageSecurityUpgrade:
		var p action.PackageSecurityUpgradeParams
		if err := strictRaw(raw, &p); err != nil {
			return nil, err
		}
		if len(p.Packages) == 0 || len(p.Packages) > 64 {
			return nil, errors.New("packages must contain 1-64 explicit names")
		}
		seen := map[string]bool{}
		for _, name := range p.Packages {
			if !packageName.MatchString(name) || seen[name] {
				return nil, fmt.Errorf("invalid or duplicate package %q", name)
			}
			seen[name] = true
		}
		return map[string]any{
			"summary":  "Upgrade only the explicitly authorized installed packages",
			"changes":  p.Packages,
			"impact":   "Target versions are resolved from the device's configured repositories at execution. Package services may restart; the action stops before dpkg if APT would touch any package outside this list.",
			"rollback": "Attempt restoring the exact recorded package versions if they are still available.",
		}, nil
	case action.TypeSSHPasswordHardening:
		var p action.SSHPasswordHardeningParams
		if err := strictRaw(raw, &p); err != nil {
			return nil, err
		}
		if p.RollbackAfterSeconds != 0 && (p.RollbackAfterSeconds < 30 || p.RollbackAfterSeconds > 600) {
			return nil, errors.New("rollbackAfterSeconds must be 30-600")
		}
		return map[string]any{"summary": "Disable SSH password authentication after validating the current configuration", "impact": "Incorrect access preparation can cause SSH lockout.", "safety": "The agent snapshots configuration, validates sshd, reloads, and automatically rolls back unless confirmed.", "rollbackAfterSeconds": p.RollbackAfterSeconds}, nil
	case action.TypeTemporaryIPBan:
		var p action.TemporaryIPBanParams
		if err := strictRaw(raw, &p); err != nil {
			return nil, err
		}
		admin, adminErr := netip.ParseAddr(p.CurrentAdminIP)
		ip, targetErr := action.ValidateTemporaryIPBanTarget(p.Address)
		if targetErr != nil || adminErr != nil || admin.Zone() != "" || ip == admin.Unmap() {
			return nil, errors.New("address must be a public IP different from currentAdminIp")
		}
		if p.TTLSeconds < 30 || p.TTLSeconds > 86400 {
			return nil, errors.New("ttlSeconds must be 30-86400")
		}
		if len(p.Reason) > 256 {
			return nil, errors.New("reason is too long")
		}
		return map[string]any{"summary": "Temporarily block one public source IP", "address": p.Address, "ttlSeconds": p.TTLSeconds, "impact": "Inbound traffic from this address is dropped until TTL expiry.", "rollback": "Remove the nftables set element early."}, nil
	case action.TypeFilePermissionRepair:
		var p action.FilePermissionRepairParams
		if err := strictRaw(raw, &p); err != nil {
			return nil, err
		}
		clean := filepath.Clean(p.Path)
		if !action.IsDefaultPermissionRepairPath(clean) {
			return nil, errors.New("path is outside the controller-approved repair roots")
		}
		if ok, _ := regexp.MatchString(`^(0o)?0?[0-7]{3}$`, p.Mode); !ok {
			return nil, errors.New("mode must be an octal permission mode without special bits")
		}
		mode := strings.TrimPrefix(p.Mode, "0o")
		mode = strings.TrimPrefix(mode, "0")
		if len(mode) != 3 {
			return nil, errors.New("mode must be a three digit octal permission mode")
		}
		if clean == action.DefaultPermissionRepairSSHPath {
			if mode != "600" && mode != "640" && mode != "644" {
				return nil, errors.New("mode is not approved for the SSH configuration")
			}
			if (p.UID != nil && *p.UID != 0) || (p.GID != nil && *p.GID != 0) {
				return nil, errors.New("SSH configuration ownership may only be set to root")
			}
		} else {
			if p.UID != nil || p.GID != nil {
				return nil, errors.New("explicit ownership changes are not approved for WitShield data roots")
			}
			exactRoot := false
			for _, root := range action.DefaultPermissionRepairRoots() {
				if clean == root {
					exactRoot = true
					break
				}
			}
			if exactRoot {
				if mode != "700" && mode != "750" {
					return nil, errors.New("mode is not approved for a WitShield data directory")
				}
			} else if mode != "600" && mode != "640" && mode != "700" && mode != "750" {
				// The Controller cannot inspect whether a remote descendant is a file
				// or directory; admit only the union of Helper-approved modes and let
				// the Helper enforce the exact target type after lstat/open.
				return nil, errors.New("mode is not approved for a WitShield data target")
			}
		}
		return map[string]any{"summary": "Repair permissions on one approved path", "path": clean, "mode": p.Mode, "impact": "Access to this file or directory changes immediately.", "rollback": "Restore recorded mode and ownership."}, nil
	default:
		return nil, errors.New("unsupported action type")
	}
}

func (s *Server) createAction(w http.ResponseWriter, r *http.Request) {
	var in struct {
		DeviceID   string          `json:"deviceId"`
		FindingID  string          `json:"findingId,omitempty"`
		Type       string          `json:"type"`
		Parameters json.RawMessage `json:"parameters"`
	}
	if !decodeJSON(w, r, &in) {
		return
	}
	device, err := s.store.Device(r.Context(), in.DeviceID)
	if err != nil {
		s.fail(w, err)
		return
	}
	if device.ObserverOnly {
		writeError(w, http.StatusConflict, "observer_only_device", "this device is enrolled in read-only observer mode and cannot execute actions")
		return
	}
	if in.FindingID != "" {
		finding, err := s.store.Finding(r.Context(), in.FindingID)
		if err != nil {
			s.fail(w, err)
			return
		}
		if finding.DeviceID != in.DeviceID {
			writeError(w, 400, "finding_device_mismatch", "finding does not belong to the selected device")
			return
		}
	}
	preview, err := validateAction(in.Type, in.Parameters)
	if err != nil {
		writeError(w, 400, "invalid_action", err.Error())
		return
	}
	previewJSON, _ := json.Marshal(preview)
	nonce, err := ids.Token("approve", 24)
	if err != nil {
		s.fail(w, err)
		return
	}
	now := s.now().UTC()
	x := domain.Action{ID: ids.New("act"), DeviceID: in.DeviceID, FindingID: in.FindingID, Type: in.Type, Parameters: in.Parameters, Preview: previewJSON, Status: domain.ActionDraft, CreatedAt: now, UpdatedAt: now}
	if err = s.store.CreateAction(r.Context(), x, secret.Hash(nonce), adminFrom(r.Context()).ID); err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, 201, map[string]any{"action": x, "approvalNonce": nonce, "approvalExpiresAt": now.Add(10 * time.Minute), "notice": "Review the preview and submit this one-time nonce within 10 minutes to approve execution."})
}
func (s *Server) listActions(w http.ResponseWriter, r *http.Request) {
	if err := s.store.ExpireActionConfirmations(r.Context(), s.now().UTC()); err != nil {
		s.fail(w, err)
		return
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	items, err := s.store.ListActions(r.Context(), r.URL.Query().Get("deviceId"), limit)
	if err != nil {
		s.fail(w, err)
		return
	}
	if items == nil {
		items = []domain.Action{}
	}
	writeJSON(w, 200, map[string]any{"items": items})
}
func (s *Server) getAction(w http.ResponseWriter, r *http.Request) {
	if err := s.store.ExpireActionConfirmations(r.Context(), s.now().UTC()); err != nil {
		s.fail(w, err)
		return
	}
	x, _, err := s.store.Action(r.Context(), r.PathValue("id"))
	if err != nil {
		s.fail(w, err)
		return
	}
	audit, _ := s.store.ActionAudit(r.Context(), x.ID, 100)
	writeJSON(w, 200, map[string]any{"action": x, "audit": audit})
}
func (s *Server) approveAction(w http.ResponseWriter, r *http.Request) {
	var in struct {
		ApprovalNonce string `json:"approvalNonce"`
	}
	if !decodeJSON(w, r, &in) {
		return
	}
	existing, _, err := s.store.Action(r.Context(), r.PathValue("id"))
	if err != nil {
		s.fail(w, err)
		return
	}
	payload, _ := json.Marshal(map[string]any{"actionId": existing.ID, "type": existing.Type, "parameters": existing.Parameters})
	now := s.now().UTC()
	cmd := domain.DeviceCommand{ID: ids.New("cmd"), DeviceID: existing.DeviceID, Type: domain.CommandExecuteAction, Payload: payload, CreatedAt: now}
	x, err := s.store.ApproveActionAndEnqueue(r.Context(), existing.ID, secret.Hash(in.ApprovalNonce), adminFrom(r.Context()).ID, cmd, now)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, 202, map[string]any{"action": x, "commandId": cmd.ID})
}
func (s *Server) rollbackAction(w http.ResponseWriter, r *http.Request) {
	existing, _, err := s.store.Action(r.Context(), r.PathValue("id"))
	if err != nil {
		s.fail(w, err)
		return
	}
	if len(existing.RollbackPayload) == 0 {
		writeError(w, 409, "rollback_unavailable", "this action has no rollback state")
		return
	}
	payload, _ := json.Marshal(map[string]any{"actionId": existing.ID, "type": existing.Type, "parameters": existing.Parameters, "rollbackPayload": existing.RollbackPayload})
	now := s.now().UTC()
	cmd := domain.DeviceCommand{ID: ids.New("cmd"), DeviceID: existing.DeviceID, Type: domain.CommandRollback, Payload: payload, CreatedAt: now}
	if err = s.store.RequestRollbackAndEnqueue(r.Context(), existing.ID, adminFrom(r.Context()).ID, cmd, now); err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, 202, map[string]any{"actionId": existing.ID, "commandId": cmd.ID, "status": domain.ActionRollingBack})
}
func (s *Server) confirmAction(w http.ResponseWriter, r *http.Request) {
	if !decodeJSON(w, r, &struct{}{}) {
		return
	}
	if err := s.store.ExpireActionConfirmations(r.Context(), s.now().UTC()); err != nil {
		s.fail(w, err)
		return
	}
	existing, _, err := s.store.Action(r.Context(), r.PathValue("id"))
	if err != nil {
		s.fail(w, err)
		return
	}
	if existing.Status != domain.ActionAwaitingConfirmation || existing.Type != string(action.TypeSSHPasswordHardening) || len(existing.RollbackPayload) == 0 || existing.ConfirmBy == nil {
		writeError(w, 409, "confirmation_unavailable", "this action is not awaiting SSH safety confirmation")
		return
	}
	payload, _ := json.Marshal(map[string]any{"actionId": existing.ID, "type": existing.Type, "parameters": existing.Parameters, "rollbackPayload": existing.RollbackPayload})
	now := s.now().UTC()
	cmd := domain.DeviceCommand{ID: ids.New("cmd"), DeviceID: existing.DeviceID, Type: domain.CommandConfirm, Payload: payload, CreatedAt: now}
	if err = s.store.RequestConfirmationAndEnqueue(r.Context(), existing.ID, adminFrom(r.Context()).ID, cmd, now); err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, 202, map[string]any{"actionId": existing.ID, "commandId": cmd.ID, "status": domain.ActionConfirming})
}
func (s *Server) audit(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	items, err := s.store.ActionAudit(r.Context(), r.URL.Query().Get("actionId"), limit)
	if err != nil {
		s.fail(w, err)
		return
	}
	if items == nil {
		items = []domain.ActionAudit{}
	}
	writeJSON(w, 200, map[string]any{"items": items})
}

func (s *Server) agentSync(w http.ResponseWriter, r *http.Request) {
	device := deviceFrom(r.Context())
	release, blocked := s.syncs.begin(device.ID)
	if release == nil {
		w.Header().Set("Retry-After", "2")
		if blocked == "device" {
			writeError(w, http.StatusConflict, "sync_already_active", "only one active command sync is allowed per device")
		} else {
			writeError(w, http.StatusTooManyRequests, "sync_capacity_reached", "command sync capacity reached")
		}
		return
	}
	defer release()
	wait := 25 * time.Second
	if raw := r.URL.Query().Get("wait"); raw != "" {
		if d, err := time.ParseDuration(raw); err == nil && d >= 0 && d <= 30*time.Second {
			wait = d
		} else {
			writeError(w, 400, "invalid_wait", "wait must be 0s-30s")
			return
		}
	}
	deadline := s.now().Add(wait)
	for {
		items, err := s.store.ClaimCommands(r.Context(), device.ID, 10, s.now())
		if err != nil {
			s.fail(w, err)
			return
		}
		if len(items) > 0 {
			writeJSON(w, 200, map[string]any{"commands": items, "serverTime": s.now().UTC()})
			return
		}
		if !s.now().Before(deadline) {
			writeJSON(w, 200, map[string]any{"commands": []domain.DeviceCommand{}, "serverTime": s.now().UTC()})
			return
		}
		select {
		case <-r.Context().Done():
			return
		// SQLite has one writer. A 400 ms poll across the former 128 long
		// polls generated hundreds of empty transactions per second. Two
		// seconds with a 16-request gate remains responsive while bounding
		// idle Controller work until command-notification wakes are added.
		case <-time.After(2 * time.Second):
		}
	}
}
func (s *Server) agentCommandStart(w http.ResponseWriter, r *http.Request) {
	device := deviceFrom(r.Context())
	authorized, err := s.store.StartActionCommand(r.Context(), device.ID, r.PathValue("id"), s.now().UTC())
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"authorized": authorized})
}
func (s *Server) agentCommandResult(w http.ResponseWriter, r *http.Request) {
	device := deviceFrom(r.Context())
	var in struct {
		OK                bool            `json:"ok"`
		Result            json.RawMessage `json:"result,omitempty"`
		RollbackPayload   json.RawMessage `json:"rollbackPayload,omitempty"`
		AuditReceipt      json.RawMessage `json:"auditReceipt,omitempty"`
		Error             string          `json:"error,omitempty"`
		IdentitySignature string          `json:"identitySignature,omitempty"`
	}
	if !decodeJSON(w, r, &in) {
		return
	}
	if len(in.Error) > 4096 || len(in.Result) > 64<<10 || len(in.RollbackPayload) > 640<<10 || len(in.AuditReceipt) > 256<<10 || len(in.IdentitySignature) > 256 {
		writeError(w, 400, "result_too_large", "command result exceeds limits")
		return
	}
	cmd, err := s.store.Command(r.Context(), device.ID, r.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) {
		// Authenticated request proof already binds this device, path and exact
		// body. A command identity older than the bounded tombstone window is a
		// terminal queue outcome, not a retryable 404 that should poison FIFO.
		writeError(w, http.StatusGone, "command_result_expired", "command result retention window has elapsed")
		return
	}
	if err != nil {
		s.fail(w, err)
		return
	}
	if cmd.Type == domain.CommandExecuteAction || cmd.Type == domain.CommandRollback || cmd.Type == domain.CommandConfirm {
		proof := identity.CommandResultProof{DeviceID: device.ID, CommandID: cmd.ID, OK: in.OK, Result: in.Result, RollbackPayload: in.RollbackPayload, AuditReceipt: in.AuditReceipt, Error: in.Error}
		if err = identity.VerifyCommandResult(device.IdentityKey, in.IdentitySignature, proof); err != nil {
			writeError(w, http.StatusUnauthorized, "invalid_device_proof", "a valid device identity proof is required for action results")
			return
		}
	}
	release, admitted := s.beginAgentWrite(w)
	if !admitted {
		return
	}
	defer release()
	if !s.admitAgentWork(w, r, 25, 0, 0) {
		return
	}
	outcome, err := s.store.CompleteCommandAndActionWithOutcome(r.Context(), device.ID, cmd.ID, in.OK, in.Result, in.RollbackPayload, in.AuditReceipt, in.Error, s.now())
	if err != nil {
		s.fail(w, err)
		return
	}
	if outcome.NewlyCompleted {
		s.notificationCommitted(outcome.Notification, outcome.NotificationQueued)
	}
	w.WriteHeader(204)
}
func (s *Server) agentReport(w http.ResponseWriter, r *http.Request) {
	device := deviceFrom(r.Context())
	var report domain.Report
	if !decodeJSON(w, r, &report) {
		return
	}
	report.DeviceID = device.ID
	now := s.now()
	if !validAgentIdentifier(report.ID) || report.StartedAt.IsZero() || report.CompletedAt.Before(report.StartedAt) || report.CompletedAt.After(now.Add(5*time.Minute)) || report.CompletedAt.Sub(report.StartedAt) > 6*time.Hour || report.Score < 0 || report.Score > 100 || len(report.Findings) > 1000 || len(report.Summary) > 64*1024 || !validAgentReportSummary(report.Summary, report.Score, len(report.Findings)) {
		writeError(w, 400, "invalid_report", "report timestamps, score or size are invalid")
		return
	}
	for i := range report.Findings {
		f := &report.Findings[i]
		if (f.ID != "" && !validAgentIdentifier(f.ID)) || !findingCategory.MatchString(f.Category) || len(f.Fingerprint) < 16 || len(f.Fingerprint) > 128 || len(f.Title) > 500 || len(f.Description) > 8000 || len(f.Evidence) > 16000 || len(f.Remediation) > 8000 || !validSeverity(f.Severity) {
			writeError(w, 400, "invalid_finding", "finding is invalid or too large")
			return
		}
		f.DeviceID = device.ID
		f.ReportID = report.ID
		f.Status = domain.FindingOpen
	}
	severity := domain.SeverityInfo
	critical := 0
	for _, f := range report.Findings {
		if f.Severity == domain.SeverityCritical {
			critical++
			severity = domain.SeverityCritical
		} else if severity == domain.SeverityInfo && f.Severity == domain.SeverityHigh {
			severity = domain.SeverityHigh
		}
	}
	data, _ := json.Marshal(map[string]any{"reportId": report.ID, "score": report.Score, "findingCount": len(report.Findings), "criticalCount": critical})
	notification := domain.NotificationEvent{ID: "report:" + report.ID, Type: "report_completed", Severity: severity, DeviceID: device.ID, Title: "Security scan completed", Message: fmt.Sprintf("Score %d/100 with %d findings (%d critical).", report.Score, len(report.Findings), critical), OccurredAt: report.CompletedAt, Data: data}
	release, admitted := s.beginAgentWrite(w)
	if !admitted {
		return
	}
	defer release()
	if !s.admitAgentWork(w, r, 100, 1, len(report.Findings)) {
		return
	}
	created, queued, err := s.store.SaveReportWithNotification(r.Context(), report, notification, now)
	if err != nil {
		s.fail(w, err)
		return
	}
	if created {
		s.notificationCommitted(&notification, queued)
	}
	writeJSON(w, 201, map[string]any{"reportId": report.ID, "replayed": !created})
}
func validSeverity(v domain.Severity) bool {
	switch v {
	case domain.SeverityInfo, domain.SeverityLow, domain.SeverityMedium, domain.SeverityHigh, domain.SeverityCritical:
		return true
	}
	return false
}

func (s *Server) agentEvents(w http.ResponseWriter, r *http.Request) {
	device := deviceFrom(r.Context())
	var in struct {
		Events            []domain.SecurityEvent `json:"events"`
		IdentitySignature string                 `json:"identitySignature"`
	}
	if !decodeJSON(w, r, &in) {
		return
	}
	if len(in.Events) == 0 || len(in.Events) > 500 || len(in.IdentitySignature) > 256 {
		writeError(w, 400, "invalid_events", "events must contain 1-500 items")
		return
	}
	if err := identity.VerifySecurityEventBatch(device.IdentityKey, in.IdentitySignature, identity.SecurityEventBatchProof{DeviceID: device.ID, Events: in.Events}); err != nil {
		writeError(w, http.StatusUnauthorized, "invalid_device_proof", "a valid device identity proof is required for security events")
		return
	}
	now := s.now().UTC()
	discarded := make([]bool, len(in.Events))
	droppedExpired, droppedFuture := 0, 0
	// Validate the entire signed batch before committing any prefix. A malformed
	// final item must not make the Agent retry an HTTP 400 after earlier items
	// were already accepted. Authenticated events older than retention are a
	// successful no-op so a week-long outage cannot poison the durable FIFO.
	for i := range in.Events {
		e := &in.Events[i]
		e.DeviceID = device.ID
		if !validAgentIdentifier(e.ID) || e.OccurredAt.IsZero() || len(e.Payload) > 4*1024 || len(e.SourceIP) > 64 || !validSecurityEventType(e.Type) {
			writeError(w, 400, "invalid_event", "security event is invalid")
			return
		}
		if e.OccurredAt.Before(now.Add(-7 * 24 * time.Hour)) {
			discarded[i] = true
			droppedExpired++
		} else if e.OccurredAt.After(now.Add(5 * time.Minute)) {
			// A badly skewed Agent clock must not poison the durable FIFO. The
			// signed event is acknowledged but cannot influence defense state.
			discarded[i] = true
			droppedFuture++
		}
	}
	accepted := len(in.Events) - droppedExpired - droppedFuture
	if accepted == 0 {
		// Authenticated terminal no-ops deliberately bypass the mutation budget:
		// they clear an offline Agent's durable FIFO without touching SQLite.
		writeJSON(w, 202, map[string]any{"accepted": 0, "droppedExpired": droppedExpired, "droppedFuture": droppedFuture, "decisions": []defense.Evaluation{}})
		return
	}
	decisions := []defense.Evaluation{}
	release, admitted := s.beginAgentWrite(w)
	if !admitted {
		return
	}
	defer release()
	if !s.admitAgentWork(w, r, 50, 2, accepted) {
		return
	}
	for i := range in.Events {
		e := &in.Events[i]
		if discarded[i] {
			continue
		}
		outcome, err := s.store.ProcessSecurityEvent(r.Context(), *e, device.ObserverOnly, now)
		if err != nil {
			s.fail(w, err)
			return
		}
		if !outcome.Inserted || !outcome.Decision.Matched {
			continue
		}
		decisions = append(decisions, outcome.Decision)
		if outcome.Recorded {
			s.notificationCommitted(outcome.Notification, outcome.NotificationQueued)
		}
	}
	writeJSON(w, 202, map[string]any{"accepted": accepted, "droppedExpired": droppedExpired, "droppedFuture": droppedFuture, "decisions": decisions})
}

func validSecurityEventType(eventType string) bool {
	switch eventType {
	case "ssh_auth_failure", "ssh_auth_success", "ssh_auth_failure_untrusted", "ssh_auth_log_line_oversized_untrusted",
		"identity_state_changed", "access_trust_changed", "file_integrity_changed", "schedule_definition_changed",
		"service_definition_changed", "startup_definition_changed", "library_injection_changed", "kernel_policy_changed",
		"container_configuration_changed", "network_listener_opened", "network_listener_closed",
		"network_sensor_capacity_degraded", "network_sensor_capacity_restored",
		"suspicious_privileged_process_started", "deleted_executable_process_running",
		"process_sensor_capacity_degraded", "process_sensor_capacity_restored":
		return true
	default:
		return false
	}
}

func validAgentIdentifier(value string) bool { return agentIdentifier.MatchString(value) }
