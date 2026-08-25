package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/witkitlab/witshield/internal/domain"
	"github.com/witkitlab/witshield/internal/ids"
)

const maxReportsPerDevice = 100
const maxReportBytesPerDevice = 20 << 20
const maxCurrentFindingsPerDevice = 2_000
const maxResolvedCurrentFindingsPerDevice = 500
const maxCurrentFindingBytesPerDevice = 8 << 20

const currentFindingCapacityFingerprint = "witshield:current-findings-capacity"

func (s *Store) SaveReport(ctx context.Context, report domain.Report, now time.Time) error {
	_, err := s.SaveReportWithOutcome(ctx, report, now)
	return err
}

// SaveReportWithOutcome persists one immutable report and returns false when
// the exact same device/report payload was already committed. Agents keep the
// oldest offline queue item until they receive a response, so a lost HTTP
// response must be safely replayable instead of poisoning that queue forever.
func (s *Store) SaveReportWithOutcome(ctx context.Context, report domain.Report, now time.Time) (bool, error) {
	return s.saveReport(ctx, report, nil, nil, now)
}

// SaveReportWithNotification atomically persists a report and its durable
// notification. queued is the number of configured delivery channels that
// received an outbox row. Exact report replays do not enqueue duplicates.
func (s *Store) SaveReportWithNotification(ctx context.Context, report domain.Report, event domain.NotificationEvent, now time.Time) (created bool, queued int, err error) {
	created, err = s.saveReport(ctx, report, &event, &queued, now)
	return created, queued, err
}

func (s *Store) saveReport(ctx context.Context, report domain.Report, notification *domain.NotificationEvent, notificationQueued *int, now time.Time) (bool, error) {
	if report.ID == "" {
		report.ID = ids.New("rpt")
	}
	if report.Score < 0 || report.Score > 100 {
		return false, errors.New("score must be between 0 and 100")
	}
	if len(report.Summary) == 0 {
		report.Summary = json.RawMessage(`{}`)
	}
	digest, err := reportIngestDigest(report)
	if err != nil {
		return false, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	var projectedCompleted string
	projectionErr := tx.QueryRowContext(ctx, `SELECT completed_at FROM current_findings_state WHERE device_id=?`, report.DeviceID).Scan(&projectedCompleted)
	if projectionErr != nil && !errors.Is(projectionErr, sql.ErrNoRows) {
		return false, projectionErr
	}
	advancesCurrentState := errors.Is(projectionErr, sql.ErrNoRows)
	if projectionErr == nil {
		latest, parseErr := parseTime(projectedCompleted)
		if parseErr != nil {
			return false, parseErr
		}
		advancesCurrentState = report.CompletedAt.After(latest)
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO reports(id,device_id,started_at,completed_at,score,summary,ingest_digest,created_at) VALUES(?,?,?,?,?,?,?,?)`, report.ID, report.DeviceID, timeText(report.StartedAt), timeText(report.CompletedAt), report.Score, string(report.Summary), digest, timeText(now)); err != nil {
		mapped := mapSQLError(err)
		if errors.Is(mapped, ErrConflict) {
			var existingDevice, existingDigest string
			lookupErr := tx.QueryRowContext(ctx, `SELECT device_id,ingest_digest FROM reports WHERE id=?`, report.ID).Scan(&existingDevice, &existingDigest)
			if lookupErr == nil && existingDevice == report.DeviceID && existingDigest == digest {
				return false, nil
			}
			if lookupErr == nil && existingDevice == report.DeviceID && existingDigest == "" {
				// ingest_digest was added after reports were already durable. Only
				// upgrade a legacy row when every persistable field and finding,
				// including insertion order, proves this is the same canonical
				// Agent payload. Finding observation times were never persisted as
				// submitted, so non-zero caller-supplied values are deliberately not
				// eligible for this compatibility path.
				matches, matchErr := legacyReportMatchesTx(ctx, tx, report)
				if matchErr != nil {
					return false, matchErr
				}
				if matches {
					result, updateErr := tx.ExecContext(ctx, `UPDATE reports SET ingest_digest=? WHERE id=? AND device_id=? AND ingest_digest=''`, digest, report.ID, report.DeviceID)
					if updateErr != nil {
						return false, updateErr
					}
					if changed, _ := result.RowsAffected(); changed != 1 {
						return false, ErrConflict
					}
					if commitErr := tx.Commit(); commitErr != nil {
						return false, commitErr
					}
					return false, nil
				}
			}
			if lookupErr != nil && !errors.Is(lookupErr, sql.ErrNoRows) {
				return false, lookupErr
			}
		}
		return false, mapped
	}
	seen := make([]string, 0, len(report.Findings))
	for i := range report.Findings {
		f := report.Findings[i]
		if f.ID == "" {
			f.ID = ids.New("fnd")
		}
		f.ReportID = report.ID
		f.DeviceID = report.DeviceID
		if f.Status == "" {
			f.Status = domain.FindingOpen
		}
		var first string
		if advancesCurrentState {
			err = tx.QueryRowContext(ctx, `SELECT first_seen_at FROM current_findings WHERE device_id=? AND fingerprint=?`, report.DeviceID, f.Fingerprint).Scan(&first)
		} else {
			err = sql.ErrNoRows
		}
		if errors.Is(err, sql.ErrNoRows) {
			err = tx.QueryRowContext(ctx, `SELECT first_seen_at FROM findings WHERE device_id=? AND fingerprint=? AND last_seen_at<=? ORDER BY last_seen_at DESC,rowid DESC LIMIT 1`, report.DeviceID, f.Fingerprint, timeText(report.CompletedAt)).Scan(&first)
		}
		if errors.Is(err, sql.ErrNoRows) {
			f.FirstSeenAt = report.CompletedAt
		} else if err != nil {
			return false, err
		} else {
			f.FirstSeenAt, err = parseTime(first)
			if err != nil {
				return false, err
			}
		}
		f.LastSeenAt = report.CompletedAt
		_, err = tx.ExecContext(ctx, `INSERT INTO findings(id,report_id,device_id,fingerprint,category,severity,title,description,evidence,remediation,status,first_seen_at,last_seen_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)`, f.ID, f.ReportID, f.DeviceID, f.Fingerprint, f.Category, string(f.Severity), f.Title, f.Description, f.Evidence, f.Remediation, string(f.Status), timeText(f.FirstSeenAt), timeText(f.LastSeenAt))
		if err != nil {
			return false, err
		}
		if advancesCurrentState {
			_, err = tx.ExecContext(ctx, `INSERT INTO current_findings(
				device_id,fingerprint,id,report_id,category,severity,title,description,evidence,remediation,status,first_seen_at,last_seen_at,updated_at
			) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)
			ON CONFLICT(device_id,fingerprint) DO UPDATE SET
				id=excluded.id,report_id=excluded.report_id,category=excluded.category,severity=excluded.severity,
				title=excluded.title,description=excluded.description,evidence=excluded.evidence,
				remediation=excluded.remediation,status=excluded.status,
				first_seen_at=CASE WHEN current_findings.first_seen_at<excluded.first_seen_at THEN current_findings.first_seen_at ELSE excluded.first_seen_at END,
				last_seen_at=excluded.last_seen_at,updated_at=excluded.updated_at`,
				f.DeviceID, f.Fingerprint, f.ID, f.ReportID, f.Category, string(f.Severity), f.Title, f.Description, f.Evidence, f.Remediation, string(f.Status), timeText(f.FirstSeenAt), timeText(f.LastSeenAt), timeText(now))
			if err != nil {
				return false, err
			}
		}
		seen = append(seen, f.Fingerprint)
	}
	// Resolve only the current projection when the responsible check completed.
	// Report findings remain immutable historical snapshots, and unavailable
	// categories retain their previous projected state.
	unavailableCategories, preserveAll := unavailableFindingCategories(report.Summary)
	if advancesCurrentState && !preserveAll {
		query := `UPDATE current_findings SET status=?,updated_at=? WHERE device_id=? AND status=? AND fingerprint<>?`
		args := []any{string(domain.FindingResolved), timeText(now), report.DeviceID, string(domain.FindingOpen), currentFindingCapacityFingerprint}
		if len(seen) > 0 {
			query += ` AND fingerprint NOT IN (` + strings.TrimRight(strings.Repeat("?,", len(seen)), ",") + `)`
			for _, fingerprint := range seen {
				args = append(args, fingerprint)
			}
		}
		if len(unavailableCategories) > 0 {
			query += ` AND category NOT IN (` + strings.TrimRight(strings.Repeat("?,", len(unavailableCategories)), ",") + `)`
			for _, category := range unavailableCategories {
				args = append(args, category)
			}
		}
		if _, err = tx.ExecContext(ctx, query, args...); err != nil {
			return false, err
		}
	}
	if advancesCurrentState {
		projectionIncomplete := preserveAll || len(unavailableCategories) > 0
		if err = enforceCurrentFindingCapacityTx(ctx, tx, report, projectionIncomplete, now); err != nil {
			return false, err
		}
	}
	if advancesCurrentState {
		if _, err = tx.ExecContext(ctx, `INSERT INTO current_findings_state(device_id,report_id,completed_at,updated_at) VALUES(?,?,?,?)
			ON CONFLICT(device_id) DO UPDATE SET report_id=excluded.report_id,completed_at=excluded.completed_at,updated_at=excluded.updated_at`,
			report.DeviceID, report.ID, timeText(report.CompletedAt), timeText(now)); err != nil {
			return false, err
		}
	}
	// A compromised device must not be able to grow the single-node database
	// without bound. Reports are immutable snapshots, so removing an old report
	// also safely removes only its corresponding finding snapshots via the
	// foreign-key cascade. Retain at most the newest 100 reports per device,
	// subject to the independent 20 MiB content budget enforced below.
	if _, err = tx.ExecContext(ctx, `DELETE FROM reports WHERE device_id=? AND id IN (
		SELECT id FROM reports WHERE device_id=? ORDER BY completed_at DESC,rowid DESC LIMIT -1 OFFSET ?
	)`, report.DeviceID, report.DeviceID, maxReportsPerDevice); err != nil {
		return false, err
	}
	if _, err = tx.ExecContext(ctx, `WITH report_sizes AS (
		SELECT r.id,r.completed_at,r.rowid AS report_rowid,
			length(CAST(r.summary AS BLOB))+128+coalesce(sum(
				length(CAST(f.fingerprint AS BLOB))+length(CAST(f.category AS BLOB))+length(CAST(f.title AS BLOB))+
				length(CAST(f.description AS BLOB))+length(CAST(f.evidence AS BLOB))+length(CAST(f.remediation AS BLOB))+256
			),0) AS report_bytes
		FROM reports r LEFT JOIN findings f ON f.report_id=r.id
		WHERE r.device_id=? GROUP BY r.id
	), cumulative AS (
		SELECT id,sum(report_bytes) OVER (ORDER BY completed_at DESC,report_rowid DESC) AS retained_bytes FROM report_sizes
	)
	DELETE FROM reports WHERE device_id=? AND id IN (SELECT id FROM cumulative WHERE retained_bytes>?)`, report.DeviceID, report.DeviceID, maxReportBytesPerDevice); err != nil {
		return false, err
	}
	if notification != nil {
		queued, enqueueErr := enqueueNotificationTx(ctx, tx, *notification, now)
		if enqueueErr != nil {
			return false, enqueueErr
		}
		if notificationQueued != nil {
			*notificationQueued = queued
		}
	}
	if err = tx.Commit(); err != nil {
		return false, err
	}
	return true, nil
}

// legacyReportMatchesTx recognizes only the Controller's canonical Agent
// report shape. Older rows do not retain caller-supplied finding observation
// times, nor whether an fnd_* identity was supplied or generated. Requiring
// zero observation times and either the exact stored ID or the exact shape of
// an IDs-generated value keeps the compatibility surface narrow; every field
// that affects the durable report is still compared byte-for-byte.
func legacyReportMatchesTx(ctx context.Context, tx *sql.Tx, report domain.Report) (bool, error) {
	var deviceID, startedAt, completedAt, summary string
	var score int
	if err := tx.QueryRowContext(ctx, `SELECT device_id,started_at,completed_at,score,summary FROM reports WHERE id=?`, report.ID).Scan(&deviceID, &startedAt, &completedAt, &score, &summary); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false, nil
		}
		return false, err
	}
	if deviceID != report.DeviceID || startedAt != timeText(report.StartedAt) || completedAt != timeText(report.CompletedAt) || score != report.Score || summary != string(report.Summary) {
		return false, nil
	}
	rows, err := tx.QueryContext(ctx, `SELECT id,report_id,device_id,fingerprint,category,severity,title,description,evidence,remediation,status FROM findings WHERE report_id=? ORDER BY rowid`, report.ID)
	if err != nil {
		return false, err
	}
	defer rows.Close()
	index := 0
	for rows.Next() {
		if index >= len(report.Findings) {
			return false, nil
		}
		var id, reportID, findingDeviceID, fingerprint, category, severity, title, description, evidence, remediation, status string
		if err = rows.Scan(&id, &reportID, &findingDeviceID, &fingerprint, &category, &severity, &title, &description, &evidence, &remediation, &status); err != nil {
			return false, err
		}
		finding := report.Findings[index]
		if !finding.FirstSeenAt.IsZero() || !finding.LastSeenAt.IsZero() {
			return false, nil
		}
		if finding.ID == "" {
			if !looksLikeGeneratedFindingID(id) {
				return false, nil
			}
		} else if finding.ID != id {
			return false, nil
		}
		// Scanner queue payloads leave ReportID empty, while the authenticated HTTP
		// handler canonicalizes it to report.ID before the Store sees it. Accept
		// exactly those two equivalent production shapes; SaveReport historically
		// overwrote the durable identifiers before INSERT in either case.
		if (finding.ReportID != "" && finding.ReportID != report.ID) || finding.DeviceID != report.DeviceID || reportID != report.ID || findingDeviceID != report.DeviceID || finding.Fingerprint != fingerprint || finding.Category != category || string(finding.Severity) != severity || finding.Title != title || finding.Description != description || finding.Evidence != evidence || finding.Remediation != remediation || string(finding.Status) != status {
			return false, nil
		}
		index++
	}
	if err = rows.Err(); err != nil {
		return false, err
	}
	return index == len(report.Findings), nil
}

func looksLikeGeneratedFindingID(value string) bool {
	if !strings.HasPrefix(value, "fnd_") {
		return false
	}
	decoded, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(value, "fnd_"))
	return err == nil && len(decoded) == 16
}

func enforceCurrentFindingCapacityTx(ctx context.Context, tx *sql.Tx, report domain.Report, projectionIncomplete bool, now time.Time) error {
	if _, err := tx.ExecContext(ctx, `DELETE FROM current_findings WHERE device_id=? AND status=? AND rowid IN (
		SELECT rowid FROM current_findings WHERE device_id=? AND status=? ORDER BY last_seen_at DESC,rowid DESC LIMIT -1 OFFSET ?
	)`, report.DeviceID, string(domain.FindingResolved), report.DeviceID, string(domain.FindingResolved), maxResolvedCurrentFindingsPerDevice); err != nil {
		return err
	}
	var active int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM current_findings WHERE device_id=? AND status<>? AND fingerprint<>?`, report.DeviceID, string(domain.FindingResolved), currentFindingCapacityFingerprint).Scan(&active); err != nil {
		return err
	}
	maxDetailed := maxCurrentFindingsPerDevice - 1
	trimmed := 0
	if active > maxDetailed {
		if _, err := tx.ExecContext(ctx, `DELETE FROM current_findings WHERE device_id=? AND rowid IN (
			SELECT rowid FROM current_findings WHERE device_id=? AND status<>? AND fingerprint<>?
			ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END,last_seen_at DESC,rowid DESC
			LIMIT -1 OFFSET ?
		)`, report.DeviceID, report.DeviceID, string(domain.FindingResolved), currentFindingCapacityFingerprint, maxDetailed); err != nil {
			return err
		}
		trimmed += active - maxDetailed
	}
	// Row limits alone still permit roughly 80 MiB of attacker-controlled text
	// per device. Keep the independent current-risk projection within a byte
	// budget as well, retaining active risks before resolved history and higher
	// severities before lower-priority records.
	var beforeBytesTrim, afterBytesTrim int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM current_findings WHERE device_id=? AND fingerprint<>?`, report.DeviceID, currentFindingCapacityFingerprint).Scan(&beforeBytesTrim); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `WITH ordered AS (
		SELECT rowid,sum(
			length(CAST(fingerprint AS BLOB))+length(CAST(category AS BLOB))+length(CAST(title AS BLOB))+
			length(CAST(description AS BLOB))+length(CAST(evidence AS BLOB))+length(CAST(remediation AS BLOB))+256
		) OVER (ORDER BY
			CASE WHEN status=? THEN 1 ELSE 0 END,
			CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END,
			last_seen_at DESC,rowid DESC
		) AS retained_bytes
		FROM current_findings WHERE device_id=? AND fingerprint<>?
	)
	DELETE FROM current_findings WHERE device_id=? AND rowid IN (SELECT rowid FROM ordered WHERE retained_bytes>?)`,
		string(domain.FindingResolved), report.DeviceID, currentFindingCapacityFingerprint, report.DeviceID, maxCurrentFindingBytesPerDevice); err != nil {
		return err
	}
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM current_findings WHERE device_id=? AND fingerprint<>?`, report.DeviceID, currentFindingCapacityFingerprint).Scan(&afterBytesTrim); err != nil {
		return err
	}
	trimmed += beforeBytesTrim - afterBytesTrim
	if trimmed > 0 {
		capacityID := ids.New("fnd")
		description := fmt.Sprintf("The current-risk projection reached its safety capacity (%d records / %d MiB); %d lower-priority finding records were omitted. Recent retained reports remain available for detailed review.", maxCurrentFindingsPerDevice, maxCurrentFindingBytesPerDevice>>20, trimmed)
		_, err := tx.ExecContext(ctx, `INSERT INTO current_findings(device_id,fingerprint,id,report_id,category,severity,title,description,evidence,remediation,status,first_seen_at,last_seen_at,updated_at)
			VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)
			ON CONFLICT(device_id,fingerprint) DO UPDATE SET id=excluded.id,report_id=excluded.report_id,category=excluded.category,severity=excluded.severity,title=excluded.title,description=excluded.description,evidence=excluded.evidence,remediation=excluded.remediation,status=excluded.status,last_seen_at=excluded.last_seen_at,updated_at=excluded.updated_at`,
			report.DeviceID, currentFindingCapacityFingerprint, capacityID, report.ID, "system", string(domain.SeverityCritical), "Current finding capacity reached", description, "", "Review recent reports and remove duplicated or unbounded custom findings.", string(domain.FindingOpen), timeText(report.CompletedAt), timeText(report.CompletedAt), timeText(now))
		return err
	}
	if !projectionIncomplete {
		_, err := tx.ExecContext(ctx, `DELETE FROM current_findings WHERE device_id=? AND fingerprint=?`, report.DeviceID, currentFindingCapacityFingerprint)
		return err
	}
	return nil
}

func reportIngestDigest(report domain.Report) (string, error) {
	payload, err := json.Marshal(report)
	if err != nil {
		return "", fmt.Errorf("encode report receipt: %w", err)
	}
	digest := sha256.Sum256(payload)
	return hex.EncodeToString(digest[:]), nil
}

var findingCategoriesByCheck = map[string][]string{
	"ssh_configuration":   {"ssh"},
	"privileged_accounts": {"identity"},
	"shadow_permissions":  {"permissions"},
	"listening_ports":     {"network"},
	"firewall":            {"network"},
	"security_updates":    {"updates"},
	"docker_socket":       {"containers"},
}

// unavailableFindingCategories interprets the stable Scanner summary contract.
// Unknown or malformed check names conservatively preserve every old finding:
// resolving risk without knowing which category was actually checked would be
// a false security assertion.
func unavailableFindingCategories(summary json.RawMessage) ([]string, bool) {
	if len(summary) == 0 {
		return nil, false
	}
	var value struct {
		CheckErrors []string `json:"checkErrors"`
	}
	if err := json.Unmarshal(summary, &value); err != nil {
		return nil, true
	}
	categories := map[string]struct{}{}
	for _, checkError := range value.CheckErrors {
		name, _, ok := strings.Cut(checkError, ":")
		if !ok {
			return nil, true
		}
		mapped, ok := findingCategoriesByCheck[strings.TrimSpace(name)]
		if !ok {
			return nil, true
		}
		for _, category := range mapped {
			categories[category] = struct{}{}
		}
	}
	out := make([]string, 0, len(categories))
	for category := range categories {
		out = append(out, category)
	}
	sort.Strings(out)
	return out, false
}

func scanReport(row interface{ Scan(...any) error }) (domain.Report, error) {
	var r domain.Report
	var started, completed, summary string
	err := row.Scan(&r.ID, &r.DeviceID, &started, &completed, &r.Score, &summary)
	if errors.Is(err, sql.ErrNoRows) {
		return r, ErrNotFound
	}
	if err != nil {
		return r, err
	}
	r.StartedAt, err = parseTime(started)
	if err != nil {
		return r, err
	}
	r.CompletedAt, err = parseTime(completed)
	if err != nil {
		return r, err
	}
	r.Summary = json.RawMessage(summary)
	return r, nil
}
func scanFinding(row interface{ Scan(...any) error }) (domain.Finding, error) {
	var f domain.Finding
	var first, last string
	err := row.Scan(&f.ID, &f.ReportID, &f.DeviceID, &f.Fingerprint, &f.Category, &f.Severity, &f.Title, &f.Description, &f.Evidence, &f.Remediation, &f.Status, &first, &last)
	if errors.Is(err, sql.ErrNoRows) {
		return f, ErrNotFound
	}
	if err != nil {
		return f, err
	}
	f.FirstSeenAt, err = parseTime(first)
	if err != nil {
		return f, err
	}
	f.LastSeenAt, err = parseTime(last)
	return f, err
}

const findingColumns = `id,report_id,device_id,fingerprint,category,severity,title,description,evidence,remediation,status,first_seen_at,last_seen_at`

func (s *Store) Report(ctx context.Context, id string) (domain.Report, error) {
	r, err := scanReport(s.db.QueryRowContext(ctx, `SELECT id,device_id,started_at,completed_at,score,summary FROM reports WHERE id=?`, id))
	if err != nil {
		return r, err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT `+findingColumns+` FROM findings WHERE report_id=? ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END,title`, id)
	if err != nil {
		return r, err
	}
	defer rows.Close()
	for rows.Next() {
		f, e := scanFinding(rows)
		if e != nil {
			return r, e
		}
		r.Findings = append(r.Findings, f)
	}
	return r, rows.Err()
}
func (s *Store) ListReports(ctx context.Context, deviceID string, limit int) ([]domain.Report, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	q := `SELECT id,device_id,started_at,completed_at,score,summary FROM reports`
	args := []any{}
	if deviceID != "" {
		q += ` WHERE device_id=?`
		args = append(args, deviceID)
	}
	q += ` ORDER BY completed_at DESC LIMIT ?`
	args = append(args, limit)
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.Report
	for rows.Next() {
		r, e := scanReport(rows)
		if e != nil {
			return nil, e
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

type FindingFilter struct {
	DeviceID string
	Status   domain.FindingStatus
	Severity domain.Severity
	Limit    int
}

func (s *Store) ListFindings(ctx context.Context, f FindingFilter) ([]domain.Finding, error) {
	if f.Limit <= 0 || f.Limit > maxCurrentFindingsPerDevice {
		f.Limit = 100
	}
	where := []string{"1=1"}
	args := []any{}
	if f.DeviceID != "" {
		where = append(where, "device_id=?")
		args = append(args, f.DeviceID)
	}
	if f.Status != "" {
		where = append(where, "status=?")
		args = append(args, string(f.Status))
	}
	if f.Severity != "" {
		where = append(where, "severity=?")
		args = append(args, string(f.Severity))
	}
	q := `SELECT ` + findingColumns + ` FROM current_findings WHERE ` + strings.Join(where, " AND ") + ` ORDER BY CASE WHEN fingerprint=? THEN 0 ELSE 1 END,CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END,last_seen_at DESC,rowid DESC LIMIT ?`
	args = append(args, currentFindingCapacityFingerprint, f.Limit)
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.Finding
	for rows.Next() {
		x, e := scanFinding(rows)
		if e != nil {
			return nil, e
		}
		out = append(out, x)
	}
	return out, rows.Err()
}

func (s *Store) Finding(ctx context.Context, id string) (domain.Finding, error) {
	finding, err := scanFinding(s.db.QueryRowContext(ctx, `SELECT `+findingColumns+` FROM current_findings WHERE id=?`, id))
	if !errors.Is(err, ErrNotFound) {
		return finding, err
	}
	// Historical report views and already-created actions may retain a snapshot
	// ID after the projection has advanced. Keep that lookup compatible while
	// current lists remain independent of retention.
	return scanFinding(s.db.QueryRowContext(ctx, `SELECT `+findingColumns+` FROM findings WHERE id=?`, id))
}

func (s *Store) EnqueueCommand(ctx context.Context, c domain.DeviceCommand) error {
	if c.ID == "" {
		c.ID = ids.New("cmd")
	}
	if len(c.Payload) == 0 {
		c.Payload = json.RawMessage(`{}`)
	}
	if c.Type != domain.CommandScan {
		_, err := s.db.ExecContext(ctx, `INSERT INTO device_commands(id,device_id,type,payload,created_at) VALUES(?,?,?,?,?)`, c.ID, c.DeviceID, string(c.Type), string(c.Payload), timeText(c.CreatedAt))
		return mapSQLError(err)
	}
	// A device only needs the newest requested snapshot after an offline period.
	// Coalesce in the durable queue, rather than relying on the Agent to receive
	// and discard an unbounded backlog after reconnecting.
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err = supersedePendingScanCommands(ctx, tx, c.DeviceID, "", c.CreatedAt); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO device_commands(id,device_id,type,payload,created_at) VALUES(?,?,?,?,?)`, c.ID, c.DeviceID, string(c.Type), string(c.Payload), timeText(c.CreatedAt)); err != nil {
		return mapSQLError(err)
	}
	return tx.Commit()
}
func scanCommand(row interface{ Scan(...any) error }) (domain.DeviceCommand, error) {
	var c domain.DeviceCommand
	var payload string
	var created string
	var claimed, completed, result sql.NullString
	err := row.Scan(&c.ID, &c.DeviceID, &c.Type, &payload, &created, &claimed, &completed, &result, &c.Error)
	if errors.Is(err, sql.ErrNoRows) {
		return c, ErrNotFound
	}
	if err != nil {
		return c, err
	}
	c.Payload = json.RawMessage(payload)
	c.CreatedAt, err = parseTime(created)
	if err != nil {
		return c, err
	}
	if c.ClaimedAt, err = nullableTime(claimed); err != nil {
		return c, err
	}
	if c.CompletedAt, err = nullableTime(completed); err != nil {
		return c, err
	}
	if result.Valid {
		c.Result = json.RawMessage(result.String)
	}
	return c, nil
}

const commandColumns = `id,device_id,type,payload,created_at,claimed_at,completed_at,result,error`

func (s *Store) ClaimCommands(ctx context.Context, deviceID string, limit int, now time.Time) ([]domain.DeviceCommand, error) {
	if limit <= 0 || limit > 20 {
		limit = 10
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if err = expireStaleActionCommands(ctx, tx, deviceID, now); err != nil {
		return nil, err
	}
	// Databases created by older versions may already contain several pending
	// scan commands. Keep only the newest one. Preserve its claim lease: a live
	// Agent may still be finishing it, while a crashed Agent will naturally make
	// it claimable again after the normal lease timeout.
	latestScanID, err := latestPendingScanCommand(ctx, tx, deviceID)
	if err != nil {
		return nil, err
	}
	if latestScanID != "" {
		if err = supersedePendingScanCommands(ctx, tx, deviceID, latestScanID, now); err != nil {
			return nil, err
		}
	}
	rows, err := tx.QueryContext(ctx, `SELECT `+commandColumns+` FROM device_commands WHERE device_id=? AND completed_at IS NULL AND (claimed_at IS NULL OR claimed_at<?) ORDER BY created_at LIMIT ?`, deviceID, timeText(now.Add(-2*time.Minute)), limit)
	if err != nil {
		return nil, err
	}
	var out []domain.DeviceCommand
	for rows.Next() {
		c, e := scanCommand(rows)
		if e != nil {
			rows.Close()
			return nil, e
		}
		out = append(out, c)
	}
	if err = rows.Close(); err != nil {
		return nil, err
	}
	for i := range out {
		res, e := tx.ExecContext(ctx, `UPDATE device_commands SET claimed_at=? WHERE id=? AND completed_at IS NULL`, timeText(now), out[i].ID)
		if e != nil {
			return nil, e
		}
		if n, _ := res.RowsAffected(); n != 1 {
			return nil, ErrConflict
		}
		t := now.UTC()
		out[i].ClaimedAt = &t
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return out, nil
}

const supersededScanMessage = "superseded by a newer scan request"
const commandExecutionIndeterminateMessage = "privileged execution result was not received before the safety timeout; remote state is unknown and requires manual verification"

func latestPendingScanCommand(ctx context.Context, tx *sql.Tx, deviceID string) (string, error) {
	var id string
	err := tx.QueryRowContext(ctx, `SELECT id FROM device_commands WHERE device_id=? AND type=? AND completed_at IS NULL ORDER BY created_at DESC,rowid DESC LIMIT 1`, deviceID, string(domain.CommandScan)).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return id, err
}

func supersedePendingScanCommands(ctx context.Context, tx *sql.Tx, deviceID, keepID string, now time.Time) error {
	query := `UPDATE device_commands SET completed_at=?,result='{"ok":false,"superseded":true}',error=? WHERE device_id=? AND type=? AND completed_at IS NULL`
	args := []any{timeText(now), supersededScanMessage, deviceID, string(domain.CommandScan)}
	if keepID != "" {
		query += ` AND id<>?`
		args = append(args, keepID)
	}
	_, err := tx.ExecContext(ctx, query, args...)
	return err
}

func expireStaleActionCommands(ctx context.Context, tx *sql.Tx, deviceID string, now time.Time) error {
	query := `SELECT id,device_id,type,payload FROM device_commands WHERE completed_at IS NULL AND started_at IS NULL AND type IN (?,?,?) AND created_at<?`
	args := []any{string(domain.CommandExecuteAction), string(domain.CommandRollback), string(domain.CommandConfirm), timeText(now.Add(-domain.ActionCommandTTL))}
	if deviceID != "" {
		query += ` AND device_id=?`
		args = append(args, deviceID)
	}
	query += ` ORDER BY created_at LIMIT 500`
	rows, err := tx.QueryContext(ctx, query, args...)
	if err != nil {
		return err
	}
	type staleCommand struct{ id, deviceID, typ, payload string }
	var stale []staleCommand
	for rows.Next() {
		var item staleCommand
		if err = rows.Scan(&item.id, &item.deviceID, &item.typ, &item.payload); err != nil {
			rows.Close()
			return err
		}
		stale = append(stale, item)
	}
	if err = rows.Close(); err != nil {
		return err
	}
	for _, item := range stale {
		const message = "action approval expired before device delivery"
		if _, err = tx.ExecContext(ctx, `UPDATE device_commands SET completed_at=?,result='{"ok":false}',error=? WHERE id=? AND completed_at IS NULL`, timeText(now), message, item.id); err != nil {
			return err
		}
		var payload struct {
			ActionID string `json:"actionId"`
		}
		if json.Unmarshal([]byte(item.payload), &payload) != nil || payload.ActionID == "" {
			continue
		}
		res, updateErr := tx.ExecContext(ctx, `UPDATE actions SET status=?,completed_at=?,error=?,updated_at=? WHERE id=? AND device_id=? AND status IN (?,?,?,?,?)`, string(domain.ActionFailed), timeText(now), message, timeText(now), payload.ActionID, item.deviceID, string(domain.ActionApproved), string(domain.ActionExecuting), string(domain.ActionRollingBack), string(domain.ActionAwaitingConfirmation), string(domain.ActionConfirming))
		if updateErr != nil {
			return updateErr
		}
		if changed, _ := res.RowsAffected(); changed == 1 {
			if _, err = tx.ExecContext(ctx, `UPDATE temporary_bans SET status='failed' WHERE action_id=? AND status='pending'`, payload.ActionID); err != nil {
				return err
			}
			details, _ := json.Marshal(map[string]any{"commandId": item.id, "commandType": item.typ, "ttl": domain.ActionCommandTTL.String()})
			if _, err = tx.ExecContext(ctx, `INSERT INTO action_audit(action_id,actor,event,details,created_at) VALUES(?,?,?,?,?)`, payload.ActionID, "controller", "expired_before_delivery", string(details), timeText(now)); err != nil {
				return err
			}
		}
	}
	startedQuery := `SELECT id,device_id,type,payload FROM device_commands WHERE completed_at IS NULL AND started_at IS NOT NULL AND type IN (?,?,?) AND started_at<?`
	startedArgs := []any{string(domain.CommandExecuteAction), string(domain.CommandRollback), string(domain.CommandConfirm), timeText(now.Add(-domain.ActionExecutionTimeout))}
	if deviceID != "" {
		startedQuery += ` AND device_id=?`
		startedArgs = append(startedArgs, deviceID)
	}
	startedQuery += ` ORDER BY started_at LIMIT 500`
	rows, err = tx.QueryContext(ctx, startedQuery, startedArgs...)
	if err != nil {
		return err
	}
	stale = stale[:0]
	for rows.Next() {
		var item staleCommand
		if err = rows.Scan(&item.id, &item.deviceID, &item.typ, &item.payload); err != nil {
			rows.Close()
			return err
		}
		stale = append(stale, item)
	}
	if err = rows.Close(); err != nil {
		return err
	}
	for _, item := range stale {
		if _, err = tx.ExecContext(ctx, `UPDATE device_commands SET completed_at=?,result='{"ok":false,"indeterminate":true}',error=? WHERE id=? AND completed_at IS NULL`, timeText(now), commandExecutionIndeterminateMessage, item.id); err != nil {
			return err
		}
		var payload struct {
			ActionID string `json:"actionId"`
		}
		if json.Unmarshal([]byte(item.payload), &payload) != nil || payload.ActionID == "" {
			continue
		}
		res, updateErr := tx.ExecContext(ctx, `UPDATE actions SET status=?,completed_at=?,error=?,updated_at=? WHERE id=? AND device_id=? AND status IN (?,?,?)`, string(domain.ActionIndeterminate), timeText(now), commandExecutionIndeterminateMessage, timeText(now), payload.ActionID, item.deviceID, string(domain.ActionExecuting), string(domain.ActionRollingBack), string(domain.ActionConfirming))
		if updateErr != nil {
			return updateErr
		}
		if changed, _ := res.RowsAffected(); changed == 1 {
			if _, err = tx.ExecContext(ctx, `UPDATE temporary_bans SET status='indeterminate' WHERE action_id=? AND status='pending'`, payload.ActionID); err != nil {
				return err
			}
			details, _ := json.Marshal(map[string]any{"commandId": item.id, "commandType": item.typ, "timeout": domain.ActionExecutionTimeout.String(), "manualVerificationRequired": true})
			if _, err = tx.ExecContext(ctx, `INSERT INTO action_audit(action_id,actor,event,details,created_at) VALUES(?,?,?,?,?)`, payload.ActionID, "controller", "execution_result_indeterminate", string(details), timeText(now)); err != nil {
				return err
			}
		}
	}
	return nil
}

// ExpireStaleActionCommands projects time-based command expiry even while a
// device is offline. ClaimCommands also performs this check transactionally;
// this controller-wide sweep keeps the administrator view truthful without
// waiting for the device to reconnect.
func (s *Store) ExpireStaleActionCommands(ctx context.Context, now time.Time) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err = expireStaleActionCommands(ctx, tx, "", now); err != nil {
		return err
	}
	return tx.Commit()
}
func (s *Store) CompleteCommand(ctx context.Context, deviceID, id string, result json.RawMessage, errorText string, now time.Time) error {
	if len(result) == 0 {
		result = json.RawMessage(`{}`)
	}
	res, err := s.db.ExecContext(ctx, `UPDATE device_commands SET completed_at=?,result=?,error=? WHERE id=? AND device_id=? AND completed_at IS NULL`, timeText(now), string(result), errorText, id, deviceID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		var storedResult sql.NullString
		var storedError string
		if err := s.db.QueryRowContext(ctx, `SELECT result,error FROM device_commands WHERE id=? AND device_id=? AND completed_at IS NOT NULL`, id, deviceID).Scan(&storedResult, &storedError); errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		} else if err != nil {
			return err
		}
		if storedResult.Valid && storedResult.String == string(result) && storedError == errorText {
			return nil
		}
		return ErrConflict
	}
	return nil
}

func (s *Store) Command(ctx context.Context, deviceID, id string) (domain.DeviceCommand, error) {
	return scanCommand(s.db.QueryRowContext(ctx, `SELECT `+commandColumns+` FROM device_commands WHERE id=? AND device_id=?`, id, deviceID))
}

func (s *Store) CreateSchedule(ctx context.Context, x domain.Schedule) error {
	if x.ID == "" {
		x.ID = ids.New("sch")
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO schedules(id,device_id,kind,interval_seconds,enabled,next_run_at,last_run_at,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?)`, x.ID, x.DeviceID, string(x.Kind), int64(x.Interval/time.Second), x.Enabled, timeText(x.NextRunAt), nil, timeText(x.CreatedAt), timeText(x.UpdatedAt))
	return mapSQLError(err)
}
func scanSchedule(row interface{ Scan(...any) error }) (domain.Schedule, error) {
	var x domain.Schedule
	var secs int64
	var next, created, updated string
	var last sql.NullString
	err := row.Scan(&x.ID, &x.DeviceID, &x.Kind, &secs, &x.Enabled, &next, &last, &created, &updated)
	if errors.Is(err, sql.ErrNoRows) {
		return x, ErrNotFound
	}
	if err != nil {
		return x, err
	}
	x.Interval = time.Duration(secs) * time.Second
	x.Every = x.Interval.String()
	x.NextRunAt, err = parseTime(next)
	if err != nil {
		return x, err
	}
	x.LastRunAt, err = nullableTime(last)
	if err != nil {
		return x, err
	}
	x.CreatedAt, err = parseTime(created)
	if err != nil {
		return x, err
	}
	x.UpdatedAt, err = parseTime(updated)
	return x, err
}

const scheduleColumns = `id,device_id,kind,interval_seconds,enabled,next_run_at,last_run_at,created_at,updated_at`

func (s *Store) ListSchedules(ctx context.Context) ([]domain.Schedule, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+scheduleColumns+` FROM schedules ORDER BY created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.Schedule
	for rows.Next() {
		x, e := scanSchedule(rows)
		if e != nil {
			return nil, e
		}
		out = append(out, x)
	}
	return out, rows.Err()
}
func (s *Store) DueSchedules(ctx context.Context, now time.Time, limit int) ([]domain.Schedule, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := s.db.QueryContext(ctx, `SELECT `+scheduleColumns+` FROM schedules WHERE enabled=1 AND next_run_at<=? ORDER BY next_run_at LIMIT ?`, timeText(now), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.Schedule
	for rows.Next() {
		x, e := scanSchedule(rows)
		if e != nil {
			return nil, e
		}
		out = append(out, x)
	}
	return out, rows.Err()
}
func (s *Store) MarkScheduleRun(ctx context.Context, id string, expectedNext, ranAt, next time.Time) error {
	res, err := s.db.ExecContext(ctx, `UPDATE schedules SET last_run_at=?,next_run_at=?,updated_at=? WHERE id=? AND next_run_at=?`, timeText(ranAt), timeText(next), timeText(ranAt), id, timeText(expectedNext))
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrConflict
	}
	return nil
}
func (s *Store) UpdateSchedule(ctx context.Context, id string, interval time.Duration, enabled bool, next, now time.Time) error {
	res, err := s.db.ExecContext(ctx, `UPDATE schedules SET interval_seconds=?,enabled=?,next_run_at=?,updated_at=? WHERE id=?`, int64(interval/time.Second), enabled, timeText(next), timeText(now), id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}
func (s *Store) DeleteSchedule(ctx context.Context, id string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM schedules WHERE id=?`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) LatestReport(ctx context.Context, deviceID string) (domain.Report, error) {
	r, err := scanReport(s.db.QueryRowContext(ctx, `SELECT id,device_id,started_at,completed_at,score,summary FROM reports WHERE device_id=? ORDER BY completed_at DESC LIMIT 1`, deviceID))
	if err != nil {
		return r, fmt.Errorf("latest report: %w", err)
	}
	return r, nil
}
