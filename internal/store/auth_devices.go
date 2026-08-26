package store

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/witkitlab/witshield/internal/domain"
	"github.com/witkitlab/witshield/internal/ids"
)

func (s *Store) AdminCount(ctx context.Context) (int, error) {
	var count int
	err := s.db.QueryRowContext(ctx, `SELECT count(*) FROM admins`).Scan(&count)
	return count, err
}

func (s *Store) DeviceCount(ctx context.Context) (int, error) {
	var count int
	err := s.db.QueryRowContext(ctx, `SELECT count(*) FROM devices`).Scan(&count)
	return count, err
}

func (s *Store) CreateAdmin(ctx context.Context, username, passwordHash string, now time.Time) (domain.Admin, error) {
	admin := domain.Admin{ID: ids.New("adm"), Username: username, CreatedAt: now.UTC()}
	res, err := s.db.ExecContext(ctx, `INSERT INTO admins(id,username,password_hash,created_at,updated_at) SELECT ?,?,?,?,? WHERE NOT EXISTS (SELECT 1 FROM admins)`, admin.ID, admin.Username, passwordHash, timeText(now), timeText(now))
	if err != nil {
		return admin, mapSQLError(err)
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return admin, ErrConflict
	}
	return admin, nil
}

func (s *Store) AdminCredentials(ctx context.Context, username string) (domain.Admin, string, error) {
	var a domain.Admin
	var created, hash string
	err := s.db.QueryRowContext(ctx, `SELECT id,username,password_hash,created_at FROM admins WHERE username=? COLLATE NOCASE`, username).Scan(&a.ID, &a.Username, &hash, &created)
	if errors.Is(err, sql.ErrNoRows) {
		return a, "", ErrNotFound
	}
	if err != nil {
		return a, "", err
	}
	a.CreatedAt, err = parseTime(created)
	return a, hash, err
}

func (s *Store) CreateSession(ctx context.Context, adminID, tokenHash string, expiresAt, now time.Time) (domain.Session, error) {
	sess := domain.Session{ID: ids.New("ses"), AdminID: adminID, ExpiresAt: expiresAt.UTC(), CreatedAt: now.UTC()}
	_, err := s.db.ExecContext(ctx, `INSERT INTO sessions(id,token_hash,admin_id,expires_at,created_at) VALUES(?,?,?,?,?)`, sess.ID, tokenHash, adminID, timeText(expiresAt), timeText(now))
	return sess, mapSQLError(err)
}

func (s *Store) AdminBySession(ctx context.Context, tokenHash string, now time.Time) (domain.Admin, error) {
	var a domain.Admin
	var created string
	err := s.db.QueryRowContext(ctx, `SELECT a.id,a.username,a.created_at FROM sessions s JOIN admins a ON a.id=s.admin_id WHERE s.token_hash=? AND s.expires_at>?`, tokenHash, timeText(now)).Scan(&a.ID, &a.Username, &created)
	if errors.Is(err, sql.ErrNoRows) {
		return a, ErrUnauthorized
	}
	if err != nil {
		return a, err
	}
	a.CreatedAt, err = parseTime(created)
	return a, err
}

func (s *Store) DeleteSession(ctx context.Context, tokenHash string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE token_hash=?`, tokenHash)
	return err
}

func (s *Store) DeleteExpiredSessions(ctx context.Context, now time.Time) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE expires_at<=?`, timeText(now))
	return err
}

func (s *Store) CreateEnrollmentToken(ctx context.Context, item domain.EnrollmentToken, tokenHash string) error {
	var expires any
	if item.ExpiresAt != nil {
		expires = timeText(*item.ExpiresAt)
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO enrollment_tokens(id,name,token_hash,hint,max_uses,uses,expires_at,created_at) VALUES(?,?,?,?,?,?,?,?)`, item.ID, item.Name, tokenHash, item.Hint, item.MaxUses, item.Uses, expires, timeText(item.CreatedAt))
	return mapSQLError(err)
}

func (s *Store) ListEnrollmentTokens(ctx context.Context) ([]domain.EnrollmentToken, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id,name,hint,max_uses,uses,expires_at,revoked_at,created_at FROM enrollment_tokens ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.EnrollmentToken
	for rows.Next() {
		var x domain.EnrollmentToken
		var expires, revoked sql.NullString
		var created string
		if err := rows.Scan(&x.ID, &x.Name, &x.Hint, &x.MaxUses, &x.Uses, &expires, &revoked, &created); err != nil {
			return nil, err
		}
		x.ExpiresAt, err = nullableTime(expires)
		if err != nil {
			return nil, err
		}
		x.RevokedAt, err = nullableTime(revoked)
		if err != nil {
			return nil, err
		}
		x.CreatedAt, err = parseTime(created)
		if err != nil {
			return nil, err
		}
		out = append(out, x)
	}
	return out, rows.Err()
}

func (s *Store) RevokeEnrollmentToken(ctx context.Context, id string, now time.Time) error {
	res, err := s.db.ExecContext(ctx, `UPDATE enrollment_tokens SET revoked_at=? WHERE id=? AND revoked_at IS NULL`, timeText(now), id)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

const DefaultScanInterval = 24 * time.Hour

type EnrollInput struct {
	Name, Hostname, OS, Arch, AgentVersion, IdentityKey string
	ScanInterval                                        time.Duration
	ObserverOnly                                        bool
}

type EnrollmentChallengeInput struct {
	ID, EnrollmentHash, IdentityKey, ChallengeHash string
	ExpiresAt, Now                                 time.Time
}

// CreateEnrollmentChallenge authorizes a short-lived, one-time proof
// challenge. A consumed token is accepted only for the exact identity that it
// enrolled previously; merely knowing its public key is not enough to finish
// enrollment because FinalizeEnrollment also verifies the Ed25519 proof.
func (s *Store) CreateEnrollmentChallenge(ctx context.Context, in EnrollmentChallengeInput) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var tokenID string
	var maxUses, uses int
	var expires, revoked sql.NullString
	if err = tx.QueryRowContext(ctx, `SELECT id,max_uses,uses,expires_at,revoked_at FROM enrollment_tokens WHERE token_hash=?`, in.EnrollmentHash).Scan(&tokenID, &maxUses, &uses, &expires, &revoked); errors.Is(err, sql.ErrNoRows) {
		return ErrUnauthorized
	} else if err != nil {
		return err
	}
	if revoked.Valid {
		return ErrUnauthorized
	}
	var linkedTokenID string
	linkErr := tx.QueryRowContext(ctx, `SELECT enrollment_token_id FROM enrollment_identities WHERE identity_key=?`, in.IdentityKey).Scan(&linkedTokenID)
	switch {
	case linkErr == nil:
		if subtle.ConstantTimeCompare([]byte(linkedTokenID), []byte(tokenID)) != 1 {
			return ErrUnauthorized
		}
	case errors.Is(linkErr, sql.ErrNoRows):
		if uses >= maxUses {
			return ErrTokenExhausted
		}
		if expires.Valid {
			expiresAt, parseErr := parseTime(expires.String)
			if parseErr != nil {
				return parseErr
			}
			if !in.Now.Before(expiresAt) {
				return ErrTokenExpired
			}
		}
	default:
		return linkErr
	}
	if !in.ExpiresAt.After(in.Now) || in.ExpiresAt.Sub(in.Now) > 10*time.Minute {
		return errors.New("enrollment challenge expiry is invalid")
	}
	if _, err = tx.ExecContext(ctx, `DELETE FROM enrollment_challenges WHERE expires_at<=? OR (used_at IS NOT NULL AND used_at<?)`, timeText(in.Now), timeText(in.Now.Add(-time.Hour))); err != nil {
		return err
	}
	// A small per-identity window preserves transactionally idempotent parallel
	// enrollment retries (native installers can race after a network timeout),
	// while token-wide and global caps stop a valid short-lived token from using
	// random public keys to create an unbounded challenge set.
	var outstanding int
	if err = tx.QueryRowContext(ctx, `SELECT count(*) FROM enrollment_challenges WHERE enrollment_token_id=? AND identity_key=? AND used_at IS NULL AND expires_at>?`, tokenID, in.IdentityKey, timeText(in.Now)).Scan(&outstanding); err != nil {
		return err
	}
	if outstanding >= 16 {
		return ErrConflict
	}
	if err = tx.QueryRowContext(ctx, `SELECT count(*) FROM enrollment_challenges WHERE enrollment_token_id=? AND used_at IS NULL AND expires_at>?`, tokenID, timeText(in.Now)).Scan(&outstanding); err != nil {
		return err
	}
	if outstanding >= 64 {
		return ErrConflict
	}
	if err = tx.QueryRowContext(ctx, `SELECT count(*) FROM enrollment_challenges WHERE used_at IS NULL AND expires_at>?`, timeText(in.Now)).Scan(&outstanding); err != nil {
		return err
	}
	if outstanding >= 4096 {
		return ErrConflict
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO enrollment_challenges(id,enrollment_token_id,identity_key,challenge_hash,expires_at,created_at) VALUES(?,?,?,?,?,?)`, in.ID, tokenID, in.IdentityKey, in.ChallengeHash, timeText(in.ExpiresAt), timeText(in.Now))
	if err != nil {
		return mapSQLError(err)
	}
	return tx.Commit()
}

type FinalizeEnrollmentInput struct {
	ChallengeID, ChallengeHash, EnrollmentHash string
	AgentTokenHash, EncryptedAgentToken        string
	Device                                     EnrollInput
	Now                                        time.Time
}

type FinalizeEnrollmentResult struct {
	Device              domain.Device
	EncryptedAgentToken string
	Created             bool
}

// FinalizeEnrollment consumes a verified one-time challenge and either creates
// the device or retrieves the existing encrypted device credential. The whole
// decision is one SQLite transaction, so concurrent retries cannot create a
// second device or return mutually invalidated credentials.
func (s *Store) FinalizeEnrollment(ctx context.Context, in FinalizeEnrollmentInput) (FinalizeEnrollmentResult, error) {
	var out FinalizeEnrollmentResult
	if in.Device.ScanInterval == 0 {
		in.Device.ScanInterval = DefaultScanInterval
	}
	if in.Device.ScanInterval < 15*time.Minute || in.Device.ScanInterval > 365*24*time.Hour {
		return out, errors.New("initial scan interval must be between 15 minutes and 365 days")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return out, err
	}
	defer tx.Rollback()
	var tokenID, identityKey, challengeHash, challengeExpires string
	var usedAt sql.NullString
	err = tx.QueryRowContext(ctx, `SELECT enrollment_token_id,identity_key,challenge_hash,expires_at,used_at FROM enrollment_challenges WHERE id=?`, in.ChallengeID).Scan(&tokenID, &identityKey, &challengeHash, &challengeExpires, &usedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return out, ErrUnauthorized
	}
	if err != nil {
		return out, err
	}
	challengeExpiry, err := parseTime(challengeExpires)
	if err != nil {
		return out, err
	}
	if usedAt.Valid || !in.Now.Before(challengeExpiry) || subtle.ConstantTimeCompare([]byte(identityKey), []byte(in.Device.IdentityKey)) != 1 || subtle.ConstantTimeCompare([]byte(challengeHash), []byte(in.ChallengeHash)) != 1 {
		return out, ErrUnauthorized
	}
	var actualTokenID string
	var maxUses, uses int
	var tokenExpires, revoked sql.NullString
	err = tx.QueryRowContext(ctx, `SELECT id,max_uses,uses,expires_at,revoked_at FROM enrollment_tokens WHERE token_hash=?`, in.EnrollmentHash).Scan(&actualTokenID, &maxUses, &uses, &tokenExpires, &revoked)
	if errors.Is(err, sql.ErrNoRows) {
		return out, ErrUnauthorized
	}
	if err != nil {
		return out, err
	}
	if revoked.Valid || subtle.ConstantTimeCompare([]byte(actualTokenID), []byte(tokenID)) != 1 {
		return out, ErrUnauthorized
	}
	res, err := tx.ExecContext(ctx, `UPDATE enrollment_challenges SET used_at=? WHERE id=? AND used_at IS NULL`, timeText(in.Now), in.ChallengeID)
	if err != nil {
		return out, err
	}
	if count, _ := res.RowsAffected(); count != 1 {
		return out, ErrUnauthorized
	}

	var linkedTokenID, deviceStatus string
	err = tx.QueryRowContext(ctx, `SELECT i.device_id,i.enrollment_token_id,i.encrypted_agent_token,d.status FROM enrollment_identities i JOIN devices d ON d.id=i.device_id WHERE i.identity_key=?`, in.Device.IdentityKey).Scan(&out.Device.ID, &linkedTokenID, &out.EncryptedAgentToken, &deviceStatus)
	if err == nil {
		if domain.DeviceStatus(deviceStatus) == domain.DeviceRevoked || subtle.ConstantTimeCompare([]byte(linkedTokenID), []byte(tokenID)) != 1 {
			return FinalizeEnrollmentResult{}, ErrUnauthorized
		}
		// Re-scan through the standard parser so timestamps and LastSeenAt are
		// populated correctly without exposing the encrypted credential.
		device, scanErr := scanDevice(tx.QueryRowContext(ctx, `SELECT `+deviceColumns+` FROM devices WHERE id=?`, out.Device.ID))
		if scanErr != nil {
			return FinalizeEnrollmentResult{}, scanErr
		}
		if device.ObserverOnly != in.Device.ObserverOnly {
			var unfinishedActions int
			if err = tx.QueryRowContext(ctx, `SELECT count(*) FROM device_commands WHERE device_id=? AND completed_at IS NULL AND type IN (?,?,?)`, device.ID, string(domain.CommandExecuteAction), string(domain.CommandRollback), string(domain.CommandConfirm)).Scan(&unfinishedActions); err != nil {
				return FinalizeEnrollmentResult{}, err
			}
			if unfinishedActions > 0 {
				return FinalizeEnrollmentResult{}, ErrConflict
			}
			if in.Device.ObserverOnly {
				if _, err = tx.ExecContext(ctx, `UPDATE defense_policies SET auto_ban=0,updated_at=? WHERE device_id=?`, timeText(in.Now), device.ID); err != nil {
					return FinalizeEnrollmentResult{}, err
				}
			}
		}
		_, err = tx.ExecContext(ctx, `UPDATE devices SET name=?,hostname=?,os=?,arch=?,agent_version=?,observer_only=?,status=?,last_seen_at=?,updated_at=? WHERE id=?`, in.Device.Name, in.Device.Hostname, in.Device.OS, in.Device.Arch, in.Device.AgentVersion, in.Device.ObserverOnly, string(domain.DeviceOnline), timeText(in.Now), timeText(in.Now), device.ID)
		if err != nil {
			return FinalizeEnrollmentResult{}, err
		}
		device.Name, device.Hostname, device.OS, device.Arch, device.AgentVersion, device.ObserverOnly, device.Status = in.Device.Name, in.Device.Hostname, in.Device.OS, in.Device.Arch, in.Device.AgentVersion, in.Device.ObserverOnly, domain.DeviceOnline
		now := in.Now.UTC()
		device.LastSeenAt, device.UpdatedAt = &now, now
		out.Device = device
		// A committed enrollment can be recovered by requesting a fresh
		// challenge for the same identity. Retaining the consumed challenge is
		// therefore unnecessary and lets a valid token grow this table with
		// successful recovery cycles. Delete it inside the same transaction.
		if _, err = tx.ExecContext(ctx, `DELETE FROM enrollment_challenges WHERE id=?`, in.ChallengeID); err != nil {
			return FinalizeEnrollmentResult{}, err
		}
		if err = tx.Commit(); err != nil {
			return FinalizeEnrollmentResult{}, err
		}
		return out, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return FinalizeEnrollmentResult{}, err
	}
	if uses >= maxUses {
		return FinalizeEnrollmentResult{}, ErrTokenExhausted
	}
	if tokenExpires.Valid {
		expiresAt, parseErr := parseTime(tokenExpires.String)
		if parseErr != nil {
			return FinalizeEnrollmentResult{}, parseErr
		}
		if !in.Now.Before(expiresAt) {
			return FinalizeEnrollmentResult{}, ErrTokenExpired
		}
	}
	if in.EncryptedAgentToken == "" || in.AgentTokenHash == "" {
		return FinalizeEnrollmentResult{}, errors.New("new enrollment credential is missing")
	}
	d := domain.Device{ID: ids.New("dev"), Name: in.Device.Name, Hostname: in.Device.Hostname, OS: in.Device.OS, Arch: in.Device.Arch, AgentVersion: in.Device.AgentVersion, ObserverOnly: in.Device.ObserverOnly, IdentityKey: in.Device.IdentityKey, Status: domain.DeviceOnline, EnrolledAt: in.Now.UTC(), CreatedAt: in.Now.UTC(), UpdatedAt: in.Now.UTC()}
	if _, err = tx.ExecContext(ctx, `INSERT INTO devices(id,name,hostname,os,arch,agent_version,observer_only,identity_key,status,last_seen_at,enrolled_at,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)`, d.ID, d.Name, d.Hostname, d.OS, d.Arch, d.AgentVersion, d.ObserverOnly, d.IdentityKey, string(d.Status), timeText(in.Now), timeText(in.Now), timeText(in.Now), timeText(in.Now)); err != nil {
		return FinalizeEnrollmentResult{}, mapSQLError(err)
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO agent_tokens(id,device_id,token_hash,created_at) VALUES(?,?,?,?)`, ids.New("agt"), d.ID, in.AgentTokenHash, timeText(in.Now)); err != nil {
		return FinalizeEnrollmentResult{}, mapSQLError(err)
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO schedules(id,device_id,kind,interval_seconds,enabled,next_run_at,last_run_at,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?)`, ids.New("sch"), d.ID, string(domain.ScheduleScan), int64(in.Device.ScanInterval/time.Second), true, timeText(in.Now.Add(in.Device.ScanInterval)), nil, timeText(in.Now), timeText(in.Now)); err != nil {
		return FinalizeEnrollmentResult{}, err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO enrollment_identities(identity_key,device_id,enrollment_token_id,encrypted_agent_token,created_at,updated_at) VALUES(?,?,?,?,?,?)`, in.Device.IdentityKey, d.ID, tokenID, in.EncryptedAgentToken, timeText(in.Now), timeText(in.Now)); err != nil {
		return FinalizeEnrollmentResult{}, mapSQLError(err)
	}
	res, err = tx.ExecContext(ctx, `UPDATE enrollment_tokens SET uses=uses+1 WHERE id=? AND uses=?`, tokenID, uses)
	if err != nil {
		return FinalizeEnrollmentResult{}, err
	}
	if count, _ := res.RowsAffected(); count != 1 {
		return FinalizeEnrollmentResult{}, ErrConflict
	}
	if _, err = tx.ExecContext(ctx, `DELETE FROM enrollment_challenges WHERE id=?`, in.ChallengeID); err != nil {
		return FinalizeEnrollmentResult{}, err
	}
	if err = tx.Commit(); err != nil {
		return FinalizeEnrollmentResult{}, err
	}
	timestamp := in.Now.UTC()
	d.LastSeenAt = &timestamp
	out.Device, out.EncryptedAgentToken, out.Created = d, in.EncryptedAgentToken, true
	return out, nil
}

func (s *Store) EnrollDevice(ctx context.Context, enrollmentHash, agentTokenHash string, in EnrollInput, now time.Time) (domain.Device, error) {
	if in.ScanInterval == 0 {
		in.ScanInterval = DefaultScanInterval
	}
	if in.ScanInterval < 15*time.Minute || in.ScanInterval > 365*24*time.Hour {
		return domain.Device{}, errors.New("initial scan interval must be between 15 minutes and 365 days")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return domain.Device{}, err
	}
	defer tx.Rollback()
	var tokenID string
	var maxUses, uses int
	var expires, revoked sql.NullString
	err = tx.QueryRowContext(ctx, `SELECT id,max_uses,uses,expires_at,revoked_at FROM enrollment_tokens WHERE token_hash=?`, enrollmentHash).Scan(&tokenID, &maxUses, &uses, &expires, &revoked)
	if errors.Is(err, sql.ErrNoRows) {
		return domain.Device{}, ErrUnauthorized
	}
	if err != nil {
		return domain.Device{}, err
	}
	if revoked.Valid {
		return domain.Device{}, ErrUnauthorized
	}
	if uses >= maxUses {
		return domain.Device{}, ErrTokenExhausted
	}
	if expires.Valid {
		t, e := parseTime(expires.String)
		if e != nil {
			return domain.Device{}, e
		}
		if !now.Before(t) {
			return domain.Device{}, ErrTokenExpired
		}
	}
	d := domain.Device{ID: ids.New("dev"), Name: in.Name, Hostname: in.Hostname, OS: in.OS, Arch: in.Arch, AgentVersion: in.AgentVersion, ObserverOnly: in.ObserverOnly, IdentityKey: in.IdentityKey, Status: domain.DeviceOnline, EnrolledAt: now.UTC(), CreatedAt: now.UTC(), UpdatedAt: now.UTC()}
	_, err = tx.ExecContext(ctx, `INSERT INTO devices(id,name,hostname,os,arch,agent_version,observer_only,identity_key,status,last_seen_at,enrolled_at,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)`, d.ID, d.Name, d.Hostname, d.OS, d.Arch, d.AgentVersion, d.ObserverOnly, d.IdentityKey, string(d.Status), timeText(now), timeText(now), timeText(now), timeText(now))
	if err != nil {
		return domain.Device{}, err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO agent_tokens(id,device_id,token_hash,created_at) VALUES(?,?,?,?)`, ids.New("agt"), d.ID, agentTokenHash, timeText(now))
	if err != nil {
		return domain.Device{}, err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO schedules(id,device_id,kind,interval_seconds,enabled,next_run_at,last_run_at,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?)`, ids.New("sch"), d.ID, string(domain.ScheduleScan), int64(in.ScanInterval/time.Second), true, timeText(now.Add(in.ScanInterval)), nil, timeText(now), timeText(now))
	if err != nil {
		return domain.Device{}, err
	}
	res, err := tx.ExecContext(ctx, `UPDATE enrollment_tokens SET uses=uses+1 WHERE id=? AND uses=?`, tokenID, uses)
	if err != nil {
		return domain.Device{}, err
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return domain.Device{}, ErrConflict
	}
	if err := tx.Commit(); err != nil {
		return domain.Device{}, err
	}
	t := now.UTC()
	d.LastSeenAt = &t
	return d, nil
}

func scanDevice(row interface{ Scan(...any) error }) (domain.Device, error) {
	var d domain.Device
	var last sql.NullString
	var enrolled, created, updated string
	err := row.Scan(&d.ID, &d.Name, &d.Hostname, &d.OS, &d.Arch, &d.AgentVersion, &d.ObserverOnly, &d.IdentityKey, &d.Status, &last, &enrolled, &created, &updated)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return d, ErrNotFound
		}
		return d, err
	}
	if d.LastSeenAt, err = nullableTime(last); err != nil {
		return d, err
	}
	if d.EnrolledAt, err = parseTime(enrolled); err != nil {
		return d, err
	}
	if d.CreatedAt, err = parseTime(created); err != nil {
		return d, err
	}
	d.UpdatedAt, err = parseTime(updated)
	return d, err
}

const deviceColumns = `id,name,hostname,os,arch,agent_version,observer_only,identity_key,status,last_seen_at,enrolled_at,created_at,updated_at`

func (s *Store) AgentDevice(ctx context.Context, tokenHash string) (domain.Device, error) {
	return scanDevice(s.db.QueryRowContext(ctx, `SELECT `+stringsReplaceColumns(deviceColumns, "d.")+` FROM agent_tokens t JOIN devices d ON d.id=t.device_id WHERE t.token_hash=? AND t.revoked_at IS NULL AND d.status<>?`, tokenHash, string(domain.DeviceRevoked)))
}

func (s *Store) ConsumeAgentRequestNonce(ctx context.Context, deviceID, nonce string, expiresAt, now time.Time) error {
	if deviceID == "" || nonce == "" || !expiresAt.After(now) || expiresAt.Sub(now) > 10*time.Minute {
		return errors.New("agent request nonce is invalid")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `DELETE FROM agent_request_nonces WHERE expires_at<=?`, timeText(now)); err != nil {
		return err
	}
	var outstanding int
	if err = tx.QueryRowContext(ctx, `SELECT count(*) FROM agent_request_nonces WHERE device_id=? AND expires_at>?`, deviceID, timeText(now)).Scan(&outstanding); err != nil {
		return err
	}
	if outstanding >= 1_500 {
		return ErrConflict
	}
	if err = tx.QueryRowContext(ctx, `SELECT count(*) FROM agent_request_nonces WHERE expires_at>?`, timeText(now)).Scan(&outstanding); err != nil {
		return err
	}
	if outstanding >= 100_000 {
		return ErrConflict
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO agent_request_nonces(device_id,nonce,expires_at,created_at) VALUES(?,?,?,?)`, deviceID, nonce, timeText(expiresAt), timeText(now)); err != nil {
		return mapSQLError(err)
	}
	return tx.Commit()
}

// CountAgentRequestNonces exposes only aggregate replay-cache cardinality for
// resource-bound verification and operational health tests; nonce values never
// leave the Store.
func (s *Store) CountAgentRequestNonces(ctx context.Context) (int, error) {
	var count int
	err := s.db.QueryRowContext(ctx, `SELECT count(*) FROM agent_request_nonces`).Scan(&count)
	return count, err
}

func stringsReplaceColumns(columns, prefix string) string {
	parts := make([]string, 0)
	for _, p := range splitComma(columns) {
		parts = append(parts, prefix+p)
	}
	return joinComma(parts)
}
func splitComma(s string) []string {
	var out []string
	start := 0
	for i, c := range s {
		if c == ',' {
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	return append(out, s[start:])
}
func joinComma(v []string) string {
	if len(v) == 0 {
		return ""
	}
	out := v[0]
	for _, x := range v[1:] {
		out += "," + x
	}
	return out
}

func (s *Store) Heartbeat(ctx context.Context, deviceID, name, hostname, osName, arch, version string, now time.Time) error {
	res, err := s.db.ExecContext(ctx, `UPDATE devices SET name=CASE WHEN ?='' THEN name ELSE ? END,hostname=?,os=?,arch=?,agent_version=?,status=?,last_seen_at=?,updated_at=? WHERE id=? AND status<>?`, name, name, hostname, osName, arch, version, string(domain.DeviceOnline), timeText(now), timeText(now), deviceID, string(domain.DeviceRevoked))
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) Device(ctx context.Context, id string) (domain.Device, error) {
	return scanDevice(s.db.QueryRowContext(ctx, `SELECT `+deviceColumns+` FROM devices WHERE id=?`, id))
}

func (s *Store) ListDevices(ctx context.Context, offlineBefore time.Time) ([]domain.Device, error) {
	_, _ = s.db.ExecContext(ctx, `UPDATE devices SET status=? WHERE status=? AND last_seen_at<?`, string(domain.DeviceOffline), string(domain.DeviceOnline), timeText(offlineBefore))
	rows, err := s.db.QueryContext(ctx, `SELECT `+deviceColumns+` FROM devices ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.Device
	for rows.Next() {
		d, e := scanDevice(rows)
		if e != nil {
			return nil, e
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

func (s *Store) RevokeDevice(ctx context.Context, id string, now time.Time) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	res, err := tx.ExecContext(ctx, `UPDATE devices SET status=?,updated_at=? WHERE id=? AND status<>?`, string(domain.DeviceRevoked), timeText(now), id, string(domain.DeviceRevoked))
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	if _, err = tx.ExecContext(ctx, `UPDATE agent_tokens SET revoked_at=? WHERE device_id=? AND revoked_at IS NULL`, timeText(now), id); err != nil {
		return err
	}
	rows, err := tx.QueryContext(ctx, `SELECT id,type,payload,started_at FROM device_commands WHERE device_id=? AND completed_at IS NULL`, id)
	if err != nil {
		return err
	}
	type pendingCommand struct {
		id, typ, payload string
		started          bool
	}
	var pending []pendingCommand
	for rows.Next() {
		var item pendingCommand
		var started sql.NullString
		if err = rows.Scan(&item.id, &item.typ, &item.payload, &started); err != nil {
			_ = rows.Close()
			return err
		}
		item.started = started.Valid
		pending = append(pending, item)
	}
	if err = rows.Close(); err != nil {
		return err
	}
	for _, item := range pending {
		isAction := item.typ == string(domain.CommandExecuteAction) || item.typ == string(domain.CommandRollback) || item.typ == string(domain.CommandConfirm)
		message := "device was revoked before command completion"
		result := `{"ok":false,"cancelled":true}`
		if isAction && item.started {
			message = commandExecutionIndeterminateMessage
			result = `{"ok":false,"indeterminate":true}`
		}
		if _, err = tx.ExecContext(ctx, `UPDATE device_commands SET completed_at=?,result=?,error=? WHERE id=? AND completed_at IS NULL`, timeText(now), result, message, item.id); err != nil {
			return err
		}
		if !isAction {
			continue
		}
		var meta struct {
			ActionID string `json:"actionId"`
		}
		if json.Unmarshal([]byte(item.payload), &meta) != nil || meta.ActionID == "" {
			continue
		}
		status := domain.ActionCancelled
		event := "device_revoked_before_execution"
		var res sql.Result
		var updateErr error
		if item.started {
			status = domain.ActionIndeterminate
			event = "device_revoked_during_execution"
			res, updateErr = tx.ExecContext(ctx, `UPDATE actions SET status=?,completed_at=?,error=?,updated_at=? WHERE id=? AND device_id=? AND status IN (?,?,?)`, string(status), timeText(now), message, timeText(now), meta.ActionID, id, string(domain.ActionExecuting), string(domain.ActionRollingBack), string(domain.ActionConfirming))
		} else {
			res, updateErr = tx.ExecContext(ctx, `UPDATE actions SET status=?,completed_at=?,error=?,updated_at=? WHERE id=? AND device_id=? AND status IN (?,?,?,?,?)`, string(status), timeText(now), message, timeText(now), meta.ActionID, id, string(domain.ActionApproved), string(domain.ActionExecuting), string(domain.ActionRollingBack), string(domain.ActionConfirming), string(domain.ActionAwaitingConfirmation))
		}
		if updateErr != nil {
			return updateErr
		}
		if changed, _ := res.RowsAffected(); changed == 1 {
			banStatus := "cancelled"
			if item.started {
				banStatus = "indeterminate"
			}
			if item.started {
				_, err = tx.ExecContext(ctx, `UPDATE temporary_bans SET status=? WHERE action_id=? AND status IN ('pending','active','indeterminate')`, banStatus, meta.ActionID)
			} else {
				_, err = tx.ExecContext(ctx, `UPDATE temporary_bans SET status=? WHERE action_id=? AND status='pending'`, banStatus, meta.ActionID)
			}
			if err != nil {
				return err
			}
			details, _ := json.Marshal(map[string]any{"commandId": item.id, "manualVerificationRequired": item.started})
			if _, err = tx.ExecContext(ctx, `INSERT INTO action_audit(action_id,actor,event,details,created_at) VALUES(?,?,?,?,?)`, meta.ActionID, "controller", event, string(details), timeText(now)); err != nil {
				return err
			}
		}
	}
	return tx.Commit()
}

func (s *Store) RequireDevice(ctx context.Context, id string) error {
	_, err := s.Device(ctx, id)
	if err != nil {
		return fmt.Errorf("device: %w", err)
	}
	return nil
}
