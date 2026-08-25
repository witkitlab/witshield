package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/witkitlab/witshield/internal/auth"
	"github.com/witkitlab/witshield/internal/domain"
	"github.com/witkitlab/witshield/internal/identity"
	"github.com/witkitlab/witshield/internal/ids"
	"github.com/witkitlab/witshield/internal/secret"
	"github.com/witkitlab/witshield/internal/store"
)

var usernamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{2,63}$`)

func (s *Server) status(w http.ResponseWriter, r *http.Request) {
	count, err := s.store.AdminCount(r.Context())
	if err != nil {
		s.fail(w, err)
		return
	}
	authenticated := false
	token := bearer(r)
	if token == "" {
		if c, e := r.Cookie(sessionCookie); e == nil {
			token = c.Value
		}
	}
	if token != "" {
		if _, securityErr := s.sessionCookieSecurity(r); securityErr != nil {
			writeJSON(w, 200, map[string]any{"initialized": count > 0, "needsBootstrap": count == 0, "authenticated": false, "version": s.version, "mode": "controller"})
			return
		}
		_, e := s.store.AdminBySession(r.Context(), secret.Hash(token), s.now())
		authenticated = e == nil
	}
	writeJSON(w, 200, map[string]any{"initialized": count > 0, "needsBootstrap": count == 0, "authenticated": authenticated, "version": s.version, "mode": "controller"})
}
func (s *Server) bootstrap(w http.ResponseWriter, r *http.Request) {
	secureCookie, securityErr := s.sessionCookieSecurity(r)
	if securityErr != nil {
		writeError(w, http.StatusForbidden, "insecure_admin_transport", securityErr.Error())
		return
	}
	count, err := s.store.AdminCount(r.Context())
	if err != nil {
		s.fail(w, err)
		return
	}
	if count != 0 {
		writeError(w, 409, "already_bootstrapped", "administrator already exists")
		return
	}
	var in struct{ Username, Password, BootstrapToken string }
	if !decodeJSON(w, r, &in) {
		return
	}
	if !usernamePattern.MatchString(in.Username) {
		writeError(w, 400, "invalid_username", "username must be 3-64 characters using letters, digits, dot, dash or underscore")
		return
	}
	if s.bootstrapToken == "" {
		writeError(w, 503, "bootstrap_token_not_configured", "configure a bootstrap token before creating the administrator")
		return
	}
	if !constantEqual(s.bootstrapToken, in.BootstrapToken) {
		writeError(w, 403, "invalid_bootstrap_token", "invalid bootstrap token")
		return
	}
	hash, err := auth.HashPassword(in.Password)
	if err != nil {
		writeError(w, 400, "weak_password", err.Error())
		return
	}
	admin, err := s.store.CreateAdmin(r.Context(), in.Username, hash, s.now())
	if err != nil {
		s.fail(w, err)
		return
	}
	s.issueSession(w, r, admin, http.StatusCreated, secureCookie)
}
func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	secureCookie, securityErr := s.sessionCookieSecurity(r)
	if securityErr != nil {
		writeError(w, http.StatusForbidden, "insecure_admin_transport", securityErr.Error())
		return
	}
	key := s.remoteIP(r).String()
	if !s.limiter.allow(key, s.now()) {
		writeError(w, 429, "rate_limited", "too many login attempts; try again later")
		return
	}
	var in struct{ Username, Password string }
	if !decodeJSON(w, r, &in) {
		return
	}
	admin, hash, err := s.store.AdminCredentials(r.Context(), in.Username)
	if errors.Is(err, store.ErrNotFound) {
		hash = s.dummyHash
	} else if err != nil {
		s.fail(w, err)
		return
	}
	valid := auth.VerifyPassword(hash, in.Password) && err == nil
	if !valid {
		writeError(w, 401, "invalid_credentials", "invalid username or password")
		return
	}
	s.limiter.clear(key)
	s.issueSession(w, r, admin, 200, secureCookie)
}
func (s *Server) issueSession(w http.ResponseWriter, r *http.Request, admin domain.Admin, status int, secureCookie bool) {
	raw, err := ids.Token("wss", 32)
	if err != nil {
		s.fail(w, err)
		return
	}
	expires := s.now().Add(s.sessionTTL)
	if _, err = s.store.CreateSession(r.Context(), admin.ID, secret.Hash(raw), expires, s.now()); err != nil {
		s.fail(w, err)
		return
	}
	// Plain HTTP is reachable only through the explicit local-only deployment
	// policy checked before any administrator or session mutation.

	// codeql[go/cookie-secure-not-set]
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: raw, Path: "/", Expires: expires, HttpOnly: true, Secure: secureCookie, SameSite: http.SameSiteStrictMode, MaxAge: int(s.sessionTTL / time.Second)})
	writeJSON(w, status, map[string]any{"admin": admin, "expiresAt": expires})
}
func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	secureCookie, securityErr := s.sessionCookieSecurity(r)
	if securityErr != nil {
		writeError(w, http.StatusForbidden, "insecure_admin_transport", securityErr.Error())
		return
	}
	token := bearer(r)
	if token == "" {
		if c, err := r.Cookie(sessionCookie); err == nil {
			token = c.Value
		}
	}
	if token != "" {
		_ = s.store.DeleteSession(r.Context(), secret.Hash(token))
	}
	// Match the issuance mode so the browser removes the exact local or secure
	// cookie; insecure deletion is constrained by sessionCookieSecurity above.

	// codeql[go/cookie-secure-not-set]
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Path: "/", MaxAge: -1, HttpOnly: true, Secure: secureCookie, SameSite: http.SameSiteStrictMode})
	w.WriteHeader(204)
}
func (s *Server) me(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]any{"admin": adminFrom(r.Context())})
}

func (s *Server) createEnrollmentToken(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Name      string `json:"name"`
		ExpiresIn string `json:"expiresIn"`
	}
	if !decodeJSON(w, r, &in) {
		return
	}
	in.Name = strings.TrimSpace(in.Name)
	if in.Name == "" || len(in.Name) > 100 {
		writeError(w, 400, "invalid_name", "name must be 1-100 characters")
		return
	}
	duration := 15 * time.Minute
	if in.ExpiresIn != "" {
		var err error
		duration, err = time.ParseDuration(in.ExpiresIn)
		if err != nil || duration < time.Minute || duration > 24*time.Hour {
			writeError(w, 400, "invalid_expiry", "expiresIn must be between 1m and 24h")
			return
		}
	}
	raw, err := ids.Token("wse", 32)
	if err != nil {
		s.fail(w, err)
		return
	}
	expires := s.now().Add(duration)
	item := domain.EnrollmentToken{ID: ids.New("enr"), Name: in.Name, Hint: ids.Hint(raw), MaxUses: 1, ExpiresAt: &expires, CreatedAt: s.now().UTC()}
	if err = s.store.CreateEnrollmentToken(r.Context(), item, secret.Hash(raw)); err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, 201, map[string]any{"enrollmentToken": item, "token": raw})
}
func (s *Server) listEnrollmentTokens(w http.ResponseWriter, r *http.Request) {
	items, err := s.store.ListEnrollmentTokens(r.Context())
	if err != nil {
		s.fail(w, err)
		return
	}
	if items == nil {
		items = []domain.EnrollmentToken{}
	}
	writeJSON(w, 200, map[string]any{"items": items})
}
func (s *Server) revokeEnrollmentToken(w http.ResponseWriter, r *http.Request) {
	if err := s.store.RevokeEnrollmentToken(r.Context(), r.PathValue("id"), s.now()); err != nil {
		s.fail(w, err)
		return
	}
	w.WriteHeader(204)
}
func (s *Server) listDevices(w http.ResponseWriter, r *http.Request) {
	items, err := s.store.ListDevices(r.Context(), s.now().Add(-90*time.Second))
	if err != nil {
		s.fail(w, err)
		return
	}
	if items == nil {
		items = []domain.Device{}
	}
	writeJSON(w, 200, map[string]any{"items": items})
}
func (s *Server) getDevice(w http.ResponseWriter, r *http.Request) {
	x, err := s.store.Device(r.Context(), r.PathValue("id"))
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, 200, x)
}
func (s *Server) revokeDevice(w http.ResponseWriter, r *http.Request) {
	if err := s.store.RevokeDevice(r.Context(), r.PathValue("id"), s.now()); err != nil {
		s.fail(w, err)
		return
	}
	w.WriteHeader(204)
}
func (s *Server) triggerScan(w http.ResponseWriter, r *http.Request) {
	deviceID := r.PathValue("id")
	if err := s.store.RequireDevice(r.Context(), deviceID); err != nil {
		s.fail(w, err)
		return
	}
	payload, _ := json.Marshal(map[string]any{"requestedBy": adminFrom(r.Context()).ID, "requestedAt": s.now().UTC()})
	cmd := domain.DeviceCommand{ID: ids.New("cmd"), DeviceID: deviceID, Type: domain.CommandScan, Payload: payload, CreatedAt: s.now().UTC()}
	if err := s.store.EnqueueCommand(r.Context(), cmd); err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, 202, cmd)
}
func (s *Server) listReports(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	items, err := s.store.ListReports(r.Context(), r.URL.Query().Get("deviceId"), limit)
	if err != nil {
		s.fail(w, err)
		return
	}
	if items == nil {
		items = []domain.Report{}
	}
	writeJSON(w, 200, map[string]any{"items": items})
}
func (s *Server) getReport(w http.ResponseWriter, r *http.Request) {
	x, err := s.store.Report(r.Context(), r.PathValue("id"))
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, 200, x)
}
func (s *Server) listFindings(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	items, err := s.store.ListFindings(r.Context(), store.FindingFilter{DeviceID: r.URL.Query().Get("deviceId"), Status: domain.FindingStatus(r.URL.Query().Get("status")), Severity: domain.Severity(r.URL.Query().Get("severity")), Limit: limit})
	if err != nil {
		s.fail(w, err)
		return
	}
	if items == nil {
		items = []domain.Finding{}
	}
	writeJSON(w, 200, map[string]any{"items": items})
}

func (s *Server) listSchedules(w http.ResponseWriter, r *http.Request) {
	items, err := s.store.ListSchedules(r.Context())
	if err != nil {
		s.fail(w, err)
		return
	}
	if items == nil {
		items = []domain.Schedule{}
	}
	writeJSON(w, 200, map[string]any{"items": items})
}
func parseInterval(raw string) (time.Duration, error) {
	d, err := time.ParseDuration(raw)
	if err != nil || d < 15*time.Minute || d > 30*24*time.Hour {
		return 0, errors.New("every must be between 15m and 720h")
	}
	return d, nil
}
func (s *Server) createSchedule(w http.ResponseWriter, r *http.Request) {
	var in struct {
		DeviceID string              `json:"deviceId"`
		Kind     domain.ScheduleKind `json:"kind"`
		Every    string              `json:"every"`
		Enabled  *bool               `json:"enabled"`
	}
	if !decodeJSON(w, r, &in) {
		return
	}
	if in.Kind == "" {
		in.Kind = domain.ScheduleScan
	}
	if in.Kind != domain.ScheduleScan {
		writeError(w, 400, "invalid_kind", "only scan schedules are supported")
		return
	}
	d, err := parseInterval(in.Every)
	if err != nil {
		writeError(w, 400, "invalid_interval", err.Error())
		return
	}
	if err = s.store.RequireDevice(r.Context(), in.DeviceID); err != nil {
		s.fail(w, err)
		return
	}
	enabled := true
	if in.Enabled != nil {
		enabled = *in.Enabled
	}
	now := s.now().UTC()
	x := domain.Schedule{ID: ids.New("sch"), DeviceID: in.DeviceID, Kind: in.Kind, Interval: d, Every: d.String(), Enabled: enabled, NextRunAt: now.Add(d), CreatedAt: now, UpdatedAt: now}
	if err = s.store.CreateSchedule(r.Context(), x); err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, 201, x)
}
func (s *Server) updateSchedule(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Every   string `json:"every"`
		Enabled bool   `json:"enabled"`
	}
	if !decodeJSON(w, r, &in) {
		return
	}
	d, err := parseInterval(in.Every)
	if err != nil {
		writeError(w, 400, "invalid_interval", err.Error())
		return
	}
	now := s.now().UTC()
	if err = s.store.UpdateSchedule(r.Context(), r.PathValue("id"), d, in.Enabled, now.Add(d), now); err != nil {
		s.fail(w, err)
		return
	}
	w.WriteHeader(204)
}
func (s *Server) deleteSchedule(w http.ResponseWriter, r *http.Request) {
	if err := s.store.DeleteSchedule(r.Context(), r.PathValue("id")); err != nil {
		s.fail(w, err)
		return
	}
	w.WriteHeader(204)
}

func validAgentName(v string) bool { v = strings.TrimSpace(v); return v != "" && len(v) <= 100 }
func (s *Server) agentEnrollChallenge(w http.ResponseWriter, r *http.Request) {
	// Challenge and finalize are two separate protocol steps. Isolating their
	// budgets prevents 15 devices behind one NAT from exhausting a shared
	// 30-request bucket during a normal installation wave.
	if !s.enrollChallengeLimiter.allowEvicting(agentSourceLimitKey(s.remoteIP(r)), s.now().UTC(), 120) {
		w.Header().Set("Retry-After", "600")
		writeError(w, http.StatusTooManyRequests, "enrollment_rate_limited", "too many enrollment attempts")
		return
	}
	var in struct {
		EnrollmentToken   string `json:"enrollmentToken"`
		IdentityPublicKey string `json:"identityPublicKey"`
	}
	if !decodeJSON(w, r, &in) {
		return
	}
	if in.EnrollmentToken == "" || len(in.EnrollmentToken) > 512 {
		writeError(w, 401, "invalid_enrollment", "valid enrollment credentials are required")
		return
	}
	if _, err := identity.DecodePublicKey(in.IdentityPublicKey); err != nil {
		writeError(w, 400, "invalid_identity", "a valid Ed25519 identity public key is required")
		return
	}
	challenge, err := ids.Token("wsc", 32)
	if err != nil {
		s.fail(w, err)
		return
	}
	now := s.now().UTC()
	challengeID := ids.New("ech")
	err = s.store.CreateEnrollmentChallenge(r.Context(), store.EnrollmentChallengeInput{
		ID: challengeID, EnrollmentHash: secret.Hash(in.EnrollmentToken), IdentityKey: in.IdentityPublicKey,
		ChallengeHash: secret.Hash(challenge), ExpiresAt: now.Add(5 * time.Minute), Now: now,
	})
	if err != nil {
		s.fail(w, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusCreated, map[string]any{"id": challengeID, "challenge": challenge, "expiresAt": now.Add(5 * time.Minute)})
}

func (s *Server) agentEnroll(w http.ResponseWriter, r *http.Request) {
	if !s.enrollFinalizeLimiter.allowEvicting(agentSourceLimitKey(s.remoteIP(r)), s.now().UTC(), 120) {
		w.Header().Set("Retry-After", "600")
		writeError(w, http.StatusTooManyRequests, "enrollment_rate_limited", "too many enrollment attempts")
		return
	}
	var in struct {
		EnrollmentToken   string `json:"enrollmentToken"`
		Name              string `json:"name"`
		Hostname          string `json:"hostname"`
		OS                string `json:"os"`
		Arch              string `json:"arch"`
		AgentVersion      string `json:"agentVersion"`
		IdentityPublicKey string `json:"identityPublicKey"`
		ScanInterval      string `json:"scanInterval"`
		ObserverOnly      bool   `json:"observerOnly"`
		ChallengeID       string `json:"challengeId"`
		Challenge         string `json:"challenge"`
		IdentitySignature string `json:"identitySignature"`
	}
	if !decodeJSON(w, r, &in) {
		return
	}
	if !validAgentName(in.Name) || len(in.Hostname) > 255 || len(in.OS) > 200 || len(in.Arch) > 30 || len(in.AgentVersion) > 100 || len(in.IdentityPublicKey) > 128 || len(in.ScanInterval) > 32 || len(in.ChallengeID) > 128 || len(in.Challenge) > 128 || len(in.IdentitySignature) > 256 {
		writeError(w, 400, "invalid_device", "invalid device metadata")
		return
	}
	scanInterval := store.DefaultScanInterval
	if in.ScanInterval != "" {
		parsed, parseErr := time.ParseDuration(in.ScanInterval)
		if parseErr != nil || parsed < 15*time.Minute || parsed > 365*24*time.Hour {
			writeError(w, 400, "invalid_scan_interval", "initial scan interval must be between 15 minutes and 365 days")
			return
		}
		scanInterval = parsed
	}
	if in.EnrollmentToken == "" || len(in.EnrollmentToken) > 512 {
		writeError(w, 401, "missing_enrollment_token", "enrollment token is required")
		return
	}
	if in.ChallengeID == "" || in.Challenge == "" || in.IdentitySignature == "" {
		writeError(w, http.StatusUpgradeRequired, "enrollment_protocol_upgrade_required", "upgrade the Agent to a version that supports signed enrollment")
		return
	}
	proof := identity.EnrollmentProof{
		ChallengeID: in.ChallengeID, Challenge: in.Challenge, EnrollmentToken: in.EnrollmentToken,
		Name: in.Name, Hostname: in.Hostname, OS: in.OS, Arch: in.Arch, AgentVersion: in.AgentVersion,
		IdentityPublicKey: in.IdentityPublicKey, ScanInterval: in.ScanInterval, ObserverOnly: in.ObserverOnly,
	}
	if err := identity.VerifyEnrollmentProof(in.IdentityPublicKey, in.IdentitySignature, proof); err != nil {
		writeError(w, 401, "invalid_identity_proof", "valid enrollment credentials are required")
		return
	}
	agentToken, err := ids.Token("wsa", 32)
	if err != nil {
		s.fail(w, err)
		return
	}
	encryptedToken, err := s.vault.Encrypt(agentToken)
	if err != nil {
		s.fail(w, err)
		return
	}
	result, err := s.store.FinalizeEnrollment(r.Context(), store.FinalizeEnrollmentInput{
		ChallengeID: in.ChallengeID, ChallengeHash: secret.Hash(in.Challenge), EnrollmentHash: secret.Hash(in.EnrollmentToken),
		AgentTokenHash: secret.Hash(agentToken), EncryptedAgentToken: encryptedToken,
		Device: store.EnrollInput{Name: in.Name, Hostname: in.Hostname, OS: in.OS, Arch: in.Arch, AgentVersion: in.AgentVersion, IdentityKey: in.IdentityPublicKey, ScanInterval: scanInterval, ObserverOnly: in.ObserverOnly}, Now: s.now().UTC(),
	})
	if err != nil {
		s.fail(w, err)
		return
	}
	agentToken, err = s.vault.Decrypt(result.EncryptedAgentToken)
	if err != nil || len(agentToken) < 20 {
		s.log.Error("stored enrollment credential could not be recovered", "deviceId", result.Device.ID, "error", err)
		writeError(w, 500, "internal_error", "internal server error")
		return
	}
	status := http.StatusOK
	if result.Created {
		status = http.StatusCreated
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, status, map[string]any{"device": result.Device, "deviceToken": agentToken})
}
func (s *Server) agentHeartbeat(w http.ResponseWriter, r *http.Request) {
	device := deviceFrom(r.Context())
	var in struct{ Name, Hostname, OS, Arch, AgentVersion string }
	if !decodeJSON(w, r, &in) {
		return
	}
	if !validAgentName(in.Name) || len(in.Hostname) > 255 || len(in.OS) > 200 || len(in.Arch) > 30 || len(in.AgentVersion) > 100 {
		writeError(w, 400, "invalid_device", "invalid device metadata")
		return
	}
	if err := s.store.Heartbeat(r.Context(), device.ID, in.Name, in.Hostname, in.OS, in.Arch, in.AgentVersion, s.now()); err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"serverTime": s.now().UTC(), "heartbeatInterval": "30s"})
}
func contextWithTimeout(ctx context.Context, d time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, d)
}
