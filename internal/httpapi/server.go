package httpapi

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/witkitlab/witshield/internal/auth"
	"github.com/witkitlab/witshield/internal/domain"
	"github.com/witkitlab/witshield/internal/identity"
	"github.com/witkitlab/witshield/internal/secret"
	"github.com/witkitlab/witshield/internal/store"
)

const sessionCookie = "witshield_session"

type Config struct {
	Store          *store.Store
	Vault          *secret.Vault
	Version        string
	BootstrapToken string
	WebDir         string
	Logger         *slog.Logger
	SessionTTL     time.Duration
	TrustedProxies []string
}
type Server struct {
	store                  *store.Store
	vault                  *secret.Vault
	version                string
	bootstrapToken         string
	webDir                 string
	log                    *slog.Logger
	sessionTTL             time.Duration
	dummyHash              string
	now                    func() time.Time
	limiter                *loginLimiter
	agentSourceLimiter     *windowLimiter
	agentRequestLimiter    *weightedWindowLimiter
	agentWorkLimiter       *weightedWindowLimiter
	enrollChallengeLimiter *windowLimiter
	enrollFinalizeLimiter  *windowLimiter
	agentWrites            chan struct{}
	syncs                  *syncGate
	mux                    *http.ServeMux
	notifyWebhookWake      chan struct{}
	notifySMTPWake         chan struct{}
	notifyObserver         func(domain.NotificationEvent)
	trustedProxies         []netip.Prefix
	inlineScripts          []string
	healthMu               sync.RWMutex
	workers                map[string]workerHealth
}

type localHTTPTransportKey struct{}

func New(cfg Config) (*Server, error) {
	if cfg.Store == nil || cfg.Vault == nil {
		return nil, errors.New("store and vault are required")
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if strings.TrimSpace(cfg.Version) == "" {
		cfg.Version = "dev"
	}
	if cfg.SessionTTL == 0 {
		cfg.SessionTTL = 24 * time.Hour
	}
	if cfg.SessionTTL < 15*time.Minute || cfg.SessionTTL > 30*24*time.Hour {
		return nil, errors.New("session TTL outside safe range")
	}
	dummy, err := auth.HashPassword("witshield-dummy-password-never-valid")
	if err != nil {
		return nil, err
	}
	trusted, err := parseTrustedProxies(cfg.TrustedProxies)
	if err != nil {
		return nil, err
	}
	inlineScripts, err := inlineScriptHashes(cfg.WebDir)
	if err != nil {
		return nil, err
	}
	s := &Server{store: cfg.Store, vault: cfg.Vault, version: cfg.Version, bootstrapToken: cfg.BootstrapToken, webDir: cfg.WebDir, log: cfg.Logger, sessionTTL: cfg.SessionTTL, dummyHash: dummy, now: time.Now, limiter: newLoginLimiter(), agentSourceLimiter: newWindowLimiter(time.Minute, 20_000), agentRequestLimiter: newWeightedWindowLimiter(time.Minute, 20_000), agentWorkLimiter: newWeightedWindowLimiter(time.Minute, 20_000), enrollChallengeLimiter: newWindowLimiter(10*time.Minute, 10_000), enrollFinalizeLimiter: newWindowLimiter(10*time.Minute, 10_000), agentWrites: make(chan struct{}, 8), syncs: newSyncGate(16), mux: http.NewServeMux(), notifyWebhookWake: make(chan struct{}, 1), notifySMTPWake: make(chan struct{}, 1), trustedProxies: trusted, inlineScripts: inlineScripts, workers: map[string]workerHealth{
		"scheduler":            {StaleAfter: time.Minute},
		"maintenance":          {StaleAfter: 3 * time.Minute},
		"security_engineer":    {StaleAfter: 2 * time.Minute},
		"notification_webhook": {StaleAfter: 30 * time.Second},
		"notification_smtp":    {StaleAfter: 30 * time.Second},
	}}
	s.routes()
	return s, nil
}
func (s *Server) Handler() http.Handler { return securityHeaders(s.mux, s.inlineScripts) }

// LocalHTTPHandler marks requests as arriving through a listener whose network
// exposure is independently constrained to a local transport. It must only be
// attached to a loopback listener or an isolated container interface published
// exclusively on host loopback. An HTTP Host header alone never grants this
// trust because clients can choose it freely.
func (s *Server) LocalHTTPHandler() http.Handler {
	next := s.Handler()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := context.WithValue(r.Context(), localHTTPTransportKey{}, true)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
func (s *Server) routes() {
	s.mux.HandleFunc("GET /healthz", s.health)
	s.mux.HandleFunc("GET /readyz", s.ready)
	s.mux.HandleFunc("GET /api/v1/status", s.status)
	s.mux.HandleFunc("POST /api/v1/admin/bootstrap", s.bootstrap)
	s.mux.HandleFunc("POST /api/v1/auth/login", s.login)
	s.mux.Handle("POST /api/v1/auth/logout", s.requireAdmin(http.HandlerFunc(s.logout)))
	s.mux.Handle("GET /api/v1/auth/me", s.requireAdmin(http.HandlerFunc(s.me)))
	s.mux.Handle("GET /api/v1/system/health", s.requireAdmin(http.HandlerFunc(s.systemHealth)))
	s.mux.Handle("GET /api/v1/enrollment-tokens", s.requireAdmin(http.HandlerFunc(s.listEnrollmentTokens)))
	s.mux.Handle("POST /api/v1/enrollment-tokens", s.requireAdmin(http.HandlerFunc(s.createEnrollmentToken)))
	s.mux.Handle("DELETE /api/v1/enrollment-tokens/{id}", s.requireAdmin(http.HandlerFunc(s.revokeEnrollmentToken)))
	s.mux.Handle("GET /api/v1/devices", s.requireAdmin(http.HandlerFunc(s.listDevices)))
	s.mux.Handle("GET /api/v1/devices/{id}", s.requireAdmin(http.HandlerFunc(s.getDevice)))
	s.mux.Handle("DELETE /api/v1/devices/{id}", s.requireAdmin(http.HandlerFunc(s.revokeDevice)))
	s.mux.Handle("POST /api/v1/devices/{id}/scan", s.requireAdmin(http.HandlerFunc(s.triggerScan)))
	s.mux.Handle("GET /api/v1/reports", s.requireAdmin(http.HandlerFunc(s.listReports)))
	s.mux.Handle("GET /api/v1/reports/{id}", s.requireAdmin(http.HandlerFunc(s.getReport)))
	s.mux.Handle("GET /api/v1/findings", s.requireAdmin(http.HandlerFunc(s.listFindings)))
	s.mux.Handle("GET /api/v1/schedules", s.requireAdmin(http.HandlerFunc(s.listSchedules)))
	s.mux.Handle("POST /api/v1/schedules", s.requireAdmin(http.HandlerFunc(s.createSchedule)))
	s.mux.Handle("PATCH /api/v1/schedules/{id}", s.requireAdmin(http.HandlerFunc(s.updateSchedule)))
	s.mux.Handle("DELETE /api/v1/schedules/{id}", s.requireAdmin(http.HandlerFunc(s.deleteSchedule)))
	s.mux.Handle("GET /api/v1/ai/settings", s.requireAdmin(http.HandlerFunc(s.getAISettings)))
	s.mux.Handle("PUT /api/v1/ai/settings", s.requireAdmin(http.HandlerFunc(s.putAISettings)))
	s.mux.Handle("POST /api/v1/ai/test", s.requireAdmin(http.HandlerFunc(s.testAI)))
	s.mux.Handle("POST /api/v1/ai/chat", s.requireAdmin(http.HandlerFunc(s.chatAI)))
	s.mux.Handle("GET /api/v1/ai/investigation-policy", s.requireAdmin(http.HandlerFunc(s.getAIInvestigationPolicy)))
	s.mux.Handle("PUT /api/v1/ai/investigation-policy", s.requireAdmin(http.HandlerFunc(s.putAIInvestigationPolicy)))
	s.mux.Handle("GET /api/v1/sensors", s.requireAdmin(http.HandlerFunc(s.listSensorHealth)))
	s.mux.Handle("GET /api/v1/notifications/settings", s.requireAdmin(http.HandlerFunc(s.getNotificationSettings)))
	s.mux.Handle("PUT /api/v1/notifications/settings", s.requireAdmin(http.HandlerFunc(s.putNotificationSettings)))
	s.mux.Handle("POST /api/v1/notifications/test", s.requireAdmin(http.HandlerFunc(s.testNotification)))
	s.mux.Handle("GET /api/v1/actions", s.requireAdmin(http.HandlerFunc(s.listActions)))
	s.mux.Handle("POST /api/v1/actions", s.requireAdmin(http.HandlerFunc(s.createAction)))
	s.mux.Handle("GET /api/v1/actions/{id}", s.requireAdmin(http.HandlerFunc(s.getAction)))
	s.mux.Handle("POST /api/v1/actions/{id}/approve", s.requireAdmin(http.HandlerFunc(s.approveAction)))
	s.mux.Handle("POST /api/v1/actions/{id}/rollback", s.requireAdmin(http.HandlerFunc(s.rollbackAction)))
	s.mux.Handle("POST /api/v1/actions/{id}/confirm", s.requireAdmin(http.HandlerFunc(s.confirmAction)))
	s.mux.Handle("GET /api/v1/audit", s.requireAdmin(http.HandlerFunc(s.audit)))
	s.mux.Handle("GET /api/v1/security-events", s.requireAdmin(http.HandlerFunc(s.listSecurityEvents)))
	s.mux.Handle("GET /api/v1/incidents", s.requireAdmin(http.HandlerFunc(s.listIncidents)))
	s.mux.Handle("GET /api/v1/incidents/{id}", s.requireAdmin(http.HandlerFunc(s.getIncident)))
	s.mux.Handle("PATCH /api/v1/incidents/{id}", s.requireAdmin(http.HandlerFunc(s.updateIncident)))
	s.mux.Handle("POST /api/v1/incidents/{id}/investigate", s.requireAdmin(http.HandlerFunc(s.investigateIncident)))
	s.mux.Handle("POST /api/v1/response-plans/{id}/steps/{stepId}/prepare", s.requireAdmin(http.HandlerFunc(s.prepareResponseStep)))
	s.mux.Handle("GET /api/v1/devices/{id}/policy-grants", s.requireAdmin(http.HandlerFunc(s.listPolicyGrants)))
	s.mux.Handle("PUT /api/v1/devices/{id}/policy-grants/{capability}", s.requireAdmin(http.HandlerFunc(s.putPolicyGrant)))
	s.mux.Handle("GET /api/v1/devices/{id}/defense-policy", s.requireAdmin(http.HandlerFunc(s.getDefensePolicy)))
	s.mux.Handle("PUT /api/v1/devices/{id}/defense-policy", s.requireAdmin(http.HandlerFunc(s.putDefensePolicy)))
	s.mux.Handle("POST /api/v1/devices/{id}/defense-policy/simulate", s.requireAdmin(http.HandlerFunc(s.simulateDefense)))
	s.mux.Handle("POST /api/v1/devices/{id}/emergency-stop", s.requireAdmin(http.HandlerFunc(s.emergencyStop)))
	s.mux.HandleFunc("POST /agent/v1/enroll/challenge", s.agentEnrollChallenge)
	s.mux.HandleFunc("POST /agent/v1/enroll", s.agentEnroll)
	s.mux.Handle("POST /agent/v1/heartbeat", s.requireAgent(http.HandlerFunc(s.agentHeartbeat)))
	s.mux.Handle("GET /agent/v1/sync", s.requireAgent(http.HandlerFunc(s.agentSync)))
	s.mux.Handle("POST /agent/v1/commands/{id}/start", s.requireAgent(http.HandlerFunc(s.agentCommandStart)))
	s.mux.Handle("POST /agent/v1/commands/{id}/result", s.requireAgent(http.HandlerFunc(s.agentCommandResult)))
	s.mux.Handle("POST /agent/v1/reports", s.requireAgent(http.HandlerFunc(s.agentReport)))
	s.mux.Handle("POST /agent/v1/events", s.requireAgent(http.HandlerFunc(s.agentEvents)))
	s.mux.Handle("/", s.staticHandler())
}

func securityHeaders(next http.Handler, inlineScripts []string) http.Handler {
	scriptSources := "'self'"
	for _, hash := range inlineScripts {
		scriptSources += " 'sha256-" + hash + "'"
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src "+scriptSources+"; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'")
		next.ServeHTTP(w, r)
	})
}

// Next's static export includes small inline bootstrap/Flight scripts. Rather
// than weakening script-src with unsafe-inline, hash the exact script bodies
// once at startup. The installed Web assets are immutable for the lifetime of
// the Controller and upgrades restart the service, so the policy and files stay
// in lockstep.
func inlineScriptHashes(webDir string) ([]string, error) {
	if webDir == "" {
		return nil, nil
	}
	data, err := os.ReadFile(filepath.Join(webDir, "index.html"))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, errors.New("read web entrypoint for content security policy")
	}
	lower := strings.ToLower(string(data))
	result := []string{}
	for offset := 0; ; {
		start := strings.Index(lower[offset:], "<script")
		if start < 0 {
			break
		}
		start += offset
		tagEnd := strings.IndexByte(lower[start:], '>')
		if tagEnd < 0 {
			break
		}
		tagEnd += start
		closeAt := strings.Index(lower[tagEnd+1:], "</script>")
		if closeAt < 0 {
			break
		}
		closeAt += tagEnd + 1
		tag := lower[start : tagEnd+1]
		if !strings.Contains(tag, " src=") && !strings.Contains(tag, " src =") {
			digest := sha256.Sum256(data[tagEnd+1 : closeAt])
			result = append(result, base64.StdEncoding.EncodeToString(digest[:]))
		}
		offset = closeAt + len("</script>")
	}
	return result, nil
}
func (s *Server) staticHandler() http.Handler {
	if s.webDir == "" {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			writeError(w, http.StatusNotFound, "not_found", "not found")
		})
	}
	root := filepath.Clean(s.webDir)
	files := http.FileServer(http.Dir(root))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/") || strings.HasPrefix(r.URL.Path, "/agent/") {
			writeError(w, 404, "not_found", "API endpoint not found")
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
			return
		}
		clean := filepath.Clean("/" + r.URL.Path)
		candidate := filepath.Join(root, strings.TrimPrefix(clean, "/"))
		if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
			if typ := mime.TypeByExtension(filepath.Ext(candidate)); typ != "" {
				w.Header().Set("Content-Type", typ)
			}
			files.ServeHTTP(w, r)
			return
		}
		index := filepath.Join(root, "index.html")
		if _, err := os.Stat(index); err != nil {
			writeError(w, http.StatusNotFound, "not_found", "web interface is not installed")
			return
		}
		http.ServeFile(w, r, index)
	})
}
func (s *Server) health(w http.ResponseWriter, r *http.Request) {
	if err := s.store.Ping(r.Context()); err != nil {
		writeError(w, 503, "database_unavailable", "database unavailable")
		return
	}
	writeJSON(w, 200, map[string]any{"status": "ok"})
}
func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
func writeError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, map[string]any{"error": map[string]string{"code": code, "message": message}})
}

const maxJSONRequestBody = 4 << 20

func decodeJSON(w http.ResponseWriter, r *http.Request, dst any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, maxJSONRequestBody)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		writeError(w, 400, "invalid_json", "invalid JSON request")
		return false
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		writeError(w, 400, "invalid_json", "request must contain one JSON object")
		return false
	}
	return true
}
func statusFor(err error) int {
	switch {
	case errors.Is(err, store.ErrNotFound):
		return 404
	case errors.Is(err, store.ErrUnauthorized):
		return 401
	case errors.Is(err, store.ErrConflict), errors.Is(err, store.ErrTokenExhausted):
		return 409
	case errors.Is(err, store.ErrTokenExpired):
		return 410
	default:
		return 500
	}
}
func (s *Server) fail(w http.ResponseWriter, err error) {
	status := statusFor(err)
	if status == 500 {
		s.log.Error("request failed", "error", err)
		writeError(w, status, "internal_error", "internal server error")
		return
	}
	writeError(w, status, strings.ReplaceAll(strings.ToLower(http.StatusText(status)), " ", "_"), http.StatusText(status))
}

type ctxKey int

const (
	adminKey ctxKey = iota
	deviceKey
	agentBodySizeKey
)

func adminFrom(ctx context.Context) domain.Admin   { return ctx.Value(adminKey).(domain.Admin) }
func deviceFrom(ctx context.Context) domain.Device { return ctx.Value(deviceKey).(domain.Device) }
func agentBodySize(ctx context.Context) int {
	size, _ := ctx.Value(agentBodySizeKey).(int)
	return size
}
func bearer(r *http.Request) string {
	v := r.Header.Get("Authorization")
	if len(v) > 7 && strings.EqualFold(v[:7], "Bearer ") {
		return strings.TrimSpace(v[7:])
	}
	return ""
}
func (s *Server) requireAdmin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := s.sessionCookieSecurity(r); err != nil {
			writeError(w, http.StatusForbidden, "insecure_admin_transport", err.Error())
			return
		}
		token := bearer(r)
		viaCookie := false
		if token == "" {
			if c, err := r.Cookie(sessionCookie); err == nil {
				token = c.Value
				viaCookie = true
			}
		}
		if token == "" {
			writeError(w, 401, "unauthorized", "authentication required")
			return
		}
		admin, err := s.store.AdminBySession(r.Context(), secret.Hash(token), s.now())
		if err != nil {
			writeError(w, 401, "unauthorized", "invalid or expired session")
			return
		}
		if viaCookie && r.Method != http.MethodGet && r.Method != http.MethodHead && r.Method != http.MethodOptions && !s.validSameOrigin(r) {
			writeError(w, 403, "origin_mismatch", "request origin is not allowed")
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), adminKey, admin)))
	})
}
func (s *Server) requireAgent(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := bearer(r)
		if token == "" {
			writeError(w, 401, "unauthorized", "device credential required")
			return
		}
		now := s.now().UTC()
		source := agentSourceLimitKey(s.remoteIP(r))
		// A normal Agent uses well under ten requests per minute. These generous
		// ceilings accommodate large NATs while bounding work from a stolen
		// credential or a single abusive source before the SQLite lookup.
		if !s.agentSourceLimiter.allowEvicting(source, now, 600) {
			w.Header().Set("Retry-After", "60")
			writeError(w, http.StatusTooManyRequests, "agent_rate_limited", "device request rate exceeded")
			return
		}
		device, err := s.store.AgentDevice(r.Context(), secret.Hash(token))
		if err != nil {
			writeError(w, 401, "unauthorized", "invalid device credential")
			return
		}
		timestampText := r.Header.Get("X-WitShield-Timestamp")
		nonce := r.Header.Get("X-WitShield-Nonce")
		signature := r.Header.Get("X-WitShield-Signature")
		timestampMillis, parseErr := strconv.ParseInt(timestampText, 10, 64)
		nonceBytes, nonceErr := base64.RawURLEncoding.DecodeString(nonce)
		if parseErr != nil || nonceErr != nil || len(nonceBytes) < 16 || len(nonceBytes) > 32 || len(signature) > 256 {
			writeError(w, http.StatusUnauthorized, "invalid_device_proof", "a valid signed device request is required")
			return
		}
		signedAt := time.UnixMilli(timestampMillis).UTC()
		if signedAt.Before(now.Add(-5*time.Minute)) || signedAt.After(now.Add(5*time.Minute)) {
			writeError(w, http.StatusUnauthorized, "expired_device_proof", "device request proof is outside the accepted time window")
			return
		}
		body, readErr := io.ReadAll(http.MaxBytesReader(w, r.Body, maxJSONRequestBody))
		if readErr != nil {
			writeError(w, http.StatusBadRequest, "request_body_too_large", "agent request body is invalid or too large")
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
		requestURI := r.URL.EscapedPath()
		if r.URL.RawQuery != "" {
			requestURI += "?" + r.URL.RawQuery
		}
		proof := identity.AgentRequestProof{DeviceID: device.ID, Method: r.Method, RequestURI: requestURI, Timestamp: timestampText, Nonce: nonce, Body: body}
		if err = identity.VerifyAgentRequest(device.IdentityKey, signature, proof); err != nil {
			writeError(w, http.StatusUnauthorized, "invalid_device_proof", "a valid signed device request is required")
			return
		}
		// Apply the authenticated device budget before persisting the replay
		// nonce. The signature has already been verified, so a leaked bearer
		// without the Ed25519 private key still cannot consume this budget; a
		// compromised device, however, cannot amplify rejected requests into an
		// unbounded durable nonce table.
		if !s.agentRequestLimiter.allowDeviceAndGlobal(device.ID, now, 1, agentDeviceRequestsPerMinute, agentGlobalRequestsPerMinute) {
			w.Header().Set("Retry-After", "60")
			writeError(w, http.StatusTooManyRequests, "agent_rate_limited", "device request rate exceeded")
			return
		}
		if err = s.store.ConsumeAgentRequestNonce(r.Context(), device.ID, nonce, now.Add(10*time.Minute), now); err != nil {
			if errors.Is(err, store.ErrConflict) {
				writeError(w, http.StatusUnauthorized, "replayed_device_proof", "device request proof was already used")
				return
			}
			s.fail(w, err)
			return
		}
		ctx := context.WithValue(r.Context(), deviceKey, device)
		ctx = context.WithValue(ctx, agentBodySizeKey, len(body))
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func agentSourceLimitKey(ip net.IP) string {
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return "invalid:" + ip.String()
	}
	addr = addr.Unmap()
	if addr.Is6() {
		return "ipv6:" + netip.PrefixFrom(addr, 64).Masked().String()
	}
	return "ipv4:" + addr.String()
}

const (
	agentDeviceRequestsPerMinute = 120
	agentGlobalRequestsPerMinute = 20_000
	agentDeviceWorkPerMinute     = 2_500
	agentGlobalWorkPerMinute     = 20_000
)

func (s *Server) admitAgentWork(w http.ResponseWriter, r *http.Request, base, itemCost, items int) bool {
	bodyCost := (agentBodySize(r.Context()) + 4095) / 4096
	cost := base + itemCost*items + bodyCost
	if !s.agentWorkLimiter.allowDeviceAndGlobal(deviceFrom(r.Context()).ID, s.now().UTC(), cost, agentDeviceWorkPerMinute, agentGlobalWorkPerMinute) {
		w.Header().Set("Retry-After", "60")
		writeError(w, http.StatusTooManyRequests, "agent_work_rate_limited", "device work budget exceeded")
		return false
	}
	return true
}

func (s *Server) beginAgentWrite(w http.ResponseWriter) (func(), bool) {
	select {
	case s.agentWrites <- struct{}{}:
		return func() { <-s.agentWrites }, true
	default:
		w.Header().Set("Retry-After", "1")
		writeError(w, http.StatusTooManyRequests, "controller_write_busy", "Controller write capacity is busy; retry shortly")
		return nil, false
	}
}
func (s *Server) validSameOrigin(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true
	}
	scheme, host, err := parseOrigin(origin)
	if err != nil {
		return false
	}
	expectedScheme := "http"
	if s.secureRequest(r) {
		expectedScheme = "https"
	}
	return scheme == expectedScheme && strings.EqualFold(host, r.Host)
}
func parseOrigin(origin string) (string, string, error) {
	if !strings.Contains(origin, "://") {
		return "", "", errors.New("invalid origin")
	}
	parts := strings.SplitN(origin, "://", 2)
	if parts[0] != "http" && parts[0] != "https" {
		return "", "", errors.New("invalid origin")
	}
	if strings.ContainsAny(parts[1], "/?#@") {
		return "", "", errors.New("invalid origin")
	}
	return parts[0], parts[1], nil
}
func peerIP(r *http.Request) net.IP {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	return net.ParseIP(host)
}

func parseTrustedProxies(values []string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			address, addressErr := netip.ParseAddr(value)
			if addressErr != nil {
				return nil, errors.New("invalid trusted proxy IP or CIDR")
			}
			prefix = netip.PrefixFrom(address, address.BitLen())
		}
		out = append(out, prefix.Masked())
	}
	return out, nil
}

func (s *Server) isTrustedProxy(ip net.IP) bool {
	address, ok := netip.AddrFromSlice(ip)
	if !ok {
		return false
	}
	address = address.Unmap()
	for _, prefix := range s.trustedProxies {
		if prefix.Contains(address) {
			return true
		}
	}
	return false
}

func (s *Server) remoteIP(r *http.Request) net.IP {
	peer := peerIP(r)
	if !s.isTrustedProxy(peer) {
		return peer
	}
	chain := strings.Split(r.Header.Get("X-Forwarded-For"), ",")
	for i := len(chain) - 1; i >= 0; i-- {
		ip := net.ParseIP(strings.TrimSpace(chain[i]))
		if ip == nil {
			return peer // malformed chains are ignored in full
		}
		if !s.isTrustedProxy(ip) {
			return ip
		}
	}
	return peer
}

func (s *Server) secureRequest(r *http.Request) bool {
	return r.TLS != nil || (s.isTrustedProxy(peerIP(r)) && strings.EqualFold(strings.TrimSpace(r.Header.Get("X-Forwarded-Proto")), "https"))
}

func (s *Server) sessionCookieSecurity(r *http.Request) (bool, error) {
	if s.secureRequest(r) {
		return true, nil
	}
	localTransport, _ := r.Context().Value(localHTTPTransportKey{}).(bool)
	if localTransport && loopbackAuthority(r.Host) {
		return false, nil
	}
	return false, errors.New("administrator access requires HTTPS or an explicitly configured loopback-only HTTP deployment")
}

func loopbackAuthority(authority string) bool {
	host := authority
	if parsedHost, _, err := net.SplitHostPort(authority); err == nil {
		host = parsedHost
	} else if strings.HasPrefix(authority, "[") && strings.HasSuffix(authority, "]") {
		host = strings.TrimSuffix(strings.TrimPrefix(authority, "["), "]")
	} else if strings.Contains(authority, ":") {
		return false
	}
	host = strings.TrimSuffix(strings.TrimSpace(host), ".")
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
func constantEqual(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

type loginLimiter struct {
	mu        sync.Mutex
	attempts  map[string][]time.Time
	lastSweep time.Time
	maxKeys   int
}

func newLoginLimiter() *loginLimiter {
	return &loginLimiter{attempts: map[string][]time.Time{}, maxKeys: 10_000}
}
func (l *loginLimiter) allow(key string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	cut := now.Add(-10 * time.Minute)
	if l.lastSweep.IsZero() || now.Sub(l.lastSweep) >= time.Minute || len(l.attempts) >= l.maxKeys {
		for candidate, attempts := range l.attempts {
			alive := attempts[:0]
			for _, attempt := range attempts {
				if attempt.After(cut) {
					alive = append(alive, attempt)
				}
			}
			if len(alive) == 0 {
				delete(l.attempts, candidate)
			} else {
				l.attempts[candidate] = alive
			}
		}
		l.lastSweep = now
	}
	if _, exists := l.attempts[key]; !exists && len(l.attempts) >= l.maxKeys {
		return false // fail closed under a distributed source-address flood
	}
	items := l.attempts[key][:0]
	for _, t := range l.attempts[key] {
		if t.After(cut) {
			items = append(items, t)
		}
	}
	if len(items) >= 10 {
		l.attempts[key] = items
		return false
	}
	l.attempts[key] = append(items, now)
	return true
}
func (l *loginLimiter) clear(key string) { l.mu.Lock(); delete(l.attempts, key); l.mu.Unlock() }
