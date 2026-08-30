package controllercmd

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/witkitlab/witshield/internal/domain"
	"github.com/witkitlab/witshield/internal/httpapi"
	"github.com/witkitlab/witshield/internal/ids"
	"github.com/witkitlab/witshield/internal/scheduler"
	"github.com/witkitlab/witshield/internal/secret"
	"github.com/witkitlab/witshield/internal/store"
)

func Main(ctx context.Context, args []string) error {
	return MainVersion(ctx, args, "dev")
}

func MainVersion(ctx context.Context, args []string, version string) error {
	fs := flag.NewFlagSet("witshieldd", flag.ContinueOnError)
	listen := fs.String("listen", env("WITSHIELD_LISTEN", "127.0.0.1:8080"), "HTTP listen address")
	dataDir := fs.String("data-dir", env("WITSHIELD_DATA_DIR", "/var/lib/witshield"), "controller data directory")
	masterKeyFile := fs.String("master-key-file", env("WITSHIELD_MASTER_KEY_FILE", ""), "master encryption key file")
	bootstrapToken := fs.String("bootstrap-token", env("WITSHIELD_BOOTSTRAP_TOKEN", ""), "initial administrator bootstrap token")
	bootstrapTokenFile := fs.String("bootstrap-token-file", env("WITSHIELD_BOOTSTRAP_TOKEN_FILE", ""), "initial administrator bootstrap token file")
	initialEnrollmentFile := fs.String("initial-enrollment-token-file", env("WITSHIELD_INITIAL_ENROLLMENT_TOKEN_FILE", ""), "optional one-use standalone enrollment token file")
	webDir := fs.String("web-dir", env("WITSHIELD_WEB_DIR", "/usr/share/witshield/web"), "static web application directory")
	trustedProxyText := fs.String("trusted-proxies", env("WITSHIELD_TRUSTED_PROXIES", ""), "comma-separated reverse proxy IPs or CIDRs whose forwarded headers are trusted")
	localHTTPListen := fs.String("local-http-listen", env("WITSHIELD_LOCAL_HTTP_LISTEN", ""), "optional isolated listener published only through a host loopback transport")
	agentUnixListen := fs.String("agent-unix-listen", env("WITSHIELD_AGENT_UNIX_LISTEN", ""), "optional installation-owned Unix socket for a local native Agent")
	agentUnixGroup := fs.String("agent-unix-group", env("WITSHIELD_AGENT_UNIX_GROUP", "witshield-controller"), "group allowed to connect to the local Agent Unix socket")
	upgradeGateFile := fs.String("upgrade-gate-file", env("WITSHIELD_UPGRADE_GATE_FILE", ""), "optional root-owned marker that blocks non-health traffic during a transactional upgrade")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if err := os.MkdirAll(*dataDir, 0o700); err != nil {
		return err
	}
	if err := os.Chmod(*dataDir, 0o700); err != nil {
		return err
	}
	if *masterKeyFile == "" {
		*masterKeyFile = filepath.Join(*dataDir, "master.key")
	}
	if *upgradeGateFile != "" && (!filepath.IsAbs(*upgradeGateFile) || filepath.Clean(*upgradeGateFile) != *upgradeGateFile) {
		return errors.New("upgrade gate file must be one absolute clean path")
	}
	key, err := secret.LoadOrCreateKey(*masterKeyFile)
	if err != nil {
		return fmt.Errorf("master key: %w", err)
	}
	vault, err := secret.New(key)
	if err != nil {
		return err
	}
	db, err := store.Open(ctx, filepath.Join(*dataDir, "witshield.db"))
	if err != nil {
		return err
	}
	defer db.Close()
	adminCount, err := db.AdminCount(ctx)
	if err != nil {
		return err
	}
	effectiveBootstrap := strings.TrimSpace(*bootstrapToken)
	if adminCount == 0 && *bootstrapTokenFile != "" {
		value, readErr := secret.ReadFile(*bootstrapTokenFile)
		if readErr != nil {
			if !errors.Is(readErr, os.ErrNotExist) {
				return fmt.Errorf("bootstrap token file: %w", readErr)
			}
		} else {
			effectiveBootstrap = strings.TrimSpace(value)
		}
	}
	if effectiveBootstrap != "" && len(effectiveBootstrap) < 24 {
		return errors.New("bootstrap token must contain at least 24 characters")
	}
	if err = seedEnrollment(ctx, db, *initialEnrollmentFile); err != nil {
		return err
	}
	if *localHTTPListen != "" {
		if loopbackListenAddress(*listen) {
			return errors.New("local-http-listen is unnecessary when the primary listener is already loopback-only")
		}
		if !isolatedLocalListenAddress(*localHTTPListen) {
			return errors.New("local-http-listen must name a dedicated non-wildcard interface and port")
		}
		if strings.EqualFold(strings.TrimSpace(*localHTTPListen), strings.TrimSpace(*listen)) {
			return errors.New("local-http-listen must differ from the primary listener")
		}
	}
	trustedProxies := strings.FieldsFunc(*trustedProxyText, func(r rune) bool { return r == ',' || r == ' ' })
	api, err := httpapi.New(httpapi.Config{Store: db, Vault: vault, Version: version, BootstrapToken: effectiveBootstrap, WebDir: *webDir, Logger: slog.Default(), TrustedProxies: trustedProxies})
	if err != nil {
		return err
	}
	sched := scheduler.New(db, slog.Default())
	sched.SetObserver(func(err error) { api.MarkWorkerHealth("scheduler", err) })
	go func() {
		if err := sched.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
			slog.Error("scheduler stopped", "error", err)
		}
	}()
	go func() {
		if err := api.RunNotificationWorker(ctx); err != nil && !errors.Is(err, context.Canceled) {
			slog.Error("notification worker stopped", "error", err)
		}
	}()
	go func() {
		if err := api.RunSecurityEngineerWorker(ctx); err != nil && !errors.Is(err, context.Canceled) {
			slog.Error("AI security engineer worker stopped", "error", err)
		}
	}()
	go runMaintenance(ctx, db, api, slog.Default())
	primaryHandler := api.Handler()
	if loopbackListenAddress(*listen) {
		primaryHandler = api.LocalHTTPHandler()
	}
	primaryHandler = upgradeGateHandler(primaryHandler, *upgradeGateFile)
	servers := []*http.Server{controllerHTTPServer(*listen, primaryHandler)}
	if *localHTTPListen != "" {
		servers = append(servers, controllerHTTPServer(*localHTTPListen, upgradeGateHandler(api.LocalHTTPHandler(), *upgradeGateFile)))
	}
	var agentListener net.Listener
	var agentServer *http.Server
	if *agentUnixListen != "" {
		agentListener, err = listenAgentUnix(*agentUnixListen, *agentUnixGroup)
		if err != nil {
			return fmt.Errorf("agent Unix listener: %w", err)
		}
		defer func() {
			_ = agentListener.Close()
			_ = os.Remove(*agentUnixListen)
		}()
		agentServer = controllerHTTPServer("", upgradeGateHandler(agentOnlyHandler(api.Handler()), *upgradeGateFile))
	}
	errCh := make(chan error, len(servers)+1)
	for _, server := range servers {
		go func(server *http.Server) {
			slog.Info("WitShield controller listening", "address", server.Addr)
			errCh <- server.ListenAndServe()
		}(server)
	}
	if agentServer != nil {
		go func() {
			slog.Info("WitShield controller listening for the native Agent", "socket", *agentUnixListen)
			errCh <- agentServer.Serve(agentListener)
		}()
	}
	shutdown := func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		for _, server := range servers {
			_ = server.Shutdown(shutdownCtx)
		}
		if agentServer != nil {
			_ = agentServer.Shutdown(shutdownCtx)
		}
	}
	select {
	case <-ctx.Done():
		shutdown()
		return ctx.Err()
	case err = <-errCh:
		shutdown()
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}

func upgradeGateHandler(next http.Handler, gateFile string) http.Handler {
	if gateFile == "" {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, err := os.Lstat(gateFile)
		if errors.Is(err, os.ErrNotExist) {
			next.ServeHTTP(w, r)
			return
		}
		if r.URL.Path == "/healthz" || r.URL.Path == "/readyz" {
			next.ServeHTTP(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Retry-After", "5")
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte(`{"error":{"code":"upgrade_in_progress","message":"the controller is completing a verified upgrade"}}`))
	})
}

func agentOnlyHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/healthz" && !strings.HasPrefix(r.URL.Path, "/agent/") {
			http.NotFound(w, r)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func listenAgentUnix(path, groupName string) (net.Listener, error) {
	clean := filepath.Clean(path)
	if !filepath.IsAbs(clean) || clean != path || len(clean) > 100 {
		return nil, errors.New("socket path must be one short absolute clean path")
	}
	parent := filepath.Dir(clean)
	parentInfo, err := os.Lstat(parent)
	if err != nil || !parentInfo.IsDir() || parentInfo.Mode()&os.ModeSymlink != 0 || parentInfo.Mode().Perm()&0022 != 0 {
		return nil, errors.New("socket parent must be an existing non-symlink directory not writable by group or others")
	}
	group, err := user.LookupGroup(groupName)
	if err != nil {
		return nil, fmt.Errorf("look up socket group: %w", err)
	}
	groupID, err := strconv.Atoi(group.Gid)
	if err != nil || groupID < 0 {
		return nil, errors.New("socket group has an invalid numeric ID")
	}
	if info, statErr := os.Lstat(clean); statErr == nil {
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || info.Mode()&os.ModeSocket == 0 || info.Mode()&os.ModeSymlink != 0 || int(stat.Uid) != os.Geteuid() {
			return nil, errors.New("refusing unsafe pre-existing Agent socket")
		}
		if err = os.Remove(clean); err != nil {
			return nil, err
		}
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return nil, statErr
	}
	listener, err := net.Listen("unix", clean)
	if err != nil {
		return nil, err
	}
	fail := func(cause error) (net.Listener, error) {
		_ = listener.Close()
		_ = os.Remove(clean)
		return nil, cause
	}
	if err = os.Chown(clean, os.Geteuid(), groupID); err != nil {
		return fail(err)
	}
	if err = os.Chmod(clean, 0660); err != nil {
		return fail(err)
	}
	return listener, nil
}

func controllerHTTPServer(address string, handler http.Handler) *http.Server {
	// Administrator-triggered AI investigations have a bounded 90-second
	// upstream window. Keep the connection alive beyond that handler deadline so
	// the client receives the stored result instead of an unexplained EOF.
	return &http.Server{Addr: address, Handler: handler, ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 2 * time.Minute, IdleTimeout: 90 * time.Second, MaxHeaderBytes: 32 << 10}
}

func runMaintenance(ctx context.Context, db *store.Store, api *httpapi.Server, log *slog.Logger) {
	ticker := time.NewTicker(time.Minute)
	compactTicker := time.NewTicker(6 * time.Hour)
	defer ticker.Stop()
	defer compactTicker.Stop()
	if err := db.Compact(ctx, time.Now().UTC()); err != nil && !errors.Is(err, context.Canceled) {
		log.Error("controller compaction failed", "error", err)
	}
	for {
		err := db.Maintain(ctx, time.Now().UTC())
		api.MarkWorkerHealth("maintenance", err)
		if err != nil && !errors.Is(err, context.Canceled) {
			log.Error("controller maintenance failed", "error", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		case <-compactTicker.C:
			if err := db.Compact(ctx, time.Now().UTC()); err != nil && !errors.Is(err, context.Canceled) {
				log.Error("controller compaction failed", "error", err)
			}
		}
	}
}
func seedEnrollment(ctx context.Context, db *store.Store, path string) error {
	if path == "" {
		return nil
	}
	count, err := db.DeviceCount(ctx)
	if err != nil {
		return err
	}
	if count > 0 {
		return consumeNativeTokenFile(path)
	}
	value, err := secret.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("initial enrollment token: %w", err)
	}
	raw := strings.TrimSpace(value)
	if len(raw) < 32 {
		return errors.New("initial enrollment token must contain at least 32 characters")
	}
	hash := secret.Hash(raw)
	expires := time.Now().UTC().Add(15 * time.Minute)
	item := domain.EnrollmentToken{ID: "enr_initial_" + hash[:16], Name: "standalone-local-agent", Hint: ids.Hint(raw), MaxUses: 1, ExpiresAt: &expires, CreatedAt: time.Now().UTC()}
	if err = db.CreateEnrollmentToken(ctx, item, hash); err != nil && !errors.Is(err, store.ErrConflict) {
		return err
	}
	return consumeNativeTokenFile(path)
}

func consumeNativeTokenFile(path string) error {
	clean := filepath.Clean(path)
	if clean == "/run/secrets" || strings.HasPrefix(clean, "/run/secrets"+string(filepath.Separator)) {
		return nil // container secret mounts are read-only and lifecycle-managed
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("consume initial enrollment token: %w", err)
	}
	return nil
}
func env(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}
	return fallback
}

func loopbackListenAddress(address string) bool {
	host, _, err := net.SplitHostPort(strings.TrimSpace(address))
	if err != nil {
		return false
	}
	host = strings.TrimSuffix(strings.TrimSpace(host), ".")
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func isolatedLocalListenAddress(address string) bool {
	host, port, err := net.SplitHostPort(strings.TrimSpace(address))
	if err != nil || strings.TrimSpace(port) == "" {
		return false
	}
	host = strings.TrimSuffix(strings.TrimSpace(host), ".")
	return host != "" && host != "0.0.0.0" && host != "::" && host != "[::]"
}
