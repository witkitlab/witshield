package controllercmd

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
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
	trustedProxies := strings.FieldsFunc(*trustedProxyText, func(r rune) bool { return r == ',' || r == ' ' })
	api, err := httpapi.New(httpapi.Config{Store: db, Vault: vault, Version: version, BootstrapToken: effectiveBootstrap, WebDir: *webDir, Logger: slog.Default(), TrustedProxies: trustedProxies})
	if err != nil {
		return err
	}
	sched := scheduler.New(db, slog.Default())
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
	go runMaintenance(ctx, db, slog.Default())
	server := &http.Server{Addr: *listen, Handler: api.Handler(), ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 45 * time.Second, IdleTimeout: 90 * time.Second, MaxHeaderBytes: 32 << 10}
	errCh := make(chan error, 1)
	go func() {
		slog.Info("WitShield controller listening", "address", *listen)
		errCh <- server.ListenAndServe()
	}()
	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
		return ctx.Err()
	case err = <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}

func runMaintenance(ctx context.Context, db *store.Store, log *slog.Logger) {
	ticker := time.NewTicker(time.Minute)
	compactTicker := time.NewTicker(6 * time.Hour)
	defer ticker.Stop()
	defer compactTicker.Stop()
	if err := db.Compact(ctx, time.Now().UTC()); err != nil && !errors.Is(err, context.Canceled) {
		log.Error("controller compaction failed", "error", err)
	}
	for {
		if err := db.Maintain(ctx, time.Now().UTC()); err != nil && !errors.Is(err, context.Canceled) {
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
