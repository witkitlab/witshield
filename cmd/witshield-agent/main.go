package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"log/slog"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/witkitlab/witshield/internal/agent"
)

var version = "dev"
var commit = "unknown"
var buildDate = "unknown"

func main() {
	versionFlag := flag.Bool("version", false, "print version and exit")
	controller := flag.String("controller-url", env("WITSHIELD_CONTROLLER_URL", ""), "WitShield controller URL")
	enrollment := flag.String("enrollment-token", env("WITSHIELD_ENROLLMENT_TOKEN", ""), "one-use enrollment token")
	enrollmentFile := flag.String("enrollment-token-file", env("WITSHIELD_ENROLLMENT_TOKEN_FILE", ""), "one-use enrollment token file")
	consume := flag.Bool("consume-enrollment-token", envBool("WITSHIELD_CONSUME_ENROLLMENT_TOKEN", false), "remove a native token file after successful enrollment")
	name := flag.String("name", env("WITSHIELD_DEVICE_NAME", ""), "device display name")
	data := flag.String("data-dir", env("WITSHIELD_DATA_DIR", "/var/lib/witshield-agent"), "agent state directory")
	intervalText := flag.String("interval", env("WITSHIELD_SCAN_INTERVAL", "24h"), "initial Controller scan schedule interval")
	hostRoot := flag.String("host-root", env("WITSHIELD_HOST_ROOT", "/"), "explicit host filesystem root for observer mode")
	authLog := flag.String("auth-log", env("WITSHIELD_AUTH_LOG", ""), "optional explicit SSH authentication log path")
	journalctl := flag.String("journalctl", env("WITSHIELD_JOURNALCTL", "/usr/bin/journalctl"), "fixed journalctl executable used for SSH security events")
	runtimeLog := flag.String("runtime-event-log", env("WITSHIELD_RUNTIME_EVENT_LOG", "/var/log/falco/events.jsonl"), "optional Falco-compatible JSONL runtime event stream")
	observer := flag.Bool("observer-only", envBool("WITSHIELD_OBSERVER_ONLY", false), "disable every privileged action and scan the mounted host root read-only")
	helperSocket := flag.String("helper-socket", env("WITSHIELD_HELPER_SOCKET", "/run/witshield/helper.sock"), "privileged helper Unix socket")
	helperToken := flag.String("helper-token-file", env("WITSHIELD_HELPER_TOKEN_FILE", "/etc/witshield/helper.token"), "privileged helper token file")
	flag.Parse()
	if *versionFlag {
		fmt.Printf("witshield-agent %s (commit %s, built %s)\n", version, commit, buildDate)
		return
	}
	interval, err := time.ParseDuration(*intervalText)
	if err != nil {
		log.Fatalf("invalid scan interval: %v", err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	runner, err := agent.New(ctx, agent.Config{ControllerURL: *controller, Name: *name, DataDir: *data, EnrollmentToken: *enrollment, EnrollmentTokenFile: *enrollmentFile, ConsumeEnrollmentToken: *consume, Version: version, ScanInterval: interval, HostRoot: *hostRoot, AuthLogPath: *authLog, JournalctlPath: *journalctl, RuntimeEventLogPath: *runtimeLog, ObserverOnly: *observer, HelperSocket: *helperSocket, HelperTokenFile: *helperToken, Logger: slog.Default()})
	if err != nil {
		log.Fatal(err)
	}
	if err = runner.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
		log.Fatal(err)
	}
}
func env(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}
	return fallback
}
func envBool(key string, fallback bool) bool {
	value, ok := os.LookupEnv(key)
	if !ok {
		return fallback
	}
	parsed, err := strconv.ParseBool(value)
	if err != nil {
		log.Fatalf("invalid boolean %s", key)
	}
	return parsed
}
