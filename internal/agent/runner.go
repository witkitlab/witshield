package agent

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/witkitlab/witshield/internal/action"
	"github.com/witkitlab/witshield/internal/domain"
	"github.com/witkitlab/witshield/internal/identity"
	"github.com/witkitlab/witshield/internal/scanner"
	"github.com/witkitlab/witshield/internal/secret"
)

const Version = "0.1.0"

type Config struct {
	ControllerURL, Name, DataDir, EnrollmentToken, EnrollmentTokenFile string
	Version                                                            string
	ConsumeEnrollmentToken                                             bool
	ScanInterval                                                       time.Duration
	HostRoot                                                           string
	AuthLogPath                                                        string
	JournalctlPath                                                     string
	RuntimeEventLogPath                                                string
	ObserverOnly                                                       bool
	HelperSocket, HelperTokenFile                                      string
	Logger                                                             *slog.Logger
}
type Runner struct {
	cfg      Config
	state    State
	client   *Client
	queue    *Queue
	scanner  *scanner.Scanner
	helper   *HelperClient
	log      *slog.Logger
	meta     map[string]string
	scanMu   sync.Mutex
	watcher  *authLogWatcher
	journal  *journalWatcher
	baseline *baselineWatcher
	network  *networkWatcher
	process  *processWatcher
	runtime  *runtimeLogWatcher
	healthMu sync.Mutex
	sensors  map[string]*localSensorHealth
}

func New(ctx context.Context, cfg Config) (*Runner, error) {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.Version == "" {
		cfg.Version = Version
	}
	if cfg.DataDir == "" {
		return nil, errors.New("data directory is required")
	}
	if cfg.ScanInterval == 0 {
		cfg.ScanInterval = 24 * time.Hour
	}
	if cfg.ScanInterval < 15*time.Minute {
		return nil, errors.New("scan interval must be at least 15 minutes")
	}
	if cfg.Name == "" {
		host, _ := os.Hostname()
		cfg.Name = host
	}
	if len(cfg.Name) > 100 {
		return nil, errors.New("device name is too long")
	}
	if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
		return nil, err
	}
	if err := os.Chmod(cfg.DataDir, 0o700); err != nil {
		return nil, err
	}
	statePath := filepath.Join(cfg.DataDir, "state.json")
	pendingPath := filepath.Join(cfg.DataDir, "pending-enrollment.json")
	state, err := LoadState(statePath)
	if errors.Is(err, os.ErrNotExist) {
		token := strings.TrimSpace(cfg.EnrollmentToken)
		if cfg.EnrollmentTokenFile != "" {
			value, readErr := secret.ReadFile(cfg.EnrollmentTokenFile)
			if readErr != nil {
				return nil, fmt.Errorf("read enrollment token: %w", readErr)
			}
			token = strings.TrimSpace(value)
		}
		if token == "" {
			return nil, errors.New("agent is not enrolled and no enrollment token was provided")
		}
		pending, pendingErr := LoadPendingEnrollment(pendingPath)
		if errors.Is(pendingErr, os.ErrNotExist) {
			pub, priv, identityErr := NewIdentity()
			if identityErr != nil {
				return nil, identityErr
			}
			pending = PendingEnrollment{IdentityPublicKey: pub, IdentityPrivateKey: priv}
			if pendingErr = SavePendingEnrollment(pendingPath, pending); pendingErr != nil {
				return nil, fmt.Errorf("persist pending enrollment identity: %w", pendingErr)
			}
		} else if pendingErr != nil {
			return nil, fmt.Errorf("load pending enrollment identity: %w", pendingErr)
		}
		enrollClient, err := NewClient(cfg.ControllerURL, "")
		if err != nil {
			return nil, err
		}
		hostname, _ := os.Hostname()
		device, deviceToken, err := enrollClient.Enroll(ctx, EnrollRequest{EnrollmentToken: token, Name: cfg.Name, Hostname: hostname, OS: runtime.GOOS, Arch: runtime.GOARCH, AgentVersion: cfg.Version, IdentityPublicKey: pending.IdentityPublicKey, IdentityPrivateKey: pending.IdentityPrivateKey, ScanInterval: cfg.ScanInterval.String(), ObserverOnly: cfg.ObserverOnly})
		if err != nil {
			return nil, fmt.Errorf("enroll agent: %w", err)
		}
		state = State{DeviceID: device.ID, DeviceToken: deviceToken, IdentityPublicKey: pending.IdentityPublicKey, IdentityPrivateKey: pending.IdentityPrivateKey, ObserverOnly: cfg.ObserverOnly}
		if err = SaveState(statePath, state); err != nil {
			return nil, err
		}
		if err = os.Remove(pendingPath); err != nil && !errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("remove pending enrollment identity: %w", err)
		}
		if cfg.ConsumeEnrollmentToken && cfg.EnrollmentTokenFile != "" && !strings.HasPrefix(filepath.Clean(cfg.EnrollmentTokenFile), "/run/secrets/") {
			if err = os.Remove(cfg.EnrollmentTokenFile); err != nil && !errors.Is(err, os.ErrNotExist) {
				return nil, fmt.Errorf("consume enrollment token: %w", err)
			}
		}
	} else if err != nil {
		return nil, err
	}
	if state.ObserverOnly != cfg.ObserverOnly {
		return nil, errors.New("observer capability differs from the signed enrollment; re-enroll this device to change modes")
	}
	client, err := NewClient(cfg.ControllerURL, state.DeviceToken)
	if err != nil {
		return nil, err
	}
	if err = client.SetIdentity(state.DeviceID, state.IdentityPrivateKey); err != nil {
		return nil, fmt.Errorf("configure request identity: %w", err)
	}
	queue, err := NewQueue(filepath.Join(cfg.DataDir, "queue"))
	if err != nil {
		return nil, err
	}
	host, err := scanner.NewSystemHost(cfg.HostRoot)
	if err != nil {
		return nil, fmt.Errorf("host root: %w", err)
	}
	scan := scanner.NewWithHost(host, cfg.ObserverOnly)
	var helper *HelperClient
	if !cfg.ObserverOnly {
		if cfg.HelperSocket == "" || cfg.HelperTokenFile == "" {
			return nil, errors.New("native mode requires the privileged helper socket and token file")
		}
		token, err := LoadHelperToken(cfg.HelperTokenFile)
		if err != nil {
			return nil, fmt.Errorf("load helper token: %w", err)
		}
		helper = &HelperClient{Socket: cfg.HelperSocket, Token: token}
	}
	hostname, _ := os.Hostname()
	meta := map[string]string{"Name": cfg.Name, "Hostname": hostname, "OS": runtime.GOOS, "Arch": runtime.GOARCH, "AgentVersion": cfg.Version}
	authLogPath, err := resolveAuthLogPath(cfg.HostRoot, cfg.AuthLogPath)
	if err != nil {
		return nil, err
	}
	watcher := &authLogWatcher{path: authLogPath, statePath: filepath.Join(cfg.DataDir, "auth-log.offset")}
	var journal *journalWatcher
	if !cfg.ObserverOnly && runtime.GOOS == "linux" {
		if cfg.JournalctlPath == "" {
			cfg.JournalctlPath = "/usr/bin/journalctl"
		}
		if info, statErr := os.Lstat(cfg.JournalctlPath); statErr == nil && info.Mode().IsRegular() && info.Mode()&0o111 != 0 {
			journal = &journalWatcher{executable: cfg.JournalctlPath, statePath: filepath.Join(cfg.DataDir, "journal.cursor"), runner: execJournalRunner{}}
		}
	}
	baseline := &baselineWatcher{hostRoot: cfg.HostRoot, statePath: filepath.Join(cfg.DataDir, "security-baseline.json"), now: time.Now}
	network := &networkWatcher{hostRoot: cfg.HostRoot, statePath: filepath.Join(cfg.DataDir, "network-baseline.json"), now: time.Now}
	process := &processWatcher{hostRoot: cfg.HostRoot, statePath: filepath.Join(cfg.DataDir, "process-baseline.json"), helper: helper, now: time.Now}
	var runtimeWatcher *runtimeLogWatcher
	if !cfg.ObserverOnly && runtime.GOOS == "linux" && strings.TrimSpace(cfg.RuntimeEventLogPath) != "" {
		if !filepath.IsAbs(cfg.RuntimeEventLogPath) {
			return nil, errors.New("runtime event log path must be absolute")
		}
		runtimeWatcher = &runtimeLogWatcher{path: filepath.Clean(cfg.RuntimeEventLogPath), statePath: filepath.Join(cfg.DataDir, "runtime-log.offset"), now: time.Now}
	}
	runner := &Runner{cfg: cfg, state: state, client: client, queue: queue, scanner: scan, helper: helper, log: cfg.Logger, meta: meta, watcher: watcher, journal: journal, baseline: baseline, network: network, process: process, runtime: runtimeWatcher}
	runner.sensors = initialSensorHealth(cfg.ObserverOnly, journal != nil)
	return runner, nil
}
func (r *Runner) Run(ctx context.Context) error {
	_ = r.queue.Flush(ctx, r.client)
	if err := r.client.Heartbeat(ctx, r.meta, r.sensorSnapshot()); err != nil {
		r.log.Warn("initial heartbeat failed", "error", err)
	}
	go r.periodic(ctx, 30*time.Second, r.heartbeat)
	go r.periodic(ctx, 15*time.Second, r.flush)
	go r.periodic(ctx, 5*time.Second, r.pollSecurityEvents)
	go r.periodic(ctx, time.Minute, r.pollHostBaseline)
	go r.periodic(ctx, 30*time.Second, r.pollNetworkBaseline)
	go r.periodic(ctx, 10*time.Second, r.pollProcessBaseline)
	go r.periodic(ctx, 2*time.Second, r.pollRuntimeEvents)
	// The Controller is the single authority for recurring scan schedules. The
	// Agent performs one startup scan for immediate visibility, then only scans
	// in response to a Controller command. ScanInterval is only an enrollment
	// hint used to seed that device's first Controller-owned schedule; it never
	// creates a second, device-local timer.
	go func() {
		if err := r.localScan(ctx); err != nil {
			r.log.Error("initial scan failed", "error", err)
		}
	}()
	syncFailures := 0
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		commands, err := r.client.Sync(ctx, 25*time.Second)
		if err != nil {
			syncFailures++
			r.log.Warn("command sync failed", "error", err)
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(backoffDuration(syncFailures)):
			}
			continue
		}
		syncFailures = 0
		for _, cmd := range commands {
			if err = r.handleCommand(ctx, cmd); err != nil {
				r.log.Error("command handling failed", "commandId", cmd.ID, "error", err)
			}
		}
	}
}

func (r *Runner) pollHostBaseline(ctx context.Context) error {
	if r.baseline == nil {
		return nil
	}
	events, err := r.baseline.Poll(ctx)
	if err != nil {
		r.recordSensor("host_baseline", "polling", err, 0, false)
		return err
	}
	r.recordSensor("host_baseline", "polling", nil, len(events), false)
	if err = r.queueSecurityEvents(events); err != nil {
		return err
	}
	if err = r.baseline.Commit(); err != nil {
		return err
	}
	return r.queue.Flush(ctx, r.client)
}

func (r *Runner) pollNetworkBaseline(ctx context.Context) error {
	if r.network == nil {
		return nil
	}
	events, err := r.network.Poll(ctx)
	if err != nil {
		r.recordSensor("network", "polling", err, 0, false)
		return err
	}
	r.recordSensor("network", "polling", nil, len(events), false)
	if err = r.queueSecurityEvents(events); err != nil {
		return err
	}
	if err = r.network.Commit(); err != nil {
		return err
	}
	return r.queue.Flush(ctx, r.client)
}

func (r *Runner) pollProcessBaseline(ctx context.Context) error {
	if r.process == nil {
		return nil
	}
	events, err := r.process.Poll(ctx)
	if err != nil {
		r.recordSensor("process", "procfs", err, 0, false)
		return err
	}
	r.recordSensor("process", "procfs", nil, len(events), false)
	if err = r.queueSecurityEvents(events); err != nil {
		return err
	}
	if err = r.process.Commit(); err != nil {
		return err
	}
	return r.queue.Flush(ctx, r.client)
}

func (r *Runner) pollRuntimeEvents(ctx context.Context) error {
	if r.runtime == nil {
		return nil
	}
	events, checkpoint, err := r.runtime.Poll(ctx)
	if errors.Is(err, os.ErrNotExist) || errors.Is(err, os.ErrPermission) {
		r.recordOptionalSensor("runtime", "falco_jsonl", "增强运行时传感器尚未接入；基础保护继续运行")
		return nil
	}
	if err != nil {
		r.recordSensor("runtime", "falco_jsonl", err, 0, false)
		return err
	}
	r.recordSensor("runtime", "falco_jsonl", nil, len(events), false)
	if err = r.queueSecurityEvents(events); err != nil {
		return err
	}
	if err = r.runtime.Commit(checkpoint); err != nil {
		return err
	}
	return r.queue.Flush(ctx, r.client)
}
func (r *Runner) periodic(ctx context.Context, every time.Duration, fn func(context.Context) error) {
	ticker := time.NewTicker(every)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := fn(ctx); err != nil {
				r.log.Warn("periodic agent task failed", "error", err)
			}
		}
	}
}
func (r *Runner) heartbeat(ctx context.Context) error {
	return r.client.Heartbeat(ctx, r.meta, r.sensorSnapshot())
}
func (r *Runner) flush(ctx context.Context) error { return r.queue.Flush(ctx, r.client) }
func (r *Runner) pollSecurityEvents(ctx context.Context) error {
	if r.journal != nil {
		events, cursor, err := r.journal.Poll(ctx)
		if err == nil {
			r.recordSensor("authentication", "journald", nil, len(events), false)
			if err = r.queueSecurityEvents(events); err != nil {
				return err
			}
			if err = r.journal.Commit(cursor); err != nil {
				return err
			}
			return r.queue.Flush(ctx, r.client)
		}
		r.recordSensor("authentication", "auth_log_fallback", err, 0, true)
		r.log.Warn("journald security event source unavailable; trying auth log", "error", err)
	}
	events, checkpoint, err := r.watcher.Poll(ctx)
	if err != nil {
		r.recordSensor("authentication", "auth_log_fallback", err, 0, true)
		return err
	}
	// Plain auth.log has weaker provenance than native journald even when it is
	// readable, so it can inform an investigation but never authorize action.
	r.recordSensor("authentication", "auth_log_fallback", nil, len(events), true)
	if !checkpoint.valid() {
		return nil
	}
	for _, event := range events {
		if event.Type == oversizedAuthLogEventType {
			r.log.Warn("discarded oversized unverified authentication log line", "eventId", event.ID, "checkpointOffset", checkpoint.Offset)
		}
	}
	if err = r.queueSecurityEvents(events); err != nil {
		return err
	}
	// The queue entry is durable before the offset advances, so a controller
	// outage cannot lose events. Event IDs make a crash-time replay harmless.
	if err = r.watcher.Commit(checkpoint); err != nil {
		return err
	}
	return r.queue.Flush(ctx, r.client)
}

func (r *Runner) queueSecurityEvents(events []domain.SecurityEvent) error {
	if len(events) == 0 {
		return nil
	}
	signature, err := identity.SignSecurityEventBatch(r.state.IdentityPrivateKey, identity.SecurityEventBatchProof{DeviceID: r.state.DeviceID, Events: events})
	if err != nil {
		return fmt.Errorf("sign security events: %w", err)
	}
	return r.queue.Enqueue("events", "", map[string]any{"events": events, "identitySignature": signature})
}
func (r *Runner) localScan(ctx context.Context) error {
	r.scanMu.Lock()
	defer r.scanMu.Unlock()
	report, err := r.scanner.Scan(ctx, r.state.DeviceID)
	if err != nil {
		return err
	}
	if err = r.queue.Enqueue("report", "", report); err != nil {
		return err
	}
	return r.queue.Flush(ctx, r.client)
}

func resolveAuthLogPath(hostRoot, configured string) (string, error) {
	if configured != "" {
		if !filepath.IsAbs(configured) {
			return "", errors.New("auth log path must be absolute")
		}
		return filepath.Clean(configured), nil
	}
	if hostRoot == "" {
		hostRoot = "/"
	}
	if !filepath.IsAbs(hostRoot) {
		return "", errors.New("host root must be absolute")
	}
	return filepath.Join(filepath.Clean(hostRoot), "var", "log", "auth.log"), nil
}
func (r *Runner) handleCommand(ctx context.Context, cmd domain.DeviceCommand) error {
	if (cmd.Type == domain.CommandExecuteAction || cmd.Type == domain.CommandRollback || cmd.Type == domain.CommandConfirm) && (cmd.CreatedAt.IsZero() || time.Since(cmd.CreatedAt) > domain.ActionCommandTTL || cmd.CreatedAt.After(time.Now().Add(5*time.Minute))) {
		authorized, err := r.client.StartCommand(ctx, cmd.ID)
		if err != nil {
			return fmt.Errorf("reject stale action command: %w", err)
		}
		if authorized {
			return errors.New("controller incorrectly authorized a stale action command")
		}
		return nil
	}
	switch cmd.Type {
	case domain.CommandScan:
		r.scanMu.Lock()
		report, err := r.scanner.Scan(ctx, r.state.DeviceID)
		r.scanMu.Unlock()
		result := map[string]any{"ok": err == nil}
		if err == nil {
			if qErr := r.queue.Enqueue("report", "", report); qErr != nil {
				return qErr
			}
			result["result"] = map[string]any{"reportId": report.ID}
		} else {
			result["error"] = err.Error()
		}
		if err = r.queue.Enqueue("command_result", cmd.ID, result); err != nil {
			return err
		}
		return r.queue.Flush(ctx, r.client)
	case domain.CommandExecuteAction, domain.CommandRollback, domain.CommandConfirm:
		authorized, err := r.client.StartCommand(ctx, cmd.ID)
		if err != nil {
			return fmt.Errorf("start action command: %w", err)
		}
		if !authorized {
			return nil
		}
		var payload struct {
			ActionID         string          `json:"actionId"`
			Type             action.Type     `json:"type"`
			Parameters       json.RawMessage `json:"parameters"`
			RollbackPayload  json.RawMessage `json:"rollbackPayload,omitempty"`
			PolicyAuthorized bool            `json:"policyAuthorized,omitempty"`
		}
		dec := json.NewDecoder(strings.NewReader(string(cmd.Payload)))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&payload); err != nil || dec.Decode(&struct{}{}) != io.EOF || payload.ActionID == "" || !knownActionType(payload.Type) || len(payload.Parameters) == 0 || !json.Valid(payload.Parameters) || (len(payload.RollbackPayload) > 0 && !json.Valid(payload.RollbackPayload)) {
			return r.queueActionResult(ctx, cmd.ID, map[string]any{"ok": false, "error": "invalid typed action payload"})
		}
		if r.cfg.ObserverOnly {
			return r.queueActionResult(ctx, cmd.ID, map[string]any{"ok": false, "error": "actions are disabled in observer-only mode"})
		}
		if r.helper == nil {
			return r.queueActionResult(ctx, cmd.ID, map[string]any{"ok": false, "error": "privileged helper is not configured"})
		}
		operation := action.OperationExecute
		if cmd.Type == domain.CommandRollback {
			operation = action.OperationRollback
		} else if cmd.Type == domain.CommandConfirm {
			operation = action.OperationConfirm
		}
		helperResult, err := r.helper.Run(ctx, cmd.ID, payload.ActionID, payload.Type, operation, payload.Parameters, payload.RollbackPayload)
		if err != nil {
			if errors.Is(err, ErrHelperExecutionIndeterminate) {
				return r.queueActionResult(ctx, cmd.ID, map[string]any{"ok": false, "error": action.ExecutionIndeterminateMessage})
			}
			return r.queueActionResult(ctx, cmd.ID, map[string]any{"ok": false, "error": "privileged helper unavailable: " + err.Error()})
		}
		return r.queueActionResult(ctx, cmd.ID, helperResult)
	default:
		return r.queueResult(ctx, cmd.ID, map[string]any{"ok": false, "error": "unsupported command type"})
	}
}

func knownActionType(value action.Type) bool {
	switch value {
	case action.TypePackageSecurityUpgrade, action.TypeSSHPasswordHardening, action.TypeTemporaryIPBan, action.TypeFilePermissionRepair, action.TypeTemporaryProcessSuspend:
		return true
	default:
		return false
	}
}

type signedCommandResult struct {
	OK                bool            `json:"ok"`
	Result            json.RawMessage `json:"result,omitempty"`
	RollbackPayload   json.RawMessage `json:"rollbackPayload,omitempty"`
	AuditReceipt      json.RawMessage `json:"auditReceipt,omitempty"`
	Error             string          `json:"error,omitempty"`
	IdentitySignature string          `json:"identitySignature"`
}

func (r *Runner) queueActionResult(ctx context.Context, commandID string, value any) error {
	encoded, err := json.Marshal(value)
	if err != nil {
		return err
	}
	var result signedCommandResult
	decoder := json.NewDecoder(strings.NewReader(string(encoded)))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(&result); err != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return errors.New("invalid internal action result")
	}
	result.IdentitySignature, err = identity.SignCommandResult(r.state.IdentityPrivateKey, identity.CommandResultProof{
		DeviceID: r.state.DeviceID, CommandID: commandID, OK: result.OK, Result: result.Result,
		RollbackPayload: result.RollbackPayload, AuditReceipt: result.AuditReceipt, Error: result.Error,
	})
	if err != nil {
		return fmt.Errorf("sign command result: %w", err)
	}
	return r.queueResult(ctx, commandID, result)
}
func (r *Runner) queueResult(ctx context.Context, commandID string, value any) error {
	if err := r.queue.Enqueue("command_result", commandID, value); err != nil {
		return err
	}
	return r.queue.Flush(ctx, r.client)
}
func backoffDuration(attempt int) time.Duration {
	if attempt < 1 {
		attempt = 1
	}
	d := time.Duration(1<<min(attempt, 6)) * time.Second
	if d > time.Minute {
		d = time.Minute
	}
	// Independent jitter avoids a Controller restart producing a synchronized
	// reconnect wave from every installed Agent.
	jitter := d / 5
	if jitter <= 0 {
		return d
	}
	spread := int64(2*jitter) + 1
	random, err := rand.Int(rand.Reader, big.NewInt(spread))
	if err != nil {
		// Entropy failure must not stop the Agent from reconnecting. The bounded
		// base delay is safe; only the anti-herd jitter is lost for this attempt.
		return d
	}
	return d - jitter + time.Duration(random.Int64())
}
