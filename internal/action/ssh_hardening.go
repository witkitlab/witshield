package action

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

const sshManagedMarker = "# WitShield: password authentication hardening"
const maxSSHConfigBytes = 256 << 10

var systemdUnitPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.@-]{0,127}$`)

type SSHPasswordHardeningParams struct {
	// RollbackAfterSeconds is deliberately bounded. Zero selects the helper's
	// configured default.
	RollbackAfterSeconds int `json:"rollbackAfterSeconds,omitempty"`
}

type SSHHardeningConfig struct {
	Runner               Runner
	SSHDPath             string
	SystemctlPath        string
	ConfigPath           string
	ServiceName          string
	JournalDir           string
	DefaultRollbackDelay time.Duration
	MinRollbackDelay     time.Duration
	MaxRollbackDelay     time.Duration
}

type fileSnapshot struct {
	Content []byte      `json:"content"`
	Mode    fs.FileMode `json:"mode"`
	UID     int         `json:"uid"`
	GID     int         `json:"gid"`
}

type sshHardeningState struct {
	ActionID    string       `json:"actionId"`
	Snapshot    fileSnapshot `json:"snapshot"`
	AppliedHash string       `json:"appliedHash"`
	Changed     bool         `json:"changed"`
	ConfirmBy   time.Time    `json:"confirmBy,omitempty"`
}

type sshJournal struct {
	ActionID         string          `json:"actionId"`
	ParametersDigest string          `json:"parametersDigest"`
	State            json.RawMessage `json:"state"`
	StateDigest      string          `json:"stateDigest"`
	ConfirmBy        time.Time       `json:"confirmBy"`
}

type SSHPasswordHardeningPlaybook struct {
	config      SSHHardeningConfig
	lifecycleMu sync.Mutex
	mu          sync.Mutex
	timers      map[string]*time.Timer
}

func NewSSHPasswordHardeningPlaybook(config SSHHardeningConfig) (*SSHPasswordHardeningPlaybook, error) {
	if config.Runner == nil || !filepath.IsAbs(config.SSHDPath) || !filepath.IsAbs(config.SystemctlPath) ||
		!filepath.IsAbs(config.ConfigPath) || !filepath.IsAbs(config.JournalDir) || !systemdUnitPattern.MatchString(config.ServiceName) {
		return nil, errors.New("SSH hardening requires a runner, absolute paths, a service name, and a journal directory")
	}
	if config.DefaultRollbackDelay <= 0 {
		config.DefaultRollbackDelay = 2 * time.Minute
	}
	if config.MinRollbackDelay <= 0 {
		config.MinRollbackDelay = 30 * time.Second
	}
	if config.MaxRollbackDelay <= 0 {
		config.MaxRollbackDelay = 10 * time.Minute
	}
	if config.DefaultRollbackDelay < config.MinRollbackDelay || config.DefaultRollbackDelay > config.MaxRollbackDelay {
		return nil, errors.New("default SSH rollback delay is outside configured bounds")
	}
	if err := ensurePrivateDirectory(config.JournalDir); err != nil {
		return nil, fmt.Errorf("prepare SSH rollback journal: %w", err)
	}
	playbook := &SSHPasswordHardeningPlaybook{config: config, timers: make(map[string]*time.Timer)}
	if err := playbook.resumeJournals(); err != nil {
		return nil, err
	}
	return playbook, nil
}

func (p *SSHPasswordHardeningPlaybook) Type() Type { return TypeSSHPasswordHardening }

func (p *SSHPasswordHardeningPlaybook) Validate(raw json.RawMessage) error {
	params, err := decodeStrict[SSHPasswordHardeningParams](raw)
	if err != nil {
		return err
	}
	_, err = p.rollbackDelay(params)
	return err
}

func (p *SSHPasswordHardeningPlaybook) rollbackDelay(params SSHPasswordHardeningParams) (time.Duration, error) {
	if params.RollbackAfterSeconds == 0 {
		return p.config.DefaultRollbackDelay, nil
	}
	minimumSeconds := int((p.config.MinRollbackDelay + time.Second - 1) / time.Second)
	maximumSeconds := int(p.config.MaxRollbackDelay / time.Second)
	if params.RollbackAfterSeconds < minimumSeconds || params.RollbackAfterSeconds > maximumSeconds {
		return 0, fmt.Errorf("rollbackAfterSeconds must be between %d and %d", minimumSeconds, maximumSeconds)
	}
	return time.Duration(params.RollbackAfterSeconds) * time.Second, nil
}

func (p *SSHPasswordHardeningPlaybook) Precheck(ctx context.Context, _ Invocation) (Result, error) {
	snapshot, err := snapshotRegularFile(p.config.ConfigPath)
	if err != nil {
		return Result{}, err
	}
	if _, err := p.config.Runner.Run(ctx, Command{
		Path: p.config.SSHDPath, Args: []string{"-t", "-f", p.config.ConfigPath}, Timeout: 30 * time.Second,
	}); err != nil {
		return Result{}, fmt.Errorf("existing SSH configuration does not pass sshd validation: %w", err)
	}
	return Result{Summary: "SSH configuration is a regular file and passes sshd validation", Details: map[string]any{
		"path": p.config.ConfigPath, "mode": fmt.Sprintf("%04o", snapshot.Mode.Perm()),
	}}, nil
}

func (p *SSHPasswordHardeningPlaybook) Preview(_ context.Context, _ Invocation) (Result, error) {
	snapshot, err := snapshotRegularFile(p.config.ConfigPath)
	if err != nil {
		return Result{}, err
	}
	hardened, changedLines := hardenSSHConfig(snapshot.Content)
	return Result{Summary: "set PasswordAuthentication no with validation, reload, and timed rollback", Details: map[string]any{
		"path": p.config.ConfigPath, "changedLines": changedLines,
		"beforeHash": contentHash(snapshot.Content), "afterHash": contentHash(hardened),
	}}, nil
}

func (p *SSHPasswordHardeningPlaybook) Apply(ctx context.Context, invocation Invocation) (ApplyResult, error) {
	p.lifecycleMu.Lock()
	defer p.lifecycleMu.Unlock()
	params, _ := decodeStrict[SSHPasswordHardeningParams](invocation.Parameters)
	delay, _ := p.rollbackDelay(params)
	if journal, err := p.readJournal(invocation.ActionID); err == nil {
		if journal.ParametersDigest != digestParameters(invocation.Parameters) {
			return ApplyResult{}, errors.New("action ID already has a different pending SSH change")
		}
		pending, decodeErr := decodeStrict[sshHardeningState](journal.State)
		if decodeErr != nil || pending.ActionID != invocation.ActionID || pending.AppliedHash == "" {
			return ApplyResult{}, errors.New("pending SSH journal is invalid")
		}
		current, snapshotErr := snapshotRegularFile(p.config.ConfigPath)
		if snapshotErr != nil || contentHash(current.Content) != pending.AppliedHash {
			return ApplyResult{}, errors.New("pending SSH action no longer matches the active configuration")
		}
		if !time.Now().UTC().Before(journal.ConfirmBy) {
			return ApplyResult{}, errors.New("pending SSH action has reached its rollback deadline")
		}
		confirmBy := journal.ConfirmBy
		return ApplyResult{Result: Result{Summary: "SSH hardening is already pending confirmation"}, State: journal.State, ConfirmBy: &confirmBy}, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return ApplyResult{}, fmt.Errorf("inspect existing SSH rollback journal: %w", err)
	}
	if err := p.rejectOtherPendingJournal(invocation.ActionID); err != nil {
		return ApplyResult{}, err
	}
	snapshot, err := snapshotRegularFile(p.config.ConfigPath)
	if err != nil {
		return ApplyResult{}, err
	}
	if _, err := p.config.Runner.Run(ctx, Command{
		Path: p.config.SSHDPath, Args: []string{"-t", "-f", p.config.ConfigPath}, Timeout: 30 * time.Second,
	}); err != nil {
		return ApplyResult{}, fmt.Errorf("existing SSH configuration does not pass sshd validation: %w", err)
	}
	hardened, _ := hardenSSHConfig(snapshot.Content)
	changed := string(hardened) != string(snapshot.Content)
	stateValue := sshHardeningState{ActionID: invocation.ActionID, Snapshot: snapshot, AppliedHash: contentHash(hardened), Changed: changed}
	if !changed {
		state, _ := encodeState(stateValue)
		return ApplyResult{Result: Result{Summary: "SSH password authentication is already hardened"}, State: state}, nil
	}

	confirmBy := time.Now().UTC().Add(delay)
	stateValue.ConfirmBy = confirmBy
	state, err := encodeState(stateValue)
	if err != nil {
		return ApplyResult{}, err
	}
	journal := sshJournal{
		ActionID: invocation.ActionID, ParametersDigest: digestParameters(invocation.Parameters), State: state,
		StateDigest: digestBytes(state), ConfirmBy: confirmBy,
	}
	// Persist recovery material before changing sshd_config. A process or host
	// restart after this point cannot silently defeat the rollback deadline.
	if err := p.writeJournal(journal); err != nil {
		return ApplyResult{}, err
	}
	if err := writeSnapshotFile(p.config.ConfigPath, hardened, snapshot); err != nil {
		restoreErr := writeSnapshotFile(p.config.ConfigPath, snapshot.Content, snapshot)
		if restoreErr == nil {
			_ = p.deleteJournal(invocation.ActionID)
			return ApplyResult{}, fmt.Errorf("write hardened SSH configuration failed and the snapshot was restored: %w", err)
		}
		return ApplyResult{}, fmt.Errorf("write hardened SSH configuration failed and the snapshot could not be restored: %w", restoreErr)
	}
	if _, err := p.config.Runner.Run(ctx, Command{
		Path: p.config.SSHDPath, Args: []string{"-t", "-f", p.config.ConfigPath}, Timeout: 30 * time.Second,
	}); err != nil {
		restoreErr := writeSnapshotFile(p.config.ConfigPath, snapshot.Content, snapshot)
		_ = p.deleteJournal(invocation.ActionID)
		if restoreErr != nil {
			return ApplyResult{}, fmt.Errorf("hardened SSH configuration failed validation and snapshot restoration failed: %w", restoreErr)
		}
		return ApplyResult{}, fmt.Errorf("hardened SSH configuration failed validation and was restored: %w", err)
	}
	if err := p.reload(ctx); err != nil {
		rollbackErr := p.restoreSnapshot(ctx, snapshot)
		_ = p.deleteJournal(invocation.ActionID)
		if rollbackErr != nil {
			return ApplyResult{}, fmt.Errorf("SSH reload failed and snapshot restoration also failed: %w", rollbackErr)
		}
		return ApplyResult{}, fmt.Errorf("SSH reload failed and the snapshot was restored: %w", err)
	}
	p.schedule(journal)
	return ApplyResult{Result: Result{
		Summary: "SSH password authentication disabled; confirmation is required before the rollback deadline",
		Details: map[string]any{"path": p.config.ConfigPath},
	}, State: state, ConfirmBy: &confirmBy}, nil
}

func (p *SSHPasswordHardeningPlaybook) Verify(ctx context.Context, invocation Invocation) (Result, error) {
	state, err := decodeStrict[sshHardeningState](invocation.State)
	if err != nil {
		return Result{}, errors.New("invalid SSH rollback state")
	}
	current, err := snapshotRegularFile(p.config.ConfigPath)
	if err != nil {
		return Result{}, err
	}
	if contentHash(current.Content) != state.AppliedHash {
		return Result{}, errors.New("SSH configuration changed after apply")
	}
	if _, err := p.config.Runner.Run(ctx, Command{
		Path: p.config.SSHDPath, Args: []string{"-t", "-f", p.config.ConfigPath}, Timeout: 30 * time.Second,
	}); err != nil {
		return Result{}, fmt.Errorf("sshd validation failed after apply: %w", err)
	}
	effective, err := p.config.Runner.Run(ctx, Command{
		Path: p.config.SSHDPath, Args: []string{"-T", "-f", p.config.ConfigPath}, Timeout: 30 * time.Second,
	})
	if err != nil {
		return Result{}, fmt.Errorf("could not inspect effective sshd configuration: %w", err)
	}
	if !effectiveSettingIsNo(effective.Stdout, "passwordauthentication") {
		return Result{}, errors.New("effective sshd configuration still allows password authentication")
	}
	return Result{Summary: "sshd validates and reports passwordauthentication no", Details: map[string]any{
		"confirmationPending": state.Changed,
	}}, nil
}

func (p *SSHPasswordHardeningPlaybook) Rollback(ctx context.Context, invocation Invocation) (Result, error) {
	p.lifecycleMu.Lock()
	defer p.lifecycleMu.Unlock()
	state, err := decodeStrict[sshHardeningState](invocation.State)
	if err != nil {
		return Result{}, errors.New("invalid SSH rollback state")
	}
	if !state.Changed {
		return Result{Summary: "no SSH change required rollback"}, nil
	}
	journalActionID := state.ActionID
	if !actionIDPattern.MatchString(journalActionID) {
		return Result{}, errors.New("SSH rollback state has an invalid action ID")
	}
	journal, err := p.readJournal(journalActionID)
	if err != nil {
		return Result{}, fmt.Errorf("authoritative SSH rollback journal is unavailable: %w", err)
	}
	if journal.StateDigest != digestBytes(invocation.State) || journal.ParametersDigest != digestParameters(invocation.Parameters) {
		return Result{}, errors.New("SSH rollback state does not match the protected journal")
	}
	authoritative, err := decodeStrict[sshHardeningState](journal.State)
	if err != nil {
		return Result{}, errors.New("protected SSH rollback journal is invalid")
	}
	if err := p.restoreSnapshot(ctx, authoritative.Snapshot); err != nil {
		return Result{}, err
	}
	p.cancelTimer(journalActionID)
	if err := p.deleteJournal(journalActionID); err != nil {
		return Result{}, fmt.Errorf("SSH was restored but rollback journal cleanup failed: %w", err)
	}
	return Result{Summary: "SSH configuration restored from the protected snapshot and reloaded"}, nil
}

func (p *SSHPasswordHardeningPlaybook) Confirm(ctx context.Context, invocation Invocation) (Result, error) {
	p.lifecycleMu.Lock()
	defer p.lifecycleMu.Unlock()
	state, err := decodeStrict[sshHardeningState](invocation.State)
	if err != nil {
		return Result{}, errors.New("invalid SSH confirmation state")
	}
	if !state.Changed {
		return Result{Summary: "SSH configuration was already hardened; no confirmation was needed"}, nil
	}
	journalActionID := state.ActionID
	if !actionIDPattern.MatchString(journalActionID) {
		return Result{}, errors.New("SSH confirmation state has an invalid action ID")
	}
	journal, err := p.readJournal(journalActionID)
	if err != nil {
		return Result{}, errors.New("SSH confirmation window is not pending")
	}
	if journal.StateDigest != digestBytes(invocation.State) || journal.ParametersDigest != digestParameters(invocation.Parameters) {
		return Result{}, errors.New("SSH confirmation state does not match the protected journal")
	}
	if !time.Now().UTC().Before(journal.ConfirmBy) {
		return Result{}, errors.New("SSH confirmation deadline has passed")
	}
	if _, err := p.Verify(ctx, invocation); err != nil {
		return Result{}, err
	}
	if !time.Now().UTC().Before(journal.ConfirmBy) {
		return Result{}, errors.New("SSH confirmation deadline passed during verification")
	}
	// Delete the durable journal before canceling the timer. If deletion fails,
	// the safety rollback remains armed.
	if err := p.deleteJournal(journalActionID); err != nil {
		return Result{}, fmt.Errorf("could not persist SSH confirmation: %w", err)
	}
	p.cancelTimer(journalActionID)
	return Result{Summary: "SSH hardening confirmed; timed rollback disarmed"}, nil
}

func (p *SSHPasswordHardeningPlaybook) reload(ctx context.Context) error {
	if _, err := p.config.Runner.Run(ctx, Command{
		Path: p.config.SystemctlPath, Args: []string{"reload", p.config.ServiceName}, Timeout: 45 * time.Second,
	}); err != nil {
		return fmt.Errorf("reload %s: %w", p.config.ServiceName, err)
	}
	return nil
}

func (p *SSHPasswordHardeningPlaybook) restoreSnapshot(ctx context.Context, snapshot fileSnapshot) error {
	if err := writeSnapshotFile(p.config.ConfigPath, snapshot.Content, snapshot); err != nil {
		return fmt.Errorf("restore SSH snapshot: %w", err)
	}
	if _, err := p.config.Runner.Run(ctx, Command{
		Path: p.config.SSHDPath, Args: []string{"-t", "-f", p.config.ConfigPath}, Timeout: 30 * time.Second,
	}); err != nil {
		return fmt.Errorf("restored SSH snapshot failed validation: %w", err)
	}
	if err := p.reload(ctx); err != nil {
		return fmt.Errorf("restored SSH snapshot could not be reloaded: %w", err)
	}
	return nil
}

func hardenSSHConfig(content []byte) ([]byte, int) {
	newline := "\n"
	if strings.Contains(string(content), "\r\n") {
		newline = "\r\n"
	}
	lines := strings.Split(strings.ReplaceAll(string(content), "\r\n", "\n"), "\n")
	output := make([]string, 0, len(lines)+2)
	changed := 0
	markerSeen := false
	directiveSeen := false
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == sshManagedMarker {
			markerSeen = true
			continue
		}
		fields := strings.Fields(trimmed)
		if len(fields) > 0 && !strings.HasPrefix(fields[0], "#") && strings.EqualFold(fields[0], "PasswordAuthentication") {
			directiveSeen = true
			if len(fields) != 2 || !strings.EqualFold(fields[1], "no") || strings.TrimSpace(line) != "PasswordAuthentication no" {
				changed++
			}
			continue
		}
		output = append(output, line)
	}
	if !markerSeen {
		changed++
	}
	if !directiveSeen {
		changed++
	}
	// The leading directive wins before any Include and sets the global value.
	prefix := []string{sshManagedMarker, "PasswordAuthentication no"}
	output = append(prefix, output...)
	return []byte(strings.Join(output, newline)), changed
}

func effectiveSettingIsNo(output, key string) bool {
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && strings.EqualFold(fields[0], key) {
			return strings.EqualFold(fields[1], "no")
		}
	}
	return false
}

func snapshotRegularFile(path string) (fileSnapshot, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return fileSnapshot{}, fmt.Errorf("inspect %s: %w", path, err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return fileSnapshot{}, fmt.Errorf("%s must be a regular non-symlink file", path)
	}
	if info.Size() < 0 || info.Size() > maxSSHConfigBytes {
		return fileSnapshot{}, fmt.Errorf("%s exceeds the SSH configuration size limit", path)
	}
	content, err := os.ReadFile(path)
	if err != nil {
		return fileSnapshot{}, fmt.Errorf("read %s: %w", path, err)
	}
	uid, gid, ownerErr := snapshotOwner(info)
	if ownerErr != nil {
		uid, gid = -1, -1
	}
	return fileSnapshot{Content: content, Mode: info.Mode(), UID: uid, GID: gid}, nil
}

func writeSnapshotFile(path string, content []byte, snapshot fileSnapshot) error {
	parent := filepath.Dir(path)
	temp, err := os.CreateTemp(parent, ".witshield-ssh-*")
	if err != nil {
		return err
	}
	tempPath := temp.Name()
	defer os.Remove(tempPath)
	if err := temp.Chmod(snapshot.Mode.Perm()); err != nil {
		temp.Close()
		return err
	}
	if snapshot.UID >= 0 && snapshot.GID >= 0 {
		if err := temp.Chown(snapshot.UID, snapshot.GID); err != nil {
			temp.Close()
			return err
		}
	}
	if _, err := temp.Write(content); err != nil {
		temp.Close()
		return err
	}
	if err := temp.Sync(); err != nil {
		temp.Close()
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tempPath, path); err != nil {
		return err
	}
	directory, err := os.Open(parent)
	if err == nil {
		err = directory.Sync()
		_ = directory.Close()
	}
	return err
}

func contentHash(content []byte) string {
	digest := sha256.Sum256(content)
	return hex.EncodeToString(digest[:])
}

func ensurePrivateDirectory(path string) error {
	if err := os.MkdirAll(path, 0700); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("journal path must be a non-symlink directory")
	}
	if info.Mode().Perm()&0077 != 0 {
		return errors.New("journal directory must not be accessible by group or other users")
	}
	return nil
}

func (p *SSHPasswordHardeningPlaybook) journalPath(actionID string) string {
	return filepath.Join(p.config.JournalDir, "ssh-"+actionID+".json")
}

func (p *SSHPasswordHardeningPlaybook) writeJournal(journal sshJournal) error {
	if !actionIDPattern.MatchString(journal.ActionID) {
		return errors.New("unsafe action ID for SSH journal")
	}
	encoded, err := json.Marshal(journal)
	if err != nil {
		return err
	}
	temp, err := os.CreateTemp(p.config.JournalDir, ".ssh-journal-*")
	if err != nil {
		return err
	}
	tempPath := temp.Name()
	defer os.Remove(tempPath)
	if err := temp.Chmod(0600); err != nil {
		temp.Close()
		return err
	}
	if _, err := temp.Write(encoded); err != nil {
		temp.Close()
		return err
	}
	if err := temp.Sync(); err != nil {
		temp.Close()
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tempPath, p.journalPath(journal.ActionID)); err != nil {
		return err
	}
	directory, err := os.Open(p.config.JournalDir)
	if err == nil {
		err = directory.Sync()
		_ = directory.Close()
	}
	return err
}

func (p *SSHPasswordHardeningPlaybook) readJournal(actionID string) (sshJournal, error) {
	if !actionIDPattern.MatchString(actionID) {
		return sshJournal{}, errors.New("unsafe action ID")
	}
	path := p.journalPath(actionID)
	info, err := os.Lstat(path)
	if err != nil {
		return sshJournal{}, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		return sshJournal{}, errors.New("unsafe SSH journal permissions or type")
	}
	if owner, _, ownerErr := snapshotOwner(info); ownerErr != nil || owner != os.Geteuid() {
		return sshJournal{}, errors.New("SSH journal has an unexpected owner")
	}
	encoded, err := os.ReadFile(path)
	if err != nil {
		return sshJournal{}, err
	}
	journal, err := decodeStrict[sshJournal](encoded)
	if err != nil || journal.ActionID != actionID || journal.StateDigest != digestBytes(journal.State) {
		return sshJournal{}, errors.New("invalid SSH journal")
	}
	state, err := decodeStrict[sshHardeningState](journal.State)
	if err != nil || state.ActionID != actionID || !state.Changed || state.ConfirmBy.IsZero() ||
		!state.ConfirmBy.Equal(journal.ConfirmBy) || len(state.Snapshot.Content) > maxSSHConfigBytes ||
		state.Snapshot.Mode&os.ModeType != 0 || state.Snapshot.Mode&^fs.FileMode(0777) != 0 ||
		state.Snapshot.UID < 0 || state.Snapshot.GID < 0 || !validContentHash(state.AppliedHash) {
		return sshJournal{}, errors.New("invalid SSH journal state")
	}
	return journal, nil
}

func validContentHash(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(value) == 64 && len(decoded) == sha256.Size && value == strings.ToLower(value)
}

func (p *SSHPasswordHardeningPlaybook) deleteJournal(actionID string) error {
	err := os.Remove(p.journalPath(actionID))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	directory, err := os.Open(p.config.JournalDir)
	if err == nil {
		err = directory.Sync()
		_ = directory.Close()
	}
	return err
}

func (p *SSHPasswordHardeningPlaybook) resumeJournals() error {
	entries, err := os.ReadDir(p.config.JournalDir)
	if err != nil {
		return fmt.Errorf("read SSH rollback journals: %w", err)
	}
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasPrefix(name, "ssh-") || !strings.HasSuffix(name, ".json") {
			continue
		}
		actionID := strings.TrimSuffix(strings.TrimPrefix(name, "ssh-"), ".json")
		journal, err := p.readJournal(actionID)
		if err != nil {
			return fmt.Errorf("load SSH rollback journal %s: %w", strconv.Quote(name), err)
		}
		p.schedule(journal)
	}
	return nil
}

func (p *SSHPasswordHardeningPlaybook) schedule(journal sshJournal) {
	delay := time.Until(journal.ConfirmBy)
	if delay < 0 {
		delay = 0
	} else if delay > p.config.MaxRollbackDelay {
		// A backward wall-clock jump or a corrupted far-future timestamp must
		// not turn a bounded safety window into an unbounded one.
		delay = p.config.MaxRollbackDelay
	}
	p.mu.Lock()
	if previous := p.timers[journal.ActionID]; previous != nil {
		previous.Stop()
	}
	p.timers[journal.ActionID] = time.AfterFunc(delay, func() { p.expire(journal.ActionID) })
	p.mu.Unlock()
}

func (p *SSHPasswordHardeningPlaybook) expire(actionID string) {
	p.lifecycleMu.Lock()
	defer p.lifecycleMu.Unlock()
	journal, err := p.readJournal(actionID)
	if errors.Is(err, os.ErrNotExist) {
		p.cancelTimer(actionID)
		return
	}
	if err == nil {
		state, decodeErr := decodeStrict[sshHardeningState](journal.State)
		if decodeErr == nil {
			ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
			err = p.restoreSnapshot(ctx, state.Snapshot)
			cancel()
		}
	}
	if err == nil {
		_ = p.deleteJournal(actionID)
		p.cancelTimer(actionID)
		return
	}
	// Keep the durable journal and retry. A transient systemd failure must not
	// convert a temporary safety window into an untracked permanent change.
	p.mu.Lock()
	p.timers[actionID] = time.AfterFunc(time.Minute, func() { p.expire(actionID) })
	p.mu.Unlock()
}

func (p *SSHPasswordHardeningPlaybook) rejectOtherPendingJournal(actionID string) error {
	entries, err := os.ReadDir(p.config.JournalDir)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasPrefix(name, "ssh-") || !strings.HasSuffix(name, ".json") {
			continue
		}
		otherID := strings.TrimSuffix(strings.TrimPrefix(name, "ssh-"), ".json")
		if otherID != actionID {
			return fmt.Errorf("SSH hardening action %q is still pending confirmation", otherID)
		}
	}
	return nil
}

func snapshotOwner(info fs.FileInfo) (int, int, error) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, 0, errors.New("file ownership is unavailable")
	}
	return int(stat.Uid), int(stat.Gid), nil
}

func (p *SSHPasswordHardeningPlaybook) cancelTimer(actionID string) {
	p.mu.Lock()
	if timer := p.timers[actionID]; timer != nil {
		timer.Stop()
		delete(p.timers, actionID)
	}
	p.mu.Unlock()
}
