package action

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

type TemporaryProcessSuspendParams struct {
	PID        int    `json:"pid"`
	StartTime  uint64 `json:"startTime"`
	Executable string `json:"executable"`
	TTLSeconds int    `json:"ttlSeconds"`
	Reason     string `json:"reason,omitempty"`
}

type ProcessRuntimeIdentity struct {
	PID, PPID  int
	UID        uint64
	StartTime  uint64
	Executable string
	Stopped    bool
}

type ProcessController interface {
	Inspect(int) (ProcessRuntimeIdentity, error)
	Stop(int) error
	Continue(int) error
}

type TemporaryProcessSuspendPlaybook struct {
	processes  ProcessController
	journalDir string
	now        func() time.Time
	mu         sync.Mutex
	lifecycle  sync.Mutex
	timers     map[string]*time.Timer
}

type temporaryProcessSuspendState struct {
	ActionID   string `json:"actionId"`
	PID        int    `json:"pid"`
	PPID       int    `json:"ppid"`
	UID        uint64 `json:"uid"`
	StartTime  uint64 `json:"startTime"`
	Executable string `json:"executable"`
}

type processResumeJournal struct {
	Version          int             `json:"version"`
	ActionID         string          `json:"actionId"`
	ParametersDigest string          `json:"parametersDigest"`
	State            json.RawMessage `json:"state"`
	StateDigest      string          `json:"stateDigest"`
	ResumeAt         time.Time       `json:"resumeAt"`
}

func NewTemporaryProcessSuspendPlaybook(processes ProcessController, journalDir string) (*TemporaryProcessSuspendPlaybook, error) {
	if processes == nil {
		return nil, errors.New("process controller is required")
	}
	if strings.TrimSpace(journalDir) == "" {
		return nil, errors.New("process resume journal directory is required")
	}
	if err := ensurePrivateDirectory(journalDir); err != nil {
		return nil, fmt.Errorf("process resume journal directory: %w", err)
	}
	playbook := &TemporaryProcessSuspendPlaybook{processes: processes, journalDir: journalDir, now: time.Now, timers: map[string]*time.Timer{}}
	if err := playbook.resumeJournals(); err != nil {
		return nil, err
	}
	return playbook, nil
}

func (p *TemporaryProcessSuspendPlaybook) Type() Type { return TypeTemporaryProcessSuspend }

func (p *TemporaryProcessSuspendPlaybook) Validate(raw json.RawMessage) error {
	params, err := decodeStrict[TemporaryProcessSuspendParams](raw)
	if err != nil {
		return err
	}
	if params.PID < 2 || params.StartTime == 0 || params.TTLSeconds < 30 || params.TTLSeconds > 900 || len(params.Reason) > 256 {
		return errors.New("pid, startTime, ttlSeconds, or reason is outside the safe bound")
	}
	clean := filepath.Clean(params.Executable)
	if !filepath.IsAbs(clean) || clean != params.Executable || !transientExecutable(clean) {
		return errors.New("only an exact executable below /tmp, /var/tmp, or /dev/shm can be temporarily suspended")
	}
	return nil
}

func transientExecutable(path string) bool {
	for _, prefix := range []string{"/tmp/", "/var/tmp/", "/dev/shm/"} {
		if strings.HasPrefix(path, prefix) {
			return true
		}
	}
	return false
}

func (p *TemporaryProcessSuspendPlaybook) inspect(params TemporaryProcessSuspendParams) (ProcessRuntimeIdentity, error) {
	identity, err := p.processes.Inspect(params.PID)
	if err != nil {
		return identity, err
	}
	if identity.PID != params.PID || identity.StartTime != params.StartTime || strings.TrimSuffix(identity.Executable, " (deleted)") != params.Executable || identity.UID != 0 {
		return identity, errors.New("process identity changed or is not the expected privileged process")
	}
	return identity, nil
}

func (p *TemporaryProcessSuspendPlaybook) Precheck(_ context.Context, invocation Invocation) (Result, error) {
	params, err := decodeStrict[TemporaryProcessSuspendParams](invocation.Parameters)
	if err != nil {
		return Result{}, err
	}
	identity, err := p.inspect(params)
	if err != nil {
		return Result{}, err
	}
	if identity.Stopped {
		return Result{}, errors.New("process is already stopped")
	}
	return Result{Summary: "exact privileged process identity verified", Details: map[string]any{"pid": identity.PID, "executable": identity.Executable}}, nil
}

func (p *TemporaryProcessSuspendPlaybook) Preview(_ context.Context, invocation Invocation) (Result, error) {
	params, err := decodeStrict[TemporaryProcessSuspendParams](invocation.Parameters)
	if err != nil {
		return Result{}, err
	}
	return Result{Summary: "temporarily suspend one exact privileged process", Details: map[string]any{"pid": params.PID, "ttlSeconds": params.TTLSeconds, "automaticResume": true}}, nil
}

func (p *TemporaryProcessSuspendPlaybook) Apply(_ context.Context, invocation Invocation) (ApplyResult, error) {
	p.lifecycle.Lock()
	defer p.lifecycle.Unlock()
	params, err := decodeStrict[TemporaryProcessSuspendParams](invocation.Parameters)
	if err != nil {
		return ApplyResult{}, err
	}
	identity, err := p.inspect(params)
	if err != nil {
		return ApplyResult{}, err
	}
	if !actionIDPattern.MatchString(invocation.ActionID) {
		return ApplyResult{}, errors.New("temporary process action has an invalid action ID")
	}
	state, _ := json.Marshal(temporaryProcessSuspendState{ActionID: invocation.ActionID, PID: identity.PID, PPID: identity.PPID, UID: identity.UID, StartTime: identity.StartTime, Executable: identity.Executable})
	resumeAt := p.now().UTC().Add(time.Duration(params.TTLSeconds) * time.Second)
	journal := processResumeJournal{Version: 1, ActionID: invocation.ActionID, ParametersDigest: digestParameters(invocation.Parameters), State: state, StateDigest: digestBytes(state), ResumeAt: resumeAt}
	// The durable journal is the mutation boundary. A crash after this fsync but
	// before scheduling is recovered when Helper starts again.
	if err = p.writeJournal(journal); err != nil {
		return ApplyResult{}, fmt.Errorf("persist automatic process resume: %w", err)
	}
	// Arm recovery before sending SIGSTOP. This also covers a signal call that
	// reports an error after the kernel has already accepted the mutation.
	p.schedule(journal)
	if err = p.processes.Stop(identity.PID); err != nil {
		return ApplyResult{State: state}, fmt.Errorf("send temporary stop signal: %w", err)
	}
	// Process containment is not an administrator confirmation window. The
	// Helper owns automatic recovery locally, while Controller keeps the sealed
	// state so an administrator can resume early.
	return ApplyResult{Result: Result{Summary: "process temporarily suspended", Details: map[string]any{"pid": identity.PID, "resumeAt": resumeAt}}, State: state}, nil
}

func (p *TemporaryProcessSuspendPlaybook) Verify(_ context.Context, invocation Invocation) (Result, error) {
	state, err := decodeStrict[temporaryProcessSuspendState](invocation.State)
	if err != nil {
		return Result{}, err
	}
	var identity ProcessRuntimeIdentity
	for attempt := 0; attempt < 5; attempt++ {
		identity, err = p.processes.Inspect(state.PID)
		if err != nil {
			return Result{}, err
		}
		if identity.StartTime != state.StartTime || identity.Executable != state.Executable {
			return Result{}, errors.New("process identity changed before suspension could be verified")
		}
		if identity.Stopped {
			return Result{Summary: "exact process suspension verified", Details: map[string]any{"pid": state.PID}}, nil
		}
		time.Sleep(20 * time.Millisecond)
	}
	return Result{}, errors.New("exact process is not proven suspended")
}

func (p *TemporaryProcessSuspendPlaybook) Rollback(_ context.Context, invocation Invocation) (Result, error) {
	p.lifecycle.Lock()
	defer p.lifecycle.Unlock()
	state, err := decodeStrict[temporaryProcessSuspendState](invocation.State)
	if err != nil {
		return Result{}, err
	}
	// v0.3.6 and older rollback states predate the embedded ActionID. The
	// Controller-sealed envelope already binds such state to invocation.ActionID,
	// so adopt it only for this one backward-compatible resume path.
	if state.ActionID == "" {
		state.ActionID = invocation.ActionID
	}
	if state.ActionID != invocation.ActionID || !actionIDPattern.MatchString(state.ActionID) {
		return Result{}, errors.New("process resume state does not match the action")
	}
	result, err := p.resumeExact(state)
	if err != nil {
		return Result{}, err
	}
	if err = p.deleteJournal(state.ActionID); err != nil {
		return Result{}, fmt.Errorf("process resumed but journal cleanup failed: %w", err)
	}
	p.cancelTimer(state.ActionID)
	return result, nil
}

func (p *TemporaryProcessSuspendPlaybook) resumeExact(state temporaryProcessSuspendState) (Result, error) {
	identity, err := p.processes.Inspect(state.PID)
	if err != nil {
		// A process which already exited needs no resume. The implementation uses
		// a typed not-found error so other inspection failures remain visible.
		if errors.Is(err, ErrProcessNotFound) {
			return Result{Summary: "suspended process already exited; no resume required"}, nil
		}
		return Result{}, err
	}
	if identity.StartTime != state.StartTime || identity.Executable != state.Executable {
		return Result{Summary: "PID was reused; no signal sent to the replacement process"}, nil
	}
	if !identity.Stopped {
		return Result{Summary: "process was already running"}, nil
	}
	if err = p.processes.Continue(state.PID); err != nil {
		return Result{}, fmt.Errorf("resume exact process: %w", err)
	}
	return Result{Summary: "temporary process suspension released", Details: map[string]any{"pid": state.PID}}, nil
}

func (p *TemporaryProcessSuspendPlaybook) journalPath(actionID string) string {
	return filepath.Join(p.journalDir, "process-"+actionID+".json")
}

func (p *TemporaryProcessSuspendPlaybook) writeJournal(journal processResumeJournal) error {
	if !actionIDPattern.MatchString(journal.ActionID) || journal.Version != 1 || journal.StateDigest != digestBytes(journal.State) {
		return errors.New("invalid process resume journal")
	}
	encoded, err := json.Marshal(journal)
	if err != nil {
		return err
	}
	temp, err := os.CreateTemp(p.journalDir, ".process-resume-*")
	if err != nil {
		return err
	}
	tempPath := temp.Name()
	defer os.Remove(tempPath)
	if err = temp.Chmod(0600); err == nil {
		_, err = temp.Write(encoded)
	}
	if err == nil {
		err = temp.Sync()
	}
	closeErr := temp.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if err = os.Rename(tempPath, p.journalPath(journal.ActionID)); err != nil {
		return err
	}
	return syncDirectoryPath(p.journalDir)
}

func (p *TemporaryProcessSuspendPlaybook) readJournal(actionID string) (processResumeJournal, error) {
	if !actionIDPattern.MatchString(actionID) {
		return processResumeJournal{}, errors.New("unsafe process resume action ID")
	}
	info, err := os.Lstat(p.journalPath(actionID))
	if err != nil {
		return processResumeJournal{}, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		return processResumeJournal{}, errors.New("unsafe process resume journal permissions or type")
	}
	owner, _, ownerErr := snapshotOwner(info)
	if ownerErr != nil || owner != os.Geteuid() {
		return processResumeJournal{}, errors.New("process resume journal has an unexpected owner")
	}
	encoded, err := os.ReadFile(p.journalPath(actionID))
	if err != nil {
		return processResumeJournal{}, err
	}
	journal, err := decodeStrict[processResumeJournal](encoded)
	if err != nil || journal.Version != 1 || journal.ActionID != actionID || journal.StateDigest != digestBytes(journal.State) || journal.ParametersDigest == "" || journal.ResumeAt.IsZero() {
		return processResumeJournal{}, errors.New("invalid process resume journal")
	}
	state, err := decodeStrict[temporaryProcessSuspendState](journal.State)
	if err != nil || state.ActionID != actionID || state.PID < 2 || state.StartTime == 0 || !filepath.IsAbs(state.Executable) {
		return processResumeJournal{}, errors.New("invalid process resume journal state")
	}
	return journal, nil
}

func (p *TemporaryProcessSuspendPlaybook) deleteJournal(actionID string) error {
	err := os.Remove(p.journalPath(actionID))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	return syncDirectoryPath(p.journalDir)
}

func (p *TemporaryProcessSuspendPlaybook) resumeJournals() error {
	entries, err := os.ReadDir(p.journalDir)
	if err != nil {
		return fmt.Errorf("read process resume journals: %w", err)
	}
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasPrefix(name, "process-") || !strings.HasSuffix(name, ".json") {
			continue
		}
		actionID := strings.TrimSuffix(strings.TrimPrefix(name, "process-"), ".json")
		journal, err := p.readJournal(actionID)
		if err != nil {
			return fmt.Errorf("load process resume journal %s: %w", strconv.Quote(name), err)
		}
		p.schedule(journal)
	}
	return nil
}

func (p *TemporaryProcessSuspendPlaybook) schedule(journal processResumeJournal) {
	delay := time.Until(journal.ResumeAt)
	if delay < 0 {
		delay = 0
	} else if delay > 15*time.Minute {
		delay = 15 * time.Minute
	}
	p.mu.Lock()
	if previous := p.timers[journal.ActionID]; previous != nil {
		previous.Stop()
	}
	p.timers[journal.ActionID] = time.AfterFunc(delay, func() { p.expire(journal.ActionID) })
	p.mu.Unlock()
}

func (p *TemporaryProcessSuspendPlaybook) expire(actionID string) {
	p.lifecycle.Lock()
	defer p.lifecycle.Unlock()
	journal, err := p.readJournal(actionID)
	if errors.Is(err, os.ErrNotExist) {
		p.cancelTimer(actionID)
		return
	}
	if err == nil {
		var state temporaryProcessSuspendState
		state, err = decodeStrict[temporaryProcessSuspendState](journal.State)
		if err == nil {
			_, err = p.resumeExact(state)
		}
	}
	if err == nil {
		_ = p.deleteJournal(actionID)
		p.cancelTimer(actionID)
		return
	}
	// Preserve the journal and retry. A transient /proc or signal failure must
	// not convert a bounded containment into a permanent outage.
	p.mu.Lock()
	p.timers[actionID] = time.AfterFunc(time.Minute, func() { p.expire(actionID) })
	p.mu.Unlock()
}

func (p *TemporaryProcessSuspendPlaybook) cancelTimer(actionID string) {
	p.mu.Lock()
	if timer := p.timers[actionID]; timer != nil {
		timer.Stop()
		delete(p.timers, actionID)
	}
	p.mu.Unlock()
}

var ErrProcessNotFound = errors.New("process not found")
