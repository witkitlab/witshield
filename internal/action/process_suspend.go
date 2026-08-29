package action

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
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
	processes ProcessController
	now       func() time.Time
}

type temporaryProcessSuspendState struct {
	PID        int    `json:"pid"`
	PPID       int    `json:"ppid"`
	UID        uint64 `json:"uid"`
	StartTime  uint64 `json:"startTime"`
	Executable string `json:"executable"`
}

func NewTemporaryProcessSuspendPlaybook(processes ProcessController) (*TemporaryProcessSuspendPlaybook, error) {
	if processes == nil {
		return nil, errors.New("process controller is required")
	}
	return &TemporaryProcessSuspendPlaybook{processes: processes, now: time.Now}, nil
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
	params, err := decodeStrict[TemporaryProcessSuspendParams](invocation.Parameters)
	if err != nil {
		return ApplyResult{}, err
	}
	identity, err := p.inspect(params)
	if err != nil {
		return ApplyResult{}, err
	}
	state, _ := json.Marshal(temporaryProcessSuspendState{PID: identity.PID, PPID: identity.PPID, UID: identity.UID, StartTime: identity.StartTime, Executable: identity.Executable})
	if err = p.processes.Stop(identity.PID); err != nil {
		return ApplyResult{State: state}, fmt.Errorf("send temporary stop signal: %w", err)
	}
	confirmBy := p.now().UTC().Add(time.Duration(params.TTLSeconds) * time.Second)
	return ApplyResult{Result: Result{Summary: "process temporarily suspended", Details: map[string]any{"pid": identity.PID, "resumeAt": confirmBy}}, State: state, ConfirmBy: &confirmBy}, nil
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
	state, err := decodeStrict[temporaryProcessSuspendState](invocation.State)
	if err != nil {
		return Result{}, err
	}
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

var ErrProcessNotFound = errors.New("process not found")
