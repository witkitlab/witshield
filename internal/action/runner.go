package action

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"time"
)

// Command is assembled only by trusted playbook code. There is intentionally
// no shell string and no caller-controlled executable path.
type Command struct {
	Path    string
	Args    []string
	Stdin   []byte
	Timeout time.Duration
}

type CommandResult struct {
	Stdout          string
	Stderr          string
	ExitCode        int
	OutputTruncated bool
}

// Runner exists both to centralize safe direct execution and to make playbooks
// testable without mutating the host.
type Runner interface {
	Run(context.Context, Command) (CommandResult, error)
}

type ExecRunner struct {
	// AllowedPaths is mandatory. A command not on this exact allowlist is
	// rejected even when a playbook is misconfigured.
	AllowedPaths   map[string]struct{}
	MaxOutputBytes int
}

func NewExecRunner(paths ...string) *ExecRunner {
	allowed := make(map[string]struct{}, len(paths))
	for _, path := range paths {
		if filepath.IsAbs(path) {
			allowed[filepath.Clean(path)] = struct{}{}
		}
	}
	return &ExecRunner{AllowedPaths: allowed, MaxOutputBytes: 1 << 20}
}

func (r *ExecRunner) Run(ctx context.Context, command Command) (CommandResult, error) {
	path := filepath.Clean(command.Path)
	if !filepath.IsAbs(path) {
		return CommandResult{}, errors.New("command path must be absolute")
	}
	if _, ok := r.AllowedPaths[path]; !ok {
		return CommandResult{}, fmt.Errorf("command path %q is not allowlisted", path)
	}
	timeout := command.Timeout
	if timeout <= 0 || timeout > 10*time.Minute {
		timeout = 2 * time.Minute
	}
	commandCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cmd := exec.CommandContext(commandCtx, path, command.Args...)
	configureProcessGroup(cmd)
	cmd.WaitDelay = 5 * time.Second
	// Do not inherit loader, package-manager, locale, or executable-search
	// variables into a root command from the helper's process environment.
	cmd.Env = []string{
		"PATH=/usr/sbin:/usr/bin:/sbin:/bin",
		"LANG=C",
		"LC_ALL=C",
		"DEBIAN_FRONTEND=noninteractive",
	}
	cmd.Stdin = bytes.NewReader(command.Stdin)
	limit := r.MaxOutputBytes
	if limit <= 0 || limit > 8<<20 {
		limit = 1 << 20
	}
	stdout, stderr := &limitedBuffer{limit: limit}, &limitedBuffer{limit: limit}
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	err := cmd.Run()
	result := CommandResult{
		Stdout: stdout.String(), Stderr: stderr.String(),
		OutputTruncated: stdout.truncated || stderr.truncated,
	}
	if err == nil {
		return result, nil
	}
	if errors.Is(commandCtx.Err(), context.DeadlineExceeded) {
		return result, fmt.Errorf("command timed out: %w", commandCtx.Err())
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		result.ExitCode = exitErr.ExitCode()
		return result, fmt.Errorf("command failed with exit code %d", result.ExitCode)
	}
	return result, fmt.Errorf("command failed: %w", err)
}

// limitedBuffer deliberately reports successful writes after the audit-safe
// prefix is full. This keeps a noisy child from consuming unbounded memory
// without changing the child's exit behavior.
type limitedBuffer struct {
	data      []byte
	limit     int
	truncated bool
}

func (b *limitedBuffer) Write(value []byte) (int, error) {
	written := len(value)
	remaining := b.limit - len(b.data)
	if remaining > 0 {
		if remaining > len(value) {
			remaining = len(value)
		}
		b.data = append(b.data, value[:remaining]...)
	}
	if remaining < len(value) {
		b.truncated = true
	}
	return written, nil
}

func (b *limitedBuffer) String() string { return string(b.data) }
