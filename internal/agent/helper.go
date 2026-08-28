package agent

import (
	"bufio"
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"strings"
	"time"

	"github.com/witkitlab/witshield/internal/action"
	"github.com/witkitlab/witshield/internal/observation"
)

type HelperClient struct{ Socket, Token string }

// ErrHelperExecutionIndeterminate means a complete or partial request reached
// the Helper socket, but no trustworthy response came back. Retrying could
// repeat privileged side effects, so the Controller must require manual
// verification instead of treating this as an ordinary failed precheck.
var ErrHelperExecutionIndeterminate = errors.New(action.ExecutionIndeterminateMessage)

type helperRequest struct {
	Token      string           `json:"token"`
	AttemptID  string           `json:"attemptId"`
	ActionID   string           `json:"actionId"`
	Type       action.Type      `json:"type"`
	Operation  action.Operation `json:"operation"`
	Parameters json.RawMessage  `json:"parameters"`
	State      json.RawMessage  `json:"state,omitempty"`
}
type HelperResult struct {
	OK              bool            `json:"ok"`
	Result          *action.Result  `json:"result,omitempty"`
	RollbackPayload json.RawMessage `json:"rollbackPayload,omitempty"`
	AuditReceipt    *action.Receipt `json:"auditReceipt,omitempty"`
	Error           string          `json:"error,omitempty"`
}

func LoadHelperToken(path string) (string, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return "", errors.New("helper token must be a regular non-symlink file")
	}
	if info.Mode().Perm() != 0o600 && info.Mode().Perm() != 0o640 {
		return "", errors.New("helper token permissions must be 0600 or 0640")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	token := strings.TrimSpace(string(b))
	decoded, decodeErr := hex.DecodeString(token)
	if decodeErr != nil || len(decoded) != 32 || token != strings.ToLower(token) {
		return "", errors.New("helper token must be 256-bit lowercase hexadecimal")
	}
	return token, nil
}
func (c *HelperClient) Run(ctx context.Context, attemptID, actionID string, typ action.Type, operation action.Operation, params, state json.RawMessage) (HelperResult, error) {
	var out HelperResult
	if c.Socket == "" || c.Token == "" {
		return out, errors.New("privileged helper is not configured")
	}
	if operation != action.OperationExecute && operation != action.OperationRollback && operation != action.OperationConfirm {
		return out, errors.New("unsupported helper operation")
	}
	req := helperRequest{Token: c.Token, AttemptID: attemptID, ActionID: actionID, Type: typ, Operation: operation, Parameters: params, State: state}
	payload, err := json.Marshal(req)
	if err != nil {
		return out, err
	}
	if len(payload) > 1<<20 {
		return out, errors.New("helper request is too large")
	}
	dialer := net.Dialer{Timeout: 3 * time.Second}
	conn, err := dialer.DialContext(ctx, "unix", c.Socket)
	if err != nil {
		return out, err
	}
	defer conn.Close()
	deadline := time.Now().Add(11 * time.Minute)
	_ = conn.SetDeadline(deadline)
	wire := append(payload, '\n')
	written, writeErr := conn.Write(wire)
	if writeErr != nil || written != len(wire) {
		if written > 0 {
			return out, ErrHelperExecutionIndeterminate
		}
		if writeErr != nil {
			return out, writeErr
		}
		return out, io.ErrShortWrite
	}
	reader := bufio.NewReaderSize(conn, 4<<20)
	line, err := reader.ReadSlice('\n')
	if err != nil && !(errors.Is(err, io.EOF) && len(line) > 0) {
		return out, ErrHelperExecutionIndeterminate
	}
	if len(line) > 4<<20 {
		return out, ErrHelperExecutionIndeterminate
	}
	dec := json.NewDecoder(bytes.NewReader(line))
	dec.DisallowUnknownFields()
	if err = dec.Decode(&out); err != nil {
		return out, ErrHelperExecutionIndeterminate
	}
	if err = dec.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return out, ErrHelperExecutionIndeterminate
	}
	return out, nil
}

// ObserveSuspiciousProcesses calls the Helper's single fixed, read-only
// observation. It is intentionally separate from Run: it cannot select an
// executable, path, command or action type and it has no mutation semantics.
func (c *HelperClient) ObserveSuspiciousProcesses(ctx context.Context) (observation.ProcessSnapshot, error) {
	if c.Socket == "" || c.Token == "" {
		return observation.ProcessSnapshot{}, errors.New("privileged helper is not configured")
	}
	payload, err := json.Marshal(struct {
		Token string `json:"token"`
		Kind  string `json:"kind"`
	}{Token: c.Token, Kind: observation.ProcessQueryKind})
	if err != nil {
		return observation.ProcessSnapshot{}, err
	}
	dialer := net.Dialer{Timeout: 3 * time.Second}
	conn, err := dialer.DialContext(ctx, "unix", c.Socket)
	if err != nil {
		return observation.ProcessSnapshot{}, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
	if _, err = conn.Write(append(payload, '\n')); err != nil {
		return observation.ProcessSnapshot{}, err
	}
	line, err := bufio.NewReaderSize(conn, 1<<20).ReadSlice('\n')
	if err != nil && !(errors.Is(err, io.EOF) && len(line) > 0) {
		return observation.ProcessSnapshot{}, err
	}
	if len(line) > 1<<20 {
		return observation.ProcessSnapshot{}, errors.New("helper observation response is too large")
	}
	var response struct {
		OK               bool                  `json:"ok"`
		Processes        []observation.Process `json:"processes,omitempty"`
		ProcessObserved  int                   `json:"processObserved,omitempty"`
		ProcessTruncated bool                  `json:"processTruncated,omitempty"`
		Error            string                `json:"error,omitempty"`
	}
	decoder := json.NewDecoder(bytes.NewReader(line))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(&response); err != nil {
		return observation.ProcessSnapshot{}, errors.New("invalid helper observation response")
	}
	if err = decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return observation.ProcessSnapshot{}, errors.New("helper observation response has trailing data")
	}
	if !response.OK {
		if strings.TrimSpace(response.Error) == "" {
			return observation.ProcessSnapshot{}, errors.New("helper observation failed")
		}
		return observation.ProcessSnapshot{}, errors.New(truncateHelperError(response.Error))
	}
	if len(response.Processes) > 256 || response.ProcessObserved < len(response.Processes) || (!response.ProcessTruncated && response.ProcessObserved < 0) {
		return observation.ProcessSnapshot{}, errors.New("helper returned invalid process observation bounds")
	}
	for _, process := range response.Processes {
		identity, decodeErr := hex.DecodeString(process.Identity)
		if decodeErr != nil || len(identity) != 32 || process.PID < 1 || process.PPID < 0 || len(process.Name) > 131 || len(process.Executable) > 1027 || len(process.Reason) > 256 ||
			(process.EventType != "suspicious_privileged_process_started" && process.EventType != "deleted_executable_process_running") {
			return observation.ProcessSnapshot{}, errors.New("helper returned an invalid process observation")
		}
	}
	return observation.ProcessSnapshot{Processes: response.Processes, Observed: response.ProcessObserved, Truncated: response.ProcessTruncated}, nil
}

func truncateHelperError(value string) string {
	value = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, strings.TrimSpace(value))
	if len(value) > 256 {
		return value[:256]
	}
	return value
}
