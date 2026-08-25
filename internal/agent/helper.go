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
)

type HelperClient struct{ Socket, Token string }
type helperRequest struct {
	Token      string           `json:"token"`
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
func (c *HelperClient) Run(ctx context.Context, actionID string, typ action.Type, operation action.Operation, params, state json.RawMessage) (HelperResult, error) {
	var out HelperResult
	if c.Socket == "" || c.Token == "" {
		return out, errors.New("privileged helper is not configured")
	}
	if operation != action.OperationExecute && operation != action.OperationRollback && operation != action.OperationConfirm {
		return out, errors.New("unsupported helper operation")
	}
	req := helperRequest{Token: c.Token, ActionID: actionID, Type: typ, Operation: operation, Parameters: params, State: state}
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
	if _, err = conn.Write(append(payload, '\n')); err != nil {
		return out, err
	}
	reader := bufio.NewReaderSize(conn, 4<<20)
	line, err := reader.ReadSlice('\n')
	if err != nil && !(errors.Is(err, io.EOF) && len(line) > 0) {
		return out, err
	}
	if len(line) > 4<<20 {
		return out, errors.New("helper response too large")
	}
	dec := json.NewDecoder(bytes.NewReader(line))
	dec.DisallowUnknownFields()
	if err = dec.Decode(&out); err != nil {
		return out, errors.New("invalid helper response")
	}
	if err = dec.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return out, errors.New("invalid helper response")
	}
	return out, nil
}
