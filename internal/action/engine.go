package action

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

var actionIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)

const maxRollbackStateBytes = 512 << 10

type Engine struct {
	mu        sync.RWMutex
	playbooks map[Type]Playbook
	now       func() time.Time
	stateKey  []byte
}

func NewEngine(playbooks ...Playbook) (*Engine, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("create rollback-state key: %w", err)
	}
	return NewEngineWithStateKey(key, playbooks...)
}

// NewEngineWithStateKey creates an engine whose rollback payloads remain
// verifiable across process restarts. The helper derives this key from its
// protected authentication token.
func NewEngineWithStateKey(stateKey []byte, playbooks ...Playbook) (*Engine, error) {
	if len(stateKey) < 32 {
		return nil, errors.New("rollback-state key must contain at least 256 bits")
	}
	digest := sha256.Sum256(stateKey)
	engine := &Engine{playbooks: make(map[Type]Playbook), now: time.Now, stateKey: append([]byte(nil), digest[:]...)}
	for _, playbook := range playbooks {
		if playbook == nil || playbook.Type() == "" {
			return nil, errors.New("nil or unnamed playbook")
		}
		if _, exists := engine.playbooks[playbook.Type()]; exists {
			return nil, fmt.Errorf("duplicate playbook %q", playbook.Type())
		}
		engine.playbooks[playbook.Type()] = playbook
	}
	return engine, nil
}

type sealedRollbackState struct {
	Version          int             `json:"version"`
	ActionID         string          `json:"actionId"`
	Type             Type            `json:"type"`
	ParametersDigest string          `json:"parametersDigest"`
	Payload          json.RawMessage `json:"payload"`
	MAC              string          `json:"mac"`
}

func (e *Engine) Types() []Type {
	e.mu.RLock()
	defer e.mu.RUnlock()
	types := make([]Type, 0, len(e.playbooks))
	for actionType := range e.playbooks {
		types = append(types, actionType)
	}
	sort.Slice(types, func(i, j int) bool { return types[i] < types[j] })
	return types
}

func (e *Engine) Run(ctx context.Context, request Request) (receipt Receipt) {
	started := e.now().UTC()
	receipt = Receipt{
		ID:               receiptID(),
		ActionID:         request.ActionID,
		Actor:            request.Actor,
		Type:             request.Type,
		Operation:        request.Operation,
		ParametersDigest: digestParameters(request.Parameters),
		StartedAt:        started,
		Steps:            make([]AuditStep, 0, 5),
	}
	defer func() {
		receipt.FinishedAt = e.now().UTC()
		receipt.Digest = receiptDigest(receipt)
	}()

	if !actionIDPattern.MatchString(request.ActionID) || request.Actor == "" || len(request.Actor) > 128 {
		receipt.Error = ErrInvalidRequest.Error()
		return receipt
	}
	if len(request.Parameters) == 0 || !json.Valid(request.Parameters) {
		receipt.Error = ErrInvalidRequest.Error() + ": parameters must be valid JSON"
		return receipt
	}
	e.mu.RLock()
	playbook, ok := e.playbooks[request.Type]
	e.mu.RUnlock()
	if !ok {
		receipt.Error = ErrUnsupportedAction.Error()
		return receipt
	}
	if err := playbook.Validate(request.Parameters); err != nil {
		receipt.Error = fmt.Errorf("%w: %v", ErrInvalidRequest, err).Error()
		return receipt
	}
	invocation := Invocation{
		ActionID: request.ActionID, Actor: request.Actor,
		Parameters: request.Parameters, State: request.State,
	}
	if request.Operation == OperationVerify || request.Operation == OperationRollback || request.Operation == OperationConfirm {
		payload, err := e.openState(request)
		if err != nil {
			receipt.Error = err.Error()
			return receipt
		}
		invocation.State = payload
	}

	runResult := func(operation Operation, fn func() (Result, error)) bool {
		stepStarted := e.now().UTC()
		result, err := fn()
		step := AuditStep{Operation: operation, StartedAt: stepStarted, FinishedAt: e.now().UTC(), Success: err == nil}
		if err != nil {
			step.Error = err.Error()
			receipt.Error = err.Error()
		} else {
			step.Result = &result
		}
		receipt.Steps = append(receipt.Steps, step)
		return err == nil
	}
	runApply := func() bool {
		stepStarted := e.now().UTC()
		result, err := playbook.Apply(ctx, invocation)
		if err == nil && (!validState(result.State) || len(result.State) > maxRollbackStateBytes) {
			err = errors.New("playbook returned invalid or oversized rollback state")
		}
		step := AuditStep{Operation: OperationApply, StartedAt: stepStarted, FinishedAt: e.now().UTC(), Success: err == nil}
		if err != nil {
			step.Error = err.Error()
			receipt.Error = err.Error()
		} else {
			step.Result = &result.Result
			receipt.State = e.sealState(request.ActionID, request.Type, request.Parameters, result.State)
			receipt.RollbackStateDigest = digestBytes(receipt.State)
			receipt.ConfirmBy = result.ConfirmBy
			invocation.State = result.State
		}
		receipt.Steps = append(receipt.Steps, step)
		return err == nil
	}

	switch request.Operation {
	case OperationPrecheck:
		receipt.Success = runResult(OperationPrecheck, func() (Result, error) { return playbook.Precheck(ctx, invocation) })
	case OperationPreview:
		receipt.Success = runResult(OperationPreview, func() (Result, error) { return playbook.Preview(ctx, invocation) })
	case OperationApply:
		receipt.Success = runApply()
	case OperationVerify:
		if !validState(invocation.State) {
			receipt.Error = ErrRollbackStateNeeded.Error()
			break
		}
		receipt.Success = runResult(OperationVerify, func() (Result, error) { return playbook.Verify(ctx, invocation) })
	case OperationRollback:
		if !validState(invocation.State) {
			receipt.Error = ErrRollbackStateNeeded.Error()
			break
		}
		receipt.Success = runResult(OperationRollback, func() (Result, error) { return playbook.Rollback(ctx, invocation) })
	case OperationConfirm:
		if !validState(invocation.State) {
			receipt.Error = ErrRollbackStateNeeded.Error()
			break
		}
		confirmer, ok := playbook.(Confirmer)
		if !ok {
			receipt.Error = ErrUnsupportedOperation.Error()
			break
		}
		receipt.Success = runResult(OperationConfirm, func() (Result, error) { return confirmer.Confirm(ctx, invocation) })
	case OperationExecute:
		if !runResult(OperationPrecheck, func() (Result, error) { return playbook.Precheck(ctx, invocation) }) ||
			!runResult(OperationPreview, func() (Result, error) { return playbook.Preview(ctx, invocation) }) || !runApply() {
			break
		}
		if runResult(OperationVerify, func() (Result, error) { return playbook.Verify(ctx, invocation) }) {
			receipt.Success = true
			break
		}
		verifyErr := receipt.Error
		if runResult(OperationRollback, func() (Result, error) { return playbook.Rollback(ctx, invocation) }) {
			receipt.Error = "verification failed and the change was rolled back: " + verifyErr
		} else {
			receipt.Error = "verification failed; automatic rollback also failed: " + verifyErr + "; " + receipt.Error
		}
	default:
		receipt.Error = ErrUnsupportedOperation.Error()
	}
	return receipt
}

// Preview is a stable convenience API for local-mode callers. Callers which
// already have an action ID and actor should use Run so those values appear in
// the receipt.
func (e *Engine) Preview(ctx context.Context, actionType Type, parameters json.RawMessage) (Receipt, error) {
	receipt := e.Run(ctx, Request{
		ActionID: receiptID(), Actor: "local-agent", Type: actionType,
		Operation: OperationPreview, Parameters: parameters,
	})
	return receipt, receiptError(receipt)
}

// Execute performs the full checked lifecycle and returns rollback state in
// Receipt.State.
func (e *Engine) Execute(ctx context.Context, actionType Type, parameters json.RawMessage) (Receipt, error) {
	receipt := e.Run(ctx, Request{
		ActionID: receiptID(), Actor: "local-agent", Type: actionType,
		Operation: OperationExecute, Parameters: parameters,
	})
	return receipt, receiptError(receipt)
}

// Rollback restores state returned by Execute or Apply.
func (e *Engine) Rollback(ctx context.Context, actionType Type, parameters, rollbackState json.RawMessage) (Receipt, error) {
	actionID := receiptID()
	if sealed, err := decodeStrict[sealedRollbackState](rollbackState); err == nil && actionIDPattern.MatchString(sealed.ActionID) {
		actionID = sealed.ActionID
	}
	receipt := e.Run(ctx, Request{
		ActionID: actionID, Actor: "local-agent", Type: actionType,
		Operation: OperationRollback, Parameters: parameters, State: rollbackState,
	})
	return receipt, receiptError(receipt)
}

func (e *Engine) sealState(actionID string, actionType Type, parameters, payload json.RawMessage) json.RawMessage {
	state := sealedRollbackState{
		Version: 1, ActionID: actionID, Type: actionType,
		ParametersDigest: digestParameters(parameters), Payload: append(json.RawMessage(nil), payload...),
	}
	state.MAC = e.stateMAC(state)
	encoded, _ := json.Marshal(state)
	return encoded
}

func (e *Engine) openState(request Request) (json.RawMessage, error) {
	if !validState(request.State) {
		return nil, ErrRollbackStateNeeded
	}
	state, err := decodeStrict[sealedRollbackState](request.State)
	if err != nil || state.Version != 1 || !json.Valid(state.Payload) || len(state.Payload) > maxRollbackStateBytes {
		return nil, errors.New("rollback state is invalid or unsigned")
	}
	if state.ActionID != request.ActionID || state.Type != request.Type || state.ParametersDigest != digestParameters(request.Parameters) {
		return nil, errors.New("rollback state does not match the action request")
	}
	expected := e.stateMAC(state)
	if len(expected) != len(state.MAC) || !subtleConstantCompare(expected, state.MAC) {
		return nil, errors.New("rollback state signature is invalid")
	}
	return append(json.RawMessage(nil), state.Payload...), nil
}

func (e *Engine) stateMAC(state sealedRollbackState) string {
	mac := hmac.New(sha256.New, e.stateKey)
	_, _ = mac.Write([]byte(strconv.Itoa(state.Version)))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write([]byte(state.ActionID))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write([]byte(state.Type))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write([]byte(state.ParametersDigest))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write(state.Payload)
	return hex.EncodeToString(mac.Sum(nil))
}

func subtleConstantCompare(left, right string) bool {
	return hmac.Equal([]byte(left), []byte(right))
}

func receiptError(receipt Receipt) error {
	if receipt.Success {
		return nil
	}
	if receipt.Error == "" {
		return errors.New("action failed")
	}
	return errors.New(receipt.Error)
}

func validState(state json.RawMessage) bool {
	return len(state) > 0 && json.Valid(state) && string(state) != "null"
}

func receiptID() string {
	random := make([]byte, 16)
	if _, err := rand.Read(random); err != nil {
		return fmt.Sprintf("receipt-%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(random)
}

func digestBytes(value []byte) string {
	digest := sha256.Sum256(value)
	return "sha256:" + hex.EncodeToString(digest[:])
}

func digestParameters(raw json.RawMessage) string {
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return digestBytes(raw)
	}
	canonical, err := json.Marshal(value)
	if err != nil {
		return digestBytes(raw)
	}
	return digestBytes(canonical)
}

// ParametersDigest returns the canonical digest embedded in Helper receipts.
// Controller-side receipt validation uses the same function so an Agent cannot
// accidentally associate a successful receipt with different approved input.
func ParametersDigest(raw json.RawMessage) string {
	return digestParameters(raw)
}

func receiptDigest(receipt Receipt) string {
	receipt.Digest = ""
	encoded, _ := json.Marshal(receipt)
	return digestBytes(encoded)
}
