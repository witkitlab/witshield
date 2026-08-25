// Package action implements the small, typed set of privileged changes that
// WitShield is allowed to make.  Requests contain action parameters, never a
// command line or shell program.
package action

import (
	"context"
	"encoding/json"
	"errors"
	"time"
)

// Type identifies a registered, typed playbook.
type Type string

const (
	TypePackageSecurityUpgrade Type = "package_security_upgrade"
	TypeSSHPasswordHardening   Type = "ssh_password_hardening"
	TypeTemporaryIPBan         Type = "temporary_ip_ban"
	TypeFilePermissionRepair   Type = "file_permission_repair"
)

// Operation is one phase in the action lifecycle. Execute is a convenience
// operation which performs precheck, preview, apply and verify in order.
type Operation string

const (
	OperationPrecheck Operation = "precheck"
	OperationPreview  Operation = "preview"
	OperationApply    Operation = "apply"
	OperationVerify   Operation = "verify"
	OperationRollback Operation = "rollback"
	OperationExecute  Operation = "execute"
	OperationConfirm  Operation = "confirm"
)

var (
	ErrInvalidRequest       = errors.New("invalid action request")
	ErrUnsupportedAction    = errors.New("unsupported action type")
	ErrUnsupportedOperation = errors.New("unsupported action operation")
	ErrRollbackStateNeeded  = errors.New("rollback state is required")
)

// Request is the only input accepted by Engine. State is opaque data returned
// by Apply and is required by Verify, Rollback and Confirm.
type Request struct {
	ActionID   string          `json:"actionId"`
	Actor      string          `json:"actor"`
	Type       Type            `json:"type"`
	Operation  Operation       `json:"operation"`
	Parameters json.RawMessage `json:"parameters"`
	State      json.RawMessage `json:"state,omitempty"`
}

// Invocation carries validated request metadata to a playbook.
type Invocation struct {
	ActionID   string
	Actor      string
	Parameters json.RawMessage
	State      json.RawMessage
}

// Result is a deliberately small audit-safe description of a phase result.
// Details must not contain secrets or whole file snapshots.
type Result struct {
	Summary string         `json:"summary"`
	Details map[string]any `json:"details,omitempty"`
}

// ApplyResult includes the state necessary to verify or undo the change.
// ConfirmBy is set for changes which automatically roll back unless confirmed.
type ApplyResult struct {
	Result
	State     json.RawMessage `json:"state"`
	ConfirmBy *time.Time      `json:"confirmBy,omitempty"`
}

// Playbook is implemented by every privileged action. Implementations must be
// idempotent where practical and must never invoke a shell interpreter.
type Playbook interface {
	Type() Type
	Validate(parameters json.RawMessage) error
	Precheck(context.Context, Invocation) (Result, error)
	Preview(context.Context, Invocation) (Result, error)
	Apply(context.Context, Invocation) (ApplyResult, error)
	Verify(context.Context, Invocation) (Result, error)
	Rollback(context.Context, Invocation) (Result, error)
}

// Confirmer is implemented by playbooks with a timed rollback window.
type Confirmer interface {
	Confirm(context.Context, Invocation) (Result, error)
}

// AuditStep records one lifecycle phase without logging raw parameters or
// snapshots.
type AuditStep struct {
	Operation  Operation `json:"operation"`
	StartedAt  time.Time `json:"startedAt"`
	FinishedAt time.Time `json:"finishedAt"`
	Success    bool      `json:"success"`
	Result     *Result   `json:"result,omitempty"`
	Error      string    `json:"error,omitempty"`
}

// Receipt is returned for every authenticated request, including failures.
// ParametersDigest lets an auditor correlate the receipt with an approved
// request without disclosing those parameters.
type Receipt struct {
	ID               string      `json:"id"`
	ActionID         string      `json:"actionId"`
	Actor            string      `json:"actor"`
	Type             Type        `json:"type"`
	Operation        Operation   `json:"operation"`
	ParametersDigest string      `json:"parametersDigest"`
	StartedAt        time.Time   `json:"startedAt"`
	FinishedAt       time.Time   `json:"finishedAt"`
	Success          bool        `json:"success"`
	Steps            []AuditStep `json:"steps"`
	// State is returned separately as rollbackPayload by the helper. It is not
	// serialized into an audit receipt because snapshots can contain sensitive
	// configuration data.
	State               json.RawMessage `json:"-"`
	RollbackStateDigest string          `json:"rollbackStateDigest,omitempty"`
	ConfirmBy           *time.Time      `json:"confirmBy,omitempty"`
	Error               string          `json:"error,omitempty"`
	Digest              string          `json:"digest"`
}
