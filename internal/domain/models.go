package domain

import (
	"encoding/json"
	"time"
)

type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

type FindingStatus string

const (
	FindingOpen     FindingStatus = "open"
	FindingResolved FindingStatus = "resolved"
	FindingIgnored  FindingStatus = "ignored"
)

type Finding struct {
	ID          string        `json:"id"`
	ReportID    string        `json:"reportId"`
	DeviceID    string        `json:"deviceId"`
	Fingerprint string        `json:"fingerprint"`
	Category    string        `json:"category"`
	Severity    Severity      `json:"severity"`
	Title       string        `json:"title"`
	Description string        `json:"description"`
	Evidence    string        `json:"evidence,omitempty"`
	Remediation string        `json:"remediation,omitempty"`
	Status      FindingStatus `json:"status"`
	FirstSeenAt time.Time     `json:"firstSeenAt"`
	LastSeenAt  time.Time     `json:"lastSeenAt"`
}

type Report struct {
	ID          string          `json:"id"`
	DeviceID    string          `json:"deviceId"`
	StartedAt   time.Time       `json:"startedAt"`
	CompletedAt time.Time       `json:"completedAt"`
	Score       int             `json:"score"`
	Summary     json.RawMessage `json:"summary,omitempty"`
	Findings    []Finding       `json:"findings,omitempty"`
}

type DeviceStatus string

const (
	DevicePending DeviceStatus = "pending"
	DeviceOnline  DeviceStatus = "online"
	DeviceOffline DeviceStatus = "offline"
	DeviceRevoked DeviceStatus = "revoked"
)

type Device struct {
	ID           string       `json:"id"`
	Name         string       `json:"name"`
	Hostname     string       `json:"hostname"`
	OS           string       `json:"os"`
	Arch         string       `json:"arch"`
	AgentVersion string       `json:"agentVersion"`
	ObserverOnly bool         `json:"observerOnly"`
	IdentityKey  string       `json:"-"`
	Status       DeviceStatus `json:"status"`
	LastSeenAt   *time.Time   `json:"lastSeenAt,omitempty"`
	EnrolledAt   time.Time    `json:"enrolledAt"`
	CreatedAt    time.Time    `json:"createdAt"`
	UpdatedAt    time.Time    `json:"updatedAt"`
}

type EnrollmentToken struct {
	ID        string     `json:"id"`
	Name      string     `json:"name"`
	Hint      string     `json:"hint"`
	MaxUses   int        `json:"maxUses"`
	Uses      int        `json:"uses"`
	ExpiresAt *time.Time `json:"expiresAt,omitempty"`
	RevokedAt *time.Time `json:"revokedAt,omitempty"`
	CreatedAt time.Time  `json:"createdAt"`
}

type Admin struct {
	ID        string    `json:"id"`
	Username  string    `json:"username"`
	CreatedAt time.Time `json:"createdAt"`
}

type Session struct {
	ID        string    `json:"id"`
	AdminID   string    `json:"adminId"`
	ExpiresAt time.Time `json:"expiresAt"`
	CreatedAt time.Time `json:"createdAt"`
}

type AIProtocol string

const (
	AIProtocolOpenAIResponses AIProtocol = "openai_responses"
	AIProtocolOpenAIChat      AIProtocol = "openai_chat"
	AIProtocolAnthropic       AIProtocol = "anthropic_messages"
)

type AISettings struct {
	Protocol      AIProtocol `json:"protocol"`
	BaseURL       string     `json:"baseUrl"`
	Model         string     `json:"model"`
	APIKey        string     `json:"apiKey,omitempty"`
	APIKeyHint    string     `json:"apiKeyHint,omitempty"`
	KeyConfigured bool       `json:"keyConfigured"`
	CustomHeaders Headers    `json:"customHeaders,omitempty"`
	UpdatedAt     time.Time  `json:"updatedAt"`
}

type Headers map[string]string

type NotificationSettings struct {
	WebhookEnabled          bool      `json:"webhookEnabled"`
	WebhookURL              string    `json:"webhookUrl,omitempty"`
	WebhookSecretConfigured bool      `json:"webhookSecretConfigured"`
	SMTPEnabled             bool      `json:"smtpEnabled"`
	SMTPHost                string    `json:"smtpHost,omitempty"`
	SMTPPort                int       `json:"smtpPort,omitempty"`
	SMTPUsername            string    `json:"smtpUsername,omitempty"`
	SMTPPasswordConfigured  bool      `json:"smtpPasswordConfigured"`
	SMTPFrom                string    `json:"smtpFrom,omitempty"`
	SMTPTo                  []string  `json:"smtpTo,omitempty"`
	UpdatedAt               time.Time `json:"updatedAt"`
}

type NotificationEvent struct {
	ID         string          `json:"id"`
	Type       string          `json:"type"`
	Severity   Severity        `json:"severity"`
	DeviceID   string          `json:"deviceId,omitempty"`
	Title      string          `json:"title"`
	Message    string          `json:"message"`
	OccurredAt time.Time       `json:"occurredAt"`
	Data       json.RawMessage `json:"data,omitempty"`
}

type NotificationChannel string

const (
	NotificationWebhook NotificationChannel = "webhook"
	NotificationSMTP    NotificationChannel = "smtp"
)

type ScheduleKind string

const ScheduleScan ScheduleKind = "scan"

type Schedule struct {
	ID        string        `json:"id"`
	DeviceID  string        `json:"deviceId"`
	Kind      ScheduleKind  `json:"kind"`
	Interval  time.Duration `json:"-"`
	Every     string        `json:"every"`
	Enabled   bool          `json:"enabled"`
	NextRunAt time.Time     `json:"nextRunAt"`
	LastRunAt *time.Time    `json:"lastRunAt,omitempty"`
	CreatedAt time.Time     `json:"createdAt"`
	UpdatedAt time.Time     `json:"updatedAt"`
}

type CommandType string

const (
	CommandScan          CommandType = "scan"
	CommandExecuteAction CommandType = "execute_action"
	CommandRollback      CommandType = "rollback_action"
	CommandConfirm       CommandType = "confirm_action"
)

type DeviceCommand struct {
	ID          string          `json:"id"`
	DeviceID    string          `json:"deviceId"`
	Type        CommandType     `json:"type"`
	Payload     json.RawMessage `json:"payload"`
	CreatedAt   time.Time       `json:"createdAt"`
	ClaimedAt   *time.Time      `json:"claimedAt,omitempty"`
	CompletedAt *time.Time      `json:"completedAt,omitempty"`
	Result      json.RawMessage `json:"result,omitempty"`
	Error       string          `json:"error,omitempty"`
}

const ActionCommandTTL = 10 * time.Minute
const ActionExecutionTimeout = 2 * time.Hour

type ActionStatus string

const (
	ActionDraft                ActionStatus = "draft"
	ActionApproved             ActionStatus = "approved"
	ActionExecuting            ActionStatus = "executing"
	ActionAwaitingConfirmation ActionStatus = "awaiting_confirmation"
	ActionConfirming           ActionStatus = "confirming"
	ActionSucceeded            ActionStatus = "succeeded"
	ActionFailed               ActionStatus = "failed"
	ActionRollingBack          ActionStatus = "rolling_back"
	ActionRolledBack           ActionStatus = "rolled_back"
	ActionCancelled            ActionStatus = "cancelled"
	// ActionIndeterminate means the privileged operation started but its signed
	// result never reached the Controller. It must never be silently retried:
	// the remote state is unknown and requires administrator verification.
	ActionIndeterminate ActionStatus = "indeterminate"
)

type Action struct {
	ID              string          `json:"id"`
	DeviceID        string          `json:"deviceId"`
	FindingID       string          `json:"findingId,omitempty"`
	Type            string          `json:"type"`
	Parameters      json.RawMessage `json:"parameters"`
	Preview         json.RawMessage `json:"preview"`
	Status          ActionStatus    `json:"status"`
	ApprovalNonce   string          `json:"approvalNonce,omitempty"`
	ApprovedBy      string          `json:"approvedBy,omitempty"`
	ApprovedAt      *time.Time      `json:"approvedAt,omitempty"`
	ExecutedAt      *time.Time      `json:"executedAt,omitempty"`
	CompletedAt     *time.Time      `json:"completedAt,omitempty"`
	RollbackPayload json.RawMessage `json:"rollbackPayload,omitempty"`
	ConfirmBy       *time.Time      `json:"confirmBy,omitempty"`
	Error           string          `json:"error,omitempty"`
	CreatedAt       time.Time       `json:"createdAt"`
	UpdatedAt       time.Time       `json:"updatedAt"`
}

type ActionAudit struct {
	ID        int64           `json:"id"`
	ActionID  string          `json:"actionId"`
	Actor     string          `json:"actor"`
	Event     string          `json:"event"`
	Details   json.RawMessage `json:"details,omitempty"`
	CreatedAt time.Time       `json:"createdAt"`
}

type DefensePolicy struct {
	DeviceID         string        `json:"deviceId"`
	Enabled          bool          `json:"enabled"`
	EmergencyStop    bool          `json:"emergencyStop"`
	AutoBan          bool          `json:"autoBan"`
	FailureThreshold int           `json:"failureThreshold"`
	Window           time.Duration `json:"-"`
	WindowText       string        `json:"window"`
	BanDuration      time.Duration `json:"-"`
	BanDurationText  string        `json:"banDuration"`
	MaxBansPerHour   int           `json:"maxBansPerHour"`
	Allowlist        []string      `json:"allowlist"`
	UpdatedAt        time.Time     `json:"updatedAt"`
}

type SecurityEvent struct {
	ID         string          `json:"id"`
	DeviceID   string          `json:"deviceId"`
	Type       string          `json:"type"`
	SourceIP   string          `json:"sourceIp,omitempty"`
	OccurredAt time.Time       `json:"occurredAt"`
	Payload    json.RawMessage `json:"payload,omitempty"`
}

type TemporaryBan struct {
	ID        string    `json:"id"`
	ActionID  string    `json:"actionId,omitempty"`
	DeviceID  string    `json:"deviceId"`
	SourceIP  string    `json:"sourceIp"`
	Reason    string    `json:"reason"`
	ExpiresAt time.Time `json:"expiresAt"`
	CreatedAt time.Time `json:"createdAt"`
	Simulated bool      `json:"simulated"`
	Status    string    `json:"status"`
}
