export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type DeviceStatus = 'online' | 'offline' | 'attention';

export interface Device {
  id: string;
  name: string;
  hostname: string;
  os: string;
  kernel: string;
  arch: string;
  address: string;
  status: DeviceStatus;
  version: string;
  lastSeen: string;
  lastScan: string;
  score: number | null;
  findings: number;
}

export interface Finding {
  id: string;
  deviceId: string;
  severity: Severity;
  title: string;
  summary: string;
  evidence: string[];
  category: string;
  detectedAt: string;
  state: 'open' | 'accepted' | 'resolved';
  remediation?: ActionPlan;
}

export interface SecurityReport {
  id: string;
  deviceId: string;
  startedAt: string;
  completedAt: string;
  score: number;
  checks: number;
  completedChecks: number;
  coveragePercent: number;
  findingCount: number | null;
  mode: string;
  errors: string[];
  findings: Finding[];
  detailsLoaded: boolean;
}

export interface ActionStep {
  id: string;
  title: string;
  kind: 'config_patch' | 'package_upgrade' | 'temporary_block' | 'service_restart';
  preview: string;
  impact: string;
  rollback: string;
}

export interface ActionPlan {
  id: string;
  approvalNonce?: string;
  title: string;
  risk: 'low' | 'medium' | 'high';
  requiresApproval: boolean;
  expiresAt: string;
  checks: string[];
  steps: ActionStep[];
}

export interface AuditEvent {
  id: string;
  type: 'scan' | 'finding' | 'approval' | 'action' | 'rollback' | 'defense';
  title: string;
  detail: string;
  actor: string;
  device: string;
  timestamp: string;
  result: 'success' | 'pending' | 'failed' | 'blocked';
}

export interface SecurityObservation {
  id: string;
  deviceId: string;
  type: 'ssh_auth_failure_untrusted' | 'ssh_auth_log_line_oversized_untrusted' | 'defense_correlation_capacity_degraded';
  sourceIp?: string;
  occurredAt: string;
  payload: Record<string, unknown>;
}

export interface ActionRecord {
  id: string;
  deviceId: string;
  type: string;
  title: string;
  status: 'draft' | 'approved' | 'executing' | 'awaiting_confirmation' | 'confirming' | 'succeeded' | 'failed' | 'rolling_back' | 'rolled_back' | 'cancelled' | 'indeterminate';
  createdAt: string;
  updatedAt: string;
  confirmBy?: string;
  canRollback: boolean;
  error?: string;
}

export interface DefensePolicy {
  id: string;
  deviceId?: string;
  name: string;
  description: string;
  enabled: boolean;
  mode: 'observe' | 'recommend' | 'auto_contain';
  trigger: string;
  action: string;
  ttlMinutes: number;
  lastTriggered?: string;
  emergencyStop?: boolean;
  failureThreshold?: number;
  window?: string;
  banDuration?: string;
  maxBansPerHour?: number;
  allowlist?: string[];
  editable?: boolean;
}

export interface ScanSchedule {
  id: string;
  deviceId: string;
  every: string;
  enabled: boolean;
  nextRunAt: string;
  lastRunAt?: string;
}

export interface AISettings {
  protocol: 'openai_responses' | 'openai_chat' | 'anthropic_messages';
  baseUrl: string;
  model: string;
  hasKey: boolean;
  keyHint: string;
  customHeaderKeys: string[];
  privacyMode: 'minimal' | 'balanced';
}

export interface NotificationSettings {
  configured: boolean;
  webhookEnabled: boolean;
  webhookUrl: string;
  webhookSecretConfigured: boolean;
  smtpEnabled: boolean;
  smtpHost: string;
  smtpPort: number;
  smtpUsername: string;
  smtpPasswordConfigured: boolean;
  smtpFrom: string;
  smtpTo: string[];
}

export interface DashboardSnapshot {
  score: number | null;
  previousScore: number;
  checks: number;
  devicesOnline: number;
  devicesTotal: number;
  openFindings: number;
  criticalFindings: number;
  lastScan: string;
  nextScan: string;
  devices: Device[];
  reports: SecurityReport[];
  findings: Finding[];
  policies: DefensePolicy[];
  audit: AuditEvent[];
  securityEvents: SecurityObservation[];
  actions: ActionRecord[];
  ai: AISettings;
  notifications: NotificationSettings;
  schedules: ScanSchedule[];
  coverageIssues: Array<{
    deviceId: string;
    deviceName: string;
    completedChecks: number;
    checks: number;
    coveragePercent: number;
    mode: string;
    errors: string[];
  }>;
}

export type Section = 'overview' | 'findings' | 'reports' | 'devices' | 'policies' | 'audit' | 'settings';
