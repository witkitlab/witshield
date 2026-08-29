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

export type IncidentStatus = 'open' | 'investigating' | 'awaiting_approval' | 'responding' | 'monitoring' | 'resolved' | 'dismissed';

export interface SecurityIncident {
  id: string;
  deviceId: string;
  correlationKey: string;
  category: string;
  severity: Severity;
  status: IncidentStatus;
  title: string;
  summary: string;
  signalCount: number;
  firstSeenAt: string;
  lastSeenAt: string;
  lastInvestigatedAt?: string;
  createdAt: string;
  updatedAt: string;
}

export interface SecuritySignal {
  id: string;
  deviceId: string;
  type: string;
  category: string;
  severity: Severity;
  trust: 'verified' | 'unverified' | string;
  subject?: string;
  summary: string;
  source: string;
  sourceRef?: string;
  occurredAt: string;
  ingestedAt: string;
}

export interface InvestigationToolCall {
  tool: string;
  summary: string;
  startedAt: string;
  endedAt: string;
}

export interface Investigation {
  id: string;
  incidentId: string;
  status: 'queued' | 'running' | 'completed' | 'failed';
  trigger: string;
  hypothesis?: string;
  observations?: string[];
  uncertainties?: string[];
  nextChecks?: string[];
  conclusion?: string;
  confidence: number;
  model?: string;
  toolCalls?: InvestigationToolCall[];
  error?: string;
  startedAt?: string;
  completedAt?: string;
}

export interface ResponseStep {
  id: string;
  actionType: string;
  title: string;
  rationale: string;
  parameters: Record<string, unknown>;
  risk: 'low' | 'medium' | 'high';
  requiresApproval: boolean;
  actionId?: string;
}

export interface ResponsePlan {
  id: string;
  incidentId: string;
  investigationId?: string;
  title: string;
  rationale: string;
  risk: 'low' | 'medium' | 'high';
  status: 'proposed' | 'approved' | 'executing' | 'completed' | 'failed' | 'cancelled';
  requiresApproval: boolean;
  steps: ResponseStep[];
}

export interface PolicyGrant {
  deviceId: string;
  capability: string;
  enabled: boolean;
  mode: 'observe' | 'assist' | 'auto_low_risk' | 'enhanced';
  allowedActionTypes: string[];
  maxActionsPerHour: number;
  emergencyStop: boolean;
  updatedAt: string;
}

export interface IncidentDetail {
  incident: SecurityIncident;
  signals: SecuritySignal[];
  investigations: Investigation[];
  responsePlans: ResponsePlan[];
  timeline: Array<{ id: number; actor: string; type: string; summary: string; createdAt: string }>;
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

export interface AIInvestigationPolicy {
  profile: 'economy' | 'balanced' | 'sensitive';
  dailyTokenBudget: number;
  emergencyReserveTokens: number;
  shareNetworkIndicators: boolean;
  shareAccountNames: boolean;
  updatedAt: string;
}

export interface AIInvestigationUsage {
  day: string;
  regularTokensUsed: number;
  emergencyTokensUsed: number;
  investigationCalls: number;
  updatedAt: string;
}

export interface SensorHealth {
  deviceId: string;
  sensorId: string;
  name: string;
  mode: string;
  state: 'active' | 'degraded' | 'unavailable' | 'optional';
  cadenceSeconds: number;
  lastSuccessAt?: string;
  lastEventAt?: string;
  eventCount: number;
  error?: string;
  updatedAt: string;
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
  incidents: SecurityIncident[];
  policyGrants: PolicyGrant[];
  audit: AuditEvent[];
  securityEvents: SecurityObservation[];
  actions: ActionRecord[];
  ai: AISettings;
  investigationPolicy: AIInvestigationPolicy;
  investigationUsage: AIInvestigationUsage;
  sensors: SensorHealth[];
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
