import { demoDashboard } from './demo-data';
import type {
  ActionPlan,
  ActionRecord,
  AISettings,
  AuditEvent,
  DashboardSnapshot,
  DefensePolicy,
  Device,
  Finding,
  NotificationSettings,
  ScanSchedule,
  SecurityObservation,
  Severity,
} from './types';

export const demoMode = process.env.NEXT_PUBLIC_WITSHIELD_DEMO !== 'false';

export class APIError extends Error {
  status: number;
  code?: string;

  constructor(message: string, status: number, code?: string) {
    super(message);
    this.name = 'APIError';
    this.status = status;
    this.code = code;
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`/api/v1${path}`, {
    ...init,
    credentials: 'same-origin',
    headers: {
      Accept: 'application/json',
      ...(init?.body ? { 'Content-Type': 'application/json' } : {}),
      ...init?.headers,
    },
  });
  const body = response.status === 204
    ? undefined
    : await response.json().catch(() => undefined) as { error?: { code?: string; message?: string } } | T | undefined;
  if (!response.ok) {
    const error = typeof body === 'object' && body !== null && 'error' in body ? body.error : undefined;
    throw new APIError(error?.message ?? `请求失败（${response.status}）`, response.status, error?.code);
  }
  return body as T;
}

async function requestItems<T>(path: string): Promise<T[]> {
  const result = await request<{ items: T[] }>(path);
  return result.items ?? [];
}

function dateText(value?: string | null): string {
  if (!value) return '尚未';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  const delta = Date.now() - date.getTime();
  if (delta >= 0 && delta < 60_000) return '刚刚';
  if (delta >= 0 && delta < 3_600_000) return `${Math.floor(delta / 60_000)} 分钟前`;
  if (delta >= 0 && delta < 24 * 3_600_000) return `${Math.floor(delta / 3_600_000)} 小时前`;
  return new Intl.DateTimeFormat('zh-CN', { month: 'numeric', day: 'numeric', hour: '2-digit', minute: '2-digit' }).format(date);
}

function deadlineText(value?: string | null): string | undefined {
  if (!value) return undefined;
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  const today = new Date();
  const sameDay = date.getFullYear() === today.getFullYear() && date.getMonth() === today.getMonth() && date.getDate() === today.getDate();
  const formatted = new Intl.DateTimeFormat('zh-CN', sameDay
    ? { hour: '2-digit', minute: '2-digit' }
    : { month: 'numeric', day: 'numeric', hour: '2-digit', minute: '2-digit' }).format(date);
  return `${sameDay ? '今天 ' : ''}${formatted} 前`;
}

function durationMinutes(raw?: string): number {
  if (!raw) return 0;
  const match = raw.match(/^([0-9]+(?:\.[0-9]+)?)(ms|s|m|h)$/);
  if (!match) return 0;
  const value = Number(match[1]);
  return Math.max(0, Math.round(value * ({ ms: 1 / 60_000, s: 1 / 60, m: 1, h: 60 } as const)[match[2] as 'ms' | 's' | 'm' | 'h']));
}

export interface ServerStatus {
  initialized: boolean;
  authenticated: boolean;
  mode: 'standalone' | 'hub';
  version: string;
}

interface RawServerStatus {
  initialized?: boolean;
  needsBootstrap?: boolean;
  authenticated?: boolean;
  mode?: string;
  version?: string;
}

export async function getServerStatus(): Promise<ServerStatus> {
  if (demoMode) return { initialized: true, authenticated: true, mode: 'hub', version: 'v0.1.0-preview' };
  const raw = await request<RawServerStatus>('/status');
  return {
    initialized: raw.initialized ?? !raw.needsBootstrap,
    authenticated: Boolean(raw.authenticated),
    mode: raw.mode === 'standalone' ? 'standalone' : 'hub',
    version: raw.version ?? 'dev',
  };
}

export async function bootstrapAdmin(username: string, password: string, bootstrapToken?: string): Promise<void> {
  await request('/admin/bootstrap', { method: 'POST', body: JSON.stringify({ username, password, bootstrapToken: bootstrapToken ?? '' }) });
}

export async function login(username: string, password: string): Promise<void> {
  await request('/auth/login', { method: 'POST', body: JSON.stringify({ username, password }) });
}

export async function logout(): Promise<void> {
  if (!demoMode) await request('/auth/logout', { method: 'POST' });
}

interface RawDevice {
  id: string;
  name: string;
  hostname: string;
  os: string;
  arch: string;
  agentVersion: string;
  status: 'pending' | 'online' | 'offline' | 'revoked';
  lastSeenAt?: string;
}

interface RawFinding {
  id: string;
  deviceId: string;
  severity: Severity;
  title: string;
  description: string;
  evidence?: string;
  remediation?: string;
  category: string;
  status: 'open' | 'resolved' | 'ignored';
  lastSeenAt: string;
}

interface RawReport {
  id: string;
  deviceId: string;
  completedAt: string;
  score: number;
  summary?: RawReportSummary | string;
}

interface RawReportSummary {
  checks?: number;
  completedChecks?: number;
  coveragePercent?: number;
  findingCount?: number;
  checkErrors?: string[];
  mode?: string;
}

interface RawAudit {
  id: number | string;
  actionId?: string;
  actor: string;
  event: string;
  details?: unknown;
  createdAt: string;
}

interface RawSecurityObservation {
  id: string;
  deviceId: string;
  type: SecurityObservation['type'];
  sourceIp?: string;
  occurredAt: string;
  payload?: Record<string, unknown>;
}

interface RawAISettings {
  protocol?: AISettings['protocol'];
  baseUrl?: string;
  model?: string;
  keyConfigured?: boolean;
  apiKeyHint?: string;
}

interface RawNotificationSettings {
  configured?: boolean;
  webhookEnabled?: boolean;
  webhookUrl?: string;
  webhookSecretConfigured?: boolean;
  smtpEnabled?: boolean;
  smtpHost?: string;
  smtpPort?: number;
  smtpUsername?: string;
  smtpPasswordConfigured?: boolean;
  smtpFrom?: string;
  smtpTo?: string[];
}

interface RawDefensePolicy {
  deviceId: string;
  enabled: boolean;
  emergencyStop: boolean;
  autoBan: boolean;
  failureThreshold: number;
  window: string;
  banDuration: string;
  maxBansPerHour: number;
  allowlist: string[];
}

interface RawSchedule {
  id: string;
  deviceId: string;
  every: string;
  enabled: boolean;
  nextRunAt: string;
  lastRunAt?: string;
}

function evidenceLines(raw?: string): string[] {
  if (!raw) return [];
  return raw.split(/\r?\n|\s*;\s*/).map((line) => line.trim()).filter(Boolean);
}

function mapFinding(raw: RawFinding): Finding {
  return {
    id: raw.id,
    deviceId: raw.deviceId,
    severity: raw.severity,
    title: raw.title,
    summary: raw.description,
    evidence: evidenceLines(raw.evidence),
    category: raw.category,
    detectedAt: dateText(raw.lastSeenAt),
    state: raw.status === 'ignored' ? 'accepted' : raw.status,
  };
}

function mapSchedule(raw: RawSchedule): ScanSchedule {
  return { ...raw, nextRunAt: dateText(raw.nextRunAt), lastRunAt: raw.lastRunAt ? dateText(raw.lastRunAt) : undefined };
}

function mapDefense(raw: RawDefensePolicy): DefensePolicy {
  return {
    id: `policy_ssh_${raw.deviceId}`,
    deviceId: raw.deviceId,
    name: 'SSH 暴力破解临时封禁',
    description: `同一来源在 ${raw.window} 内失败登录达到 ${raw.failureThreshold} 次时，临时封禁该 IP。`,
    enabled: raw.enabled,
    mode: raw.autoBan ? 'auto_contain' : 'recommend',
    trigger: `${raw.window} 内失败 ${raw.failureThreshold} 次`,
    action: raw.autoBan ? '自动临时封禁来源 IP' : '建议临时封禁来源 IP',
    ttlMinutes: durationMinutes(raw.banDuration),
    emergencyStop: raw.emergencyStop,
    failureThreshold: raw.failureThreshold,
    window: raw.window,
    banDuration: raw.banDuration,
    maxBansPerHour: raw.maxBansPerHour,
    allowlist: raw.allowlist,
    editable: true,
  };
}

export interface LiveSnapshot {
  devices: Device[];
  findings: Finding[];
  policies: DefensePolicy[];
  audit: AuditEvent[];
  securityEvents: SecurityObservation[];
  actions: ActionRecord[];
  ai: AISettings;
  notifications: NotificationSettings;
  schedules: ScanSchedule[];
  coverageIssues: DashboardSnapshot['coverageIssues'];
  checks: number;
}

async function requestCurrentFindingsForDevices(devices: RawDevice[]): Promise<RawFinding[]> {
  // Projection capacity is per device, not per Controller. Fetch each bounded
  // device projection so one noisy host cannot crowd another host's critical
  // risks out of a global page. Small batches avoid an unbounded browser-side
  // connection burst on large self-hosted fleets.
  const findings: RawFinding[] = [];
  const concurrency = 8;
  for (let offset = 0; offset < devices.length; offset += concurrency) {
    const pages = await Promise.all(devices.slice(offset, offset + concurrency).map((device) =>
      requestItems<RawFinding>(`/findings?deviceId=${encodeURIComponent(device.id)}&status=open&limit=2000`),
    ));
    findings.push(...pages.flat());
  }
  return findings;
}

async function requestLatestReportsForDevices(devices: RawDevice[]): Promise<RawReport[]> {
  const reports: RawReport[] = [];
  const concurrency = 8;
  for (let offset = 0; offset < devices.length; offset += concurrency) {
    const pages = await Promise.all(devices.slice(offset, offset + concurrency).map((device) =>
      requestItems<RawReport>(`/reports?deviceId=${encodeURIComponent(device.id)}&limit=1`),
    ));
    reports.push(...pages.flat());
  }
  return reports;
}

async function requestSecurityObservations(): Promise<RawSecurityObservation[]> {
  // Trusted journald events can authorize a deterministic policy and belong in
  // the action/audit views. This panel is intentionally limited to untrusted
  // observations plus the Controller's capacity-health signal, so it can never
  // visually blur evidence that did and did not participate in containment.
  const types: RawSecurityObservation['type'][] = [
    'ssh_auth_failure_untrusted',
    'ssh_auth_log_line_oversized_untrusted',
    'defense_correlation_capacity_degraded',
  ];
  const pages = await Promise.all(types.map((type) =>
    requestItems<RawSecurityObservation>(`/security-events?type=${encodeURIComponent(type)}&limit=50`),
  ));
  const unique = new Map<string, RawSecurityObservation>();
  for (const item of pages.flat()) unique.set(`${item.deviceId}:${item.id}`, item);
  return [...unique.values()]
    .sort((left, right) => new Date(right.occurredAt).getTime() - new Date(left.occurredAt).getTime())
    .slice(0, 50);
}

export async function loadSnapshot(): Promise<LiveSnapshot> {
  if (demoMode) {
    return {
      devices: structuredClone(demoDashboard.devices),
      findings: structuredClone(demoDashboard.findings),
      policies: structuredClone(demoDashboard.policies),
      audit: structuredClone(demoDashboard.audit),
      securityEvents: structuredClone(demoDashboard.securityEvents),
      actions: structuredClone(demoDashboard.actions),
      ai: structuredClone(demoDashboard.ai),
      notifications: structuredClone(demoDashboard.notifications),
      schedules: structuredClone(demoDashboard.schedules),
      coverageIssues: structuredClone(demoDashboard.coverageIssues),
      checks: demoDashboard.checks,
    };
  }
  const rawDevices = await requestItems<RawDevice>('/devices');
  const [rawFindings, reports, rawAudit, rawSecurityEvents, rawActions, rawAI, rawNotifications, rawSchedules, policyResults] = await Promise.all([
    requestCurrentFindingsForDevices(rawDevices),
    requestLatestReportsForDevices(rawDevices),
    requestItems<RawAudit>('/audit?limit=200'),
    requestSecurityObservations(),
    requestItems<RawAction>('/actions?limit=200'),
    request<RawAISettings>('/ai/settings'),
    request<RawNotificationSettings>('/notifications/settings'),
    requestItems<RawSchedule>('/schedules'),
    Promise.all(rawDevices.map((device) =>
      request<RawDefensePolicy>(`/devices/${encodeURIComponent(device.id)}/defense-policy`).catch(() => null),
    )),
  ]);
  const findings = rawFindings.map(mapFinding);
  const latestReports = new Map<string, RawReport>();
  for (const report of reports) {
    const current = latestReports.get(report.deviceId);
    if (!current || new Date(report.completedAt) > new Date(current.completedAt)) latestReports.set(report.deviceId, report);
  }
  const devices: Device[] = rawDevices.map((raw) => {
    const report = latestReports.get(raw.id);
    return {
      id: raw.id,
      name: raw.name,
      hostname: raw.hostname,
      os: raw.os,
      kernel: '由 Agent 管理',
      arch: raw.arch,
      address: '主动连接',
      status: raw.status === 'online' ? 'online' : raw.status === 'pending' ? 'attention' : 'offline',
      version: raw.agentVersion,
      lastSeen: dateText(raw.lastSeenAt),
      lastScan: dateText(report?.completedAt),
      score: report?.score ?? 100,
      findings: findings.filter((finding) => finding.deviceId === raw.id && finding.state === 'open').length,
    };
  });
  const audit: AuditEvent[] = rawAudit.map((raw) => ({
    id: String(raw.id),
    type: raw.event.includes('rollback') ? 'rollback' : raw.event.includes('approv') ? 'approval' : raw.event.includes('defen') || raw.event.includes('ban') ? 'defense' : 'action',
    title: raw.event.replaceAll('_', ' '),
    detail: raw.details ? JSON.stringify(raw.details) : `动作 ${raw.actionId ?? ''}`.trim(),
    actor: raw.actor,
    device: raw.actionId ?? '控制台',
    timestamp: dateText(raw.createdAt),
    result: raw.event.includes('fail') || raw.event.includes('block') ? 'failed' : raw.event.includes('request') ? 'pending' : 'success',
  }));
  let checks = 0;
  const coverageIssues: DashboardSnapshot['coverageIssues'] = [];
  for (const report of latestReports.values()) {
    const summary = parseReportSummary(report.summary);
    checks += summary.checks ?? 0;
    if ((summary.checkErrors?.length ?? 0) > 0 || (summary.coveragePercent ?? 100) < 100) {
      const device = devices.find((item) => item.id === report.deviceId);
      coverageIssues.push({
        deviceId: report.deviceId,
        deviceName: device?.name ?? report.deviceId,
        completedChecks: summary.completedChecks ?? Math.max(0, (summary.checks ?? 0) - (summary.checkErrors?.length ?? 0)),
        checks: summary.checks ?? 0,
        coveragePercent: summary.coveragePercent ?? 0,
        mode: summary.mode ?? 'unknown',
        errors: summary.checkErrors ?? [],
      });
    }
  }
  return {
    devices,
    findings,
    audit,
    securityEvents: rawSecurityEvents.map((item) => ({
      id: item.id,
      deviceId: item.deviceId,
      type: item.type,
      sourceIp: item.sourceIp,
      occurredAt: dateText(item.occurredAt),
      payload: item.payload ?? {},
    })),
    actions: rawActions.map(mapAction),
    policies: policyResults.filter((item): item is RawDefensePolicy => Boolean(item)).map(mapDefense),
    ai: {
      protocol: rawAI.protocol ?? 'openai_responses',
      baseUrl: rawAI.baseUrl ?? 'https://api.openai.com/v1',
      model: rawAI.model ?? '',
      hasKey: Boolean(rawAI.keyConfigured),
      keyHint: rawAI.apiKeyHint ?? '',
      privacyMode: 'minimal',
    },
    notifications: mapNotifications(rawNotifications),
    schedules: rawSchedules.map(mapSchedule),
    coverageIssues,
    checks,
  };
}

function parseReportSummary(summary?: RawReport['summary']): RawReportSummary {
  if (!summary) return {};
  if (typeof summary !== 'string') return summary;
  try { return JSON.parse(summary) as RawReportSummary; }
  catch { return {}; }
}

function mapNotifications(raw: RawNotificationSettings): NotificationSettings {
  return {
    configured: raw.configured ?? Boolean(raw.webhookEnabled || raw.smtpEnabled || raw.webhookUrl || raw.smtpHost),
    webhookEnabled: Boolean(raw.webhookEnabled),
    webhookUrl: raw.webhookUrl ?? '',
    webhookSecretConfigured: Boolean(raw.webhookSecretConfigured),
    smtpEnabled: Boolean(raw.smtpEnabled),
    smtpHost: raw.smtpHost ?? '',
    smtpPort: raw.smtpPort ?? 587,
    smtpUsername: raw.smtpUsername ?? '',
    smtpPasswordConfigured: Boolean(raw.smtpPasswordConfigured),
    smtpFrom: raw.smtpFrom ?? '',
    smtpTo: raw.smtpTo ?? [],
  };
}

export interface NotificationSettingsDraft extends NotificationSettings {
  webhookSecret?: string;
  smtpPassword?: string;
  clearWebhookSecret?: boolean;
  clearSmtpPassword?: boolean;
}

export async function saveNotificationSettings(input: NotificationSettingsDraft): Promise<NotificationSettings> {
  if (demoMode) {
    await new Promise((resolve) => setTimeout(resolve, 450));
    return {
      ...input,
      configured: input.webhookEnabled || input.smtpEnabled,
      webhookSecretConfigured: input.clearWebhookSecret ? false : input.webhookSecretConfigured || Boolean(input.webhookSecret),
      smtpPasswordConfigured: input.clearSmtpPassword ? false : input.smtpPasswordConfigured || Boolean(input.smtpPassword),
    };
  }
  const result = await request<RawNotificationSettings>('/notifications/settings', {
    method: 'PUT',
    body: JSON.stringify({
      webhookEnabled: input.webhookEnabled,
      webhookUrl: input.webhookUrl,
      ...(input.webhookSecret ? { webhookSecret: input.webhookSecret } : {}),
      ...(input.clearWebhookSecret ? { clearWebhookSecret: true } : {}),
      smtpEnabled: input.smtpEnabled,
      smtpHost: input.smtpHost,
      smtpPort: input.smtpPort,
      smtpUsername: input.smtpUsername,
      ...(input.smtpPassword ? { smtpPassword: input.smtpPassword } : {}),
      ...(input.clearSmtpPassword ? { clearSmtpPassword: true } : {}),
      smtpFrom: input.smtpFrom,
      smtpTo: input.smtpTo,
    }),
  });
  return mapNotifications({ ...result, configured: input.webhookEnabled || input.smtpEnabled });
}

export async function testNotifications(): Promise<void> {
  if (demoMode) {
    await new Promise((resolve) => setTimeout(resolve, 550));
    return;
  }
  await request('/notifications/test', { method: 'POST' });
}

export async function requestScan(deviceId: string): Promise<void> {
  if (demoMode) {
    await new Promise((resolve) => setTimeout(resolve, 850));
    return;
  }
  await request(`/devices/${encodeURIComponent(deviceId)}/scan`, { method: 'POST' });
}

export async function createEnrollmentToken(): Promise<{ id: string; token: string; expiresAt: string }> {
  if (demoMode) return { id: 'enroll_demo', token: 'enroll_demo_7H9K-M2QD-W8TX', expiresAt: new Date(Date.now() + 15 * 60_000).toISOString() };
  const result = await request<{ enrollmentToken: { id: string; expiresAt: string }; token: string }>('/enrollment-tokens', {
    method: 'POST',
    body: JSON.stringify({ name: '网页一次性接入', expiresIn: '15m' }),
  });
  return { id: result.enrollmentToken.id, token: result.token, expiresAt: result.enrollmentToken.expiresAt };
}

export async function saveAISettings(input: AISettings & { apiKey?: string; customHeaders?: Record<string, string> }): Promise<AISettings> {
  if (demoMode) {
    await new Promise((resolve) => setTimeout(resolve, 450));
    return { ...input, hasKey: input.hasKey || Boolean(input.apiKey), keyHint: input.apiKey ? `••••${input.apiKey.slice(-4)}` : input.keyHint };
  }
  const result = await request<RawAISettings>('/ai/settings', {
    method: 'PUT',
    body: JSON.stringify({
      protocol: input.protocol,
      baseUrl: input.baseUrl,
      model: input.model,
      ...(input.apiKey ? { apiKey: input.apiKey } : {}),
      ...(input.customHeaders ? { customHeaders: input.customHeaders } : {}),
    }),
  });
  return {
    protocol: result.protocol ?? input.protocol,
    baseUrl: result.baseUrl ?? input.baseUrl,
    model: result.model ?? input.model,
    hasKey: Boolean(result.keyConfigured),
    keyHint: result.apiKeyHint ?? '',
    privacyMode: input.privacyMode,
  };
}

export async function testAISettings(input: AISettings & { apiKey?: string }): Promise<{ ok: boolean; latencyMs: number; model: string }> {
  if (demoMode) {
    await new Promise((resolve) => setTimeout(resolve, 700));
    return { ok: true, latencyMs: 438, model: input.model };
  }
  return request('/ai/test', {
    method: 'POST',
    body: JSON.stringify({ settings: { protocol: input.protocol, baseUrl: input.baseUrl, model: input.model, ...(input.apiKey ? { apiKey: input.apiKey } : {}) } }),
  });
}

export async function chatAI(message: string, deviceId?: string, findingIds: string[] = []): Promise<string> {
  if (demoMode) {
    await new Promise((resolve) => setTimeout(resolve, 500));
    return '我会把扫描证据与推断分开说明。当前是交互演示；连接你自己的模型后，这里会基于该设备的最少必要、脱敏证据回答。';
  }
  const result = await request<{ message: string; canExecute: false }>('/ai/chat', {
    method: 'POST',
    body: JSON.stringify({ message, deviceId, findingIds }),
  });
  return result.message;
}

interface RawAction {
  id: string;
  deviceId: string;
  type: string;
  status: ActionRecord['status'];
  preview: Record<string, unknown>;
  createdAt: string;
  updatedAt: string;
  confirmBy?: string;
  rollbackPayload?: unknown;
  error?: string;
}

function mapAction(raw: RawAction): ActionRecord {
  const title = raw.type === 'ssh_password_hardening'
    ? '安全关闭 SSH 密码登录'
    : raw.type === 'package_security_upgrade'
      ? '安装指定安全更新'
      : raw.type === 'temporary_ip_ban'
        ? '临时封禁 SSH 攻击来源'
        : '修复文件权限';
  return {
    id: raw.id,
    deviceId: raw.deviceId,
    type: raw.type,
    title,
    status: raw.status,
    createdAt: dateText(raw.createdAt),
    updatedAt: dateText(raw.updatedAt),
    confirmBy: deadlineText(raw.confirmBy),
    canRollback: raw.rollbackPayload !== undefined && raw.rollbackPayload !== null,
    error: raw.error || undefined,
  };
}

function actionPlan(raw: RawAction, approvalNonce: string): ActionPlan {
  const preview = raw.preview ?? {};
  const impact = String(preview.impact ?? '执行只影响计划中列出的配置。');
  const rollback = String(preview.rollback ?? preview.safety ?? '失败时停止并报告，不执行额外变更。');
  const isSSH = raw.type === 'ssh_password_hardening';
  return {
    id: raw.id,
    approvalNonce,
    title: isSSH ? '安全关闭 SSH 密码登录' : '安装指定安全更新',
    risk: isSSH ? 'medium' : 'low',
    requiresApproval: true,
    expiresAt: '本次页面会话有效',
    checks: isSSH
      ? ['执行前验证当前 SSH 配置', '变更后要求你确认当前连接仍可用', '未在期限内确认则自动恢复原配置']
      : ['执行前验证包管理器状态', '只允许显式列出的包名并先模拟', '记录升级前版本用于回滚'],
    steps: [{
      id: `${raw.id}_step`,
      title: String(preview.summary ?? (isSSH ? '修改 SSH 登录策略' : '升级安全软件包')),
      kind: isSSH ? 'config_patch' : 'package_upgrade',
      preview: Array.isArray(preview.changes) ? preview.changes.join(' ') : isSSH ? 'PasswordAuthentication yes → no' : raw.type,
      impact,
      rollback,
    }],
  };
}

export function canCreateAction(finding: Finding): boolean {
  const category = finding.category.toLowerCase();
  return (category === 'ssh' && /password/i.test(finding.title)) || category === 'updates' || category === '软件包';
}

function packageNames(finding: Finding): string[] {
  const candidates = finding.evidence.join(',').split(/[\s,，]+/);
  return [...new Set(candidates.filter((item) => /^[a-z0-9][a-z0-9+.-]{0,127}(?::[a-z0-9][a-z0-9-]{0,31})?$/.test(item) && /[a-z]/.test(item)))].slice(0, 64);
}

export async function createActionForFinding(finding: Finding): Promise<ActionPlan> {
  if (demoMode) {
    await new Promise((resolve) => setTimeout(resolve, 550));
    if (finding.remediation) return structuredClone(finding.remediation);
    throw new APIError('此发现当前没有可自动执行的安全修复模板', 409, 'action_unavailable');
  }
  const ssh = finding.category.toLowerCase() === 'ssh' && /password/i.test(finding.title);
  const packages = ssh ? [] : packageNames(finding);
  if (!ssh && packages.length === 0) throw new APIError('没有提取到可安全升级的明确包名', 409, 'packages_unavailable');
  const result = await request<{ action: RawAction; approvalNonce: string }>('/actions', {
    method: 'POST',
    body: JSON.stringify({
      deviceId: finding.deviceId,
      findingId: finding.id,
      type: ssh ? 'ssh_password_hardening' : 'package_security_upgrade',
      parameters: ssh ? { rollbackAfterSeconds: 300 } : { packages },
    }),
  });
  return actionPlan(result.action, result.approvalNonce);
}

export async function approveAction(actionId: string, approvalNonce?: string): Promise<void> {
  if (demoMode) {
    await new Promise((resolve) => setTimeout(resolve, 650));
    return;
  }
  if (!approvalNonce) throw new APIError('批准凭据已失效，请重新生成修复计划', 409, 'approval_nonce_missing');
  await request(`/actions/${encodeURIComponent(actionId)}/approve`, { method: 'POST', body: JSON.stringify({ approvalNonce }) });
}

export async function rollbackAction(actionId: string): Promise<void> {
  if (demoMode) {
    await new Promise((resolve) => setTimeout(resolve, 500));
    return;
  }
  await request(`/actions/${encodeURIComponent(actionId)}/rollback`, { method: 'POST', body: JSON.stringify({}) });
}

export async function confirmAction(actionId: string): Promise<void> {
  if (demoMode) {
    await new Promise((resolve) => setTimeout(resolve, 450));
    return;
  }
  await request(`/actions/${encodeURIComponent(actionId)}/confirm`, { method: 'POST', body: JSON.stringify({}) });
}

function rawPolicy(deviceId: string, policy: DefensePolicy): RawDefensePolicy {
  return {
    deviceId,
    enabled: policy.enabled,
    emergencyStop: Boolean(policy.emergencyStop),
    autoBan: policy.mode === 'auto_contain',
    failureThreshold: policy.failureThreshold ?? 30,
    window: policy.window ?? '5m',
    banDuration: policy.banDuration ?? `${policy.ttlMinutes || 15}m`,
    maxBansPerHour: policy.maxBansPerHour ?? 20,
    allowlist: policy.allowlist ?? [],
  };
}

export async function saveDefensePolicy(deviceId: string, policy: DefensePolicy): Promise<DefensePolicy> {
  if (demoMode) {
    await new Promise((resolve) => setTimeout(resolve, 400));
    return mapDefense(rawPolicy(deviceId, policy));
  }
  const result = await request<RawDefensePolicy>(`/devices/${encodeURIComponent(deviceId)}/defense-policy`, { method: 'PUT', body: JSON.stringify(rawPolicy(deviceId, policy)) });
  return mapDefense(result);
}

export async function setEmergencyStop(deviceId: string, active: boolean): Promise<void> {
  if (demoMode) {
    await new Promise((resolve) => setTimeout(resolve, 350));
    return;
  }
  await request(`/devices/${encodeURIComponent(deviceId)}/emergency-stop`, { method: 'POST', body: JSON.stringify({ active }) });
}

export async function createSchedule(deviceId: string, every: string, enabled = true): Promise<ScanSchedule> {
  if (demoMode) {
    await new Promise((resolve) => setTimeout(resolve, 300));
    return { id: `schedule_${deviceId}_${every}`, deviceId, every, enabled, nextRunAt: '按计划运行' };
  }
  return mapSchedule(await request<RawSchedule>('/schedules', { method: 'POST', body: JSON.stringify({ deviceId, kind: 'scan', every, enabled }) }));
}

export async function updateSchedule(schedule: ScanSchedule, enabled: boolean): Promise<ScanSchedule> {
  if (demoMode) {
    await new Promise((resolve) => setTimeout(resolve, 300));
    return { ...schedule, enabled };
  }
  await request(`/schedules/${encodeURIComponent(schedule.id)}`, { method: 'PATCH', body: JSON.stringify({ every: schedule.every, enabled }) });
  return { ...schedule, enabled };
}
