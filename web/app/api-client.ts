import { demoDashboard } from './demo-data';
import type {
  ActionPlan,
  ActionRecord,
  AISettings,
  AIInvestigationPolicy,
  AIInvestigationUsage,
  AuditEvent,
  DashboardSnapshot,
  DefensePolicy,
  Device,
  Finding,
  NotificationSettings,
  IncidentDetail,
  Investigation,
  PolicyGrant,
  ResponsePlan,
  ScanSchedule,
  SecurityIncident,
  SecurityReport,
  SecurityObservation,
  SensorHealth,
  Severity,
	SystemHealth,
} from './types';

export const demoMode = process.env.NEXT_PUBLIC_WITSHIELD_DEMO !== 'false';
const demoInvestigationResults = new Map<string, { investigation: Investigation; responsePlan?: ResponsePlan }>();

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
  startedAt?: string;
  completedAt: string;
  score: number;
  summary?: unknown;
  findings?: RawFinding[];
}

interface RawReportSummary {
  checks?: number;
  completedChecks?: number;
  coveragePercent?: number;
  findingCount?: number;
  checkErrors?: string[];
  mode?: string;
  formatErrors: string[];
}

interface VerifiedReportCoverage {
  known: boolean;
  checks: number;
  completedChecks: number;
  coveragePercent: number;
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
  customHeaders?: Record<string, string>;
  verifiedAt?: string;
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

type RawIncident = Omit<SecurityIncident, 'firstSeenAt' | 'lastSeenAt' | 'lastInvestigatedAt' | 'createdAt' | 'updatedAt'> & {
  firstSeenAt: string;
  lastSeenAt: string;
  lastInvestigatedAt?: string;
  createdAt: string;
  updatedAt: string;
};

type RawPolicyGrant = Omit<PolicyGrant, 'updatedAt'> & { updatedAt: string };

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

function mapIncident(raw: RawIncident): SecurityIncident {
  return {
    ...raw,
    firstSeenAt: dateText(raw.firstSeenAt),
    lastSeenAt: dateText(raw.lastSeenAt),
    lastInvestigatedAt: raw.lastInvestigatedAt ? dateText(raw.lastInvestigatedAt) : undefined,
    createdAt: dateText(raw.createdAt),
    updatedAt: dateText(raw.updatedAt),
  };
}

export interface LiveSnapshot {
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
  coverageIssues: DashboardSnapshot['coverageIssues'];
  checks: number;
  systemHealth?: SystemHealth;
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
      // The dashboard needs only the current score and coverage. Keep refresh
      // cost bounded to one report per device; full history is fetched only
      // after an administrator explicitly selects one device in Reports.
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
      reports: structuredClone(demoDashboard.reports),
      findings: structuredClone(demoDashboard.findings),
      policies: structuredClone(demoDashboard.policies),
      incidents: structuredClone(demoDashboard.incidents),
      policyGrants: structuredClone(demoDashboard.policyGrants),
      audit: structuredClone(demoDashboard.audit),
      securityEvents: structuredClone(demoDashboard.securityEvents),
      actions: structuredClone(demoDashboard.actions),
      ai: structuredClone(demoDashboard.ai),
      investigationPolicy: structuredClone(demoDashboard.investigationPolicy),
      investigationUsage: structuredClone(demoDashboard.investigationUsage),
      sensors: structuredClone(demoDashboard.sensors),
      notifications: structuredClone(demoDashboard.notifications),
      schedules: structuredClone(demoDashboard.schedules),
      coverageIssues: structuredClone(demoDashboard.coverageIssues),
      checks: demoDashboard.checks,
		systemHealth: { status: 'ok', database: 'ok', checkedAt: new Date().toISOString(), workers: [
			{ name: 'scheduler', status: 'ok', lastRunAt: new Date().toISOString(), lastSuccessAt: new Date().toISOString(), staleAfterSeconds: 60 },
			{ name: 'security_engineer', status: 'ok', lastRunAt: new Date().toISOString(), lastSuccessAt: new Date().toISOString(), staleAfterSeconds: 30 },
		] },
    };
  }
  const rawDevices = await requestItems<RawDevice>('/devices');
  const [rawFindings, reportHistory, rawAudit, rawSecurityEvents, rawActions, rawAI, rawInvestigation, rawSensors, rawNotifications, rawSchedules, rawIncidents, rawSystemHealth, policyResults, grantResults] = await Promise.all([
    requestCurrentFindingsForDevices(rawDevices),
    requestLatestReportsForDevices(rawDevices),
    requestItems<RawAudit>('/audit?limit=200'),
    requestSecurityObservations(),
    requestItems<RawAction>('/actions?limit=200'),
    request<RawAISettings>('/ai/settings'),
    request<{ policy: AIInvestigationPolicy; usage: AIInvestigationUsage }>('/ai/investigation-policy'),
    requestItems<SensorHealth>('/sensors'),
    request<RawNotificationSettings>('/notifications/settings'),
    requestItems<RawSchedule>('/schedules'),
    requestItems<RawIncident>('/incidents?limit=200'),
		request<SystemHealth>('/system/health').catch(() => undefined),
    Promise.all(rawDevices.map((device) =>
      request<RawDefensePolicy>(`/devices/${encodeURIComponent(device.id)}/defense-policy`).catch(() => null),
    )),
    Promise.all(rawDevices.map((device) =>
      requestItems<RawPolicyGrant>(`/devices/${encodeURIComponent(device.id)}/policy-grants`).catch(() => []),
    )),
  ]);
  const reportsByID = new Map(reportHistory.map((report) => [report.id, report]));
  const reports = [...reportsByID.values()].sort((left, right) => new Date(right.completedAt).getTime() - new Date(left.completedAt).getTime());
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
      score: report?.score ?? null,
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
  for (const device of devices) {
    if (!latestReports.has(device.id)) {
      coverageIssues.push({
        deviceId: device.id,
        deviceName: device.name,
        completedChecks: 0,
        checks: 0,
        coveragePercent: 0,
        mode: 'pending',
        errors: ['尚未收到首次扫描报告'],
      });
    }
  }
  for (const report of latestReports.values()) {
    const summary = parseReportSummary(report.summary);
    const coverage = verifiedReportCoverage(summary);
    checks += coverage.known ? coverage.checks : 0;
    const summaryErrors = [...summary.formatErrors, ...(summary.checkErrors ?? [])];
    if (!coverage.known || summaryErrors.length > 0 || coverage.coveragePercent < 100) {
      const device = devices.find((item) => item.id === report.deviceId);
      const errors = summaryErrors.length
        ? summaryErrors
        : coverage.known
          ? []
          : ['报告摘要缺少可验证的检查覆盖信息'];
      coverageIssues.push({
        deviceId: report.deviceId,
        deviceName: device?.name ?? report.deviceId,
        completedChecks: coverage.known ? coverage.completedChecks : 0,
        checks: coverage.known ? coverage.checks : 0,
        coveragePercent: coverage.known ? coverage.coveragePercent : 0,
        mode: summary.mode ?? 'unknown',
        errors,
      });
    }
  }
  return {
    devices,
    reports: reports.map((report) => mapReport(report)),
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
    incidents: rawIncidents.map(mapIncident),
    policyGrants: grantResults.flat().map((item) => ({ ...item, updatedAt: dateText(item.updatedAt) })),
      ai: {
      protocol: rawAI.protocol ?? 'openai_responses',
      baseUrl: rawAI.baseUrl ?? 'https://api.openai.com/v1',
      model: rawAI.model ?? '',
      hasKey: Boolean(rawAI.keyConfigured),
      keyHint: rawAI.apiKeyHint ?? '',
      customHeaderKeys: Object.keys(rawAI.customHeaders ?? {}).sort(),
      privacyMode: 'minimal',
      verifiedAt: rawAI.verifiedAt,
    },
    investigationPolicy: { ...rawInvestigation.policy, updatedAt: dateText(rawInvestigation.policy.updatedAt) },
    investigationUsage: { ...rawInvestigation.usage, updatedAt: dateText(rawInvestigation.usage.updatedAt) },
    sensors: rawSensors.map((sensor) => ({ ...sensor, lastSuccessAt: sensor.lastSuccessAt ? dateText(sensor.lastSuccessAt) : undefined, lastEventAt: sensor.lastEventAt ? dateText(sensor.lastEventAt) : undefined, updatedAt: dateText(sensor.updatedAt) })),
    notifications: mapNotifications(rawNotifications),
    schedules: rawSchedules.map(mapSchedule),
    coverageIssues,
    checks,
		systemHealth: rawSystemHealth,
  };
}

export async function saveInvestigationPolicy(policy: AIInvestigationPolicy): Promise<AIInvestigationPolicy> {
  if (demoMode) {
    await new Promise((resolve) => setTimeout(resolve, 250));
    demoDashboard.investigationPolicy = { ...structuredClone(policy), updatedAt: '刚刚' };
    return structuredClone(demoDashboard.investigationPolicy);
  }
  const raw = await request<AIInvestigationPolicy>('/ai/investigation-policy', {
    method: 'PUT',
    body: JSON.stringify({
      profile: policy.profile,
      dailyTokenBudget: policy.dailyTokenBudget,
      emergencyReserveTokens: policy.emergencyReserveTokens,
      shareNetworkIndicators: policy.shareNetworkIndicators,
      shareAccountNames: policy.shareAccountNames,
    }),
  });
  return { ...raw, updatedAt: dateText(raw.updatedAt) };
}

function mapReport(raw: RawReport, detailsLoaded = Array.isArray(raw.findings)): SecurityReport {
  const summary = parseReportSummary(raw.summary);
  const coverage = verifiedReportCoverage(summary);
  const errors = [...summary.formatErrors, ...(summary.checkErrors ?? [])];
  if (!coverage.known && errors.length === 0) errors.push('报告摘要缺少可验证的检查覆盖信息');
  return {
    id: raw.id,
    deviceId: raw.deviceId,
    startedAt: dateText(raw.startedAt),
    completedAt: dateText(raw.completedAt),
    score: raw.score,
    checks: coverage.known ? coverage.checks : 0,
    completedChecks: coverage.known ? coverage.completedChecks : 0,
    coveragePercent: coverage.known ? coverage.coveragePercent : 0,
    findingCount: summary.findingCount ?? (detailsLoaded ? (raw.findings?.length ?? 0) : null),
    mode: summary.mode ?? 'unknown',
    errors,
    findings: (raw.findings ?? []).map(mapFinding),
    detailsLoaded,
  };
}

export async function getReport(reportId: string): Promise<SecurityReport> {
  if (demoMode) {
    const report = demoDashboard.reports.find((item) => item.id === reportId);
    if (!report) throw new APIError('没有找到这份报告', 404, 'report_not_found');
    return structuredClone(report);
  }
  return mapReport(await request<RawReport>(`/reports/${encodeURIComponent(reportId)}`), true);
}

/**
 * The Controller retains at most 100 reports for each device. This request is
 * intentionally user-driven rather than part of `loadSnapshot`, so a fleet
 * refresh cannot grow with both device count and report retention.
 */
export async function getReportsForDevice(deviceId: string): Promise<SecurityReport[]> {
  if (demoMode) {
    return structuredClone(demoDashboard.reports.filter((report) => report.deviceId === deviceId));
  }
  const reports = await requestItems<RawReport>(`/reports?deviceId=${encodeURIComponent(deviceId)}&limit=100`);
  const unique = new Map(reports.map((report) => [report.id, report]));
  return [...unique.values()]
    .sort((left, right) => new Date(right.completedAt).getTime() - new Date(left.completedAt).getTime())
    .map((report) => mapReport(report));
}

function parseReportSummary(summary?: RawReport['summary']): RawReportSummary {
  const invalid = (): RawReportSummary => ({ formatErrors: ['报告摘要格式无效，无法验证扫描覆盖信息'] });
  if (summary === undefined || summary === null || summary === '') return { formatErrors: [] };
  let value: unknown = summary;
  if (typeof value === 'string') {
    try { value = JSON.parse(value) as unknown; }
    catch { return invalid(); }
  }
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return invalid();
  const source = value as Record<string, unknown>;
  let malformed = false;
  const readInteger = (key: string, maximum: number): number | undefined => {
    if (!(key in source)) return undefined;
    const candidate = source[key];
    if (!Number.isInteger(candidate) || (candidate as number) < 0 || (candidate as number) > maximum) {
      malformed = true;
      return undefined;
    }
    return candidate as number;
  };
  const checks = readInteger('checks', 10_000);
  const completedChecks = readInteger('completedChecks', 10_000);
  const findingCount = readInteger('findingCount', 100_000);
  let coveragePercent: number | undefined;
  if ('coveragePercent' in source) {
    const candidate = source.coveragePercent;
    if (typeof candidate === 'number' && Number.isFinite(candidate) && candidate >= 0 && candidate <= 100) coveragePercent = candidate;
    else malformed = true;
  }
  let checkErrors: string[] | undefined;
  if ('checkErrors' in source) {
    const candidate = source.checkErrors;
    if (Array.isArray(candidate) && candidate.length <= 10_000 && candidate.every((item) => typeof item === 'string' && item.length <= 4_000)) {
      checkErrors = candidate.slice();
    } else malformed = true;
  }
  let mode: string | undefined;
  if ('mode' in source) {
    if (source.mode === 'native' || source.mode === 'observer') mode = source.mode;
    else malformed = true;
  }
  if (checks !== undefined && completedChecks !== undefined && completedChecks > checks) malformed = true;
  return {
    checks,
    completedChecks: malformed && completedChecks !== undefined && checks !== undefined && completedChecks > checks ? undefined : completedChecks,
    coveragePercent,
    findingCount,
    checkErrors,
    mode,
    formatErrors: malformed ? ['报告摘要格式无效，无法验证扫描覆盖信息'] : [],
  };
}

function verifiedReportCoverage(summary: RawReportSummary): VerifiedReportCoverage {
  const checks = summary.checks;
  const completedChecks = summary.completedChecks;
  const coveragePercent = summary.coveragePercent;
  const expectedCoverage = checks && completedChecks !== undefined
    ? Math.floor((completedChecks * 100) / checks)
    : undefined;
  const known = summary.formatErrors.length === 0
    && Number.isInteger(checks)
    && (checks ?? 0) > 0
    && Number.isInteger(completedChecks)
    && (completedChecks ?? -1) >= 0
    && (completedChecks ?? Number.MAX_SAFE_INTEGER) <= (checks ?? 0)
    && typeof coveragePercent === 'number'
    && Number.isFinite(coveragePercent)
    && coveragePercent >= 0
    && coveragePercent <= 100
    && coveragePercent === expectedCoverage;
  return {
    known,
    checks: known ? (checks ?? 0) : 0,
    completedChecks: known ? (completedChecks ?? 0) : 0,
    coveragePercent: known ? (coveragePercent ?? 0) : 0,
  };
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
    return { ...input, hasKey: input.hasKey || Boolean(input.apiKey), keyHint: input.apiKey ? `••••${input.apiKey.slice(-4)}` : input.keyHint, customHeaderKeys: input.customHeaders ? Object.keys(input.customHeaders).sort() : input.customHeaderKeys };
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
    customHeaderKeys: Object.keys(result.customHeaders ?? {}).sort(),
    privacyMode: input.privacyMode,
    verifiedAt: result.verifiedAt,
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

export async function testSavedAISettings(): Promise<{ ok: boolean; latencyMs: number; model: string; verifiedAt: string }> {
  if (demoMode) {
    await new Promise((resolve) => setTimeout(resolve, 350));
    return { ok: true, latencyMs: 438, model: 'demo-model', verifiedAt: new Date().toISOString() };
  }
  return request('/ai/test', { method: 'POST' });
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
	const isPackage = raw.type === 'package_security_upgrade';
	const isBan = raw.type === 'temporary_ip_ban';
	const title = isSSH ? '安全关闭 SSH 密码登录' : isPackage ? '安装指定安全更新' : isBan ? '临时限制异常来源' : '修复关键文件权限';
	return {
		id: raw.id,
		approvalNonce,
		title,
		risk: isBan ? 'low' : isSSH || raw.type === 'file_permission_repair' ? 'medium' : 'high',
		requiresApproval: true,
		expiresAt: '本次页面会话有效',
		checks: isSSH
			? ['执行前验证当前 SSH 配置', '变更后要求你确认当前连接仍可用', '未在期限内确认则自动恢复原配置']
			: isPackage
				? ['执行前验证包管理器状态与已安装架构', '执行时解析目标版本；APT 如需触碰未列出的包会在 dpkg 前停止', '记录实际版本变化用于验证与回滚']
				: ['执行前由受限 Helper 再次验证目标与参数', '只运行注册的强类型 Playbook，不执行模型生成的命令', '执行后验证结果并保存可审计的回滚状态'],
		steps: [{
			id: `${raw.id}_step`,
			title: String(preview.summary ?? title),
			kind: isBan ? 'temporary_block' : isPackage ? 'package_upgrade' : 'config_patch',
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

export async function getIncident(incidentId: string): Promise<IncidentDetail> {
  if (demoMode) {
    const incident = demoDashboard.incidents.find((item) => item.id === incidentId);
    if (!incident) throw new APIError('没有找到这个安全事件', 404, 'incident_not_found');
    const result = demoInvestigationResults.get(incidentId);
    return { incident: structuredClone(incident), signals: [], investigations: result ? [structuredClone(result.investigation)] : [], responsePlans: result?.responsePlan ? [structuredClone(result.responsePlan)] : [], timeline: [] };
  }
  const raw = await request<IncidentDetail>(`/incidents/${encodeURIComponent(incidentId)}`);
  return { ...raw, incident: mapIncident(raw.incident as unknown as RawIncident) };
}

export async function investigateIncident(incidentId: string): Promise<{ investigation: Investigation; responsePlan?: ResponsePlan }> {
  if (demoMode) {
    await new Promise((resolve) => setTimeout(resolve, 700));
    const result: { investigation: Investigation; responsePlan?: ResponsePlan } = {
      investigation: {
        id: `inv_${incidentId}`, incidentId, status: 'completed', trigger: 'administrator', confidence: 86,
        hypothesis: '异常登录活动来自持续的凭据探测。',
        observations: ['同一公网来源在 5 分钟内产生 12 次可信 SSH 登录失败。', '当前事件中没有成功登录信号。'],
        uncertainties: ['尚不能判断来源是自动扫描还是定向凭据攻击。'],
        nextChecks: ['持续核对该来源后续登录结果与服务器账号变化。'],
        conclusion: '确定性认证日志显示同一公网来源在短时间内重复失败。尚未发现成功登录证据，建议持续观察并临时限制该来源。',
        model: demoDashboard.ai.model,
        toolCalls: [
          { tool: 'incident_signals', summary: '读取 12 条已归一化事件信号', startedAt: '刚刚', endedAt: '刚刚' },
          { tool: 'current_findings', summary: '核对当前确定性风险', startedAt: '刚刚', endedAt: '刚刚' },
          { tool: 'latest_posture_report', summary: '核对最近巡检覆盖率与主机安全分', startedAt: '刚刚', endedAt: '刚刚' },
          { tool: 'incident_timeline', summary: '核对事件生命周期与管理员操作', startedAt: '刚刚', endedAt: '刚刚' },
        ],
      },
      responsePlan: {
        id: `rsp_${incidentId}`, incidentId, title: '临时限制异常登录来源', rationale: '来源达到确定性阈值，动作可逆且带有效期。',
        risk: 'low', status: 'proposed', requiresApproval: true,
        steps: [{ id: 'step_demo_ban', actionType: 'temporary_ip_ban', title: '临时封禁来源 IP', rationale: '降低持续凭据探测噪声。', parameters: { address: '203.0.113.84', currentAdminIp: '198.51.100.10', ttlSeconds: 900, reason: 'WitShield incident response plan' }, risk: 'low', requiresApproval: true }],
      },
    };
    demoInvestigationResults.set(incidentId, structuredClone(result));
    const incident = demoDashboard.incidents.find((item) => item.id === incidentId);
    if (incident) {
      incident.status = result.responsePlan ? 'awaiting_approval' : 'monitoring';
      incident.lastInvestigatedAt = '刚刚';
      incident.updatedAt = '刚刚';
      incident.summary = result.investigation.conclusion ?? '调查已完成，请查看结论。';
    }
    return result;
  }
  const result = await request<{ investigation: Investigation; responsePlan?: ResponsePlan }>(`/incidents/${encodeURIComponent(incidentId)}/investigate`, { method: 'POST', body: JSON.stringify({}) });
  return result;
}

export async function prepareResponsePlanStep(planId: string, stepId: string): Promise<ActionPlan> {
	if (demoMode) {
		await new Promise((resolve) => setTimeout(resolve, 350));
		return {
			id: `act_${stepId}`, approvalNonce: `approve_${stepId}`, title: '执行响应计划', risk: 'low',
			requiresApproval: true, expiresAt: '本次页面会话有效',
			checks: ['Controller 重新验证强类型参数', '受限 Helper 执行并验证结果', '保留审计与回滚状态'],
			steps: [{ id: stepId, title: '执行已审查步骤', kind: 'config_patch', preview: '仅执行当前响应步骤', impact: '影响范围以预览为准', rollback: '失败时按 Playbook 回滚' }],
		};
	}
	const result = await request<{ action: RawAction; approvalNonce: string }>(`/response-plans/${encodeURIComponent(planId)}/steps/${encodeURIComponent(stepId)}/prepare`, { method: 'POST', body: JSON.stringify({}) });
	return actionPlan(result.action, result.approvalNonce);
}

export async function updateIncidentStatus(incidentId: string, status: 'open' | 'resolved' | 'dismissed', summary?: string): Promise<SecurityIncident> {
  if (demoMode) {
    const existing = demoDashboard.incidents.find((item) => item.id === incidentId);
    if (!existing) throw new APIError('没有找到这个安全事件', 404, 'incident_not_found');
    existing.status = status;
    existing.updatedAt = '刚刚';
    return structuredClone(existing);
  }
  return mapIncident(await request<RawIncident>(`/incidents/${encodeURIComponent(incidentId)}`, { method: 'PATCH', body: JSON.stringify({ status, summary }) }));
}

export async function savePolicyGrant(grant: PolicyGrant): Promise<PolicyGrant> {
  if (demoMode) {
    await new Promise((resolve) => setTimeout(resolve, 350));
    const updated = { ...structuredClone(grant), updatedAt: '刚刚' };
    const index = demoDashboard.policyGrants.findIndex((item) => item.deviceId === grant.deviceId && item.capability === grant.capability);
    if (index >= 0) demoDashboard.policyGrants[index] = updated;
    else demoDashboard.policyGrants.push(updated);
    return updated;
  }
  const raw = await request<RawPolicyGrant>(`/devices/${encodeURIComponent(grant.deviceId)}/policy-grants/${encodeURIComponent(grant.capability)}`, {
    method: 'PUT',
    body: JSON.stringify({
      enabled: grant.enabled, mode: grant.mode, allowedActionTypes: grant.allowedActionTypes,
      maxActionsPerHour: grant.maxActionsPerHour, emergencyStop: grant.emergencyStop,
    }),
  });
  return { ...raw, updatedAt: dateText(raw.updatedAt) };
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
    const updated = mapDefense(rawPolicy(deviceId, policy));
    const index = demoDashboard.policies.findIndex((item) => item.id === updated.id);
    if (index >= 0) demoDashboard.policies[index] = structuredClone(updated);
    else demoDashboard.policies.push(structuredClone(updated));
    return updated;
  }
  const result = await request<RawDefensePolicy>(`/devices/${encodeURIComponent(deviceId)}/defense-policy`, { method: 'PUT', body: JSON.stringify(rawPolicy(deviceId, policy)) });
  return mapDefense(result);
}

export async function setEmergencyStop(deviceId: string, active: boolean): Promise<void> {
  if (demoMode) {
    await new Promise((resolve) => setTimeout(resolve, 350));
    demoDashboard.policies = demoDashboard.policies.map((policy) => policy.deviceId === deviceId ? { ...policy, emergencyStop: active } : policy);
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
