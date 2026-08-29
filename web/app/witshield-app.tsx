'use client';

import {
  Activity,
  ArrowUp,
  Bell,
  Check,
  CheckCircle2,
  ChevronRight,
  Clock3,
  Copy,
  Eye,
  FileText,
  KeyRound,
  LayoutDashboard,
  LoaderCircle,
  LockKeyhole,
  LogOut,
  Mail,
  Plus,
  Radar,
  RefreshCw,
  RotateCcw,
  ScanSearch,
  ScrollText,
  Server,
  Settings,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
  Send,
  TestTube2,
  TriangleAlert,
  Webhook,
  X,
} from 'lucide-react';
import { useCallback, useEffect, useState } from 'react';
import {
  approveAction,
  bootstrapAdmin,
  canCreateAction,
  chatAI,
  confirmAction,
  createActionForFinding,
  createEnrollmentToken,
  createSchedule,
  demoMode,
  getServerStatus,
  getReport,
  getIncident,
  getReportsForDevice,
  investigateIncident,
  loadSnapshot,
  login,
  logout,
  requestScan,
  rollbackAction,
  saveAISettings,
  saveInvestigationPolicy,
  saveDefensePolicy,
  savePolicyGrant,
	prepareResponsePlanStep,
  saveNotificationSettings,
  setEmergencyStop,
  testAISettings,
  testNotifications,
  updateSchedule,
  updateIncidentStatus,
} from './api-client';
import { demoDashboard } from './demo-data';
import type { ActionPlan, AISettings, DashboardSnapshot, DefensePolicy, Finding, IncidentDetail, NotificationSettings, PolicyGrant, ScanSchedule, Section, SecurityIncident, SecurityReport, Severity } from './types';

const navigation: Array<{ id: Section; label: string; icon: typeof LayoutDashboard }> = [
  { id: 'overview', label: '总览', icon: LayoutDashboard },
  { id: 'findings', label: '风险', icon: TriangleAlert },
  { id: 'reports', label: '报告', icon: FileText },
  { id: 'devices', label: '设备', icon: Server },
  { id: 'policies', label: 'AI 安全工程师', icon: Sparkles },
  { id: 'audit', label: '执行记录', icon: ScrollText },
  { id: 'settings', label: '设置', icon: Settings },
];

const severityName: Record<Severity, string> = {
  critical: '严重', high: '高风险', medium: '中风险', low: '低风险', info: '提示',
};

type BootState = 'loading' | 'setup' | 'login' | 'ready' | 'error';

export function WitShieldApp() {
  const [section, setSection] = useState<Section>('overview');
  const [bootState, setBootState] = useState<BootState>('loading');
  const [dashboard, setDashboard] = useState<DashboardSnapshot>(() => structuredClone(demoDashboard));
  const [selectedDeviceId, setSelectedDeviceId] = useState(demoDashboard.devices[0].id);
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);
  const [showEnroll, setShowEnroll] = useState(false);
  const [enrollment, setEnrollment] = useState<{ token: string; expiresAt: string } | null>(null);
  const [scanning, setScanning] = useState(false);
  const [toast, setToast] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const selectedDevice = dashboard.devices.find((device) => device.id === selectedDeviceId) ?? dashboard.devices[0];

  const notify = useCallback((message: string) => {
    setToast(message);
    window.setTimeout(() => setToast(null), 2800);
  }, []);

  const refresh = useCallback(async () => {
    const live = await loadSnapshot();
    const openFindings = live.findings.filter((finding) => finding.state === 'open');
    const scoredDevices = live.devices
      .map((device) => device.score)
      .filter((score): score is number => score !== null);
    const score = scoredDevices.length
      ? Math.round(scoredDevices.reduce((sum, value) => sum + value, 0) / scoredDevices.length)
      : null;
    setDashboard((current) => ({
      ...current,
      ...live,
      score,
      checks: live.checks,
      devicesOnline: live.devices.filter((device) => device.status === 'online').length,
      devicesTotal: live.devices.length,
      openFindings: openFindings.length,
      criticalFindings: openFindings.filter((finding) => finding.severity === 'critical' || finding.severity === 'high').length,
      nextScan: live.schedules.filter((schedule) => schedule.enabled)[0]?.nextRunAt ?? '尚未安排',
      lastScan: live.devices.map((device) => device.lastScan).find((value) => value !== '尚未') ?? '尚未',
    }));
    if (live.devices.length && !live.devices.some((device) => device.id === selectedDeviceId)) {
      setSelectedDeviceId(live.devices[0].id);
    }
  }, [selectedDeviceId]);

  useEffect(() => {
    let active = true;
    getServerStatus()
      .then(async (status) => {
        if (!active) return;
        if (!status.initialized) return setBootState('setup');
        if (!status.authenticated) return setBootState('login');
        await refresh();
        setBootState('ready');
      })
      .catch((cause: unknown) => {
        if (!active) return;
        setError(cause instanceof Error ? cause.message : '无法连接巡御服务');
        setBootState('error');
      });
    return () => { active = false; };
  }, [refresh]);

  async function handleScan() {
    if (!selectedDevice || scanning) return;
    setScanning(true);
    try {
      await requestScan(selectedDevice.id);
      notify(demoMode ? '扫描任务已完成，报告已更新' : '扫描已加入队列，Agent 在线后执行');
      if (!demoMode) await refresh();
    } catch (cause) {
      notify(cause instanceof Error ? cause.message : '启动扫描失败');
    } finally {
      setScanning(false);
    }
  }

  async function handleEnrollment() {
    setShowEnroll(true);
    setEnrollment(null);
    try {
      const result = await createEnrollmentToken();
      setEnrollment({ token: result.token, expiresAt: result.expiresAt });
    } catch (cause) {
      notify(cause instanceof Error ? cause.message : '创建设备注册码失败');
    }
  }

  if (bootState === 'loading') return <LoadingScreen />;
  if (bootState === 'setup' || bootState === 'login') {
    return <AuthScreen mode={bootState} onReady={async () => { await refresh(); setBootState('ready'); }} />;
  }
  if (bootState === 'error') {
    return <ErrorScreen message={error ?? '服务暂时不可用'} onRetry={() => window.location.reload()} />;
  }

  return (
    <main className="app-shell">
      <aside className="sidebar">
        <button className="brand brand-button" onClick={() => setSection('overview')}>
          <span className="brand-mark" aria-hidden="true"><ShieldCheck /></span>
          <span><strong>妙计巡御</strong><small>WitShield AI</small></span>
        </button>

        <nav aria-label="主要导航">
          {navigation.map(({ id, label, icon: Icon }) => (
            <button className={section === id ? 'nav-item active' : 'nav-item'} key={id} onClick={() => setSection(id)}>
              <Icon size={16} strokeWidth={1.8} />
              {label}
              {id === 'findings' && dashboard.openFindings > 0 && <span className="nav-count">{dashboard.openFindings}</span>}
            </button>
          ))}
        </nav>

        <div className="sidebar-bottom">
          {demoMode && <span className="demo-chip"><Eye size={12} />交互演示</span>}
          {selectedDevice && (
            <button className="device-card" onClick={() => setSection('devices')}>
              <div className="device-line"><span className="status-dot" /><strong>Agent 在线</strong></div>
              <p>{selectedDevice.hostname}</p>
              <small>{selectedDevice.lastSeen}完成同步</small>
            </button>
          )}
        </div>
      </aside>

      <section className="workspace">
        <header className="topbar">
          <div>
            <p className="eyebrow">AI Agent 服务器管家</p>
            <h1>{sectionTitle(section)}</h1>
          </div>
          <div className="top-actions">
            <button className="icon-button" aria-label="查看需要关注的记录" onClick={() => setSection('audit')}><Bell size={17} />{dashboard.criticalFindings > 0 && <span className="notification-dot" />}</button>
            {section !== 'settings' && <button className="secondary-button" onClick={() => setSection('reports')}>查看报告</button>}
            <button className="primary-button" aria-label={scanning ? '正在扫描' : '立即扫描'} onClick={handleScan} disabled={scanning || !selectedDevice}>
              {scanning ? <LoaderCircle className="spin" size={15} /> : <ScanSearch size={15} />}
              {scanning ? '扫描中' : '立即扫描'}
            </button>
            <button className="avatar" aria-label="打开管理员设置" onClick={() => setSection('settings')}>A</button>
          </div>
        </header>

        {section === 'overview' && (
          <Overview dashboard={dashboard} selectedDeviceId={selectedDeviceId} onFinding={setSelectedFinding} onSection={setSection} />
        )}
        {section === 'findings' && <FindingsView findings={dashboard.findings} devices={dashboard.devices} onFinding={setSelectedFinding} />}
        {section === 'reports' && <ReportsView devices={dashboard.devices} onSelectDevice={setSelectedDeviceId} onFinding={setSelectedFinding} />}
        {section === 'devices' && (
          <DevicesView dashboard={dashboard} selectedDeviceId={selectedDeviceId} onSelect={setSelectedDeviceId} onEnroll={handleEnrollment} />
        )}
        {section === 'policies' && (
			<SecurityEngineerView key={selectedDevice?.id ?? 'none'} dashboard={dashboard} deviceId={selectedDevice?.id ?? ''} onRefresh={refresh} notify={notify} />
        )}
        {section === 'audit' && <AuditView dashboard={dashboard} onChanged={async (message) => { notify(message); await refresh(); }} />}
        {section === 'settings' && <SettingsView settings={dashboard.ai} notifications={dashboard.notifications} schedules={dashboard.schedules} deviceId={selectedDevice?.id ?? ''} onScheduleUpdate={(schedule) => setDashboard((current) => ({ ...current, schedules: [...current.schedules.filter((item) => item.id !== schedule.id), schedule] }))} onSaved={(ai) => { setDashboard((current) => ({ ...current, ai })); notify('AI 设置已安全保存'); }} onNotificationsSaved={(notifications) => { setDashboard((current) => ({ ...current, notifications })); notify('通知渠道已安全保存'); }} onLogout={async () => { await logout(); setBootState('login'); }} />}
      </section>

      {selectedFinding && <FindingDrawer finding={selectedFinding} onClose={() => setSelectedFinding(null)} onPlan={(plan) => {
        setSelectedFinding((finding) => finding ? { ...finding, remediation: plan } : null);
        setDashboard((current) => ({ ...current, findings: current.findings.map((finding) => finding.id === selectedFinding.id ? { ...finding, remediation: plan } : finding) }));
      }} onApproved={() => { notify('已批准，巡御正在执行并验证修复'); setSelectedFinding(null); if (!demoMode) void refresh(); }} />}
      {showEnroll && <EnrollmentModal enrollment={enrollment} onClose={() => setShowEnroll(false)} onCopied={() => notify('安装命令已复制')} />}
      {toast && <div className="toast" role="status"><CheckCircle2 size={16} />{toast}</div>}
    </main>
  );
}

function sectionTitle(section: Section) {
  return ({ overview: '服务器安全概览', findings: '风险与变化', reports: '扫描报告', devices: '受保护的设备', policies: 'AI 安全工程师', audit: '执行与审计记录', settings: '巡御设置' } as const)[section];
}

function Overview({ dashboard, selectedDeviceId, onFinding, onSection }: {
  dashboard: DashboardSnapshot;
  selectedDeviceId: string;
  onFinding: (finding: Finding) => void;
  onSection: (section: Section) => void;
}) {
  const deviceFindings = dashboard.findings.filter((finding) => finding.deviceId === selectedDeviceId && finding.state === 'open');
  const hasScore = dashboard.score !== null;
  const selectedDevice = dashboard.devices.find((device) => device.id === selectedDeviceId);
  return (
    <div className="content-grid">
      <section className="main-column">
        <article className="posture-card">
          <div className="posture-copy">
            <span className="health-pill"><span className="status-dot" />{dashboard.devicesOnline > 0 ? '防护运行中' : '等待 Agent 上线'}</span>
            <h2>{hasScore ? '今日安全状态' : '等待首次安全扫描'}</h2>
            <p>{hasScore ? `巡御已检查 ${dashboard.checks} 项服务器配置，发现 ${dashboard.criticalFindings} 项需要优先处理的问题。` : '尚未收到可验证的扫描报告；在此之前不会把未知状态显示为安全。'}</p>
            <div className="score-row"><strong>{hasScore ? dashboard.score : '—'}</strong><span>{hasScore ? '/ 100' : '待扫描'}<br /><small>{!hasScore ? '尚无安全评分' : dashboard.coverageIssues.length ? '仅基于已完成的检查' : `较昨日提升 ${Math.max(0, (dashboard.score ?? 0) - dashboard.previousScore)} 分`}</small></span></div>
          </div>
          <div className="orbit" aria-label={hasScore ? `安全评分 ${dashboard.score} 分` : '尚无安全评分，等待首次扫描'} style={{ '--score': `${(dashboard.score ?? 0) * 3.6}deg` } as React.CSSProperties}>
            <span>{hasScore ? dashboard.score : '—'}</span><small>{hasScore ? '安全分' : '待扫描'}</small>
          </div>
        </article>

        {dashboard.coverageIssues.length > 0 && <article className="coverage-alert" role="status"><ShieldAlert size={19} /><div><strong>{dashboard.coverageIssues.length} 台设备的检查不完整</strong><p>安全分只反映已成功运行的确定性检查，不能视为全量安全分。</p><div className="coverage-list">{dashboard.coverageIssues.map((issue) => <details key={issue.deviceId}><summary>{issue.mode === 'pending' ? `${issue.deviceName} · 等待首次扫描` : `${issue.deviceName} · ${issue.completedChecks}/${issue.checks} 项完成（${issue.coveragePercent}%）`}</summary><ul>{issue.errors.map((error) => <li key={error}>{error}</li>)}</ul></details>)}</div></div></article>}

        <div className="metric-grid">
          <Metric icon={Server} label="在线设备" value={`${dashboard.devicesOnline}/${dashboard.devicesTotal}`} detail={dashboard.devicesTotal === 0 ? '尚未接入 Agent' : dashboard.devicesOnline === dashboard.devicesTotal ? '所有 Agent 工作正常' : `${dashboard.devicesTotal - dashboard.devicesOnline} 台需要检查连接`} />
          <Metric icon={TriangleAlert} label="待处理风险" value={String(dashboard.openFindings)} detail={`${dashboard.criticalFindings} 项需要优先处理`} warning />
          <Metric icon={Clock3} label="下次扫描" value={dashboard.nextScan} detail={`上次：${dashboard.lastScan}`} />
        </div>

        <div className="section-heading">
          <div><p className="eyebrow">需要关注</p><h2>巡御发现了 {deviceFindings.length} 个变化</h2></div>
          <button className="text-button" onClick={() => onSection('findings')}>查看全部 <ChevronRight size={14} /></button>
        </div>
        <div className="finding-list">
          {deviceFindings.slice(0, 3).map((finding) => <FindingRow finding={finding} key={finding.id} onClick={() => onFinding(finding)} />)}
        </div>
      </section>
      <AssistantPanel deviceId={selectedDeviceId} finding={deviceFindings[0]} hasScanned={typeof selectedDevice?.score === 'number'} onFinding={onFinding} />
    </div>
  );
}

function Metric({ icon: Icon, label, value, detail, warning = false }: { icon: typeof Server; label: string; value: string; detail: string; warning?: boolean }) {
  return <article className="metric-card"><span className={warning ? 'metric-icon warning' : 'metric-icon'}><Icon size={17} /></span><div><p>{label}</p><strong>{value}</strong><small>{detail}</small></div></article>;
}

function FindingRow({ finding, onClick }: { finding: Finding; onClick: () => void }) {
  return (
    <button className="finding-card" onClick={onClick}>
      <span className={`severity ${finding.severity}`}>{severityName[finding.severity]}</span>
      <div className="finding-copy"><h3>{finding.title}</h3><p>{finding.summary}</p></div>
      <span className="row-action">{finding.remediation ? '查看修复计划' : '查看证据'}<ChevronRight size={14} /></span>
    </button>
  );
}

function AssistantPanel({ deviceId, finding, hasScanned, onFinding }: { deviceId: string; finding?: Finding; hasScanned: boolean; onFinding: (finding: Finding) => void }) {
  const [prompt, setPrompt] = useState('');
  const [messages, setMessages] = useState<Array<{ role: 'user' | 'assistant'; text: string }>>([]);
  const [thinking, setThinking] = useState(false);
  async function submit(text: string) {
    if (!text.trim()) return;
    const message = text.trim();
    setMessages((items) => [...items, { role: 'user', text: message }]);
    setPrompt('');
    setThinking(true);
    try {
      const reply = await chatAI(message, deviceId, finding ? [finding.id] : []);
      setMessages((items) => [...items, { role: 'assistant', text: reply }]);
    } catch (cause) {
      setMessages((items) => [...items, { role: 'assistant', text: cause instanceof Error ? cause.message : '暂时无法连接 AI 模型。' }]);
    } finally {
      setThinking(false);
    }
  }
  return (
    <aside className="assistant-panel">
      <div className="assistant-heading"><span className="assistant-mark"><Sparkles size={17} /></span><div><h2>巡御 Agent</h2><p><span className="status-dot" />随时可以协助</p></div></div>
      <div className="agent-message">
        <p>{hasScanned ? `今天的扫描已经完成。${finding ? `最值得先处理的是“${finding.title}”，我可以先解释原因或展示安全修复计划。` : '当前没有需要优先处理的风险。'}` : '该设备尚未完成首次扫描。收到可验证的报告后，我会基于最少必要证据解释风险并提出修复方案。'}</p>
        {messages.map((message, index) => <div className={`mini-message ${message.role}`} key={`${message.role}-${index}`}><strong>{message.role === 'user' ? '你' : '巡御'}</strong><p>{message.text}</p></div>)}
        {thinking && <div className="mini-message assistant"><strong>巡御</strong><p><LoaderCircle className="spin" size={14} /> 正在基于最少必要证据分析…</p></div>}
        <div className="suggestion-list">
          <button onClick={() => finding && void submit(`解释“${finding.title}”的判断依据与实际影响`)}>解释最高风险</button>
          <button onClick={() => finding && onFinding(finding)}>生成安全修复计划</button>
          <button onClick={() => void submit('总结本周服务器发生的安全变化')}>本周发生了什么？</button>
        </div>
      </div>
      <div className="guardrail-note"><LockKeyhole size={15} /><div><strong>经你授权才行动</strong><p>执行前展示授权范围、影响和回滚方案。</p></div></div>
      <form className="prompt-box" onSubmit={(event) => { event.preventDefault(); void submit(prompt); }}>
        <label htmlFor="prompt">与巡御讨论这台服务器</label>
        <textarea id="prompt" value={prompt} onChange={(event) => setPrompt(event.target.value)} placeholder="例如：为什么 8080 端口突然开放了？" rows={3} />
        <div><span>AI 仅获取最少必要的结构化信息</span><button type="submit" aria-label="发送" disabled={thinking}><ArrowUp size={15} /></button></div>
      </form>
    </aside>
  );
}

function FindingsView({ findings, devices, onFinding }: { findings: Finding[]; devices: DashboardSnapshot['devices']; onFinding: (finding: Finding) => void }) {
  const [severity, setSeverity] = useState<'all' | Severity>('all');
  const [deviceId, setDeviceId] = useState('all');
  const filtered = findings.filter((finding) => (severity === 'all' || finding.severity === severity) && (deviceId === 'all' || finding.deviceId === deviceId));
  return (
    <div className="page-surface">
      <div className="filter-bar">
        <div className="segmented-control">{(['all', 'critical', 'high', 'medium', 'low'] as const).map((item) => <button className={severity === item ? 'selected' : ''} onClick={() => setSeverity(item)} key={item}>{item === 'all' ? '全部' : severityName[item]}</button>)}</div>
        <select value={deviceId} onChange={(event) => setDeviceId(event.target.value)} aria-label="筛选设备"><option value="all">所有设备</option>{devices.map((device) => <option value={device.id} key={device.id}>{device.name}</option>)}</select>
      </div>
      <div className="table-heading"><span>风险</span><span>设备</span><span>发现时间</span><span>状态</span></div>
      <div className="risk-table">{filtered.map((finding) => (
        <button className="risk-row" key={finding.id} onClick={() => onFinding(finding)}>
          <span className={`severity ${finding.severity}`}>{severityName[finding.severity]}</span>
          <span className="risk-main"><strong>{finding.title}</strong><small>{finding.summary}</small></span>
          <span>{devices.find((device) => device.id === finding.deviceId)?.hostname ?? finding.deviceId}</span>
          <span>{finding.detectedAt}</span><span className="status-label">待处理</span><ChevronRight size={15} />
        </button>
      ))}</div>
    </div>
  );
}

function ReportsView({ devices, onSelectDevice, onFinding }: {
  devices: DashboardSnapshot['devices'];
  onSelectDevice: (id: string) => void;
  onFinding: (finding: Finding) => void;
}) {
  const [deviceFilter, setDeviceFilter] = useState('');
  const [reports, setReports] = useState<SecurityReport[] | null>(null);
  const [historyError, setHistoryError] = useState<string | null>(null);
  const [historyRequest, setHistoryRequest] = useState(0);
  const [selectedReportId, setSelectedReportId] = useState('');
  const history = reports ?? [];
  const selectedSummary = history.find((report) => report.id === selectedReportId) ?? history[0];
  const selectedReportKey = selectedSummary?.id ?? '';
  const [loaded, setLoaded] = useState<{ id: string; report?: SecurityReport; error?: string } | null>(null);
  const [detailRequest, setDetailRequest] = useState(0);

  useEffect(() => {
    let active = true;
    if (!deviceFilter) return () => { active = false; };
    getReportsForDevice(deviceFilter)
      .then((history) => { if (active) setReports(history); })
      .catch((cause: unknown) => { if (active) setHistoryError(cause instanceof Error ? cause.message : '读取历史报告失败'); });
    return () => { active = false; };
  }, [deviceFilter, historyRequest]);

  useEffect(() => {
    let active = true;
    if (!selectedReportKey) return () => { active = false; };
    getReport(selectedReportKey)
      .then((report) => { if (active) setLoaded({ id: selectedReportKey, report }); })
      .catch((cause: unknown) => { if (active) setLoaded({ id: selectedReportKey, error: cause instanceof Error ? cause.message : '读取报告失败' }); });
    return () => { active = false; };
  }, [selectedReportKey, detailRequest]);

  const current = loaded?.id === selectedReportKey && loaded.report ? loaded.report : selectedSummary;
  const loading = Boolean(selectedReportKey && !current?.detailsLoaded && loaded?.id !== selectedReportKey);
  const reportError = loaded?.id === selectedReportKey ? loaded.error : undefined;
  const detailsReady = Boolean(current?.detailsLoaded && !reportError);
  const currentDevice = devices.find((device) => device.id === current?.deviceId);
  function selectDevice(value: string) {
    setReports(null);
    setHistoryError(null);
    setSelectedReportId('');
    setLoaded(null);
    setDeviceFilter(value);
    if (value) onSelectDevice(value);
  }

  function retryHistory() {
    setReports(null);
    setHistoryError(null);
    setSelectedReportId('');
    setLoaded(null);
    setHistoryRequest((value) => value + 1);
  }

  return (
    <div className="page-surface reports-surface">
      <div className="reports-toolbar">
        <div><p className="eyebrow">确定性扫描结果</p><h2>历史报告与检查覆盖</h2><p>评分只来自实际完成的检查；失败或缺失的检查会明确列出，不会按安全处理。</p></div>
        <select value={deviceFilter} onChange={(event) => selectDevice(event.target.value)} aria-label="筛选报告设备"><option value="">选择一台设备</option>{devices.map((device) => <option value={device.id} key={device.id}>{device.name}</option>)}</select>
      </div>
      {!deviceFilter ? <div className="report-empty"><FileText size={22} /><h3>选择一台设备查看完整历史</h3><p>总览刷新只读取各设备最新报告，避免设备数量与历史保留数量同时放大请求。选择设备后会读取其最多 100 份保留报告。</p></div>
        : reports === null && !historyError ? <div className="report-empty"><LoaderCircle className="spin" size={22} /><h3>正在读取设备历史</h3><p>正在加载这台设备保留的扫描报告。</p></div>
          : historyError ? <div className="report-empty" role="alert"><ShieldAlert size={22} /><h3>无法加载此设备的历史报告</h3><p>{historyError}</p><button className="secondary-button" onClick={retryHistory}>重试读取历史报告</button></div>
            : history.length === 0 ? <div className="report-empty"><FileText size={22} /><h3>还没有扫描报告</h3><p>Agent 完成首次扫描后，评分、覆盖率、检查错误和发现会出现在这里。</p></div> : <div className="reports-layout">
        <aside className="report-history" aria-label="扫描报告历史">
          {history.map((report) => {
            const device = devices.find((item) => item.id === report.deviceId);
            return <button className={report.id === selectedSummary?.id ? 'report-history-item selected' : 'report-history-item'} key={report.id} onClick={() => setSelectedReportId(report.id)}>
              <span className="report-score-mini">{report.score}</span>
              <span><strong>{device?.name ?? report.deviceId}</strong><small>{report.completedAt} · {report.completedChecks}/{report.checks || '—'} 项</small></span>
              <ChevronRight size={14} />
            </button>;
          })}
        </aside>
        <section className="report-detail" aria-live="polite">
          {current && <>
            <header className="report-detail-header">
              <div><span className="health-pill"><span className="status-dot" />扫描已完成</span><h2>{currentDevice?.name ?? current.deviceId}</h2><p>{current.completedAt} · {current.mode === 'observer' ? 'Docker 只读观察' : current.mode === 'native' ? '原生 Agent' : current.mode}</p></div>
              <div className="report-score"><strong>{current.score}</strong><span>/ 100<small>安全分</small></span></div>
            </header>
            <div className="report-metrics">
              <Metric icon={CheckCircle2} label="已完成检查" value={`${current.completedChecks}/${current.checks || '—'}`} detail={`覆盖率 ${current.coveragePercent}%`} />
              <Metric icon={TriangleAlert} label="报告内发现" value={current.findingCount === null ? '待确认' : String(current.findingCount)} detail={current.findingCount === null ? '完整详情加载后确认' : current.findingCount > 0 ? '按风险优先级列出' : '没有发现新的风险'} warning={(current.findingCount ?? 0) > 0} />
              <Metric icon={Clock3} label="扫描时间" value={current.completedAt} detail={`开始：${current.startedAt}`} />
            </div>
            {(current.coveragePercent < 100 || current.errors.length > 0) && <div className="report-coverage-warning"><ShieldAlert size={18} /><div><strong>这不是全量安全分</strong><p>{current.completedChecks}/{current.checks || '未知'} 项检查完成，未完成部分不会被推定为安全。</p>{current.errors.length > 0 && <ul>{current.errors.map((item) => <li key={item}>{item}</li>)}</ul>}</div></div>}
            <div className="report-findings-heading"><div><p className="eyebrow">报告内容</p><h3>本次扫描发现</h3></div><span>{loading ? '正在加载详情' : reportError ? '详情读取失败' : detailsReady && current.findings.length ? `${current.findings.length} 项可查看证据` : detailsReady && current.findingCount === 0 ? '暂无报告内发现' : '详情尚未确认'}</span></div>
            <div className="report-findings">
              {loading ? <p className="report-loading"><LoaderCircle className="spin" size={14} />正在核对完整报告，尚不判断为“没有发现”…</p>
                : reportError ? <div className="report-detail-state" role="alert"><strong>无法确认报告详情</strong><p>{reportError}。{current.findingCount === null ? '摘要未提供发现数量，因此不会被当作 0 项。' : `摘要中的 ${current.findingCount} 项发现不会被当作 0 项。`}</p><button className="secondary-button" onClick={() => { setLoaded(null); setDetailRequest((value) => value + 1); }}>重试读取完整报告</button></div>
                  : !detailsReady ? <p className="report-detail-state">完整报告尚未加载，当前只显示摘要。</p>
                    : <>
                      {current.findingCount !== null && current.findingCount !== current.findings.length && <div className="report-detail-state" role="alert"><strong>报告摘要与详情不一致</strong><p>摘要记录了 {current.findingCount} 项发现，但详情返回了 {current.findings.length} 项证据。请重新扫描或检查 Controller 日志。</p></div>}
                      {current.findings.length ? current.findings.map((finding) => <FindingRow finding={finding} key={finding.id} onClick={() => onFinding(finding)} />)
                        : current.findingCount === 0 ? <p className="empty-action-records">这份完整报告没有记录新的发现。</p> : null}
                    </>}
            </div>
          </>}
        </section>
      </div>}
    </div>
  );
}

function DevicesView({ dashboard, selectedDeviceId, onSelect, onEnroll }: { dashboard: DashboardSnapshot; selectedDeviceId: string; onSelect: (id: string) => void; onEnroll: () => void }) {
  return (
    <div className="page-surface">
      <div className="surface-heading"><div><p>通过一次性注册码安全连接服务器，Agent 无需开放入站端口。</p></div><button className="primary-button" onClick={onEnroll}><Plus size={15} />添加设备</button></div>
      <div className="device-grid">{dashboard.devices.map((device) => (
        <button className={selectedDeviceId === device.id ? 'device-tile selected' : 'device-tile'} key={device.id} onClick={() => onSelect(device.id)}>
          <div className="device-tile-top"><span className="server-icon"><Server size={19} /></span><span className={`device-status ${device.status}`}><span />{device.status === 'online' ? '在线' : '离线'}</span></div>
          <h3>{device.name}</h3><p>{device.hostname}</p>
          <dl><div><dt>系统</dt><dd>{device.os}</dd></div><div><dt>架构</dt><dd>{device.arch}</dd></div><div><dt>Agent</dt><dd>{device.version}</dd></div><div><dt>安全分</dt><dd>{device.score ?? '待扫描'}</dd></div></dl>
          <footer><span>{device.findings} 个待处理风险</span><span>{device.lastSeen}</span></footer>
        </button>
      ))}</div>
    </div>
  );
}

const capabilityCopy: Record<string, { title: string; description: string; icon: typeof Radar }> = {
  'network.auth_bruteforce': { title: '登录与网络攻击', description: '关联认证失败和来源行为，必要时执行带时限的网络遏制。', icon: Radar },
  'identity.persistence': { title: '账号与持久化', description: '关注特权账号、SSH Key、sudoers、计划任务和异常登录变化。', icon: KeyRound },
  'workload.runtime': { title: '进程、服务与容器', description: '调查异常进程、systemd 服务、容器行为及非预期工作负载。', icon: Activity },
  'file.integrity': { title: '文件与配置完整性', description: '关联敏感文件、权限和关键配置的异常变化。', icon: FileText },
  'vulnerability.remediation': { title: '漏洞与补丁处置', description: '持续发现漏洞和待更新组件，生成可验证的修复计划。', icon: ShieldCheck },
};

const autonomyCopy: Record<PolicyGrant['mode'], { label: string; detail: string }> = {
  observe: { label: '仅观察', detail: '记录信号，不调用 AI 主动调查' },
  assist: { label: 'AI 协助', detail: '主动调查并提出方案，执行前询问你' },
  auto_low_risk: { label: '自动低风险处置', detail: '主动调查；只有确定性规则预授权的可逆动作会自动执行' },
  enhanced: { label: '增强自动化', detail: '也调查低风险信号；AI 计划和高风险动作仍需批准' },
};

const incidentStatusCopy: Record<SecurityIncident['status'], string> = {
  open: '待调查', investigating: '调查中', awaiting_approval: '等待批准', responding: '处置中', monitoring: '持续观察', resolved: '已解决', dismissed: '已忽略',
};

function SecurityEngineerView({ dashboard, deviceId, onRefresh, notify }: {
  dashboard: DashboardSnapshot;
  deviceId: string;
  onRefresh: () => Promise<void>;
  notify: (message: string) => void;
}) {
  const [selectedIncidentId, setSelectedIncidentId] = useState('');
  const [detail, setDetail] = useState<IncidentDetail | null>(null);
  const [detailLoading, setDetailLoading] = useState(false);
  const [investigating, setInvestigating] = useState<string | null>(null);
  const [savingGrant, setSavingGrant] = useState<string | null>(null);
	const [savingInvestigationPolicy, setSavingInvestigationPolicy] = useState(false);
	const [prepared, setPrepared] = useState<{ stepId: string; plan: ActionPlan } | null>(null);
	const [approving, setApproving] = useState(false);
	const [incidentScope, setIncidentScope] = useState<'active' | 'all' | 'closed'>('active');
	const [severityFilter, setSeverityFilter] = useState<'all' | Severity>('all');
  const incidents = dashboard.incidents.filter((item) => item.deviceId === deviceId);
  const grants = dashboard.policyGrants.filter((item) => item.deviceId === deviceId);
  const policies = dashboard.policies.filter((item) => item.deviceId === deviceId);
  const activeIncidents = incidents.filter((item) => item.status !== 'resolved' && item.status !== 'dismissed');
  const automaticGrants = grants.filter((item) => item.enabled && (item.mode === 'auto_low_risk' || item.mode === 'enhanced') && !item.emergencyStop);
  const assistedGrants = grants.filter((item) => item.enabled && item.mode === 'assist');
  const presence = automaticGrants.length ? '自动防御已在授权边界内运行' : assistedGrants.length ? 'AI 安全工程师正在协助值守' : '确定性传感器正在观察';
	const filteredIncidents = incidents.filter((incident) => {
		const closed = incident.status === 'resolved' || incident.status === 'dismissed';
		if (incidentScope === 'active' && closed) return false;
		if (incidentScope === 'closed' && !closed) return false;
		return severityFilter === 'all' || incident.severity === severityFilter;
	});
	const selectedDevice = dashboard.devices.find((device) => device.id === deviceId);
	const sensors = dashboard.sensors.filter((sensor) => sensor.deviceId === deviceId);
	const latestInvestigation = detail?.investigations[0];

  async function openIncident(id: string) {
    setSelectedIncidentId(id);
	setDetail(null);
	setPrepared(null);
    setDetailLoading(true);
    try { setDetail(await getIncident(id)); }
    catch (cause) { notify(cause instanceof Error ? cause.message : '读取事件详情失败'); }
    finally { setDetailLoading(false); }
  }

  async function runInvestigation(id: string) {
    setInvestigating(id);
    try {
      await investigateIncident(id);
      notify('AI 安全工程师已完成本轮调查');
      await onRefresh();
      await openIncident(id);
    } catch (cause) {
      notify(cause instanceof Error ? cause.message : 'AI 调查失败，事件仍保持打开');
      await onRefresh();
    } finally { setInvestigating(null); }
  }

  async function changeGrant(grant: PolicyGrant, patch: Partial<PolicyGrant>) {
    setSavingGrant(grant.capability);
    try {
		const next = { ...grant, ...patch };
		if (grant.capability === 'workload.runtime' && next.mode === 'enhanced' && !next.allowedActionTypes.includes('temporary_process_suspend')) {
			next.allowedActionTypes = [...next.allowedActionTypes, 'temporary_process_suspend'];
		}
		await savePolicyGrant(next);
      notify('值守授权已保存');
      await onRefresh();
    } catch (cause) {
      notify(cause instanceof Error ? cause.message : '保存授权失败');
    } finally { setSavingGrant(null); }
  }

	async function changeInvestigationPolicy(patch: Partial<DashboardSnapshot['investigationPolicy']>) {
		setSavingInvestigationPolicy(true);
		try {
			await saveInvestigationPolicy({ ...dashboard.investigationPolicy, ...patch });
			notify('AI 调查策略已保存');
			await onRefresh();
		} catch (cause) {
			notify(cause instanceof Error ? cause.message : '保存 AI 调查策略失败');
		} finally {
			setSavingInvestigationPolicy(false);
		}
	}

	function investigationProfilePatch(profile: DashboardSnapshot['investigationPolicy']['profile']): Partial<DashboardSnapshot['investigationPolicy']> {
		if (profile === 'economy') return { profile, dailyTokenBudget: 30000, emergencyReserveTokens: 20000 };
		if (profile === 'sensitive') return { profile, dailyTokenBudget: 120000, emergencyReserveTokens: 30000 };
		return { profile, dailyTokenBudget: 60000, emergencyReserveTokens: 20000 };
	}

  async function closeIncident(status: 'resolved' | 'dismissed') {
    if (!selectedIncidentId) return;
    try {
      await updateIncidentStatus(selectedIncidentId, status);
      notify(status === 'resolved' ? '事件已标记为解决' : '事件已忽略');
      setSelectedIncidentId(''); setDetail(null); setPrepared(null);
      await onRefresh();
    } catch (cause) { notify(cause instanceof Error ? cause.message : '更新事件失败'); }
  }

	async function prepareStep(planId: string, stepId: string) {
		try {
			const plan = await prepareResponsePlanStep(planId, stepId);
			setPrepared({ stepId, plan });
		} catch (cause) {
			notify(cause instanceof Error ? cause.message : '准备响应动作失败');
		}
	}

	async function approvePrepared() {
		if (!prepared) return;
		setApproving(true);
		try {
			await approveAction(prepared.plan.id, prepared.plan.approvalNonce);
			notify('响应动作已批准，Agent 将执行、验证并保留回滚状态');
			setPrepared(null);
			await onRefresh();
			if (selectedIncidentId) await openIncident(selectedIncidentId);
		} catch (cause) {
			notify(cause instanceof Error ? cause.message : '批准响应动作失败');
		} finally {
			setApproving(false);
		}
	}

  return (
    <div className="security-engineer-page">
      <section className="engineer-hero">
        <div className="engineer-presence"><span className="engineer-avatar"><ShieldCheck size={28} /></span><div><p className="eyebrow">常驻 AI 安全工程师</p><h2>{presence}</h2><p>本地 Agent 持续收集确定性信号；AI 只在事件或巡检任务触发时使用受控的只读工具调查，所有执行仍经过能力授权和强类型 Playbook。</p></div></div>
        <div className="engineer-metrics"><div><strong>{activeIncidents.length}</strong><span>进行中的事件</span></div><div><strong>{assistedGrants.length + automaticGrants.length}</strong><span>已启用能力</span></div><div><strong>{automaticGrants.length}</strong><span>允许自动处置</span></div></div>
      </section>

		<section className="sensor-ribbon" aria-label="安全感知范围">
			{sensors.length ? sensors.map((sensor) => <div key={sensor.sensorId} title={sensor.error ?? `${sensor.mode} · ${sensor.lastSuccessAt ?? '等待采样'}`}><span className={`sensor-${sensor.state}`} /><strong>{sensor.name}</strong><small>{sensor.state === 'active' ? `${sensor.cadenceSeconds}s 实时更新` : sensor.state === 'optional' ? '可选增强' : sensor.state === 'degraded' ? '覆盖已降级' : '暂不可用'}</small></div>) : <div><span className={selectedDevice?.status === 'online' ? 'sensor-degraded' : 'sensor-unavailable'} /><strong>等待传感器状态</strong><small>{selectedDevice?.status === 'online' ? 'Agent 正在首次采样' : '等待设备连接'}</small></div>}
		</section>

      <div className="engineer-layout">
        <section className="incident-workbench">
			<div className="engineer-section-heading"><div><p className="eyebrow">调查工作台</p><h2>安全事件</h2><p>一个事件档案串联信号、AI 调查、响应计划、管理员决策和执行回执。</p></div><span>{activeIncidents.length ? `${activeIncidents.length} 项需要关注` : '当前没有待调查事件'}</span></div>
			<div className="incident-toolbar" aria-label="筛选安全事件">
				<div className="segmented-control">{(['active', 'all', 'closed'] as const).map((scope) => <button className={incidentScope === scope ? 'active' : ''} key={scope} onClick={() => { setIncidentScope(scope); setSelectedIncidentId(''); setDetail(null); setPrepared(null); }}>{scope === 'active' ? '进行中' : scope === 'all' ? '全部' : '已关闭'}</button>)}</div>
				<select aria-label="按风险等级筛选" value={severityFilter} onChange={(event) => { setSeverityFilter(event.target.value as 'all' | Severity); setSelectedIncidentId(''); setDetail(null); setPrepared(null); }}><option value="all">全部风险</option><option value="critical">严重</option><option value="high">高风险</option><option value="medium">中风险</option><option value="low">低风险</option><option value="info">提示</option></select>
			</div>
			<div className="incident-case-layout">
				<div className="incident-queue">
					{filteredIncidents.length === 0 && <div className="engineer-empty"><Sparkles size={22} /><h3>正在持续值守</h3><p>当前筛选范围没有事件；传感器和确定性巡检仍在运行。</p></div>}
					{filteredIncidents.map((incident) => <article className={selectedIncidentId === incident.id ? 'incident-card selected' : 'incident-card'} key={incident.id}>
						<button className="incident-card-main" onClick={() => void openIncident(incident.id)}>
							<span className={`severity ${incident.severity}`}>{severityName[incident.severity]}</span>
							<span className="incident-copy"><span><strong>{incident.title}</strong><em className={`incident-status ${incident.status}`}>{incidentStatusCopy[incident.status]}</em></span><p>{incident.summary}</p><small>{incident.signalCount} 条信号 · {incident.lastSeenAt}</small></span>
							<ChevronRight size={16} />
						</button>
						{(incident.status === 'open' || incident.status === 'monitoring') && <button className="investigate-button" onClick={() => void runInvestigation(incident.id)} disabled={investigating === incident.id || !dashboard.ai.model}>{investigating === incident.id ? <LoaderCircle className="spin" size={14} /> : <Sparkles size={14} />}{investigating === incident.id ? '调查中' : dashboard.ai.model ? 'AI 调查' : '先配置 AI'}</button>}
					</article>)}
				</div>

				<section className={selectedIncidentId ? 'incident-detail active' : 'incident-detail'} aria-live="polite">
					{!selectedIncidentId && <div className="case-placeholder"><ShieldCheck size={26} /><h3>选择一个事件开始调查</h3><p>这里会按时间顺序展示事实证据、AI 判断、不确定性、响应计划和真实执行结果。</p></div>}
					{detailLoading && !detail ? <p className="incident-loading"><LoaderCircle className="spin" size={15} />正在读取调查记录…</p> : detail && <>
						<header className="case-header"><div><span className={`severity ${detail.incident.severity}`}>{severityName[detail.incident.severity]}</span><p className="eyebrow">{detail.incident.category.replaceAll('_', ' ')}</p><h3>{detail.incident.title}</h3><small>{detail.incident.signalCount} 条信号 · 首次 {detail.incident.firstSeenAt} · 最近 {detail.incident.lastSeenAt}</small></div><button className="icon-button" onClick={() => { setSelectedIncidentId(''); setDetail(null); }} aria-label="关闭事件详情"><X size={16} /></button></header>
						<section className="case-conclusion"><div><Sparkles size={16} /><span><strong>{latestInvestigation ? 'AI 调查结论' : '等待调查'}</strong><small>{latestInvestigation?.hypothesis ?? '当前仅展示确定性事件摘要'}</small></span><em>{latestInvestigation ? `${latestInvestigation.confidence}% 置信度` : incidentStatusCopy[detail.incident.status]}</em></div><p>{latestInvestigation?.conclusion ?? detail.incident.summary}</p></section>
						{latestInvestigation && <div className="investigation-summary"><div><strong>{latestInvestigation.observations?.length ?? 0}</strong><span>已确认事实</span></div><div><strong>{latestInvestigation.uncertainties?.length ?? 0}</strong><span>关键未知</span></div><div><strong>{latestInvestigation.toolCalls?.length ?? 0}</strong><span>只读工具</span></div><div><strong>{detail.signals.length}</strong><span>保留信号</span></div></div>}
						{latestInvestigation && <div className="case-evidence-grid">
							<section><header><CheckCircle2 size={15} /><strong>已确认事实</strong></header><ul>{(latestInvestigation.observations?.length ? latestInvestigation.observations : ['本轮没有输出可直接确认的新事实。']).map((item) => <li key={item}>{item}</li>)}</ul></section>
							<section><header><TriangleAlert size={15} /><strong>仍需确认</strong></header><ul>{(latestInvestigation.uncertainties?.length ? latestInvestigation.uncertainties : ['当前没有额外标记的关键未知。']).map((item) => <li key={item}>{item}</li>)}</ul></section>
							<section><header><ScanSearch size={15} /><strong>下一步只读检查</strong></header><ul>{(latestInvestigation.nextChecks?.length ? latestInvestigation.nextChecks : ['继续监测新的相关信号。']).map((item) => <li key={item}>{item}</li>)}</ul></section>
						</div>}
						{detail.signals.length > 0 && <section className="case-section"><header><div><p className="eyebrow">Evidence</p><h4>事件证据</h4></div><span>{detail.signals.length} 条</span></header><div className="signal-list">{detail.signals.slice(0, 12).map((signal) => <article key={signal.id}><span className={`signal-dot ${signal.severity}`} /><div><strong>{signal.summary}</strong><p>{signal.type.replaceAll('_', ' ')}{signal.subject ? ` · ${signal.subject}` : ''}</p><small>{signal.source.replaceAll('_', ' ')} · {signal.occurredAt}</small></div><em className={signal.trust === 'verified' ? 'verified' : ''}>{signal.trust === 'verified' ? '已验证' : '未验证'}</em></article>)}</div></section>}
						{latestInvestigation?.toolCalls?.length ? <section className="case-section"><header><div><p className="eyebrow">Read-only trace</p><h4>调查工具记录</h4></div></header><div className="tool-trace">{latestInvestigation.toolCalls.map((call) => <div key={`${call.tool}-${call.startedAt}`}><Check size={13} /><span><strong>{call.tool.replaceAll('_', ' ')}</strong><small>{call.summary}</small></span></div>)}</div></section> : null}
						{detail.responsePlans[0] && <div className="response-plan-card"><span className={`plan-risk ${detail.responsePlans[0].risk}`}>{detail.responsePlans[0].risk === 'low' ? '低风险' : detail.responsePlans[0].risk === 'medium' ? '中风险' : '高风险'}</span><div><h4>{detail.responsePlans[0].title}</h4><p>{detail.responsePlans[0].rationale}</p>{detail.responsePlans[0].steps.map((step) => <div className="response-step" key={step.id}><ShieldCheck size={15} /><span><strong>{step.title}</strong><small>{step.rationale}</small></span>{step.actionId ? <em>已进入执行记录</em> : <button className="text-button" onClick={() => void prepareStep(detail.responsePlans[0].id, step.id)}>审查并执行</button>}</div>)}</div></div>}
						{prepared && <div className="prepared-action"><div><p className="eyebrow">一次性动作批准</p><h4>{prepared.plan.title}</h4><p>{prepared.plan.steps[0]?.impact}</p><small>批准凭据 10 分钟后失效；执行前 Agent 和 Helper 会再次验证同一组参数。</small></div><div><button className="secondary-button" onClick={() => setPrepared(null)}>取消</button><button className="primary-button" onClick={() => void approvePrepared()} disabled={approving}>{approving ? <LoaderCircle className="spin" size={14} /> : <Check size={14} />}批准这一步</button></div></div>}
						{detail.timeline.length > 0 && <section className="case-section"><header><div><p className="eyebrow">Case history</p><h4>事件时间线</h4></div></header><div className="case-timeline">{detail.timeline.slice(-12).map((event) => <div key={event.id}><span /><p><strong>{event.summary}</strong><small>{event.actor} · {event.createdAt}</small></p></div>)}</div></section>}
						{detail.incident.status !== 'resolved' && detail.incident.status !== 'dismissed' && <footer><button className="secondary-button" onClick={() => void closeIncident('dismissed')}>忽略事件</button><button className="primary-button" onClick={() => void closeIncident('resolved')}>标记为已解决</button></footer>}
					</>}
				</section>
			</div>
        </section>

        <aside className="capability-panel">
          <div className="engineer-section-heading compact"><div><p className="eyebrow">权限边界</p><h2>值守能力</h2><p>每类能力独立授权，不存在一个无限权限的总开关。</p></div></div>
		  <section className="investigation-policy-card">
			<header><div><strong>AI 调查节奏</strong><p>只有新证据才触发，预算用完后本地检测与确定性防御继续运行。</p></div>{savingInvestigationPolicy && <LoaderCircle className="spin" size={14} />}</header>
			<div className="profile-picker">{(['economy', 'balanced', 'sensitive'] as const).map((profile) => <button key={profile} className={dashboard.investigationPolicy.profile === profile ? 'active' : ''} disabled={savingInvestigationPolicy} onClick={() => void changeInvestigationPolicy(investigationProfilePatch(profile))}><strong>{profile === 'economy' ? '节省' : profile === 'balanced' ? '平衡' : '敏锐'}</strong><small>{profile === 'economy' ? '仅严重事件 · 3 万/日' : profile === 'balanced' ? '中风险及以上 · 6 万/日' : '低风险及以上 · 12 万/日'}</small></button>)}</div>
			<div className="budget-meter"><span><strong>{dashboard.investigationUsage.regularTokensUsed.toLocaleString()}</strong> / {dashboard.investigationPolicy.dailyTokenBudget.toLocaleString()} 估算 Token</span><span>{dashboard.investigationUsage.investigationCalls} 次调查</span></div>
			<div className="budget-track"><span style={{ width: `${Math.min(100, Math.round(dashboard.investigationUsage.regularTokensUsed / Math.max(1, dashboard.investigationPolicy.dailyTokenBudget) * 100))}%` }} /></div>
			<label className="compact-check"><input type="checkbox" checked={dashboard.investigationPolicy.shareNetworkIndicators} disabled={savingInvestigationPolicy} onChange={(event) => void changeInvestigationPolicy({ shareNetworkIndicators: event.target.checked })} /><span>允许发送必要的网络标识</span></label>
			<label className="compact-check"><input type="checkbox" checked={dashboard.investigationPolicy.shareAccountNames} disabled={savingInvestigationPolicy} onChange={(event) => void changeInvestigationPolicy({ shareAccountNames: event.target.checked })} /><span>允许发送必要的账号名称</span></label>
		  </section>
          <div className="capability-list">{grants.map((grant) => {
            const meta = capabilityCopy[grant.capability] ?? { title: grant.capability, description: '受控安全能力', icon: ShieldCheck };
            const Icon = meta.icon;
            return <article className={grant.enabled ? 'capability-card enabled' : 'capability-card'} key={grant.capability}>
              <header><span><Icon size={17} /></span><div><strong>{meta.title}</strong><p>{meta.description}</p></div><button className={grant.enabled ? 'switch on' : 'switch'} onClick={() => void changeGrant(grant, { enabled: !grant.enabled, mode: !grant.enabled && grant.mode === 'observe' ? 'assist' : grant.mode })} disabled={savingGrant === grant.capability} aria-label={grant.enabled ? `关闭${meta.title}` : `开启${meta.title}`}><span /></button></header>
              <label><span>响应方式</span><select value={grant.mode} disabled={!grant.enabled || savingGrant === grant.capability} onChange={(event) => void changeGrant(grant, { mode: event.target.value as PolicyGrant['mode'] })}><option value="observe">仅观察</option><option value="assist">AI 协助</option><option value="auto_low_risk">自动低风险处置</option>{grant.capability !== 'network.auth_bruteforce' && <option value="enhanced">增强自动化</option>}</select></label>
              <small>{autonomyCopy[grant.mode].detail}</small>
            </article>;
          })}</div>
        </aside>
      </div>

      <details className="engineer-advanced">
        <summary><span><Radar size={16} />登录攻击的确定性触发规则</span><small>配置阈值、封禁时长与管理员保护地址</small><ChevronRight size={15} /></summary>
        <PoliciesView policies={policies} deviceId={deviceId} automaticActive={automaticGrants.length > 0} onUpdate={async () => { notify('确定性策略已保存'); await onRefresh(); }} onEmergency={async (active) => { notify(active ? '已停止尚未开始的自动动作' : '自动防御已恢复'); await onRefresh(); }} />
      </details>
    </div>
  );
}

function PoliciesView({ policies, deviceId, automaticActive, onUpdate, onEmergency }: { policies: DefensePolicy[]; deviceId: string; automaticActive: boolean; onUpdate: (policy: DefensePolicy) => void; onEmergency: (active: boolean) => void }) {
  const [saving, setSaving] = useState<string | null>(null);
  const [policyError, setPolicyError] = useState<string | null>(null);
  const [editing, setEditing] = useState<DefensePolicy | null>(null);
  const [allowlistText, setAllowlistText] = useState('');
  const devicePolicies = policies.filter((policy) => !policy.deviceId || policy.deviceId === deviceId);
  const emergencyActive = devicePolicies.some((policy) => policy.emergencyStop);
  const autoContainActive = (automaticActive || devicePolicies.some((policy) => policy.enabled && policy.mode === 'auto_contain')) && !emergencyActive;
  async function update(policy: DefensePolicy) {
    setSaving(policy.id); setPolicyError(null);
    try { onUpdate(await saveDefensePolicy(deviceId, policy)); return true; }
    catch (cause) { setPolicyError(cause instanceof Error ? cause.message : '保存策略失败'); return false; }
    finally { setSaving(null); }
  }
  async function emergency() {
    setSaving('emergency'); setPolicyError(null);
    try { await setEmergencyStop(deviceId, !emergencyActive); onEmergency(!emergencyActive); }
    catch (cause) { setPolicyError(cause instanceof Error ? cause.message : '更新紧急停止状态失败'); }
    finally { setSaving(null); }
  }
  function edit(policy: DefensePolicy) {
    setEditing({
      ...policy,
      failureThreshold: policy.failureThreshold ?? 10,
      window: policy.window ?? '5m',
      banDuration: policy.banDuration ?? `${policy.ttlMinutes || 15}m`,
      maxBansPerHour: policy.maxBansPerHour ?? 10,
      allowlist: policy.allowlist ?? [],
    });
    setAllowlistText((policy.allowlist ?? []).join('\n'));
    setPolicyError(null);
  }
  async function savePolicy(event: React.FormEvent) {
    event.preventDefault();
    if (!editing) return;
    const allowlist = allowlistText.split(/[\n,;]+/).map((value) => value.trim()).filter(Boolean);
    if (editing.mode === 'auto_contain' && !allowlist.some((value) => !/^127\.|^::1(?:\/|$)/.test(value))) {
      setPolicyError('开启自动封禁前，必须填写至少一个非回环的管理员 IP 或 CIDR，防止将自己锁在服务器外。');
      return;
    }
		if (await update({ ...editing, enabled: editing.mode === 'auto_contain' ? true : editing.enabled, allowlist })) setEditing(null);
  }
	function bannerAction() {
		if (emergencyActive || autoContainActive) {
			void emergency();
			return;
		}
		const firstEditable = devicePolicies.find((policy) => policy.editable !== false);
		if (firstEditable) edit(firstEditable);
	}
  return (
    <div className="page-surface">
		<div className="defense-banner"><ShieldAlert size={21} /><div><strong>{emergencyActive ? '本机自动防御已紧急停止' : autoContainActive ? '本机自动防御正按预授权规则运行' : '当前只记录、调查和建议'}</strong><p>{emergencyActive ? '不会创建新动作，所有尚未开始的预授权动作已取消；已生效的限时动作仍按 TTL 自动恢复。' : '只有明确启用的确定性规则可触发可逆动作；AI 调查不能自行扩大权限。下面单独配置 SSH 登录攻击规则。'}</p></div><button className={emergencyActive || autoContainActive ? 'danger-outline' : 'secondary-button'} onClick={bannerAction} disabled={!deviceId || saving === 'emergency'}>{saving === 'emergency' && <LoaderCircle className="spin" size={14} />}{emergencyActive ? '恢复自动防御' : autoContainActive ? '紧急停止' : '配置自动防御'}</button></div>
      {policyError && <p className="form-error" role="alert">{policyError}</p>}
      <div className="policy-list">{devicePolicies.length === 0 && <div className="empty-state"><Server size={20} /><p>连接设备后即可配置防御策略。</p></div>}{devicePolicies.map((policy) => (
        <article className="policy-card" key={policy.id}>
          <div className="policy-main"><div className="policy-title"><span className="policy-icon"><Radar size={18} /></span><div><h3>{policy.name}</h3><p>{policy.description}</p></div></div><div className="policy-controls">{policy.editable !== false && <button className="text-button" onClick={() => editing?.id === policy.id ? setEditing(null) : edit(policy)}>{editing?.id === policy.id ? '收起' : '配置'}</button>}<button className={policy.enabled ? 'switch on' : 'switch'} onClick={() => void update({ ...policy, enabled: !policy.enabled })} aria-label={policy.enabled ? '关闭策略' : '开启策略'} disabled={policy.editable === false || saving === policy.id}><span /></button></div></div>
          <div className="policy-rules"><div><small>触发条件</small><strong>{policy.trigger}</strong></div><ChevronRight size={14} /><div><small>响应动作</small><strong>{policy.action}</strong></div><ChevronRight size={14} /><div><small>自动恢复</small><strong>{policy.ttlMinutes ? `${policy.ttlMinutes} 分钟后` : '不适用'}</strong></div></div>
          {editing?.id === policy.id && <form className="policy-editor" onSubmit={(event) => void savePolicy(event)}>
            <div className="policy-editor-grid">
              <label><span>响应模式</span><select value={editing.mode} onChange={(event) => setEditing({ ...editing, mode: event.target.value as DefensePolicy['mode'] })}><option value="recommend">只建议（需人工确认）</option><option value="auto_contain">自动临时封禁</option></select></label>
              <label><span>失败登录阈值</span><input type="number" min={3} max={10000} required value={editing.failureThreshold} onChange={(event) => setEditing({ ...editing, failureThreshold: Number(event.target.value) })} /></label>
              <label><span>统计窗口</span><input required value={editing.window} onChange={(event) => setEditing({ ...editing, window: event.target.value })} placeholder="5m" /><small>10s 至 24h</small></label>
              <label><span>封禁时长</span><input required value={editing.banDuration} onChange={(event) => setEditing({ ...editing, banDuration: event.target.value })} placeholder="15m" /><small>1m 至 24h，到期自动解除</small></label>
              <label><span>每小时最多封禁</span><input type="number" min={1} max={1000} required value={editing.maxBansPerHour} onChange={(event) => setEditing({ ...editing, maxBansPerHour: Number(event.target.value) })} /></label>
              <label className="span-two"><span>管理员保护地址（IP / CIDR）</span><textarea rows={3} value={allowlistText} onChange={(event) => setAllowlistText(event.target.value)} placeholder={'203.0.113.8\n10.20.0.0/16'} /><small>每行一个。自动封禁前至少需要一个非回环管理地址，以防自锁；请勿填写过宽网段。</small></label>
            </div>
            <div className="policy-editor-note"><ShieldCheck size={15} /><p><strong>AI 不参与触发判定。</strong>只有 SSH 失败日志的确定性规则能创建限时封禁，动作全程审计。</p></div>
            <div className="form-actions"><button type="button" className="secondary-button" onClick={() => setEditing(null)}>取消</button><button className="primary-button" disabled={saving === policy.id}>{saving === policy.id ? <LoaderCircle className="spin" size={14} /> : <Check size={14} />}保存防御策略</button></div>
          </form>}
          <footer><span className={`mode-badge ${policy.mode}`}>{policy.mode === 'auto_contain' ? '自动遏制' : policy.mode === 'recommend' ? '建议处置' : '仅观察'}</span>{saving === policy.id && <span><LoaderCircle className="spin" size={13} />保存中</span>}{policy.lastTriggered && <span>最近触发：{policy.lastTriggered}</span>}</footer>
        </article>
      ))}</div>
    </div>
  );
}

function AuditView({ dashboard, onChanged }: { dashboard: DashboardSnapshot; onChanged: (message: string) => Promise<void> }) {
  const [busy, setBusy] = useState<string | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);
  async function confirm(id: string) {
    setBusy(id); setActionError(null);
    try { await confirmAction(id); await onChanged('已发送 SSH 保留确认，Agent 正在解除安全回滚计时器'); }
    catch (cause) { setActionError(cause instanceof Error ? cause.message : '确认失败'); }
    finally { setBusy(null); }
  }
  async function rollback(id: string) {
    setBusy(id); setActionError(null);
    try { await rollbackAction(id); await onChanged('回滚已加入队列，完成后会写入审计记录'); }
    catch (cause) { setActionError(cause instanceof Error ? cause.message : '回滚失败'); }
    finally { setBusy(null); }
  }
  const visibleActions = dashboard.actions.filter((item) => item.status !== 'draft').slice(0, 20);
  const attentionActions = dashboard.actions.filter((item) => item.status === 'awaiting_confirmation' || item.status === 'rolling_back' || item.status === 'indeterminate').length;
  return (
    <div className="page-surface audit-surface">
      <div className="audit-summary"><Metric icon={Activity} label="审计事件" value={String(dashboard.audit.length)} detail="管理员动作均有记录" /><Metric icon={Eye} label="安全观察" value={String(dashboard.securityEvents.length)} detail="未验证，不触发自动处置" /><Metric icon={RotateCcw} label="待人工关注" value={String(attentionActions)} detail="含待确认、回滚及未知结果" /></div>
      <section className="security-observations" aria-labelledby="security-observations-title">
        <div className="section-heading compact"><div><p className="eyebrow">只读线索</p><h2 id="security-observations-title">安全观察</h2><p>来自设备日志的未验证线索独立展示，不参与自动防御判定。</p></div></div>
        <div className="observation-list">{dashboard.securityEvents.length ? dashboard.securityEvents.map((item) => {
          const capacity = item.type === 'defense_correlation_capacity_degraded';
          const oversized = item.type === 'ssh_auth_log_line_oversized_untrusted';
          const device = dashboard.devices.find((candidate) => candidate.id === item.deviceId);
          const title = capacity ? '关联窗口容量保护已触发' : oversized ? '超长认证日志行已安全丢弃' : '发现未通过可信解析的认证线索';
          const detail = capacity
            ? '安全关联窗口达到保护容量，请检查异常流量与策略健康状态。系统不会据此直接执行防御动作。'
            : oversized
              ? '该日志行超过安全解析上限，Agent 已丢弃并继续读取后续日志，避免异常输入放大资源占用。'
              : '日志内容未满足可信解析规则，仅作为排障线索保留；它不会增加自动封禁计数。';
          return <article className={`observation-row ${capacity ? 'critical' : oversized ? 'warning' : 'neutral'}`} key={`${item.deviceId}:${item.id}`}>
            <span className="observation-icon">{capacity ? <ShieldAlert size={17} /> : oversized ? <TriangleAlert size={17} /> : <Eye size={17} />}</span>
            <div className="observation-copy"><header><strong>{title}</strong><span className="observation-badge">{capacity ? '系统健康 · 不会自动处置' : '未验证 · 不会自动处置'}</span></header><p>{detail}</p><footer><span>设备 {device?.name ?? item.deviceId}</span><span>来源 {maskSourceIP(item.sourceIp)}</span><time>{item.occurredAt}</time></footer></div>
          </article>;
        }) : <p className="empty-action-records">当前没有需要管理员查看的安全观察。</p>}</div>
      </section>
      <section className="action-center" aria-label="动作状态与回滚">
        <div className="section-heading compact"><div><p className="eyebrow">动作控制</p><h2>确认、追踪或回滚已批准的变更</h2></div></div>
        {actionError && <p className="form-error" role="alert">{actionError}</p>}
        <div className="action-records">{visibleActions.length ? visibleActions.map((item) => {
          const awaiting = item.status === 'awaiting_confirmation';
          const indeterminate = item.status === 'indeterminate';
          const running = ['approved', 'executing', 'confirming', 'rolling_back'].includes(item.status);
          const indeterminateDetail = item.error
            ? `未能确认安全终态：${item.error}。请通过带外终端、Helper 审计和下一次扫描核验真实状态；系统不会自动重试。`
            : '未能确认安全终态。操作可能已经生效、部分生效或已回滚；请通过带外终端、Helper 审计和下一次扫描核验，系统不会自动重试。';
          return <article className={awaiting || indeterminate ? `action-record urgent${indeterminate ? ' indeterminate' : ''}` : 'action-record'} key={item.id}>
            <span className="action-record-icon">{awaiting || indeterminate ? <ShieldAlert size={17} /> : running ? <LoaderCircle className="spin" size={17} /> : item.status === 'succeeded' ? <CheckCircle2 size={17} /> : <RotateCcw size={17} />}</span>
            <div><header><strong>{item.title}</strong><span className={`action-status ${item.status}`}>{actionStatusText(item.status)}</span></header><p>{awaiting ? `请先从另一个终端验证 SSH 仍能登录，并在 ${item.confirmBy ?? '安全期限内'}完成保留确认；否则 Helper 自动恢复原配置。` : indeterminate ? indeterminateDetail : item.error || `最近更新：${item.updatedAt}`}</p><small>设备 {item.deviceId} · 动作 {item.id}</small></div>
            <div className="action-record-buttons">{awaiting && <button className="primary-button" disabled={busy === item.id} onClick={() => void confirm(item.id)}>{busy === item.id ? <LoaderCircle className="spin" size={14} /> : <ShieldCheck size={14} />}确认 SSH 可用并保留</button>}{item.canRollback && (item.status === 'succeeded' || item.status === 'failed' || item.status === 'indeterminate' || awaiting) && <button className="secondary-button" disabled={busy === item.id} onClick={() => void rollback(item.id)}><RotateCcw size={14} />立即回滚</button>}</div>
          </article>;
        }) : <p className="empty-action-records">当前没有需要确认或可回滚的动作。</p>}</div>
      </section>
      <div className="timeline">{dashboard.audit.map((event) => (
        <article className="timeline-item" key={event.id}><span className={`timeline-icon ${event.type}`}>{event.type === 'scan' ? <ScanSearch size={15} /> : event.type === 'action' ? <Check size={15} /> : <Activity size={15} />}</span><div><header><strong>{event.title}</strong><time>{event.timestamp}</time></header><p>{event.detail}</p><footer>{event.device}<span>·</span>{event.actor}<span className={`result ${event.result}`}>{event.result === 'success' ? '成功' : event.result === 'pending' ? '等待中' : '已阻止'}</span></footer></div></article>
      ))}</div>
    </div>
  );
}

function maskSourceIP(source?: string): string {
  if (!source) return '无来源地址';
  const ipv4 = source.split('.');
  if (ipv4.length === 4 && ipv4.every((part) => /^\d{1,3}$/.test(part))) return `${ipv4[0]}.${ipv4[1]}.*.*`;
  if (source.includes(':')) {
    const visible = source.split(':').filter(Boolean).slice(0, 2).join(':');
    return visible ? `${visible}:…` : 'IPv6（已隐藏）';
  }
  return '已隐藏';
}

function actionStatusText(status: DashboardSnapshot['actions'][number]['status']) {
  return ({ draft: '待审批', approved: '已排队', executing: '执行中', awaiting_confirmation: '等待连接确认', confirming: '确认中', succeeded: '已成功', failed: '执行失败', rolling_back: '回滚中', rolled_back: '已回滚', cancelled: '已取消', indeterminate: '需人工核验' } as const)[status];
}

function sameAIEndpointOrigin(a: string, b: string): boolean {
  try {
    return new URL(a).origin === new URL(b).origin;
  } catch {
    return a.trim() === b.trim();
  }
}

function SettingsView({ settings, notifications, schedules, deviceId, onScheduleUpdate, onSaved, onNotificationsSaved, onLogout }: { settings: AISettings; notifications: NotificationSettings; schedules: ScanSchedule[]; deviceId: string; onScheduleUpdate: (schedule: ScanSchedule) => void; onSaved: (settings: AISettings) => void; onNotificationsSaved: (settings: NotificationSettings) => void; onLogout: () => Promise<void> }) {
  const [form, setForm] = useState<AISettings & { apiKey?: string }>({ ...settings, apiKey: '' });
  const [notificationForm, setNotificationForm] = useState({
    ...notifications,
    webhookSecret: '',
    smtpPassword: '',
    clearWebhookSecret: false,
    clearSmtpPassword: false,
    smtpToText: notifications.smtpTo.join(', '),
  });
  const [testing, setTesting] = useState(false);
  const [saving, setSaving] = useState(false);
  const [notificationSaving, setNotificationSaving] = useState(false);
  const [notificationTesting, setNotificationTesting] = useState(false);
  const [scheduleSaving, setScheduleSaving] = useState<string | null>(null);
  const [testResult, setTestResult] = useState<string | null>(null);
  const [notificationResult, setNotificationResult] = useState<string | null>(null);
  const [settingsError, setSettingsError] = useState<string | null>(null);
  const [notificationError, setNotificationError] = useState<string | null>(null);
  const endpointOriginChanged = !sameAIEndpointOrigin(settings.baseUrl, form.baseUrl);
  const endpointKeyRequired = settings.hasKey && endpointOriginChanged && !form.apiKey;
  async function testConnection() {
    if (endpointKeyRequired) { setSettingsError('更换 API 地址后，请重新输入该地址对应的 API Key'); return; }
    setTesting(true); setTestResult(null); setSettingsError(null);
    try { const result = await testAISettings(form); setTestResult(`连接成功 · ${result.model} · ${result.latencyMs} ms`); }
    catch (cause) { setTestResult(cause instanceof Error ? cause.message : '连接失败'); }
    finally { setTesting(false); }
  }
  async function save(event: React.FormEvent) {
    event.preventDefault();
    if (endpointKeyRequired) { setSettingsError('更换 API 地址后，请重新输入该地址对应的 API Key'); return; }
    setSaving(true); setSettingsError(null);
    try {
      const clearBoundHeaders = endpointOriginChanged && settings.customHeaderKeys.length > 0;
      onSaved(await saveAISettings({ ...form, ...(clearBoundHeaders ? { customHeaders: {} } : {}) }));
      setForm((current) => ({ ...current, apiKey: '' }));
    }
    catch (cause) { setSettingsError(cause instanceof Error ? cause.message : '保存 AI 设置失败'); }
    finally { setSaving(false); }
  }
  async function toggleSchedule(every: '24h' | '168h') {
    if (!deviceId) { setSettingsError('请先连接并选择一台设备'); return; }
    setScheduleSaving(every); setSettingsError(null);
    try {
      const existing = schedules.find((schedule) => schedule.deviceId === deviceId && schedule.every.startsWith(every));
      onScheduleUpdate(existing ? await updateSchedule(existing, !existing.enabled) : await createSchedule(deviceId, every, true));
    } catch (cause) {
      setSettingsError(cause instanceof Error ? cause.message : '更新扫描计划失败');
    } finally {
      setScheduleSaving(null);
    }
  }
  async function saveNotifications(event: React.FormEvent) {
    event.preventDefault(); setNotificationSaving(true); setNotificationError(null); setNotificationResult(null);
    try {
      const saved = await saveNotificationSettings({
        ...notificationForm,
        smtpTo: notificationForm.smtpToText.split(/[\n,;]+/).map((value) => value.trim()).filter(Boolean),
      });
      onNotificationsSaved(saved);
      setNotificationForm((current) => ({
        ...current,
        ...saved,
        webhookSecret: '',
        smtpPassword: '',
        clearWebhookSecret: false,
        clearSmtpPassword: false,
        smtpToText: saved.smtpTo.join(', '),
      }));
      setNotificationResult('配置已保存，可以发送测试通知');
    } catch (cause) {
      setNotificationError(cause instanceof Error ? cause.message : '保存通知设置失败');
    } finally {
      setNotificationSaving(false);
    }
  }
  async function sendNotificationTest() {
    setNotificationTesting(true); setNotificationError(null); setNotificationResult(null);
    try { await testNotifications(); setNotificationResult('测试通知已成功送达已启用的渠道'); }
    catch (cause) { setNotificationError(cause instanceof Error ? cause.message : '测试通知发送失败'); }
    finally { setNotificationTesting(false); }
  }
  const daily = schedules.find((schedule) => schedule.deviceId === deviceId && schedule.every.startsWith('24h'));
  const weekly = schedules.find((schedule) => schedule.deviceId === deviceId && schedule.every.startsWith('168h'));
  return (
    <div className="settings-layout">
      <form className="settings-card" onSubmit={save}>
        <div className="settings-heading"><span className="settings-icon"><Sparkles size={18} /></span><div><h2>AI 模型</h2><p>由你提供 API。扫描与规则引擎不依赖模型也能运行。</p></div></div>
        <div className="form-grid">
          <label><span>兼容协议</span><select value={form.protocol} onChange={(event) => setForm({ ...form, protocol: event.target.value as AISettings['protocol'] })}><option value="openai_responses">OpenAI Responses</option><option value="openai_chat">OpenAI Chat Completions</option><option value="anthropic_messages">Anthropic Messages</option></select></label>
          <label><span>模型名称</span><input value={form.model} onChange={(event) => setForm({ ...form, model: event.target.value })} placeholder="gpt-5.4" /></label>
          <label className="span-two"><span>API Base URL</span><input value={form.baseUrl} onChange={(event) => setForm({ ...form, baseUrl: event.target.value })} inputMode="url" placeholder="https://api.openai.com/v1" />{settings.customHeaderKeys.length > 0 && <small>{endpointOriginChanged ? `保存时会清除旧地址绑定的自定义请求头：${settings.customHeaderKeys.join('、')}` : `已安全保存自定义请求头：${settings.customHeaderKeys.join('、')}（值不会返回浏览器）`}</small>}</label>
          <label className="span-two"><span>API Key</span><div className="secret-input"><KeyRound size={15} /><input type="password" value={form.apiKey} required={endpointKeyRequired} onChange={(event) => setForm({ ...form, apiKey: event.target.value })} placeholder={endpointOriginChanged ? '更换地址后需重新输入 API Key' : settings.hasKey ? `${settings.keyHint}（留空保持不变）` : '输入 API Key'} /></div><small>{endpointOriginChanged ? '密钥不会自动带到新的 API 地址；请重新输入以确认信任边界。' : '由本机主密钥加密保存，特权 Helper 无法读取。'}</small></label>
          <section className="span-two ai-privacy-card" aria-labelledby="ai-privacy-title">
            <div className="ai-privacy-summary">
              <span className="ai-privacy-icon"><ShieldCheck size={17} /></span>
              <div>
                <span className="field-label">数据发送策略</span>
                <div className="ai-privacy-title"><strong id="ai-privacy-title">最小化</strong><span>推荐 · 当前固定</span></div>
                <p>仅向模型发送当前问题相关的发现和必要证据，不上传整台服务器的数据。</p>
              </div>
            </div>
            <details className="ai-privacy-details">
              <summary>查看发送范围与保护方式<ChevronRight size={14} /></summary>
              <div className="ai-privacy-detail-grid">
                <div><strong>会发送</strong><p>相关的开放风险（最多 20 项）、最新安全评分与报告时间；证据会先脱敏并截断。</p></div>
                <div><strong>不会发送</strong><p>完整日志、任意文件正文、环境变量、密码、私钥、API Key 和未选择的历史报告。</p></div>
                <div><strong>如何隔离</strong><p>服务器文本会标记为不可信数据，与系统指令分开；模型只能解释和建议，不能直接执行操作。</p></div>
              </div>
            </details>
          </section>
        </div>
        <div className="form-actions"><button type="button" className="secondary-button" onClick={() => void testConnection()} disabled={testing}>{testing ? <LoaderCircle className="spin" size={15} /> : <TestTube2 size={15} />}测试连接</button><button className="primary-button" disabled={saving}>{saving ? <LoaderCircle className="spin" size={15} /> : <Check size={15} />}保存设置</button>{testResult && <span className="test-result">{testResult}</span>}</div>
        {settingsError && <p className="form-error" role="alert">{settingsError}</p>}
      </form>
      <form className="settings-card notification-settings" onSubmit={saveNotifications}>
        <div className="settings-heading"><span className="settings-icon"><Send size={18} /></span><div><h2>安全通知</h2><p>扫描发现重要变化或自动防御触发后，通过你自己的渠道发送报告。</p></div></div>
        <div className="notification-channel-grid">
          <section className={notificationForm.webhookEnabled ? 'channel-panel enabled' : 'channel-panel'}>
            <header><span className="channel-icon"><Webhook size={17} /></span><div><strong>Webhook</strong><p>签名 JSON 事件，适合接入告警平台或自动化流程。</p></div><button type="button" className={notificationForm.webhookEnabled ? 'switch on' : 'switch'} onClick={() => setNotificationForm((current) => ({ ...current, webhookEnabled: !current.webhookEnabled }))} aria-label={notificationForm.webhookEnabled ? '关闭 Webhook 通知' : '开启 Webhook 通知'}><span /></button></header>
            {notificationForm.webhookEnabled && <div className="channel-fields">
              <label><span>Webhook URL</span><input type="url" inputMode="url" required value={notificationForm.webhookUrl} onChange={(event) => setNotificationForm((current) => ({ ...current, webhookUrl: event.target.value }))} placeholder="https://alerts.example.com/witshield" /></label>
              <label><span>HMAC 签名密钥</span><div className="secret-input"><KeyRound size={15} /><input type="password" minLength={16} required={!notificationForm.webhookSecretConfigured} disabled={notificationForm.clearWebhookSecret} value={notificationForm.webhookSecret} onChange={(event) => setNotificationForm((current) => ({ ...current, webhookSecret: event.target.value, clearWebhookSecret: false }))} placeholder={notificationForm.webhookSecretConfigured ? '已安全保存（留空保持不变）' : '至少 16 个字符'} /></div></label>
              {notificationForm.webhookSecretConfigured && <label className="clear-secret"><input type="checkbox" checked={notificationForm.clearWebhookSecret} onChange={(event) => setNotificationForm((current) => ({ ...current, clearWebhookSecret: event.target.checked, webhookEnabled: event.target.checked ? false : current.webhookEnabled, webhookSecret: event.target.checked ? '' : current.webhookSecret }))} /><span>清除已保存的签名密钥（同时关闭渠道）</span></label>}
              <small>请求携带时间戳与 SHA-256 签名；禁用代理和重定向，公网地址必须使用 HTTPS。</small>
            </div>}
          </section>
          <section className={notificationForm.smtpEnabled ? 'channel-panel enabled' : 'channel-panel'}>
            <header><span className="channel-icon"><Mail size={17} /></span><div><strong>电子邮件</strong><p>通过你的 SMTP 服务向一个或多个收件人发送报告。</p></div><button type="button" className={notificationForm.smtpEnabled ? 'switch on' : 'switch'} onClick={() => setNotificationForm((current) => ({ ...current, smtpEnabled: !current.smtpEnabled }))} aria-label={notificationForm.smtpEnabled ? '关闭邮件通知' : '开启邮件通知'}><span /></button></header>
            {notificationForm.smtpEnabled && <div className="channel-fields smtp-fields">
              <label><span>SMTP 主机</span><input required value={notificationForm.smtpHost} onChange={(event) => setNotificationForm((current) => ({ ...current, smtpHost: event.target.value }))} placeholder="smtp.example.com" /></label>
              <label><span>端口</span><input type="number" min={1} max={65535} required value={notificationForm.smtpPort} onChange={(event) => setNotificationForm((current) => ({ ...current, smtpPort: Number(event.target.value) }))} /></label>
              <label><span>用户名</span><input autoComplete="username" value={notificationForm.smtpUsername} onChange={(event) => setNotificationForm((current) => ({ ...current, smtpUsername: event.target.value }))} placeholder="alerts@example.com" /></label>
              <label><span>密码</span><div className="secret-input"><KeyRound size={15} /><input type="password" autoComplete="new-password" required={Boolean(notificationForm.smtpUsername) && !notificationForm.smtpPasswordConfigured} disabled={notificationForm.clearSmtpPassword} value={notificationForm.smtpPassword} onChange={(event) => setNotificationForm((current) => ({ ...current, smtpPassword: event.target.value, clearSmtpPassword: false }))} placeholder={notificationForm.smtpPasswordConfigured ? '已安全保存（留空保持不变）' : 'SMTP 密码'} /></div></label>
              {notificationForm.smtpPasswordConfigured && <label className="clear-secret span-two"><input type="checkbox" checked={notificationForm.clearSmtpPassword} onChange={(event) => setNotificationForm((current) => ({ ...current, clearSmtpPassword: event.target.checked, smtpEnabled: event.target.checked ? false : current.smtpEnabled, smtpPassword: event.target.checked ? '' : current.smtpPassword }))} /><span>清除已保存的 SMTP 密码（同时关闭渠道）</span></label>}
              <label><span>发件人</span><input type="email" required value={notificationForm.smtpFrom} onChange={(event) => setNotificationForm((current) => ({ ...current, smtpFrom: event.target.value }))} placeholder="alerts@example.com" /></label>
              <label><span>收件人</span><input required value={notificationForm.smtpToText} onChange={(event) => setNotificationForm((current) => ({ ...current, smtpToText: event.target.value }))} placeholder="admin@example.com, sec@example.com" /></label>
              <small className="span-two">465 端口使用隐式 TLS；其他公网 SMTP 必须支持 STARTTLS。凭据仅加密保存在控制器。</small>
            </div>}
          </section>
        </div>
        <div className="form-actions"><button type="button" className="secondary-button" onClick={() => void sendNotificationTest()} disabled={notificationTesting || !notifications.configured || (!notifications.webhookEnabled && !notifications.smtpEnabled)}>{notificationTesting ? <LoaderCircle className="spin" size={15} /> : <TestTube2 size={15} />}测试已保存配置</button><button className="primary-button" disabled={notificationSaving}>{notificationSaving ? <LoaderCircle className="spin" size={15} /> : <Check size={15} />}保存通知渠道</button>{notificationResult && <span className="test-result" role="status">{notificationResult}</span>}</div>
        {notificationError && <p className="form-error" role="alert">{notificationError}</p>}
      </form>
      <section className="settings-card"><div className="settings-heading"><span className="settings-icon"><Clock3 size={18} /></span><div><h2>扫描计划</h2><p>按设备设置固定间隔；Agent 离线时任务会排队，恢复连接后执行。</p></div></div><div className="schedule-row"><div><strong>每日安全扫描</strong><p>每 24 小时 · 软件包、配置、端口与账号{daily?.nextRunAt ? ` · 下次 ${daily.nextRunAt}` : ''}</p></div><button className={daily?.enabled ? 'switch on' : 'switch'} onClick={() => void toggleSchedule('24h')} aria-label={daily?.enabled ? '关闭每日安全扫描' : '开启每日安全扫描'} disabled={!deviceId || scheduleSaving === '24h'}><span /></button></div><div className="schedule-row"><div><strong>每周基线检查</strong><p>每 7 天 · 运行同一套确定性检查并保留趋势{weekly?.nextRunAt ? ` · 下次 ${weekly.nextRunAt}` : ''}</p></div><button className={weekly?.enabled ? 'switch on' : 'switch'} onClick={() => void toggleSchedule('168h')} aria-label={weekly?.enabled ? '关闭每周基线检查' : '开启每周基线检查'} disabled={!deviceId || scheduleSaving === '168h'}><span /></button></div></section>
      <section className="settings-card danger-zone"><div className="settings-heading"><span className="settings-icon"><LockKeyhole size={18} /></span><div><h2>管理员会话</h2><p>当前为单管理员模式。设备凭据与管理员会话相互隔离。</p></div></div><button className="secondary-button" onClick={onLogout}><LogOut size={15} />退出登录</button></section>
    </div>
  );
}

function FindingDrawer({ finding, onClose, onPlan, onApproved }: { finding: Finding; onClose: () => void; onPlan: (plan: ActionPlan) => void; onApproved: () => void }) {
  const [approving, setApproving] = useState(false);
  const [generating, setGenerating] = useState(false);
  const [confirmed, setConfirmed] = useState(false);
  const [plan, setPlan] = useState<ActionPlan | undefined>(finding.remediation);
  const [planError, setPlanError] = useState<string | null>(null);
  async function generate() {
    setGenerating(true); setPlanError(null);
    try { const result = await createActionForFinding(finding); setPlan(result); onPlan(result); }
    catch (cause) { setPlanError(cause instanceof Error ? cause.message : '无法生成安全修复计划'); }
    finally { setGenerating(false); }
  }
  async function approve() {
    if (!plan || !confirmed) return;
    setApproving(true);
    try { await approveAction(plan.id, plan.approvalNonce); onApproved(); }
    catch (cause) { setPlanError(cause instanceof Error ? cause.message : '批准失败'); }
    finally { setApproving(false); }
  }
  const packagePlan = plan?.steps.some((step) => step.kind === 'package_upgrade') ?? false;
  return (
    <div className="overlay" role="presentation" onMouseDown={(event) => event.target === event.currentTarget && onClose()}>
      <aside className="drawer" role="dialog" aria-modal="true" aria-labelledby="finding-title">
        <header><div><span className={`severity ${finding.severity}`}>{severityName[finding.severity]}</span><p>{finding.category} · {finding.detectedAt}</p></div><button className="icon-button" onClick={onClose} aria-label="关闭"><X size={18} /></button></header>
        <div className="drawer-body"><h2 id="finding-title">{finding.title}</h2><p className="lead">{finding.summary}</p><section><h3>判断依据</h3><ul className="evidence-list">{finding.evidence.map((item) => <li key={item}><Check size={14} />{item}</li>)}</ul></section>
          {plan ? <section className="plan-card"><div className="plan-heading"><div><p className="eyebrow">待你确认的修复计划</p><h3>{plan.title}</h3></div><span className={`plan-risk ${plan.risk}`}>{plan.risk === 'low' ? '低影响' : '需谨慎'}</span></div><p className="plan-checks-label">批准后由设备 Agent 强制执行这些前置检查；任一检查失败都不会修改系统：</p><div className="precheck-list">{plan.checks.map((check) => <span key={check}><ShieldCheck size={14} />{check}</span>)}</div>{plan.steps.map((step, index) => <article className="action-step" key={step.id}><span className="step-number">{index + 1}</span><div><h4>{step.title}</h4><pre>{step.preview}</pre><dl><div><dt>影响</dt><dd>{step.impact}</dd></div><div><dt>回滚</dt><dd>{step.rollback}</dd></div></dl></div></article>)}<label className="approval-check"><input type="checkbox" checked={confirmed} onChange={(event) => setConfirmed(event.target.checked)} /><span>{packagePlan ? '我已核对授权的软件包范围，并了解目标版本将在设备执行时解析；如 APT 需要修改任何未列出的包，本次操作会在 dpkg 前停止。' : '我已查看具体变更、影响和回滚方案，同意在设备端检查通过后执行这一次修复。'}</span></label></section> : <section className="empty-plan"><Eye size={20} /><div><h3>当前仅提供证据</h3><p>巡御不会在没有明确修复方案和回滚步骤时执行操作。</p>{canCreateAction(finding) && <button className="secondary-button" onClick={() => void generate()} disabled={generating}>{generating ? <LoaderCircle className="spin" size={15} /> : <Sparkles size={15} />}生成安全修复计划</button>}</div></section>}
          {planError && <p className="form-error" role="alert">{planError}</p>}
        </div>
        <footer className="drawer-footer"><button className="secondary-button" onClick={onClose}>暂不处理</button>{plan && <button className="primary-button" disabled={!confirmed || approving} onClick={() => void approve()}>{approving ? <LoaderCircle className="spin" size={15} /> : <ShieldCheck size={15} />}批准并执行</button>}</footer>
      </aside>
    </div>
  );
}

function EnrollmentModal({ enrollment, onClose, onCopied }: { enrollment: { token: string; expiresAt: string } | null; onClose: () => void; onCopied: () => void }) {
  const controllerUrl = typeof window !== 'undefined' ? window.location.origin : 'https://your-console.example';
  const shellQuote = (value: string) => `'${value.replaceAll("'", `'"'"'`)}'`;
  const command = enrollment
    ? `curl --proto '=https' --tlsv1.2 -fsSL https://github.com/witkitlab/witshield/releases/latest/download/install.sh | sudo env WITSHIELD_CONTROLLER_URL=${shellQuote(controllerUrl)} WITSHIELD_ENROLLMENT_TOKEN=${shellQuote(enrollment.token)} bash -s -- --mode agent`
    : '';
  async function copy() {
    if (navigator.clipboard?.writeText) {
      await navigator.clipboard.writeText(command);
    } else {
      const field = document.createElement('textarea');
      field.value = command;
      field.style.position = 'fixed';
      field.style.opacity = '0';
      document.body.appendChild(field);
      field.select();
      document.execCommand('copy');
      field.remove();
    }
    onCopied();
  }
  return <div className="overlay centered" role="presentation"><section className="modal" role="dialog" aria-modal="true" aria-labelledby="enroll-title"><header><span className="modal-icon"><Plus size={20} /></span><div><h2 id="enroll-title">添加一台服务器</h2><p>注册码只显示一次，并在 15 分钟后失效。</p></div><button className="icon-button" onClick={onClose} aria-label="关闭添加设备窗口"><X size={18} /></button></header>{enrollment ? <><ol className="install-steps"><li><span>1</span><div><strong>登录要保护的服务器</strong><p>使用具有 sudo 权限的账号。</p></div></li><li><span>2</span><div><strong>运行一行安装命令</strong><pre>{command}</pre><button className="copy-button" onClick={copy}><Copy size={14} />复制命令</button><p>这条命令含 15 分钟、单次使用的注册码，Shell 历史可能保留它；更严格的环境请改用文档中的 0600 token 文件方式。</p></div></li><li><span>3</span><div><strong>等待 Agent 出现在设备列表</strong><p>注册后将换取独立设备凭据，注册码立即作废。</p></div></li></ol><div className="security-note"><LockKeyhole size={15} />Agent 主动连接控制台，不需要开放服务器入站端口。</div></> : <div className="modal-loading"><LoaderCircle className="spin" />正在创建一次性注册码…</div>}</section></div>;
}

function AuthScreen({ mode, onReady }: { mode: 'setup' | 'login'; onReady: () => Promise<void> }) {
  const [username, setUsername] = useState('admin');
  const [password, setPassword] = useState('');
  const [confirm, setConfirm] = useState('');
  const [bootstrapToken, setBootstrapToken] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  async function submit(event: React.FormEvent) {
    event.preventDefault(); setError(null);
    if (mode === 'setup' && password !== confirm) return setError('两次输入的密码不一致');
    if (password.length < 12) return setError('密码至少需要 12 个字符');
    setBusy(true);
    try { if (mode === 'setup') await bootstrapAdmin(username, password, bootstrapToken || undefined); else await login(username, password); await onReady(); }
    catch (cause) { setError(cause instanceof Error ? cause.message : '操作失败'); }
    finally { setBusy(false); }
  }
  return <main className="auth-shell"><section className="auth-card"><div className="auth-brand"><span className="brand-mark"><ShieldCheck /></span><div><strong>妙计巡御</strong><small>WitShield AI</small></div></div><p className="eyebrow">AI Agent 服务器管家</p><h1>{mode === 'setup' ? '创建唯一管理员' : '欢迎回来'}</h1><p className="auth-intro">{mode === 'setup' ? '控制台首版采用单管理员模式。完成初始化后即可连接第一台服务器。' : '登录你的自建巡御控制台。'}</p><form onSubmit={submit}><label><span>管理员名称</span><input value={username} onChange={(event) => setUsername(event.target.value)} autoComplete="username" /></label><label><span>密码</span><input type="password" value={password} onChange={(event) => setPassword(event.target.value)} autoComplete={mode === 'setup' ? 'new-password' : 'current-password'} /></label>{mode === 'setup' && <><label><span>再次输入密码</span><input type="password" value={confirm} onChange={(event) => setConfirm(event.target.value)} autoComplete="new-password" /></label><label><span>初始化令牌（如安装程序要求）</span><input type="password" value={bootstrapToken} onChange={(event) => setBootstrapToken(event.target.value)} /></label></>}{error && <p className="form-error">{error}</p>}<button className="primary-button auth-submit" disabled={busy}>{busy ? <LoaderCircle className="spin" size={16} /> : <LockKeyhole size={16} />}{mode === 'setup' ? '完成安全初始化' : '登录控制台'}</button></form><small className="auth-footnote">凭据只保存在你的服务器；巡御没有公共账号中心。</small></section></main>;
}

function LoadingScreen() { return <main className="loading-screen"><span className="brand-mark"><ShieldCheck /></span><LoaderCircle className="spin" size={22} /><p>正在连接巡御 Agent…</p></main>; }
function ErrorScreen({ message, onRetry }: { message: string; onRetry: () => void }) { return <main className="loading-screen"><span className="error-mark"><X size={21} /></span><h1>暂时无法连接巡御</h1><p>{message}</p><button className="primary-button" onClick={onRetry}><RefreshCw size={15} />重新连接</button></main>; }
