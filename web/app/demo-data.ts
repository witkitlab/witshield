import type { DashboardSnapshot } from './types';

export const demoDashboard: DashboardSnapshot = {
  score: 76,
  previousScore: 72,
  checks: 14,
  devicesOnline: 2,
  devicesTotal: 2,
  openFindings: 5,
  criticalFindings: 1,
  lastScan: '今天 09:42',
  nextScan: '明天 03:00',
  devices: [
    {
      id: 'dev_local', name: '生产服务器', hostname: 'ubuntu-prod-01', os: 'Ubuntu 24.04.2 LTS',
      kernel: '6.8.0-64-generic', arch: 'arm64', address: '10.0.0.12', status: 'online',
      version: 'v0.1.0', lastSeen: '刚刚', lastScan: '今天 09:42', score: 59, findings: 3,
    },
    {
      id: 'dev_edge', name: '边缘节点', hostname: 'edge-shanghai-02', os: 'Debian 12.10',
      kernel: '6.1.0-35-amd64', arch: 'x86_64', address: '10.0.0.23', status: 'online',
      version: 'v0.1.0', lastSeen: '18 秒前', lastScan: '今天 03:00', score: 92, findings: 2,
    },
  ],
  reports: [
    {
      id: 'report_demo_local', deviceId: 'dev_local', startedAt: '今天 09:41', completedAt: '今天 09:42',
      score: 59, checks: 7, completedChecks: 7, coveragePercent: 100, findingCount: 3, mode: 'native', errors: [],
      detailsLoaded: true,
      findings: [
        {
          id: 'finding_ssh_password', deviceId: 'dev_local', severity: 'critical', category: 'SSH',
          title: 'SSH 允许密码登录', summary: '公网 SSH 服务仍允许使用账号密码认证，增加凭据撞库与暴力破解风险。',
          evidence: ['sshd_config: PasswordAuthentication yes', '22/tcp 监听于 0.0.0.0'], detectedAt: '今天 09:42', state: 'open',
        },
        {
          id: 'finding_packages', deviceId: 'dev_local', severity: 'medium', category: '软件包',
          title: '3 个安全更新待安装', summary: 'openssl、curl 与 linux-libc-dev 存在可用的发行版安全更新。',
          evidence: ['openssl 3.0.13-0ubuntu3.4 → 3.0.13-0ubuntu3.5'], detectedAt: '今天 09:42', state: 'open',
        },
        {
          id: 'finding_port', deviceId: 'dev_local', severity: 'low', category: '网络暴露',
          title: '发现新的监听端口 8080', summary: '端口由 docker-proxy 暴露，当前没有对应的用途说明。',
          evidence: ['0.0.0.0:8080 → container/web:8080'], detectedAt: '今天 09:42', state: 'open',
        },
      ],
    },
    {
      id: 'report_demo_edge', deviceId: 'dev_edge', startedAt: '今天 02:59', completedAt: '今天 03:00',
      score: 92, checks: 7, completedChecks: 7, coveragePercent: 100, findingCount: 2, mode: 'observer', errors: [],
      detailsLoaded: true,
      findings: [
        {
          id: 'finding_updates_edge', deviceId: 'dev_edge', severity: 'medium', category: '软件包',
          title: '边缘节点内核需要安全更新', summary: '新内核安装后需要在维护窗口重启。',
          evidence: ['linux-image-amd64 6.1.140-1 可用', '当前运行 6.1.137-1'], detectedAt: '今天 03:00', state: 'open',
        },
        {
          id: 'finding_audit', deviceId: 'dev_edge', severity: 'info', category: '审计',
          title: '审计日志保留期较短', summary: 'journald 当前最大占用为 128 MB，预计仅保留约 4 天。',
          evidence: ['SystemMaxUse=128M', '最近 24 小时日志量 31 MB'], detectedAt: '今天 03:00', state: 'open',
        },
      ],
    },
  ],
  findings: [
    {
      id: 'finding_ssh_password', deviceId: 'dev_local', severity: 'critical', category: 'SSH',
      title: 'SSH 允许密码登录', summary: '公网 SSH 服务仍允许使用账号密码认证，增加凭据撞库与暴力破解风险。',
      evidence: ['sshd_config: PasswordAuthentication yes', '22/tcp 监听于 0.0.0.0', '最近 24 小时出现 163 次失败登录'],
      detectedAt: '今天 09:42', state: 'open',
      remediation: {
        id: 'plan_ssh_harden', title: '安全关闭 SSH 密码登录', risk: 'medium', requiresApproval: true,
        expiresAt: '30 分钟后',
        checks: ['执行前验证当前 SSH 配置', '变更后确认当前连接仍可用', '未确认则在 5 分钟内自动回滚'],
        steps: [{
          id: 'step_sshd', title: '修改 SSH 登录策略', kind: 'config_patch',
          preview: '- PasswordAuthentication yes\n+ PasswordAuthentication no',
          impact: '新的 SSH 密码登录将被拒绝；现有连接不会中断。',
          rollback: '恢复原配置快照并重新加载 sshd。',
        }],
      },
    },
    {
      id: 'finding_packages', deviceId: 'dev_local', severity: 'medium', category: '软件包',
      title: '3 个安全更新待安装', summary: 'openssl、curl 与 linux-libc-dev 存在可用的发行版安全更新。',
      evidence: ['openssl 3.0.13-0ubuntu3.4 → 3.0.13-0ubuntu3.5', '无需重启内核', '预计下载 8.4 MB'],
      detectedAt: '今天 09:42', state: 'open',
      remediation: {
        id: 'plan_packages', title: '安装指定安全更新', risk: 'low', requiresApproval: true,
        expiresAt: '30 分钟后', checks: ['验证 APT 锁和已安装架构', '目标版本在执行时解析；未列出的包一律拒绝', '记录实际版本变化用于验证与回滚'],
        steps: [{
          id: 'step_packages', title: '升级三个安全软件包', kind: 'package_upgrade',
          preview: 'openssl curl linux-libc-dev（仅安全仓库候选版本）',
          impact: '目标版本由设备执行时从已配置软件源解析；相关服务可能重新加载，如需触碰未列出的包会在 dpkg 前停止。',
          rollback: '使用缓存包恢复原版本；若仓库不再提供则停止并报告。',
        }],
      },
    },
    {
      id: 'finding_port', deviceId: 'dev_local', severity: 'low', category: '网络暴露',
      title: '发现新的监听端口 8080', summary: '端口由 docker-proxy 暴露，当前没有对应的用途说明。',
      evidence: ['0.0.0.0:8080 → container/web:8080', '首次出现：今天 09:31', '安全组可从公网访问'],
      detectedAt: '今天 09:42', state: 'open',
    },
    {
      id: 'finding_updates_edge', deviceId: 'dev_edge', severity: 'medium', category: '软件包',
      title: '边缘节点内核需要安全更新', summary: '新内核安装后需要在维护窗口重启。',
      evidence: ['linux-image-amd64 6.1.140-1 可用', '当前运行 6.1.137-1'],
      detectedAt: '今天 03:00', state: 'open',
    },
    {
      id: 'finding_audit', deviceId: 'dev_edge', severity: 'info', category: '审计',
      title: '审计日志保留期较短', summary: 'journald 当前最大占用为 128 MB，预计仅保留约 4 天。',
      evidence: ['SystemMaxUse=128M', '最近 24 小时日志量 31 MB'],
      detectedAt: '今天 03:00', state: 'open',
    },
  ],
  incidents: [
    {
      id: 'incident_ssh_probe', deviceId: 'dev_local', correlationKey: 'event:ssh_auth_failure:203.0.113.84',
      category: 'identity_access', severity: 'high', status: 'open', title: '持续的 SSH 凭据探测',
      summary: '同一公网来源在 5 分钟内产生 12 次经过可信解析的 SSH 登录失败，尚未观察到成功登录。',
      signalCount: 12, firstSeenAt: '今天 09:31', lastSeenAt: '2 分钟前', createdAt: '今天 09:31', updatedAt: '2 分钟前',
    },
    {
      id: 'incident_port_change', deviceId: 'dev_local', correlationKey: 'finding:demo-port',
      category: 'network', severity: 'low', status: 'monitoring', title: '新的公网监听端口',
      summary: '8080 端口由容器工作负载开放；已进入观察状态，等待确认是否属于预期变更。',
      signalCount: 2, firstSeenAt: '今天 09:31', lastSeenAt: '今天 09:42', lastInvestigatedAt: '今天 09:43', createdAt: '今天 09:31', updatedAt: '今天 09:43',
    },
  ],
  policyGrants: [
    { deviceId: 'dev_local', capability: 'network.auth_bruteforce', enabled: true, mode: 'assist', allowedActionTypes: ['temporary_ip_ban'], maxActionsPerHour: 10, emergencyStop: false, updatedAt: '今天 08:00' },
    { deviceId: 'dev_local', capability: 'identity.persistence', enabled: true, mode: 'assist', allowedActionTypes: ['ssh_password_hardening'], maxActionsPerHour: 5, emergencyStop: false, updatedAt: '今天 08:00' },
    { deviceId: 'dev_local', capability: 'workload.runtime', enabled: true, mode: 'assist', allowedActionTypes: [], maxActionsPerHour: 5, emergencyStop: false, updatedAt: '今天 08:00' },
    { deviceId: 'dev_local', capability: 'file.integrity', enabled: true, mode: 'assist', allowedActionTypes: ['file_permission_repair'], maxActionsPerHour: 5, emergencyStop: false, updatedAt: '今天 08:00' },
    { deviceId: 'dev_local', capability: 'vulnerability.remediation', enabled: true, mode: 'assist', allowedActionTypes: ['package_security_upgrade'], maxActionsPerHour: 2, emergencyStop: false, updatedAt: '今天 08:00' },
  ],
  policies: [
    {
      id: 'policy_ssh_dev_local', deviceId: 'dev_local', name: 'SSH 暴力破解临时封禁',
      description: '同一来源 5 分钟内失败登录达到 10 次时，临时封禁该 IP。', enabled: true,
      mode: 'recommend', trigger: '5 分钟内失败 10 次', action: '建议临时封禁来源 IP', ttlMinutes: 15,
      failureThreshold: 10, window: '5m', banDuration: '15m', maxBansPerHour: 10,
      allowlist: ['127.0.0.0/8', '::1/128'], editable: true,
    },
    {
      id: 'policy_new_port', deviceId: 'dev_local', name: '新端口暴露提醒', description: '监听地址或防火墙暴露范围变化时立即通知。',
      enabled: true, mode: 'observe', trigger: '发现新的监听端口', action: '通知管理员', ttlMinutes: 0, lastTriggered: '今天 09:42', editable: false,
    },
  ],
  audit: [
    { id: 'audit_1', type: 'scan', title: '完成每日安全扫描', detail: '完成 7 项内置检查，新增 2 个发现。', actor: '计划任务', device: 'ubuntu-prod-01', timestamp: '今天 09:42', result: 'success' },
    { id: 'audit_2', type: 'finding', title: '发现新的监听端口', detail: '0.0.0.0:8080 由 docker-proxy 开放。', actor: '网络暴露扫描器', device: 'ubuntu-prod-01', timestamp: '今天 09:42', result: 'success' },
    { id: 'audit_3', type: 'scan', title: '完成每日安全扫描', detail: '完成 7 项内置检查，没有高风险变化。', actor: '计划任务', device: 'edge-shanghai-02', timestamp: '今天 03:00', result: 'success' },
    { id: 'audit_4', type: 'action', title: '修复敏感文件权限', detail: '/etc/witshield/credentials 权限已从 0640 调整为 0600。', actor: '管理员批准', device: 'ubuntu-prod-01', timestamp: '昨天 18:21', result: 'success' },
  ],
  securityEvents: [
    {
      id: 'evt_demo_untrusted', deviceId: 'dev_local', type: 'ssh_auth_failure_untrusted',
      sourceIp: '203.0.113.84', occurredAt: '今天 09:37', payload: { reason: 'line did not satisfy the trusted parser' },
    },
    {
      id: 'evt_demo_oversized', deviceId: 'dev_edge', type: 'ssh_auth_log_line_oversized_untrusted',
      occurredAt: '今天 03:02', payload: { discardedBytes: 289112 },
    },
  ],
  actions: [
    {
      id: 'action_demo_ssh', deviceId: 'dev_local', type: 'ssh_password_hardening', title: '安全关闭 SSH 密码登录',
      status: 'awaiting_confirmation', createdAt: '刚刚', updatedAt: '刚刚', confirmBy: '4 分钟内', canRollback: true,
    },
    {
      id: 'action_demo_permissions', deviceId: 'dev_local', type: 'file_permission_repair', title: '修复文件权限',
      status: 'succeeded', createdAt: '昨天 18:21', updatedAt: '昨天 18:21', canRollback: true,
    },
  ],
  ai: {
    protocol: 'openai_responses', baseUrl: 'https://api.openai.com/v1', model: 'gpt-5.4',
    hasKey: true, keyHint: '••••••••••••K3mP', customHeaderKeys: ['X-Organization'], privacyMode: 'minimal',
  },
  notifications: {
    configured: true,
    webhookEnabled: true,
    webhookUrl: 'https://ops.example.com/hooks/witshield',
    webhookSecretConfigured: true,
    smtpEnabled: false,
    smtpHost: '',
    smtpPort: 587,
    smtpUsername: '',
    smtpPasswordConfigured: false,
    smtpFrom: '',
    smtpTo: [],
  },
  coverageIssues: [],
  schedules: [
    { id: 'schedule_daily_local', deviceId: 'dev_local', every: '24h', enabled: true, nextRunAt: '明天 03:00', lastRunAt: '今天 03:00' },
    { id: 'schedule_weekly_local', deviceId: 'dev_local', every: '168h', enabled: true, nextRunAt: '星期日 04:00' },
    { id: 'schedule_daily_edge', deviceId: 'dev_edge', every: '24h', enabled: true, nextRunAt: '明天 03:00', lastRunAt: '今天 03:00' },
  ],
};
