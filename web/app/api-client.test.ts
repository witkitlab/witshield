import { afterEach, describe, expect, it, vi } from 'vitest';

function json(data: unknown, status = 200) {
  return new Response(JSON.stringify(data), { status, headers: { 'Content-Type': 'application/json' } });
}

async function liveClient() {
  vi.stubEnv('NEXT_PUBLIC_WITSHIELD_DEMO', 'false');
  vi.resetModules();
  return import('./api-client');
}

afterEach(() => {
  vi.unstubAllEnvs();
  vi.restoreAllMocks();
});

describe('live API client contracts', () => {
  it('maps the public status response used by the controller', async () => {
    const fetchMock = vi.fn().mockResolvedValue(json({ initialized: true, authenticated: false, mode: 'controller', version: 'dev' }));
    vi.stubGlobal('fetch', fetchMock);
    const client = await liveClient();

    await expect(client.getServerStatus()).resolves.toEqual({ initialized: true, authenticated: false, mode: 'hub', version: 'dev' });
    expect(fetchMock).toHaveBeenCalledWith('/api/v1/status', expect.objectContaining({ credentials: 'same-origin' }));
  });

  it('creates a single-use 15-minute enrollment token with the backend schema', async () => {
    const fetchMock = vi.fn().mockResolvedValue(json({
      enrollmentToken: { id: 'enr_1', expiresAt: '2026-08-26T00:15:00Z' },
      token: 'wse_secret',
    }, 201));
    vi.stubGlobal('fetch', fetchMock);
    const client = await liveClient();

    await expect(client.createEnrollmentToken()).resolves.toEqual({ id: 'enr_1', expiresAt: '2026-08-26T00:15:00Z', token: 'wse_secret' });
    const init = fetchMock.mock.calls[0][1] as RequestInit;
    expect(JSON.parse(String(init.body))).toEqual({ name: '网页一次性接入', expiresIn: '15m' });
  });

  it('keeps the one-time approval nonce in the explicit approval request', async () => {
    const fetchMock = vi.fn().mockResolvedValue(new Response(null, { status: 204 }));
    vi.stubGlobal('fetch', fetchMock);
    const client = await liveClient();

    await client.approveAction('act_1', 'approve_once');
    const init = fetchMock.mock.calls[0][1] as RequestInit;
    expect(JSON.parse(String(init.body))).toEqual({ approvalNonce: 'approve_once' });
    await expect(client.approveAction('act_2')).rejects.toMatchObject({ code: 'approval_nonce_missing' });
  });

  it('describes package approval as an explicit fail-closed scope', async () => {
    const fetchMock = vi.fn().mockResolvedValue(json({
      action: {
        id: 'act_pkg_scope', deviceId: 'dev_1', type: 'package_security_upgrade', status: 'draft',
        preview: {
          summary: 'Upgrade only the explicitly authorized installed packages',
          changes: ['openssl'],
          impact: "Target versions are resolved from the device's configured repositories at execution. Package services may restart; the action stops before dpkg if APT would touch any package outside this list.",
          rollback: 'Attempt restoring the exact recorded package versions if they are still available.',
        },
        createdAt: '2026-08-26T00:00:00Z', updatedAt: '2026-08-26T00:00:00Z',
      },
      approvalNonce: 'approve_pkg_scope',
    }, 201));
    vi.stubGlobal('fetch', fetchMock);
    const client = await liveClient();

    const plan = await client.createActionForFinding({
      id: 'finding_pkg', deviceId: 'dev_1', severity: 'medium', title: 'openssl 需要更新',
      summary: '发现安全更新', evidence: ['openssl'], category: '软件包', detectedAt: '刚刚', state: 'open',
    });

    expect(plan.approvalNonce).toBe('approve_pkg_scope');
    expect(plan.steps[0].preview).toBe('openssl');
    expect(plan.checks).toContain('执行时解析目标版本；APT 如需触碰未列出的包会在 dpkg 前停止');
    expect(plan.steps[0].impact).toContain('stops before dpkg');
    const init = fetchMock.mock.calls[0][1] as RequestInit;
    expect(JSON.parse(String(init.body))).toMatchObject({ type: 'package_security_upgrade', parameters: { packages: ['openssl'] } });
  });

  it('uses explicit action endpoints for SSH confirmation and rollback', async () => {
    const fetchMock = vi.fn().mockResolvedValue(json({ status: 'queued' }, 202));
    vi.stubGlobal('fetch', fetchMock);
    const client = await liveClient();

    await client.confirmAction('act_ssh');
    await client.rollbackAction('act_pkg');

    expect(fetchMock).toHaveBeenNthCalledWith(1, '/api/v1/actions/act_ssh/confirm', expect.objectContaining({ method: 'POST', body: '{}' }));
    expect(fetchMock).toHaveBeenNthCalledWith(2, '/api/v1/actions/act_pkg/rollback', expect.objectContaining({ method: 'POST', body: '{}' }));
  });

  it('tests an unsaved AI draft without first persisting its key', async () => {
    const fetchMock = vi.fn().mockResolvedValue(json({ ok: true, latencyMs: 42, model: 'test-model' }));
    vi.stubGlobal('fetch', fetchMock);
    const client = await liveClient();

    await client.testAISettings({ protocol: 'openai_responses', baseUrl: 'https://ai.example/v1', model: 'test-model', apiKey: 'draft-secret', hasKey: false, keyHint: '', customHeaderKeys: [], privacyMode: 'minimal' });
    const init = fetchMock.mock.calls[0][1] as RequestInit;
    expect(JSON.parse(String(init.body))).toEqual({ settings: { protocol: 'openai_responses', baseUrl: 'https://ai.example/v1', model: 'test-model', apiKey: 'draft-secret' } });
  });

  it('can explicitly clear origin-bound custom headers while moving an AI endpoint', async () => {
    const fetchMock = vi.fn().mockResolvedValue(json({
      protocol: 'openai_chat', baseUrl: 'https://new-ai.example/v1', model: 'new-model',
      keyConfigured: true, apiKeyHint: '••••1234', customHeaders: {},
    }));
    vi.stubGlobal('fetch', fetchMock);
    const client = await liveClient();

    await expect(client.saveAISettings({
      protocol: 'openai_chat', baseUrl: 'https://new-ai.example/v1', model: 'new-model',
      apiKey: 'new-provider-key-1234', customHeaders: {}, hasKey: true, keyHint: '••••old',
      customHeaderKeys: ['X-Organization'], privacyMode: 'minimal',
    })).resolves.toMatchObject({ customHeaderKeys: [] });
    const init = fetchMock.mock.calls[0][1] as RequestInit;
    expect(JSON.parse(String(init.body))).toMatchObject({ apiKey: 'new-provider-key-1234', customHeaders: {} });
  });

  it('writes notification secrets once and never expects them in the response', async () => {
    const fetchMock = vi.fn().mockResolvedValue(json({
      webhookEnabled: true,
      webhookUrl: 'https://alerts.example/hook',
      webhookSecretConfigured: true,
      smtpEnabled: false,
      smtpPasswordConfigured: false,
    }));
    vi.stubGlobal('fetch', fetchMock);
    const client = await liveClient();

    await expect(client.saveNotificationSettings({
      configured: false,
      webhookEnabled: true,
      webhookUrl: 'https://alerts.example/hook',
      webhookSecretConfigured: false,
      webhookSecret: 'sixteen-character-secret',
      smtpEnabled: false,
      smtpHost: '',
      smtpPort: 587,
      smtpUsername: '',
      smtpPasswordConfigured: false,
      smtpFrom: '',
      smtpTo: [],
    })).resolves.toMatchObject({ configured: true, webhookSecretConfigured: true });
    const init = fetchMock.mock.calls[0][1] as RequestInit;
    const body = JSON.parse(String(init.body));
    expect(body.webhookSecret).toBe('sixteen-character-secret');
    expect(body).not.toHaveProperty('smtpPassword');
    expect(fetchMock).toHaveBeenCalledWith('/api/v1/notifications/settings', expect.objectContaining({ method: 'PUT' }));
  });

  it('surfaces incomplete observer coverage instead of treating the score as exhaustive', async () => {
    const fetchMock = vi.fn(async (url: string) => {
      if (url.endsWith('/devices')) return json({ items: [{ id: 'dev_1', name: 'observer', hostname: 'host', os: 'Linux', arch: 'amd64', agentVersion: 'dev', status: 'online' }] });
      if (url.includes('/findings')) return json({ items: [] });
      if (url.includes('/reports')) return json({ items: [{ id: 'rpt_1', deviceId: 'dev_1', completedAt: '2026-08-26T00:00:00Z', score: 100, summary: { checks: 6, completedChecks: 4, coveragePercent: 66, checkErrors: ['accounts: host path unavailable'], mode: 'observer' } }] });
      if (url.includes('/audit')) return json({ items: [] });
      if (url.includes('/security-events')) return json({ items: [{ id: 'evt_1', deviceId: 'dev_1', type: 'ssh_auth_failure_untrusted', sourceIp: '203.0.113.88', occurredAt: '2026-08-26T00:00:01Z', payload: {} }] });
      if (url.includes('/actions')) return json({ items: [] });
      if (url.endsWith('/ai/settings')) return json({ protocol: 'openai_responses', baseUrl: 'https://api.openai.com/v1', model: 'gpt-5.4', keyConfigured: false });
      if (url.endsWith('/notifications/settings')) return json({ configured: false, webhookEnabled: false, smtpEnabled: false });
      if (url.endsWith('/schedules')) return json({ items: [] });
      if (url.includes('/defense-policy')) return json({ deviceId: 'dev_1', enabled: false, emergencyStop: false, autoBan: false, failureThreshold: 10, window: '5m0s', banDuration: '15m0s', maxBansPerHour: 10, allowlist: [] });
      return json({ error: { message: 'unexpected URL' } }, 500);
    });
    vi.stubGlobal('fetch', fetchMock);
    const client = await liveClient();

    const snapshot = await client.loadSnapshot();
    expect(snapshot.coverageIssues).toEqual([{ deviceId: 'dev_1', deviceName: 'observer', completedChecks: 4, checks: 6, coveragePercent: 66, mode: 'observer', errors: ['accounts: host path unavailable'] }]);
    expect(snapshot.securityEvents).toHaveLength(1);
    expect(snapshot.securityEvents[0]).toMatchObject({ id: 'evt_1', deviceId: 'dev_1', type: 'ssh_auth_failure_untrusted' });
    const observationURLs = fetchMock.mock.calls.map(([url]) => String(url)).filter((url) => url.includes('/security-events'));
    expect(observationURLs).toHaveLength(3);
    expect(observationURLs.every((url) => url.includes('type='))).toBe(true);
  });

  it('keeps a newly enrolled device unscored until its first report arrives', async () => {
    const fetchMock = vi.fn(async (url: string) => {
      if (url.endsWith('/devices')) return json({ items: [{ id: 'dev_new', name: 'new server', hostname: 'fresh-host', os: 'Linux', arch: 'amd64', agentVersion: 'dev', status: 'online' }] });
      if (url.includes('/findings') || url.includes('/reports') || url.includes('/audit') || url.includes('/security-events') || url.includes('/actions') || url.endsWith('/schedules')) return json({ items: [] });
      if (url.endsWith('/ai/settings')) return json({ protocol: 'openai_responses', baseUrl: 'https://api.openai.com/v1', model: 'gpt-5.4', keyConfigured: false });
      if (url.endsWith('/notifications/settings')) return json({ configured: false, webhookEnabled: false, smtpEnabled: false });
      if (url.includes('/defense-policy')) return json({ deviceId: 'dev_new', enabled: false, emergencyStop: false, autoBan: false, failureThreshold: 10, window: '5m0s', banDuration: '15m0s', maxBansPerHour: 10, allowlist: [] });
      return json({ error: { message: 'unexpected URL' } }, 500);
    });
    vi.stubGlobal('fetch', fetchMock);
    const client = await liveClient();

    const snapshot = await client.loadSnapshot();
    expect(snapshot.devices[0]).toMatchObject({ id: 'dev_new', score: null, lastScan: '尚未' });
    expect(snapshot.checks).toBe(0);
    expect(snapshot.coverageIssues).toEqual([{
      deviceId: 'dev_new',
      deviceName: 'new server',
      completedChecks: 0,
      checks: 0,
      coveragePercent: 0,
      mode: 'pending',
      errors: ['尚未收到首次扫描报告'],
    }]);
  });

  it('does not treat an incomplete report summary as verified full coverage', async () => {
    const fetchMock = vi.fn(async (input: string) => {
      const url = String(input);
      if (url.endsWith('/devices')) return json({ items: [{ id: 'dev_unknown', name: 'unknown host', hostname: 'unknown', os: 'Linux', arch: 'amd64', agentVersion: 'dev', status: 'online' }] });
      if (url.includes('/reports?deviceId=dev_unknown&limit=1')) return json({ items: [{
        id: 'rpt_unknown', deviceId: 'dev_unknown', completedAt: '2026-08-26T00:00:00Z', score: 100, summary: {},
      }] });
      if (url.includes('/findings') || url.includes('/audit') || url.includes('/security-events') || url.includes('/actions') || url.endsWith('/schedules')) return json({ items: [] });
      if (url.endsWith('/ai/settings')) return json({ protocol: 'openai_responses', baseUrl: 'https://api.openai.com/v1', model: 'gpt-5.4', keyConfigured: false });
      if (url.endsWith('/notifications/settings')) return json({ configured: false, webhookEnabled: false, smtpEnabled: false });
      if (url.includes('/defense-policy')) return json({ deviceId: 'dev_unknown', enabled: false, emergencyStop: false, autoBan: false, failureThreshold: 10, window: '5m0s', banDuration: '15m0s', maxBansPerHour: 10, allowlist: [] });
      return json({ error: { message: `unexpected URL: ${url}` } }, 500);
    });
    vi.stubGlobal('fetch', fetchMock);
    const client = await liveClient();

    const snapshot = await client.loadSnapshot();
    expect(snapshot.devices[0]).toMatchObject({ id: 'dev_unknown', score: 100 });
    expect(snapshot.checks).toBe(0);
    expect(snapshot.coverageIssues).toEqual([{
      deviceId: 'dev_unknown',
      deviceName: 'unknown host',
      completedChecks: 0,
      checks: 0,
      coveragePercent: 0,
      mode: 'unknown',
      errors: ['报告摘要缺少可验证的检查覆盖信息'],
    }]);
  });

  it('normalizes malformed agent report fields instead of crashing the dashboard', async () => {
    const fetchMock = vi.fn(async (input: string) => {
      const url = String(input);
      if (url.endsWith('/devices')) return json({ items: [{ id: 'dev_malformed', name: 'malformed host', hostname: 'malformed', os: 'Linux', arch: 'amd64', agentVersion: 'dev', status: 'online' }] });
      if (url.includes('/reports?deviceId=dev_malformed&limit=1')) return json({ items: [{
        id: 'rpt_malformed', deviceId: 'dev_malformed', completedAt: '2026-08-26T00:00:00Z', score: 100,
        summary: { checks: 7, completedChecks: 7, coveragePercent: 100, findingCount: -2, checkErrors: 'oops', mode: { unsafe: true } },
      }] });
      if (url.includes('/findings') || url.includes('/audit') || url.includes('/security-events') || url.includes('/actions') || url.endsWith('/schedules')) return json({ items: [] });
      if (url.endsWith('/ai/settings')) return json({ protocol: 'openai_responses', baseUrl: 'https://api.openai.com/v1', model: 'gpt-5.4', keyConfigured: false });
      if (url.endsWith('/notifications/settings')) return json({ configured: false, webhookEnabled: false, smtpEnabled: false });
      if (url.includes('/defense-policy')) return json({ deviceId: 'dev_malformed', enabled: false, emergencyStop: false, autoBan: false, failureThreshold: 10, window: '5m0s', banDuration: '15m0s', maxBansPerHour: 10, allowlist: [] });
      return json({ error: { message: `unexpected URL: ${url}` } }, 500);
    });
    vi.stubGlobal('fetch', fetchMock);
    const client = await liveClient();

    const snapshot = await client.loadSnapshot();
    expect(snapshot.coverageIssues).toEqual([expect.objectContaining({
      deviceId: 'dev_malformed',
      errors: ['报告摘要格式无效，无法验证扫描覆盖信息'],
    })]);
    expect(Array.isArray(snapshot.coverageIssues[0].errors)).toBe(true);
    expect(snapshot.reports[0]).toMatchObject({ mode: 'unknown', findingCount: null, errors: ['报告摘要格式无效，无法验证扫描覆盖信息'] });
  });

  it('keeps dashboard refreshes bounded to one latest report per device', async () => {
    const fetchMock = vi.fn(async (input: string) => {
      const url = String(input);
      if (url.endsWith('/devices')) return json({ items: [
        { id: 'dev_quiet', name: 'quiet host', hostname: 'quiet', os: 'Linux', arch: 'amd64', agentVersion: 'dev', status: 'online' },
        { id: 'dev_busy', name: 'busy host', hostname: 'busy', os: 'Linux', arch: 'amd64', agentVersion: 'dev', status: 'online' },
      ] });
      if (url.includes('/reports?deviceId=dev_quiet&limit=1')) return json({ items: [{
        id: 'rpt_quiet', deviceId: 'dev_quiet', completedAt: '2026-08-25T00:00:00Z', score: 91,
        summary: { checks: 5, completedChecks: 5, coveragePercent: 100, findingCount: 1, mode: 'native' },
      }] });
      if (url.includes('/reports?deviceId=dev_busy&limit=1')) return json({ items: [{
        id: 'rpt_busy', deviceId: 'dev_busy', completedAt: '2026-08-26T00:00:00Z', score: 73,
        summary: { checks: 6, completedChecks: 6, coveragePercent: 100, findingCount: 4, mode: 'observer' },
      }] });
      if (url.includes('/findings') || url.includes('/audit') || url.includes('/security-events') || url.includes('/actions') || url.endsWith('/schedules')) return json({ items: [] });
      if (url.endsWith('/ai/settings')) return json({ protocol: 'openai_responses', baseUrl: 'https://api.openai.com/v1', model: 'gpt-5.4', keyConfigured: false });
      if (url.endsWith('/notifications/settings')) return json({ configured: false, webhookEnabled: false, smtpEnabled: false });
      if (url.includes('/defense-policy')) return json({ enabled: false, emergencyStop: false, autoBan: false, failureThreshold: 10, window: '5m0s', banDuration: '15m0s', maxBansPerHour: 10, allowlist: [] });
      return json({ error: { message: `unexpected URL: ${url}` } }, 500);
    });
    vi.stubGlobal('fetch', fetchMock);
    const client = await liveClient();

    const snapshot = await client.loadSnapshot();
    expect(snapshot.reports).toEqual(expect.arrayContaining([
      expect.objectContaining({ id: 'rpt_quiet', detailsLoaded: false, findingCount: 1 }),
      expect.objectContaining({ id: 'rpt_busy', detailsLoaded: false, findingCount: 4 }),
    ]));
    const reportHistoryURLs = fetchMock.mock.calls
      .map(([url]) => String(url))
      .filter((url) => url.includes('/reports?'));
    expect(reportHistoryURLs).toEqual(expect.arrayContaining([
      '/api/v1/reports?deviceId=dev_quiet&limit=1',
      '/api/v1/reports?deviceId=dev_busy&limit=1',
    ]));
    expect(reportHistoryURLs).toHaveLength(2);
    expect(reportHistoryURLs.some((url) => url.includes('limit=100'))).toBe(false);
  });

  it('loads a selected device history on demand as summaries, then marks an explicit report read as detailed', async () => {
    const fetchMock = vi.fn(async (input: string) => {
      const url = String(input);
      if (url.includes('/reports?deviceId=dev_quiet&limit=100')) return json({ items: [{
        id: 'rpt_quiet', deviceId: 'dev_quiet', completedAt: '2026-08-25T00:00:00Z', score: 91,
        summary: { checks: 5, completedChecks: 5, coveragePercent: 100, findingCount: 1, mode: 'native' },
      }] });
      if (url.endsWith('/reports/rpt_quiet')) return json({
        id: 'rpt_quiet', deviceId: 'dev_quiet', completedAt: '2026-08-25T00:00:00Z', score: 91,
        summary: { checks: 5, completedChecks: 5, coveragePercent: 100, findingCount: 1, mode: 'native' }, findings: [],
      });
      return json({ error: { message: `unexpected URL: ${url}` } }, 500);
    });
    vi.stubGlobal('fetch', fetchMock);
    const client = await liveClient();

    await expect(client.getReportsForDevice('dev_quiet')).resolves.toEqual([expect.objectContaining({
      id: 'rpt_quiet',
      detailsLoaded: false,
      findingCount: 1,
    })]);
    expect(fetchMock).toHaveBeenCalledWith('/api/v1/reports?deviceId=dev_quiet&limit=100', expect.anything());
    await expect(client.getReport('rpt_quiet')).resolves.toMatchObject({
      id: 'rpt_quiet',
      detailsLoaded: true,
      findings: [],
    });
  });

  it('keeps a missing summary finding count unknown until full detail is loaded', async () => {
    const fetchMock = vi.fn(async (input: string) => {
      const url = String(input);
      if (url.includes('/reports?deviceId=dev_unknown&limit=100')) return json({ items: [{
        id: 'rpt_unknown', deviceId: 'dev_unknown', completedAt: '2026-08-26T00:00:00Z', score: 88, summary: {},
      }] });
      if (url.endsWith('/reports/rpt_unknown')) return json({
        id: 'rpt_unknown', deviceId: 'dev_unknown', completedAt: '2026-08-26T00:00:00Z', score: 88, summary: {}, findings: [{
          id: 'finding_late', deviceId: 'dev_unknown', severity: 'high', title: 'late detail', description: 'detail only', category: 'test', status: 'open', lastSeenAt: '2026-08-26T00:00:00Z',
        }],
      });
      return json({ error: { message: `unexpected URL: ${url}` } }, 500);
    });
    vi.stubGlobal('fetch', fetchMock);
    const client = await liveClient();

    await expect(client.getReportsForDevice('dev_unknown')).resolves.toEqual([
      expect.objectContaining({
        id: 'rpt_unknown', detailsLoaded: false, findingCount: null,
        checks: 0, completedChecks: 0, coveragePercent: 0,
        errors: ['报告摘要缺少可验证的检查覆盖信息'],
      }),
    ]);
    await expect(client.getReport('rpt_unknown')).resolves.toMatchObject({
      id: 'rpt_unknown', detailsLoaded: true, findingCount: 1,
    });
  });

  it('keeps missing or inconsistent coverage tuples unknown in report history', async () => {
    const fetchMock = vi.fn(async (input: string) => {
      const url = String(input);
      if (url.includes('/reports?deviceId=dev_tuple&limit=100')) return json({ items: [
        { id: 'rpt_missing_completed', deviceId: 'dev_tuple', completedAt: '2026-08-26T00:00:00Z', score: 100, summary: { checks: 5, coveragePercent: 100, findingCount: 0, checkErrors: [], mode: 'native' } },
        { id: 'rpt_inconsistent', deviceId: 'dev_tuple', completedAt: '2026-08-25T00:00:00Z', score: 100, summary: { checks: 5, completedChecks: 4, coveragePercent: 100, findingCount: 0, checkErrors: [], mode: 'native' } },
      ] });
      return json({ error: { message: `unexpected URL: ${url}` } }, 500);
    });
    vi.stubGlobal('fetch', fetchMock);
    const client = await liveClient();

    const reports = await client.getReportsForDevice('dev_tuple');
    expect(reports).toHaveLength(2);
    for (const report of reports) {
      expect(report).toMatchObject({
        checks: 0, completedChecks: 0, coveragePercent: 0,
        errors: ['报告摘要缺少可验证的检查覆盖信息'],
      });
    }
  });
});
