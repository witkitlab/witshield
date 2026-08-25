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
});
