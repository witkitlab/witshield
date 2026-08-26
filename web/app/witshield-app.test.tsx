import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import * as apiClient from './api-client';
import { demoDashboard } from './demo-data';
import { WitShieldApp } from './witshield-app';

describe('WitShieldApp', () => {
  it('loads the product dashboard and opens a complete remediation review', async () => {
    render(<WitShieldApp />);

    expect(await screen.findByText('服务器安全概览')).toBeInTheDocument();
    expect(screen.getByText('妙计巡御')).toBeInTheDocument();
    expect(screen.getByText('AI Agent 服务器管家')).toBeInTheDocument();
    expect(screen.getByText('今日安全状态')).toBeInTheDocument();

    const findingButtons = screen.getAllByRole('button', { name: /SSH 允许密码登录/ });
    fireEvent.click(findingButtons[0]);

    expect(await screen.findByRole('dialog', { name: 'SSH 允许密码登录' })).toBeInTheDocument();
    expect(screen.getByText('安全关闭 SSH 密码登录')).toBeInTheDocument();
    expect(screen.getByText(/PasswordAuthentication no/)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /批准并执行/ })).toBeDisabled();

    fireEvent.click(screen.getByRole('checkbox'));
    expect(screen.getByRole('button', { name: /批准并执行/ })).toBeEnabled();
  });

  it('does not claim package target versions were reviewed before device execution', async () => {
    render(<WitShieldApp />);
    await screen.findByText('服务器安全概览');

    fireEvent.click(screen.getAllByRole('button', { name: /3 个安全更新待安装/ })[0]);

    expect(await screen.findByRole('dialog', { name: '3 个安全更新待安装' })).toBeInTheDocument();
    expect(screen.getByText(/目标版本在执行时解析；未列出的包一律拒绝/)).toBeInTheDocument();
    expect(screen.getByText(/我已核对授权的软件包范围/)).toBeInTheDocument();
    expect(screen.queryByText(/我已查看具体变更、影响和回滚方案/)).not.toBeInTheDocument();
  });

  it('opens real report history instead of redirecting to the audit timeline', async () => {
    render(<WitShieldApp />);
    await screen.findByText('服务器安全概览');

    fireEvent.click(screen.getByRole('button', { name: '查看报告' }));
    expect(await screen.findByText('扫描报告')).toBeInTheDocument();
    expect(screen.getByText('历史报告与检查覆盖')).toBeInTheDocument();
    expect(screen.getByText(/评分只来自实际完成的检查/)).toBeInTheDocument();
    expect(screen.getByText('选择一台设备查看完整历史')).toBeInTheDocument();
    expect(screen.getByText(/总览刷新只读取各设备最新报告/)).toBeInTheDocument();

    fireEvent.change(screen.getByRole('combobox', { name: '筛选报告设备' }), { target: { value: 'dev_edge' } });
    expect(await screen.findByText('边缘节点')).toBeInTheDocument();
    expect(screen.getAllByText(/44\/44/).length).toBeGreaterThan(0);
    expect((await screen.findAllByText('边缘节点内核需要安全更新')).length).toBeGreaterThan(0);
    expect(screen.getAllByText('审计日志保留期较短').length).toBeGreaterThan(0);
    expect(screen.queryByText('这份报告没有记录新的发现。')).not.toBeInTheDocument();
  });

  it('keeps an unloaded report failure visible and retryable instead of claiming zero findings', async () => {
    vi.spyOn(apiClient, 'getReport').mockRejectedValueOnce(new Error('网络暂时不可用'));
    render(<WitShieldApp />);
    await screen.findByText('服务器安全概览');

    fireEvent.click(screen.getByRole('button', { name: '查看报告' }));
    fireEvent.change(screen.getByRole('combobox', { name: '筛选报告设备' }), { target: { value: 'dev_local' } });
    expect(await screen.findByText('无法确认报告详情')).toBeInTheDocument();
    expect(screen.getByRole('alert')).toHaveTextContent('摘要中的 3 项发现不会被当作 0 项');
    expect(screen.getByRole('button', { name: '重试读取完整报告' })).toBeInTheDocument();
    expect(screen.queryByText('这份完整报告没有记录新的发现。')).not.toBeInTheDocument();
  });

  it('shows an unknown summary count as pending when report detail fails', async () => {
    const unknown = structuredClone(demoDashboard.reports[0]);
    unknown.id = 'report_unknown_count';
    unknown.findingCount = null;
    unknown.findings = [];
    unknown.detailsLoaded = false;
    vi.spyOn(apiClient, 'getReportsForDevice').mockResolvedValueOnce([unknown]);
    vi.spyOn(apiClient, 'getReport').mockRejectedValueOnce(new Error('详情接口暂时不可用'));
    render(<WitShieldApp />);
    await screen.findByText('服务器安全概览');

    fireEvent.click(screen.getByRole('button', { name: '查看报告' }));
    fireEvent.change(screen.getByRole('combobox', { name: '筛选报告设备' }), { target: { value: unknown.deviceId } });
    expect(await screen.findByText('无法确认报告详情')).toBeInTheDocument();
    expect(screen.getByRole('alert')).toHaveTextContent('摘要未提供发现数量，因此不会被当作 0 项');
    expect(screen.getByText('待确认')).toBeInTheDocument();
    expect(screen.queryByText('没有发现新的风险')).not.toBeInTheDocument();
  });

  it('warns when a loaded detail contains fewer findings than its summary', async () => {
    const summary = structuredClone(demoDashboard.reports[0]);
    summary.id = 'report_count_mismatch';
    summary.findingCount = 2;
    summary.findings = [];
    summary.detailsLoaded = false;
    const detail = structuredClone(summary);
    detail.findings = [structuredClone(demoDashboard.findings[0])];
    detail.detailsLoaded = true;
    vi.spyOn(apiClient, 'getReportsForDevice').mockResolvedValueOnce([summary]);
    vi.spyOn(apiClient, 'getReport').mockResolvedValueOnce(detail);
    render(<WitShieldApp />);
    await screen.findByText('服务器安全概览');

    fireEvent.click(screen.getByRole('button', { name: '查看报告' }));
    fireEvent.change(screen.getByRole('combobox', { name: '筛选报告设备' }), { target: { value: summary.deviceId } });
    expect(await screen.findByText('报告摘要与详情不一致')).toBeInTheDocument();
    expect(screen.getByRole('alert')).toHaveTextContent('摘要记录了 2 项发现，但详情返回了 1 项证据');
    expect(screen.getByText(detail.findings[0].title)).toBeInTheDocument();
  });

  it('loads report history only after a device is chosen and offers a clear retry on failure', async () => {
    const getReports = vi.spyOn(apiClient, 'getReportsForDevice')
      .mockRejectedValueOnce(new Error('连接暂时不可用'))
      .mockResolvedValueOnce(structuredClone(demoDashboard.reports.filter((report) => report.deviceId === 'dev_edge')));
    render(<WitShieldApp />);
    await screen.findByText('服务器安全概览');

    fireEvent.click(screen.getByRole('button', { name: '查看报告' }));
    expect(getReports).not.toHaveBeenCalled();
    fireEvent.change(screen.getByRole('combobox', { name: '筛选报告设备' }), { target: { value: 'dev_edge' } });
    expect(await screen.findByText('无法加载此设备的历史报告')).toBeInTheDocument();
    expect(screen.getByRole('alert')).toHaveTextContent('连接暂时不可用');
    fireEvent.click(screen.getByRole('button', { name: '重试读取历史报告' }));
    expect(await screen.findByText('边缘节点内核需要安全更新')).toBeInTheDocument();
    expect(getReports).toHaveBeenCalledTimes(2);
  });

  it('keeps the demo edge-report summary and complete detail list in sync', () => {
    const edgeReport = demoDashboard.reports.find((report) => report.id === 'report_demo_edge');
    expect(edgeReport).toMatchObject({ findingCount: 2, detailsLoaded: true });
    expect(edgeReport?.findings).toHaveLength(2);
  });

  it('creates a one-time enrollment command from the devices page', async () => {
    render(<WitShieldApp />);
    await screen.findByText('服务器安全概览');

    fireEvent.click(screen.getByRole('button', { name: /^设备$/ }));
    expect(await screen.findByText('受保护的设备')).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: /添加设备/ }));

    expect(await screen.findByRole('dialog', { name: '添加一台服务器' })).toBeInTheDocument();
    await waitFor(() => expect(screen.getByText(/enroll_demo_/)).toBeInTheDocument());
    const command = screen.getByText(/curl --proto/).textContent ?? '';
    expect(command).toContain("--proto '=https'");
    expect(command).toContain('WITSHIELD_CONTROLLER_URL=');
    expect(command).toContain('WITSHIELD_ENROLLMENT_TOKEN=');
    expect(command).toContain('--mode agent');
    expect(command).not.toContain('--token');
    expect(screen.getByText(/不需要开放服务器入站端口/)).toBeInTheDocument();
  });

  it('tests and saves a custom AI endpoint without exposing the key', async () => {
    render(<WitShieldApp />);
    await screen.findByText('服务器安全概览');

    fireEvent.click(screen.getByRole('button', { name: /^设置$/ }));
    expect(await screen.findByText('巡御设置')).toBeInTheDocument();
    const baseUrl = screen.getByDisplayValue('https://api.openai.com/v1');
    fireEvent.change(baseUrl, { target: { value: 'https://ai.example.test/v1' } });
    expect(screen.getByText(/保存时会清除旧地址绑定的自定义请求头：X-Organization/)).toBeInTheDocument();
    const apiKey = screen.getByPlaceholderText('更换地址后需重新输入 API Key');
    fireEvent.change(apiKey, { target: { value: 'test-secret-1234' } });
    expect(apiKey).toHaveValue('test-secret-1234');
    fireEvent.click(screen.getByRole('button', { name: /测试连接/ }));

    expect(await screen.findByText(/连接成功/)).toBeInTheDocument();
    expect(screen.queryByText('test-secret-1234')).not.toBeInTheDocument();
    fireEvent.click(screen.getAllByRole('button', { name: '保存设置' })[0]);
    await waitFor(() => expect(screen.queryByText(/X-Organization/)).not.toBeInTheDocument());
  });

  it('never reuses a stored API key after the endpoint origin changes', async () => {
    render(<WitShieldApp />);
    await screen.findByText('服务器安全概览');

    fireEvent.click(screen.getByRole('button', { name: /^设置$/ }));
    fireEvent.change(screen.getByDisplayValue('https://api.openai.com/v1'), { target: { value: 'https://other.example.test/v1' } });
    expect(screen.getByText(/密钥不会自动带到新的 API 地址/)).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: /测试连接/ }));
    expect(screen.getByRole('alert')).toHaveTextContent('请重新输入该地址对应的 API Key');
  });

  it('uses the configured AI assistant and returns an answer', async () => {
    render(<WitShieldApp />);
    await screen.findByText('服务器安全概览');

    fireEvent.click(screen.getByRole('button', { name: '解释最高风险' }));
    expect(await screen.findByText(/当前是交互演示/)).toBeInTheDocument();
  });

  it('updates schedules and supports a reversible emergency stop', async () => {
    render(<WitShieldApp />);
    await screen.findByText('服务器安全概览');

    fireEvent.click(screen.getByRole('button', { name: /^设置$/ }));
    const daily = await screen.findByRole('button', { name: '关闭每日安全扫描' });
    fireEvent.click(daily);
    expect(await screen.findByRole('button', { name: '开启每日安全扫描' })).toBeInTheDocument();

    fireEvent.click(screen.getByRole('button', { name: /^防御策略$/ }));
    fireEvent.click(await screen.findByRole('button', { name: '紧急停止' }));
    expect(await screen.findByText('自动防御已紧急停止')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: '恢复自动防御' })).toBeInTheDocument();
  });

  it('keeps untrusted security observations separate from automatic defense', async () => {
    render(<WitShieldApp />);
    await screen.findByText('服务器安全概览');

    fireEvent.click(screen.getByRole('button', { name: /^执行记录$/ }));
    expect(await screen.findByRole('heading', { name: '安全观察' })).toBeInTheDocument();
    expect(screen.getByText('发现未通过可信解析的认证线索')).toBeInTheDocument();
    expect(screen.getByText('203.0.*.*', { exact: false })).toBeInTheDocument();
    expect(screen.getAllByText(/不会自动处置/).length).toBeGreaterThan(0);
    expect(screen.getByText(/不会增加自动封禁计数/)).toBeInTheDocument();
  });

  it('shows the proven failure reason and rollback control for an indeterminate action', async () => {
    const originalActions = structuredClone(demoDashboard.actions);
    demoDashboard.actions.unshift({
      id: 'act_indeterminate_demo', deviceId: 'dev_local', type: 'temporary_ip_ban', title: '临时封禁 SSH 攻击来源',
      status: 'indeterminate', createdAt: '刚刚', updatedAt: '刚刚', canRollback: true,
      error: '验证失败，自动回滚也失败',
    });
    try {
      render(<WitShieldApp />);
      await screen.findByText('服务器安全概览');
      fireEvent.click(screen.getByRole('button', { name: /^执行记录$/ }));

      expect(await screen.findByText(/未能确认安全终态：验证失败，自动回滚也失败/)).toBeInTheDocument();
      expect(screen.queryByText(/没有在安全期限内收到可信设备回执/)).not.toBeInTheDocument();
      expect(screen.getAllByRole('button', { name: '立即回滚' }).length).toBeGreaterThan(0);
    } finally {
      demoDashboard.actions.splice(0, demoDashboard.actions.length, ...originalActions);
    }
  });

  it('configures report delivery and sends a test without revealing stored secrets', async () => {
    render(<WitShieldApp />);
    await screen.findByText('服务器安全概览');

    fireEvent.click(screen.getByRole('button', { name: /^设置$/ }));
    expect(await screen.findByText('安全通知')).toBeInTheDocument();
    expect(screen.getByDisplayValue('https://ops.example.com/hooks/witshield')).toBeInTheDocument();
    expect(screen.queryByDisplayValue(/K3mP|secret/i)).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: '测试已保存配置' }));
    expect(await screen.findByText('测试通知已成功送达已启用的渠道')).toBeInTheDocument();
  });

  it('requires an administrator allowlist before enabling automatic containment', async () => {
    render(<WitShieldApp />);
    await screen.findByText('服务器安全概览');

    fireEvent.click(screen.getByRole('button', { name: /^防御策略$/ }));
    fireEvent.click(await screen.findByRole('button', { name: '配置' }));
    fireEvent.change(screen.getByLabelText('响应模式'), { target: { value: 'auto_contain' } });
    fireEvent.click(screen.getByRole('button', { name: '保存防御策略' }));
    expect(await screen.findByRole('alert')).toHaveTextContent('管理员 IP 或 CIDR');

    fireEvent.change(screen.getByLabelText(/管理员保护地址/), { target: { value: '127.0.0.0/8\n203.0.113.8' } });
    fireEvent.click(screen.getByRole('button', { name: '保存防御策略' }));
    expect(await screen.findByText('自动遏制')).toBeInTheDocument();
  });
});
