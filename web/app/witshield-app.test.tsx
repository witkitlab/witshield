import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import { WitShieldApp } from './witshield-app';

describe('WitShieldApp', () => {
  it('loads the product dashboard and opens a complete remediation review', async () => {
    render(<WitShieldApp />);

    expect(await screen.findByText('服务器整体稳定')).toBeInTheDocument();
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

  it('creates a one-time enrollment command from the devices page', async () => {
    render(<WitShieldApp />);
    await screen.findByText('服务器整体稳定');

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
    await screen.findByText('服务器整体稳定');

    fireEvent.click(screen.getByRole('button', { name: /^设置$/ }));
    expect(await screen.findByText('妙盾设置')).toBeInTheDocument();
    const baseUrl = screen.getByDisplayValue('https://api.openai.com/v1');
    fireEvent.change(baseUrl, { target: { value: 'https://ai.example.test/v1' } });
    fireEvent.change(screen.getAllByPlaceholderText(/留空保持不变/)[0], { target: { value: 'test-secret-1234' } });
    fireEvent.click(screen.getByRole('button', { name: /测试连接/ }));

    expect(await screen.findByText(/连接成功/)).toBeInTheDocument();
    expect(screen.queryByText('test-secret-1234')).not.toBeInTheDocument();
  });

  it('uses the configured AI assistant and returns an answer', async () => {
    render(<WitShieldApp />);
    await screen.findByText('服务器整体稳定');

    fireEvent.click(screen.getByRole('button', { name: '解释最高风险' }));
    expect(await screen.findByText(/当前是交互演示/)).toBeInTheDocument();
  });

  it('updates schedules and supports a reversible emergency stop', async () => {
    render(<WitShieldApp />);
    await screen.findByText('服务器整体稳定');

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
    await screen.findByText('服务器整体稳定');

    fireEvent.click(screen.getByRole('button', { name: /^执行记录$/ }));
    expect(await screen.findByRole('heading', { name: '安全观察' })).toBeInTheDocument();
    expect(screen.getByText('发现未通过可信解析的认证线索')).toBeInTheDocument();
    expect(screen.getByText('203.0.*.*', { exact: false })).toBeInTheDocument();
    expect(screen.getAllByText(/不会自动处置/).length).toBeGreaterThan(0);
    expect(screen.getByText(/不会增加自动封禁计数/)).toBeInTheDocument();
  });

  it('configures report delivery and sends a test without revealing stored secrets', async () => {
    render(<WitShieldApp />);
    await screen.findByText('服务器整体稳定');

    fireEvent.click(screen.getByRole('button', { name: /^设置$/ }));
    expect(await screen.findByText('安全通知')).toBeInTheDocument();
    expect(screen.getByDisplayValue('https://ops.example.com/hooks/witshield')).toBeInTheDocument();
    expect(screen.queryByDisplayValue(/K3mP|secret/i)).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: '测试已保存配置' }));
    expect(await screen.findByText('测试通知已成功送达已启用的渠道')).toBeInTheDocument();
  });

  it('requires an administrator allowlist before enabling automatic containment', async () => {
    render(<WitShieldApp />);
    await screen.findByText('服务器整体稳定');

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
