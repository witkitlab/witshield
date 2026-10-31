import { fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { MarketingHome } from './marketing-home';

const writeText = vi.fn().mockResolvedValue(undefined);
const headline = '一条命令，检查服务器常见风险；能自动处理的，先预览，再由你确认。';
const checkCommand = 'curl -fsSLO https://github.com/witkitlab/witshield/releases/download/v0.4.0/check.sh && \\\nless check.sh && sudo bash check.sh --version v0.4.0';

beforeEach(() => {
  writeText.mockReset().mockResolvedValue(undefined);
  Object.defineProperty(navigator, 'clipboard', {
    configurable: true,
    value: { writeText },
  });
});

describe('MarketingHome', () => {
  it('leads with the check command and terminal demo, and preserves the full product details below', () => {
    render(<MarketingHome />);

    const hero = screen.getByRole('region', { name: headline });
    expect(within(hero).getByRole('heading', { level: 1 })).toHaveTextContent(headline);
    expect(within(hero).getByText(/curl -fsSLO/)).toHaveTextContent(/check\.sh.*less check\.sh.*sudo bash check\.sh --version v0\.4\.0/);
    expect(within(hero).getByRole('button', { name: '复制' })).toBeInTheDocument();
    expect(within(hero).getByText('v0.4.0 已发布')).toBeInTheDocument();
    expect(within(hero).getByText(/--fix 仍为实验性功能/)).toBeInTheDocument();
    expect(within(hero).getByRole('img', { name: /巡御命令行演示/ })).toHaveAttribute('src', '/check-demo.gif');
    expect(within(hero).getByRole('link', { name: '打开完整演示' })).toHaveAttribute('href', '/demo');
    expect(hero).not.toContainElement(screen.getByTitle('跨端控制台 desktop'));
    expect(screen.getByTitle('跨端控制台 desktop')).toHaveAttribute('src', '/demo');
    expect(screen.getByTitle('跨端控制台 mobile')).toHaveAttribute('src', '/demo');
    expect(screen.getByTitle('交互式产品演示')).toHaveAttribute('src', '/demo');
    expect(screen.getByText('固定演示数据 · 不连接真实服务器')).toBeInTheDocument();
    expect(screen.getByText('Docker 观察模式')).toBeInTheDocument();
    expect(screen.getByText(/不授予宿主机修复或自动防御权限/)).toBeInTheDocument();
  });

  it('switches the complete marketing surface to English', () => {
    render(<MarketingHome />);

    fireEvent.click(screen.getByRole('button', { name: 'Switch to English' }));

    expect(screen.getByRole('heading', { level: 1 })).toHaveTextContent('One command to check common server risks. Preview supported fixes, then decide what to apply.');
    expect(screen.getByRole('img', { name: /WitShield CLI walkthrough/ })).toHaveAttribute('src', '/check-demo.gif');
    expect(screen.getAllByText('v0.4.0 · Released')).toHaveLength(2);
    expect(screen.getByText(/Repairs with --fix remain experimental/)).toBeInTheDocument();
    expect(screen.getByText('AI proposes.')).toBeInTheDocument();
    expect(document.documentElement).toHaveAttribute('lang', 'en');
  });

  it('copies the review-first check command and announces success', async () => {
    render(<MarketingHome />);
    const hero = within(screen.getByRole('region', { name: headline }));

    fireEvent.click(hero.getByRole('button', { name: '复制' }));

    expect(writeText).toHaveBeenCalledOnce();
    expect(writeText).toHaveBeenCalledWith(checkCommand);
    expect(await hero.findByRole('button', { name: '已复制' })).toBeInTheDocument();
    expect(hero.getByRole('status')).toHaveTextContent('命令已复制到剪贴板。');
    expect(screen.getByRole('button', { name: '复制' })).toBeInTheDocument();
  });

  it('offers a focused, selected command for manual copying if clipboard access fails', async () => {
    writeText.mockRejectedValueOnce(new Error('Clipboard permission denied'));
    render(<MarketingHome />);
    const hero = within(screen.getByRole('region', { name: headline }));

    fireEvent.click(hero.getByRole('button', { name: '复制' }));

    const command = await hero.findByRole('textbox', { name: '手动复制命令' });
    expect(command).toHaveValue(checkCommand);
    expect(command).toHaveAttribute('readonly');
    await waitFor(() => expect(command).toHaveFocus());
    expect((command as HTMLTextAreaElement).selectionStart).toBe(0);
    expect((command as HTMLTextAreaElement).selectionEnd).toBe(checkCommand.length);
    expect(hero.getByRole('status')).toHaveTextContent('复制失败。已选中命令，请手动复制。');

    fireEvent.click(hero.getByRole('button', { name: '复制' }));
    expect(await hero.findByRole('button', { name: '已复制' })).toBeInTheDocument();
    expect(hero.queryByRole('textbox')).not.toBeInTheDocument();
  });

  it('keeps the command available when the clipboard API is unavailable', async () => {
    Object.defineProperty(navigator, 'clipboard', { configurable: true, value: undefined });
    render(<MarketingHome />);
    const hero = within(screen.getByRole('region', { name: headline }));

    fireEvent.click(hero.getByRole('button', { name: '复制' }));

    expect(await hero.findByRole('textbox', { name: '手动复制命令' })).toHaveValue(checkCommand);
    expect(writeText).not.toHaveBeenCalled();
  });

  it('retains the review-first installation command for the full version', async () => {
    render(<MarketingHome />);

    fireEvent.click(screen.getAllByRole('button', { name: '复制' })[1]);

    expect(writeText.mock.calls[0][0]).toContain('less install.sh');
    expect(await screen.findByRole('button', { name: '已复制' })).toBeInTheDocument();
    expect(within(screen.getByRole('region', { name: headline })).getByRole('button', { name: '复制' })).toBeInTheDocument();
  });
});
