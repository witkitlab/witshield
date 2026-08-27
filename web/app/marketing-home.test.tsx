import { fireEvent, render, screen } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { MarketingHome } from './marketing-home';

const writeText = vi.fn().mockResolvedValue(undefined);

beforeEach(() => {
  writeText.mockClear();
  Object.defineProperty(navigator, 'clipboard', {
    configurable: true,
    value: { writeText },
  });
});

describe('MarketingHome', () => {
  it('shows a real isolated product demo and truthful deployment boundaries', () => {
    render(<MarketingHome />);

    expect(screen.getByRole('heading', { level: 1 })).toHaveTextContent('让每台服务器，都有一位懂边界的智能守卫。');
    expect(screen.getByTitle('交互式产品演示')).toHaveAttribute('src', '/demo');
    expect(screen.getByText('固定演示数据 · 不连接真实服务器')).toBeInTheDocument();
    expect(screen.getByText('Docker 观察模式')).toBeInTheDocument();
    expect(screen.getByText(/不授予宿主机修复或自动防御权限/)).toBeInTheDocument();
  });

  it('switches the complete marketing surface to English', () => {
    render(<MarketingHome />);

    fireEvent.click(screen.getByRole('button', { name: 'Switch to English' }));

    expect(screen.getByRole('heading', { level: 1 })).toHaveTextContent(/An intelligent.*guard for every.*server you run\./);
    expect(screen.getByText('AI proposes.')).toBeInTheDocument();
    expect(document.documentElement).toHaveAttribute('lang', 'en');
  });

  it('copies the auditable installation command', async () => {
    render(<MarketingHome />);

    fireEvent.click(screen.getByRole('button', { name: '复制' }));

    expect(writeText).toHaveBeenCalledOnce();
    expect(writeText.mock.calls[0][0]).toContain('less install.sh');
    expect(await screen.findByRole('button', { name: '已复制' })).toBeInTheDocument();
  });
});
