import type { Metadata } from 'next';
import './globals.css';

const socialImage = 'https://raw.githubusercontent.com/witkitlab/witshield/main/web/public/og.png';

export const metadata: Metadata = {
  metadataBase: new URL('https://github.com/witkitlab/witshield'),
  title: '妙盾 · AI Agent 服务器管家',
  description: '主动巡检风险，在你授权后修复，并在攻击发生时按策略自动响应。',
  openGraph: {
    type: 'website',
    locale: 'zh_CN',
    title: '妙盾 · AI Agent 服务器管家',
    description: '主动巡检风险，在你授权后修复，并在攻击发生时按策略自动响应。',
    images: [{ url: socialImage, width: 1200, height: 630, alt: '妙盾 · AI Agent 服务器管家' }],
  },
  twitter: {
    card: 'summary_large_image',
    title: '妙盾 · AI Agent 服务器管家',
    description: '主动巡检风险，在你授权后修复，并在攻击发生时按策略自动响应。',
    images: [socialImage],
  },
};

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="zh-CN">
      <body>{children}</body>
    </html>
  );
}
