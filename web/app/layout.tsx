import type { Metadata } from 'next';
import './globals.css';

export const metadata: Metadata = {
  metadataBase: new URL('https://github.com/witkitlab/witshield'),
  title: '妙盾｜开源服务器 AI Agent 智能守卫',
  description: '会巡检、会解释，经你授权才行动的开源服务器 AI Agent 智能守卫。',
  openGraph: {
    type: 'website',
    locale: 'zh_CN',
    title: '妙盾 WitShield AI',
    description: '开源服务器 AI Agent 智能守卫',
    images: [{ url: '/og.png', width: 1200, height: 630, alt: '妙盾 WitShield AI：开源服务器 AI Agent 智能守卫' }],
  },
  twitter: {
    card: 'summary_large_image',
    title: '妙盾 WitShield AI',
    description: '开源服务器 AI Agent 智能守卫',
    images: ['/og.png'],
  },
};

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="zh-CN">
      <body>{children}</body>
    </html>
  );
}
