import type { Metadata } from 'next';
import './globals.css';

const socialImage = 'https://raw.githubusercontent.com/witkitlab/witshield/main/web/public/og.png';
const siteTitle = '妙计巡御 · 一条命令检查服务器常见风险';
const siteDescription = '开源服务器基础体检工具。检查常见风险，查看安全分和处理建议；支持的修复先预览，再由你确认。';

export const metadata: Metadata = {
  metadataBase: new URL('https://github.com/witkitlab/witshield'),
  title: siteTitle,
  description: siteDescription,
  openGraph: {
    type: 'website',
    locale: 'zh_CN',
    title: siteTitle,
    description: siteDescription,
    images: [{ url: socialImage, width: 1200, height: 630, alt: '妙计巡御 · 服务器安全体检' }],
  },
  twitter: {
    card: 'summary_large_image',
    title: siteTitle,
    description: siteDescription,
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
