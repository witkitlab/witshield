import type { Metadata } from 'next';
import { WitShieldApp } from '../witshield-app';

export const metadata: Metadata = {
  title: '交互式产品演示 · 妙计巡御',
  description: '使用固定演示数据体验妙计巡御，不连接任何真实服务器。',
  robots: { index: false, follow: false },
};

export default function DemoPage() {
  return <WitShieldApp />;
}
