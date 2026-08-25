import type { NextConfig } from 'next';

const nextConfig: NextConfig = {
  output: process.env.WITSHIELD_STATIC_EXPORT === '1' ? 'export' : undefined,
  // Release preflight and the container build set this to the same source
  // commit, avoiding Next's otherwise random build ID in separately built but
  // source-identical artifacts.
  generateBuildId: async () => process.env.WITSHIELD_BUILD_ID || 'witshield-local',
};

export default nextConfig;
