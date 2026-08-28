import type { NextConfig } from 'next';

const isStaticExport = process.env.WITSHIELD_STATIC_EXPORT === '1';
const isPagesExport = isStaticExport && process.env.NEXT_PUBLIC_WITSHIELD_DEMO === 'true';

const nextConfig: NextConfig = {
  output: isStaticExport ? 'export' : undefined,
  // GitHub Pages serves directory indexes reliably. The embedded controller
  // build keeps its existing root-only layout.
  trailingSlash: isPagesExport,
  // Release preflight and the container build set this to the same source
  // commit, avoiding Next's otherwise random build ID in separately built but
  // source-identical artifacts.
  generateBuildId: async () => process.env.WITSHIELD_BUILD_ID || 'witshield-local',
};

export default nextConfig;
