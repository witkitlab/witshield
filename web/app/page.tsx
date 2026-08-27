import { WitShieldApp } from './witshield-app';
import { MarketingHome } from './marketing-home';

export default function Home() {
  if (process.env.NEXT_PUBLIC_WITSHIELD_DEMO === 'false') {
    return <WitShieldApp />;
  }

  return <MarketingHome />;
}
