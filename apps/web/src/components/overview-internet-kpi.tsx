import Link from 'next/link';
import { InfoBox } from '@adminlte/react';

import type { FetchState } from '@/lib/api-response';
import type { InternetResponse } from '@/lib/api-contracts-internet';
import { overviewInternetCard } from '@/lib/internet-view';

/**
 * The overview Internet KPI. It shows what the Internet API reported (status, throughput,
 * utilisation) and nothing it did not: without a declaration, a permission or a successful read it
 * stays an explicit "Not connected" / "Restricted" / "Unknown" surface, as the placeholder was.
 * Only a real reading links through to the Internet page.
 */
export function OverviewInternetKpi({ state }: { state: FetchState<InternetResponse> }) {
  const card = overviewInternetCard(state);
  const box = (
    <InfoBox
      icon="bi-globe2"
      text="Internet"
      title={card.title}
      theme={card.theme}
      progress={card.progress ?? 0}
      progressText={card.detail}
    />
  );
  if (state.kind === 'ok' && state.data.state === 'ok' && state.data.links.length > 0) {
    return (
      <Link
        className={`overview-kpi-link ${card.progress === undefined ? 'overview-kpi--unknown' : ''}`}
        href="/internet"
        aria-label={`Internet: ${card.title}. ${card.detail}. Open Internet status.`}
      >
        {box}
      </Link>
    );
  }
  return <div className="overview-kpi--unknown">{box}</div>;
}
