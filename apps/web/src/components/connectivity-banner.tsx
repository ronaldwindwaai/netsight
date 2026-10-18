'use client';

import { usePathname } from 'next/navigation';
import { useEffect, useState } from 'react';

import { STALE_AFTER_MS, connectivityState, describeConnectivity } from '@/lib/pwa/connectivity';

const CHECK_EVERY_MS = 30_000;

interface ConnectivityBannerProps {
  staleAfterMs?: number;
  checkEveryMs?: number;
}

function Notice({ staleAfterMs, checkEveryMs }: Required<ConnectivityBannerProps>) {
  const [loadedAtMs] = useState(() => Date.now());
  // Start "online" so server and client markup agree; the real value is read right after mount.
  const [online, setOnline] = useState(true);
  const [nowMs, setNowMs] = useState(loadedAtMs);

  useEffect(() => {
    const sync = () => {
      setOnline(window.navigator.onLine);
      setNowMs(Date.now());
    };
    sync();
    window.addEventListener('online', sync);
    window.addEventListener('offline', sync);
    const timer = window.setInterval(sync, checkEveryMs);
    return () => {
      window.removeEventListener('online', sync);
      window.removeEventListener('offline', sync);
      window.clearInterval(timer);
    };
  }, [checkEveryMs]);

  const state = connectivityState({ online, loadedAtMs, nowMs, staleAfterMs });
  const notice = describeConnectivity(state, loadedAtMs);
  if (notice === null) return null;

  return (
    <div className={`alert alert-${state === 'offline' ? 'warning' : 'info'} connectivity-banner`}>
      <div className="d-flex flex-wrap align-items-center gap-2">
        <i className={`bi ${state === 'offline' ? 'bi-wifi-off' : 'bi-clock-history'}`} aria-hidden="true" />
        <div className="flex-grow-1">
          <strong>{notice.message}</strong>
          <span className="d-block small">{notice.detail}</span>
        </div>
        {state === 'stale' ? (
          <button type="button" className="btn btn-sm btn-outline-secondary" onClick={() => window.location.reload()}>
            Reload
          </button>
        ) : null}
      </div>
    </div>
  );
}

/**
 * Says so when what is on screen is not live: the device is offline, or the page was loaded long ago. It
 * shows no notice while the page is live and never shows data of its own. The layout stays mounted across
 * client-side navigations, so the notice is keyed by path: its age restarts on navigation (a same-path
 * refresh keeps the older stamp, which can only understate freshness). The live region stays mounted
 * (empty) so a notice appearing later is announced reliably.
 */
export function ConnectivityBanner({ staleAfterMs = STALE_AFTER_MS, checkEveryMs = CHECK_EVERY_MS }: ConnectivityBannerProps) {
  const pathname = usePathname();
  return (
    <div role="status" aria-live="polite">
      <Notice key={pathname} staleAfterMs={staleAfterMs} checkEveryMs={checkEveryMs} />
    </div>
  );
}
