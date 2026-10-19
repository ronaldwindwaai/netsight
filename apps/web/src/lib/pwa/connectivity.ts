/** A page left open this long without a reload is treated as possibly out of date. */
export const STALE_AFTER_MS = 5 * 60 * 1000;

export type ConnectivityState = 'live' | 'offline' | 'stale';

export interface ConnectivityInput {
  online: boolean;
  loadedAtMs: number;
  nowMs: number;
  staleAfterMs?: number;
}

export interface ConnectivityNotice {
  message: string;
  detail: string;
}

/** Offline wins over stale; a clock that moved backwards counts as fresh, never as a negative age. */
export function connectivityState(input: ConnectivityInput): ConnectivityState {
  if (!input.online) return 'offline';
  const age = input.nowMs - input.loadedAtMs;
  return age >= (input.staleAfterMs ?? STALE_AFTER_MS) ? 'stale' : 'live';
}

function utcStamp(ms: number): string {
  return `${new Date(ms).toISOString().slice(0, 16).replace('T', ' ')} UTC`;
}

/** Plain, honest wording for a non-live state; null while the page is live (no banner). */
export function describeConnectivity(state: ConnectivityState, loadedAtMs: number): ConnectivityNotice | null {
  if (state === 'live') return null;
  const loaded = utcStamp(loadedAtMs);
  if (state === 'offline') {
    return {
      message: 'You are offline. What is on screen is not live.',
      detail: `It was loaded at ${loaded}. Netsight keeps no copy of operational data for offline use, so nothing newer is available until you reconnect.`,
    };
  }
  return {
    message: 'This page may be out of date.',
    detail: `It was loaded at ${loaded}. Reload to see the current state.`,
  };
}
