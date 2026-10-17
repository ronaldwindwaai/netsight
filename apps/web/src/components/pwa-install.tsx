'use client';
import { useEffect, useState } from 'react';

type InstallPrompt = Event & {prompt: () => Promise<void>; userChoice: Promise<{outcome: string}>};
export function PwaInstall() {
  const [prompt, setPrompt] = useState<InstallPrompt | null>(null);
  const [failed, setFailed] = useState(false);
  useEffect(() => {
    if (!window.isSecureContext || !('serviceWorker' in navigator)) return;
    let active = true;
    const install = (event: Event) => {
      if (!('prompt' in event) || typeof event.prompt !== 'function') return;
      event.preventDefault();
      if (active) setPrompt(event as InstallPrompt);
    };
    const installed = () => { if (active) setPrompt(null); };
    window.addEventListener('beforeinstallprompt', install);
    window.addEventListener('appinstalled', installed);
    void navigator.serviceWorker.register('/sw.js', {scope: '/', updateViaCache: 'none'})
      .catch(() => { if (active) setFailed(true); });
    return () => {
      active = false;
      window.removeEventListener('beforeinstallprompt', install);
      window.removeEventListener('appinstalled', installed);
    };
  }, []);
  async function install() {
    const selected = prompt;
    setPrompt(null);
    if (!selected) return;
    try { await selected.prompt(); await selected.userChoice; }
    catch { setFailed(true); }
  }
  return <>
    {prompt ? <button type="button" className="btn btn-outline-secondary btn-sm me-2" onClick={() => void install()}>
      <i className="bi bi-download me-1" aria-hidden="true" />Install Netsight
    </button> : null}
    {failed ? <span className="small text-body-secondary me-2" role="status">Offline support unavailable</span> : null}
  </>;
}
