/**
 * Path view of a stored diagnostic session (S7 Step 4d): User, access point, access switch, core,
 * firewall and server, built only from explicit NetBox cables. A tier nothing explicit establishes
 * is shown as Unknown and a missing cable as "No explicit link"; nothing is drawn from inference.
 * The suspected tier is marked in text as well as colour. Device names are untrusted text nodes.
 */
import { Card } from '@adminlte/react';

import { StateSurface } from '@/components/state-surface';
import type { DiagnosticPath, DiagnosticPathHop } from '@/lib/api-contracts-diagnostic-session';
import { formatUtcTimestamp } from '@/lib/format-time';
import { tierLabel } from '@/lib/diagnostic-session-view';

function PathUnavailable({ state }: { state: 'not-connected' | 'unknown' }) {
  return state === 'not-connected' ? (
    <StateSurface
      icon="bi bi-plug"
      title="Topology source not connected"
      detail="The explicit topology (NetBox cables) is not connected, so no path is drawn. This is not the same as there being no path."
    />
  ) : (
    <StateSurface
      icon="bi bi-question-circle"
      title="Path unknown"
      detail="The path could not be established: the topology source could not be read or the target is not in it. Nothing is drawn in its place."
    />
  );
}

function Hop({ hop, link }: { hop: DiagnosticPathHop; link: DiagnosticPath['links'][number] | null }) {
  const suspected = hop.highlight === 'suspected';
  const known = hop.state === 'known';
  return (
    <li
      className={`diagnostic-hop border rounded p-2 ${suspected ? 'border-warning border-2' : ''}`}
      data-suspected={suspected ? 'true' : 'false'}
      data-state={hop.state}
    >
      <div className="small text-body-secondary text-uppercase" data-testid="hop-tier">
        {tierLabel(hop.tier)}
      </div>
      <div className={known ? 'fw-semibold' : 'fw-semibold text-body-secondary'}>
        {known && hop.name !== null ? hop.name : 'Unknown'}
      </div>
      {suspected ? (
        <span className="badge text-bg-warning">Suspected (inferred)</span>
      ) : null}
      {link !== null ? (
        <div
          className="small text-body-secondary mt-1"
          data-testid="path-link"
          data-state={link.state}
        >
          <i
            className={link.state === 'known' ? 'bi bi-arrow-down' : 'bi bi-dash-lg'}
            aria-hidden="true"
          />{' '}
          {link.state === 'known' ? 'Explicit cable to the next tier' : 'No explicit link to the next tier'}
        </div>
      ) : null}
    </li>
  );
}

export function PathView({ path }: { path: DiagnosticPath }) {
  return (
    <section aria-label="Network path" className="mb-3">
      <Card
        className="operational-card"
        title="Network path"
        icon="bi bi-diagram-3"
        variant="outline"
        theme="primary"
        bodyClass="p-3"
      >
        {path.state === 'ok' ? (
          <>
            <ol className="diagnostic-path list-unstyled d-flex flex-wrap gap-2 mb-2" aria-label="Network path">
              {path.hops.map((hop, index) => (
                <Hop key={hop.tier} hop={hop} link={path.links[index] ?? null} />
              ))}
            </ol>
            <p className="small text-body-secondary mb-0">
              Built only from explicit NetBox cables
              {path.observed_at !== null ? ` read ${formatUtcTimestamp(path.observed_at)}` : ''}. A
              tier or link that no explicit cable establishes stays unknown; the suspected tier is
              inferred from the probable cause and is not measured.
            </p>
          </>
        ) : (
          <PathUnavailable state={path.state} />
        )}
      </Card>
    </section>
  );
}
