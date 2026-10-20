import Link from 'next/link';

const LINKS = [
  { href: '/alerts', icon: 'bi-bell', label: 'Alerts', hint: 'Source alerts and maintenance windows' },
  { href: '/diagnostics', icon: 'bi-activity', label: 'Run a diagnostic', hint: 'Read-only checks and probable cause' },
  { href: '/config/changes', icon: 'bi-file-diff', label: 'Configuration changes', hint: 'Saved versions; timing alone is not a cause' },
  { href: '/actions', icon: 'bi-shield-check', label: 'Action requests', hint: 'Proposed, approved and dry-run actions' },
] as const;

/** Where to look next from an incident, so the record is never a dead end. Links carry no identifiers. */
export function IncidentRelatedLinks() {
  return (
    <nav aria-label="Investigate next">
      <p className="small text-body-secondary mb-1">Investigate next</p>
      <ul className="list-inline mb-0">
        {LINKS.map((link) => (
          <li key={link.href} className="list-inline-item">
            <Link className="btn btn-sm btn-outline-secondary" href={link.href} title={link.hint}>
              <i className={`bi ${link.icon} me-1`} aria-hidden="true" />
              {link.label}
            </Link>
          </li>
        ))}
      </ul>
    </nav>
  );
}
