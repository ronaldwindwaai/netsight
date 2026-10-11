import Link from 'next/link';

import { trafficHref } from '@/lib/traffic-view';
import type { TrafficSection, TrafficWindow } from '@/lib/traffic-view';

const SECTIONS: ReadonlyArray<{ id: TrafficSection; label: string }> = [
  { id: 'overview', label: 'Overview' },
  { id: 'flows', label: 'Flow Explorer' },
  { id: 'applications', label: 'Applications' },
  { id: 'destinations', label: 'Destinations' },
  { id: 'anomalies', label: 'Anomalies' },
];

/**
 * The traffic sections. Each link keeps the selected time window, so moving between sections
 * compares like with like; the current page is marked with `aria-current`, not colour alone.
 */
export function TrafficNav({ active, window }: { active: TrafficSection; window: TrafficWindow }) {
  return (
    <nav aria-label="Traffic sections" className="mb-3">
      <ul className="nav nav-pills">
        {SECTIONS.map((section) => {
          const current = section.id === active;
          return (
            <li className="nav-item" key={section.id}>
              <Link
                className={`nav-link${current ? ' active' : ''}`}
                href={trafficHref(section.id, window)}
                aria-current={current ? 'page' : undefined}
              >
                {section.label}
              </Link>
            </li>
          );
        })}
      </ul>
    </nav>
  );
}
