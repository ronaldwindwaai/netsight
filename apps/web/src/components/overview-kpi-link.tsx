import type { ComponentProps } from 'react';
import Link from 'next/link';
import { InfoBox } from '@adminlte/react';

interface OverviewKpiLinkProps {
  /** Absent when the viewer cannot open the page; the tile is then plain text, not a dead link. */
  href?: string;
  icon: string;
  label: string;
  value: string;
  detail: string;
  theme: ComponentProps<typeof InfoBox>['theme'];
  /** Absent when the tile has no measurement; it is then drawn as unknown. */
  progress?: number;
}

/**
 * One overview tile that links to its page. The link name comes from the visible text (label, value
 * and detail), so what is announced is exactly what is shown, including "Not summarised".
 */
export function OverviewKpiLink({ href, icon, label, value, detail, theme, progress }: OverviewKpiLinkProps) {
  const box = (
    <InfoBox icon={icon} text={label} title={value} theme={theme} progress={progress ?? 0} progressText={detail} />
  );
  const className = `overview-kpi-link ${progress === undefined ? 'overview-kpi--unknown' : ''}`;
  if (href === undefined) return <div className={className}>{box}</div>;
  return (
    <Link className={className} href={href}>
      {box}
    </Link>
  );
}
