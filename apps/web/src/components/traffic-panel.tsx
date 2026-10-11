import type { ReactNode } from 'react';

/**
 * A labelled card region for one traffic panel. The `section` carries the accessible name, so a
 * screen reader can jump between panels; the heading repeats it for sighted users.
 */
export function TrafficPanel({
  title,
  icon,
  label,
  note,
  children,
}: {
  title: string;
  icon: string;
  /** Accessible name when it should differ from the visible title. */
  label?: string;
  note?: string;
  children: ReactNode;
}) {
  return (
    <section
      aria-label={label ?? title}
      className="card card-outline card-primary operational-card h-100"
    >
      <div className="card-header">
        <h3 className="card-title h6 mb-0">
          <i className={`bi ${icon} me-1`} aria-hidden="true" />
          {title}
        </h3>
      </div>
      <div className="card-body pt-2">
        {note ? <p className="small text-body-secondary mb-2">{note}</p> : null}
        {children}
      </div>
    </section>
  );
}
