/**
 * A status carried by a word and an icon as well as a colour, so it never depends on colour alone.
 * The label is either a fixed phrase or a classification the operator policy supplied; any text that
 * came from a flow source is rendered by the caller as plain text and never reaches this component.
 */
export function StatusWord({
  label,
  icon,
  theme,
}: {
  label: string;
  icon: string;
  theme: 'success' | 'warning' | 'danger' | 'secondary' | 'info';
}) {
  return (
    <span className={`badge rounded-pill text-bg-${theme}`}>
      <i className={`bi ${icon} me-1`} aria-hidden="true" />
      {label}
    </span>
  );
}
