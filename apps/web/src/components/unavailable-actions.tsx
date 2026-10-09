/**
 * Write actions are not wired in this slice. They are rendered as clearly
 * disabled controls with a visible explanation (disabled buttons are not
 * focusable, so the reason is plain text rather than a tooltip).
 */
export function UnavailableActions({
  id,
  label,
  actions,
}: {
  id: string;
  label: string;
  actions: readonly string[];
}) {
  const noteId = `${id}-note`;
  return (
    <div>
      <div className="d-flex flex-wrap gap-2" role="group" aria-label={label}>
        {actions.map((action) => (
          <button
            key={action}
            type="button"
            className="btn btn-outline-secondary btn-sm"
            disabled
            aria-disabled="true"
            aria-describedby={noteId}
          >
            {action}
          </button>
        ))}
      </div>
      <p id={noteId} className="small text-body-secondary mt-1 mb-0">
        <i className="bi bi-lock me-1" aria-hidden="true" />
        Not available yet. Changes will require an authenticated, CSRF-protected request and are
        audited by the Netsight API.
      </p>
    </div>
  );
}
