import { Badge } from '@adminlte/react';

import type {
  AssetClass,
  InventoryField,
  Provenance,
  ReconcileStatus,
} from '@/lib/api-contracts-inventory';
import {
  NOT_REPORTED,
  classLabel,
  provenancePresentation,
  reconcilePresentation,
} from '@/lib/inventory-view';

/** Where a value came from, as a word and an icon (never colour alone), with the meaning on hover. */
export function ProvenanceBadge({ provenance }: { provenance: Provenance }) {
  const view = provenancePresentation(provenance);
  return (
    <span title={view.explanation}>
      <Badge theme={view.theme} pill>
        <i className={`bi ${view.icon} me-1`} aria-hidden="true" />
        {view.label}
      </Badge>
    </span>
  );
}

export function ReconcileBadge({ status }: { status: ReconcileStatus }) {
  const view = reconcilePresentation(status);
  return (
    <span title={view.explanation}>
      <Badge theme={view.theme} pill>
        <i className={`bi ${view.icon} me-1`} aria-hidden="true" />
        {view.label}
      </Badge>
    </span>
  );
}

export function ClassBadge({ value }: { value: AssetClass }) {
  const theme = value === 'unknown-asset' ? 'warning' : value === 'unclassified' ? 'secondary' : 'primary';
  return (
    <Badge theme={theme} pill>
      {classLabel(value)}
    </Badge>
  );
}

/**
 * One value with its provenance. A conflict shows NetBox's value (the intended state) and, under it,
 * what each side reported; an unreported value is "Not reported", never blank or zero. The text is
 * untrusted source content and is only ever rendered as a text node.
 */
export function FieldValue({ field, mono = false }: { field: InventoryField; mono?: boolean }) {
  return (
    <div>
      <span className={mono ? 'font-monospace text-break' : 'text-break'}>
        {field.value ?? <span className="text-body-secondary">{NOT_REPORTED}</span>}
      </span>{' '}
      <ProvenanceBadge provenance={field.provenance} />
      {field.provenance === 'conflict' ? (
        <div className="small text-body-secondary">
          NetBox: <span className="text-break">{field.netbox}</span> · Telemetry:{' '}
          <span className="text-break">{field.discovered}</span>
        </div>
      ) : null}
    </div>
  );
}
