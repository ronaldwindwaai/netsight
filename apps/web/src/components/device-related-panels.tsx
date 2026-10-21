import Link from 'next/link';

import type { Device } from '@/lib/api-contracts';
import { PERSON_ID } from '@/lib/api-contracts-identity-core';
import { relatedLinks } from '@/lib/device-links';
import type { Permissions, RelatedLink } from '@/lib/device-links';

export function LinkList({ links }: { links: RelatedLink[] }) {
  return (
    <ul className="list-unstyled mb-0">
      {links.map((link) => (
        <li className="mb-2" key={link.id}>
          <Link href={link.href}>
            <i className="bi bi-box-arrow-up-right me-1" aria-hidden="true" />
            {link.label}
          </Link>
          <span className="d-block small text-body-secondary">{link.scope}</span>
        </li>
      ))}
    </ul>
  );
}

/** The one wording for a source that is not connected: never an empty or healthy-looking result. */
export function NotConnected({ label }: { label: string }) {
  return (
    <p className="text-body-secondary">
      <i className="bi bi-plug me-2" aria-hidden="true" />
      {label} is not yet connected for this device. Nothing is estimated in its place.
    </p>
  );
}

/**
 * Tabs whose per-device telemetry is not connected stay honest about that, and still point at the
 * screens that can show related evidence, saying what each one does not filter.
 */
export function RelatedTab({
  device,
  ids,
  missing,
  permissions,
}: {
  device: Device;
  ids: ReadonlyArray<RelatedLink['id']>;
  missing: string;
  permissions: Permissions;
}) {
  const links = relatedLinks(device, permissions).filter((link) => ids.includes(link.id));
  const flowsWanted = ids.includes('flows');
  return (
    <div className="py-3">
      <NotConnected label={missing} />
      {flowsWanted && device.ip_addresses.length === 0 ? (
        <p className="small text-body-secondary">
          No address is recorded for this device, so there is no flow view to link to.
        </p>
      ) : null}
      <LinkList links={links} />
    </div>
  );
}

function Owner({ device }: { device: Device }) {
  const id = device.owner_identity_id;
  if (id === null) return <>Not tracked yet</>;
  if (!PERSON_ID.test(id)) return <>Not linked to a person</>;
  return <Link href={`/users/${encodeURIComponent(id)}`}>Owner identity</Link>;
}

function ListOrPending({ values, mono = false }: { values: string[]; mono?: boolean }) {
  if (values.length === 0) return <>Not tracked yet</>;
  return (
    <ul className={`list-unstyled mb-0${mono ? ' font-monospace' : ''}`}>
      {values.map((value) => (
        <li key={value}>{value}</li>
      ))}
    </ul>
  );
}

/** Identity facts the summary grid does not show: every address, owner, and where the record comes from. */
export function DeviceIdentityFacts({ device }: { device: Device }) {
  const aliases = device.source_aliases.map((alias) => `${alias.source}: ${alias.native_id}`);
  return (
    <dl className="device-summary mb-0">
      <div>
        <dt>IP addresses</dt>
        <dd>
          <ListOrPending mono values={device.ip_addresses} />
        </dd>
      </div>
      <div>
        <dt>MAC addresses</dt>
        <dd>
          <ListOrPending mono values={device.mac_addresses} />
        </dd>
      </div>
      <div>
        <dt>Owner</dt>
        <dd>
          <Owner device={device} />
        </dd>
      </div>
      <div>
        <dt>Known to sources as</dt>
        <dd>
          <ListOrPending values={aliases} />
        </dd>
      </div>
      <div>
        <dt>Last observed</dt>
        <dd>{device.freshness.observed_at ?? 'Not tracked yet'}</dd>
      </div>
      <div>
        <dt>Observed by</dt>
        <dd>{device.freshness.source ?? 'Not tracked yet'}</dd>
      </div>
    </dl>
  );
}

export function RelatedLinksCard({ device, permissions }: { device: Device; permissions: Permissions }) {
  return (
    <section aria-labelledby="device-related" className="border-top pt-3 px-3 pb-2">
      <h2 className="h6" id="device-related">
        Related views
      </h2>
      <LinkList links={relatedLinks(device, permissions)} />
    </section>
  );
}
