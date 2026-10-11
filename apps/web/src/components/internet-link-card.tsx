/**
 * One declared WAN link: status, interface metrics (LibreNMS), quality and availability (stored
 * probe samples). Every measured value is what a source reported or "Not reported"; each block
 * says which source it came from and how fresh it is, and a block whose source is absent or
 * failing says so instead of showing a value. ISP, gateway and probe location are operator
 * declarations and are labelled "configured". A role without internet:read_detail gets those, the
 * public IP and the throughput withheld by the API: they read "Restricted", never "Not reported".
 * All text is rendered as data.
 */
import type { ReactNode } from 'react';

import type {
  WanAvailability,
  WanInterfaceReading,
  WanLink,
  WanQuality,
} from '@/lib/api-contracts-internet';
import { formatSpeed } from '@/lib/format-speed';
import { formatUtcTimestamp } from '@/lib/format-time';
import {
  NOT_REPORTED,
  RESTRICTED,
  formatDuration,
  formatMillis,
  formatPercent,
  freshnessLabel,
  statusPresentation,
} from '@/lib/internet-view';

const BADGE_THEME = {
  success: 'text-bg-success',
  warning: 'text-bg-warning',
  danger: 'text-bg-danger',
  secondary: 'text-bg-secondary',
} as const;

export function LinkStatusBadge({ status }: { status: WanLink['status'] }) {
  const presentation = statusPresentation(status);
  return (
    <span className={`badge rounded-pill ${BADGE_THEME[presentation.theme]}`}>
      <i className={`bi ${presentation.icon} me-1`} aria-hidden="true" />
      {presentation.label}
    </span>
  );
}

function Row({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="d-flex justify-content-between gap-3 py-1 border-bottom">
      <dt className="fw-normal text-body-secondary">{label}</dt>
      <dd className="mb-0 text-end">{children}</dd>
    </div>
  );
}

function reported(value: string | null): string {
  return value === null || value.trim().length === 0 ? NOT_REPORTED : value;
}

function Block({
  title,
  source,
  freshness,
  children,
}: {
  title: string;
  source: string;
  freshness: Parameters<typeof freshnessLabel>[0];
  children: ReactNode;
}) {
  const stale = freshness.state === 'stale';
  return (
    <section className="col-lg-4" aria-label={`${title} for this link`}>
      <h4 className="h6 mb-0">{title}</h4>
      <p className="small text-body-secondary mb-2">
        Source: {source}. {freshnessLabel(freshness)}
      </p>
      {stale ? (
        <p className="small text-warning-emphasis mb-2">
          <i className="bi bi-clock-history me-1" aria-hidden="true" />
          Stale: these are last-known values, not current telemetry.
        </p>
      ) : null}
      {children}
    </section>
  );
}

function Notice({ icon, title, detail }: { icon: string; title: string; detail: string }) {
  return (
    <p className="small mb-0" role="status">
      <i className={`bi ${icon} me-1`} aria-hidden="true" />
      <strong>{title}.</strong> {detail}
    </p>
  );
}

function InterfaceBlock({
  reading,
  redacted,
}: {
  reading: WanInterfaceReading;
  redacted: boolean;
}) {
  let body: ReactNode;
  if (reading.state === 'not-connected') {
    body = (
      <Notice
        icon="bi-plug"
        title="Interface source not connected"
        detail="No LibreNMS port is declared for this link, or LibreNMS is not configured. Nothing is estimated."
      />
    );
  } else if (reading.state === 'unknown') {
    body = (
      <Notice
        icon="bi-question-circle"
        title="Interface state unknown"
        detail="LibreNMS did not return a usable reading for the declared port. Nothing is estimated."
      />
    );
  } else {
    body = (
      <dl className="mb-0">
        <Row label="Operational status">{reading.oper_status ?? NOT_REPORTED}</Row>
        <Row label="Capacity">{formatSpeed(reading.capacity_bps)}</Row>
        <Row label="Download (in)">{redacted ? RESTRICTED : formatSpeed(reading.rx_bps)}</Row>
        <Row label="Upload (out)">{redacted ? RESTRICTED : formatSpeed(reading.tx_bps)}</Row>
        <Row label="Utilisation">{redacted ? RESTRICTED : formatPercent(reading.utilisation_pct)}</Row>
        <Row label="Public IP">{redacted ? RESTRICTED : reported(reading.public_ip)}</Row>
      </dl>
    );
  }
  return (
    <Block title="Interface" source="LibreNMS" freshness={reading.freshness}>
      {body}
    </Block>
  );
}

const OUTCOME_LABEL = { pass: 'Pass', fail: 'Fail', unknown: 'Unknown' } as const;

function QualityBlock({ quality }: { quality: WanQuality }) {
  let body: ReactNode;
  if (quality.state === 'not-connected') {
    body = (
      <Notice
        icon="bi-plug"
        title="Probe samples not connected"
        detail="No sample store is configured, so no latency, jitter, loss or DNS result can be shown."
      />
    );
  } else if (quality.state === 'unknown') {
    body = (
      <Notice
        icon="bi-question-circle"
        title="Probe samples unreadable"
        detail="The sample store could not be read. Nothing is estimated."
      />
    );
  } else if (quality.sample_count === 0 && quality.dns_status === null) {
    body = (
      <Notice
        icon="bi-inboxes"
        title="No probe samples yet"
        detail={`No samples were stored in the last ${Math.round(quality.window_seconds / 60)} minutes. Sampling may be off or no probe source serves this link.`}
      />
    );
  } else {
    body = (
      <dl className="mb-0">
        <Row label="Latency">{formatMillis(quality.latency_ms)}</Row>
        <Row label="Jitter">{formatMillis(quality.jitter_ms)}</Row>
        <Row label="Packet loss">{formatPercent(quality.loss_pct)}</Row>
        <Row label="DNS">
          {quality.dns_status === null
            ? NOT_REPORTED
            : `${OUTCOME_LABEL[quality.dns_status]}${quality.dns_latency_ms === null ? '' : `, ${formatMillis(quality.dns_latency_ms)}`}`}
        </Row>
        <Row label="Samples in window">{quality.sample_count}</Row>
      </dl>
    );
  }
  return (
    <Block
      title={`Quality, last ${Math.round(quality.window_seconds / 60)} min`}
      source="stored probe samples"
      freshness={quality.freshness}
    >
      {body}
    </Block>
  );
}

function AvailabilityBlock({ availability }: { availability: WanAvailability }) {
  let body: ReactNode;
  if (availability.state === 'not-connected') {
    body = (
      <Notice
        icon="bi-plug"
        title="Availability not connected"
        detail="No sample store is configured, so uptime and outages cannot be computed."
      />
    );
  } else if (availability.state === 'unknown') {
    body = (
      <Notice
        icon="bi-question-circle"
        title="Availability unknown"
        detail="The sample store could not be read. Nothing is estimated."
      />
    );
  } else {
    body = (
      <>
        {availability.current_outage_started_at !== null ? (
          <p className="small fw-semibold text-danger-emphasis mb-2" role="alert">
            <i className="bi bi-x-octagon-fill me-1" aria-hidden="true" />
            Outage in progress since {formatUtcTimestamp(availability.current_outage_started_at)} (
            {formatDuration(availability.current_outage_seconds)})
          </p>
        ) : null}
        <dl className="mb-0">
          <Row label="Uptime">{formatPercent(availability.uptime_pct)}</Row>
          <Row label="Time covered by samples">{formatPercent(availability.coverage_pct)}</Row>
          <Row label="Outage now">
            {availability.current_outage_started_at === null ? 'None observed' : 'Yes'}
          </Row>
        </dl>
        <p className="small text-body-secondary mt-2 mb-0">
          Rolling 24 hours. Time without a probe round is unknown, not up.
        </p>
      </>
    );
  }
  return (
    <Block title="Availability, 24 h" source="stored probe samples" freshness={availability.freshness}>
      {body}
    </Block>
  );
}

export function InternetLinkCard({
  link,
  detailRedacted = false,
}: {
  link: WanLink;
  /** The API withheld the ISP, gateway, public IP and throughput from this viewer. */
  detailRedacted?: boolean;
}) {
  const { configured } = link;
  return (
    <article className="card operational-card mb-3" aria-label={`WAN link ${link.name}`}>
      <header className="card-header d-flex flex-wrap align-items-center gap-2">
        <h3 className="h5 mb-0 me-2">{link.name}</h3>
        <span className="badge text-bg-light border">
          {link.role === 'primary' ? 'Primary' : 'Backup'}
        </span>
        <LinkStatusBadge status={link.status} />
        <span className="small text-body-secondary ms-auto">
          Status is inferred from the interface and the latest probe round.
        </span>
      </header>
      <div className="card-body">
        <p className="small text-body-secondary mb-3">
          Configured by an administrator (not measured):{' '}
          {detailRedacted
            ? 'ISP and gateway restricted to your role'
            : `ISP ${reported(configured.isp)}; gateway ${reported(configured.gateway)}`}
          ; probe location {reported(configured.probe_location)}.
        </p>
        <div className="row g-3">
          <InterfaceBlock reading={link.interface} redacted={detailRedacted} />
          <QualityBlock quality={link.quality} />
          <AvailabilityBlock availability={link.availability} />
        </div>
      </div>
    </article>
  );
}
