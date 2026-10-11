import '@/test/dom-setup';

import assert from 'node:assert/strict';
import { afterEach, describe, it } from 'node:test';

import { cleanup, render, screen, within } from '@testing-library/react';

import {
  AttributionPanel,
  BasisBadge,
  EvidenceList,
  LinkList,
  SourceNotices,
} from '@/components/identity-parts';
import {
  HOSTILE,
  ALICE,
  ambiguousAttribution,
  ambiguousLink,
  evidence,
  identityLink,
  inferredLink,
  link,
  observedAttribution,
  source,
  sourceNotConnected,
  sourceUnknown,
  unknownAttribution,
  unknownLink,
} from '@/test/identity-fixtures';

afterEach(() => cleanup());

describe('the basis badge', () => {
  it('is a word and an icon for every basis, with its meaning as text', () => {
    for (const [basis, word] of [
      ['observed', 'Observed'],
      ['inferred', 'Inferred'],
      ['unknown', 'Unknown'],
    ] as const) {
      const { container, unmount } = render(<BasisBadge basis={basis} />);
      assert.equal(container.textContent?.trim(), word);
      assert.ok(container.querySelector('i[aria-hidden="true"]'));
      assert.ok(container.querySelector('[title]')?.getAttribute('title')?.length);
      unmount();
    }
  });
});

describe('evidence drill-down', () => {
  it('lists each record with its source, kind, confidence and window behind a disclosure', () => {
    render(<EvidenceList evidence={[evidence(), evidence({ id: 'radius:s-1', source: 'radius', kind: 'radius-session', valid_to: null })]} />);
    const summary = screen.getByText(/Evidence \(2\)/);
    assert.equal(summary.tagName, 'SUMMARY');
    const text = document.body.textContent ?? '';
    assert.match(text, /DHCP lease/);
    assert.match(text, /RADIUS \/ 802\.1X session/);
    assert.match(text, /confidence 95%/);
    assert.match(text, /no end recorded/);
    assert.match(text, /dhcp:lease-1/);
  });

  it('says plainly when there is none', () => {
    render(<EvidenceList evidence={[]} />);
    assert.match(document.body.textContent ?? '', /No evidence recorded/);
  });
});

describe('a link', () => {
  it('shows relation, both ends, basis, confidence, window and as-of time', () => {
    render(<LinkList label="Network" links={[link()]} />);
    const item = screen.getByRole('listitem');
    const text = item.textContent ?? '';
    assert.match(text, /IP address to MAC address/);
    assert.match(text, /10\.0\.0\.10/);
    assert.match(text, /aa:bb:cc:00:00:01/);
    assert.match(text, /Observed/);
    assert.match(text, /95%/);
    assert.match(text, /Valid from 2026-10-11 10:00:00 UTC until 2026-10-11 14:00:00 UTC/);
    assert.match(text, /as of 2026-10-11 12:00:00 UTC/i);
    assert.ok(within(item).getByText(/Evidence \(1\)/));
  });

  it('explains an inferred link instead of presenting it as fact', () => {
    render(<LinkList label="Assigned" links={[inferredLink()]} />);
    const text = screen.getByRole('listitem').textContent ?? '';
    assert.match(text, /Inferred/);
    assert.match(text, /asset-register assignment/);
    assert.match(text, /70%/);
  });

  it('shows an unknown link with its reason, no confidence and no target', () => {
    render(<LinkList label="Network" links={[unknownLink()]} />);
    const text = screen.getByRole('listitem').textContent ?? '';
    assert.match(text, /Unknown/);
    assert.match(text, /Not identified/);
    assert.match(text, /no longer holds/);
    assert.match(text, /Not reported/);
    assert.match(text, /No validity window/);
  });

  it('lists every candidate of an ambiguous link with its own basis and selects none', () => {
    render(<LinkList label="Network" links={[ambiguousLink()]} />);
    const text = document.body.textContent ?? '';
    assert.match(text, /2 candidates/);
    assert.match(text, /aa:bb:cc:00:00:01/);
    assert.match(text, /aa:bb:cc:00:00:02/);
    assert.match(text, /none is selected/i);
  });

  it('renders hostile labels as text, never as markup', () => {
    const hostile = link({ source: { type: 'device', id: 'device-44444444-4444-4444-8444-444444444444', label: HOSTILE } });
    const { container } = render(<LinkList label="Network" links={[hostile]} />);
    assert.ok((container.textContent ?? '').includes(HOSTILE));
    assert.equal(container.querySelector('img'), null);
    assert.equal(container.querySelectorAll('script').length, 0);
  });

  it('renders an empty list as nothing rather than an empty heading', () => {
    const { container } = render(<LinkList label="Network" links={[]} />);
    assert.equal(container.textContent, '');
  });
});

describe('the attribution', () => {
  it('names an observed person with the basis and the supporting links', () => {
    render(<AttributionPanel attribution={observedAttribution()} />);
    const region = screen.getByRole('region', { name: 'Who is behind it' });
    assert.match(region.textContent ?? '', /Observed: Alice Example/);
    assert.match(region.textContent ?? '', /Direct sources agree/);
    assert.ok(within(region).getByText(/Evidence \(3\)/));
  });

  it('hedges an inferred person and says why', () => {
    render(
      <AttributionPanel
        attribution={{
          basis: 'inferred',
          reason: 'declared-assignment',
          ambiguous: false,
          links: [identityLink({ basis: 'inferred', confidence: 0.7, reason: 'declared-assignment' })],
          candidates: [],
        }}
      />,
    );
    const text = screen.getByRole('region').textContent ?? '';
    assert.match(text, /Inferred: possibly Alice Example/);
    assert.match(text, /asset-register assignment/);
    assert.doesNotMatch(text, /Observed/);
  });

  it('says not identified for an address alone', () => {
    render(<AttributionPanel attribution={unknownAttribution('ip-only')} />);
    const text = screen.getByRole('region').textContent ?? '';
    assert.match(text, /Not identified/);
    assert.match(text, /not identity/);
    assert.doesNotMatch(text, /Alice/);
  });

  it('lists all candidates of an ambiguous attribution and picks none', () => {
    render(<AttributionPanel attribution={ambiguousAttribution()} />);
    const text = screen.getByRole('region').textContent ?? '';
    assert.match(text, /Ambiguous: 2 possible people/);
    assert.match(text, /Alice Example/);
    assert.match(text, /Bob Example/);
    assert.match(text, /none is selected/i);
    assert.equal(screen.getAllByRole('listitem').length, 2);
  });

  it('says a restricted role cannot see the person', () => {
    render(<AttributionPanel attribution={unknownAttribution('restricted')} />);
    const text = screen.getByRole('region').textContent ?? '';
    assert.match(text, /Person withheld/);
    assert.match(text, /Your role may see the endpoint but not who is behind it/);
  });

  it('carries a hostile person name as text', () => {
    const attribution = observedAttribution();
    attribution.links[0] = identityLink({ target: { ...ALICE, label: HOSTILE } });
    const { container } = render(<AttributionPanel attribution={attribution} />);
    assert.ok((container.textContent ?? '').includes(HOSTILE));
    assert.equal(container.querySelector('img'), null);
  });
});

describe('source notices', () => {
  it('says nothing when every source was read and is fresh', () => {
    const { container } = render(<SourceNotices sources={[source()]} />);
    assert.equal(container.textContent, '');
  });

  it('names a source that is not connected, one that failed and one that is stale', () => {
    render(
      <SourceNotices
        sources={[
          source(),
          sourceNotConnected('netbox'),
          sourceUnknown('radius'),
          source({ source: 'dhcp', freshness: { state: 'stale', observed_at: '2026-10-11T08:00:00Z', source: 'dhcp' } }),
        ]}
      />,
    );
    const text = document.body.textContent ?? '';
    assert.match(text, /netbox: not connected/);
    assert.match(text, /radius: could not be read/);
    assert.match(text, /dhcp: last evidence 2026-10-11 08:00:00 UTC/);
    assert.match(text, /absence of evidence/i);
  });
});
