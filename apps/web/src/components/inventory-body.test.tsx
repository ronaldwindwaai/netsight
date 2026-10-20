import '@/test/dom-setup';

import assert from 'node:assert/strict';
import { afterEach, describe, it } from 'node:test';

import { cleanup, render, screen, within } from '@testing-library/react';

import { InventoryBody } from '@/components/inventory-body';
import { InventoryFilters } from '@/components/inventory-filters';
import { InventoryDetailBody } from '@/components/inventory-detail-body';
import type { InventoryDetail, InventoryList } from '@/lib/api-contracts-inventory';
import { parseInventoryQuery } from '@/lib/inventory-view';
import {
  DEVICE_ID,
  DEVICE_ID_2,
  HOSTILE,
  failureState,
  inventoryDetail,
  inventoryItem,
  inventoryList,
  inventoryNotOk,
  okState,
  sources,
  unknownAsset,
} from '@/test/step8-fixtures';

afterEach(() => cleanup());

const NONE = parseInventoryQuery({});
const body = (state: Parameters<typeof InventoryBody>[0]['state'], query = NONE) => (
  <InventoryBody state={state} query={query} />
);

describe('every outcome of the inventory read has its own surface', () => {
  it('permission denied explains the missing permission and shows no data', () => {
    render(body(failureState<InventoryList>('forbidden', 403)));
    const text = screen.getByRole('status').textContent ?? '';
    assert.match(text, /not available to your role/);
    assert.match(text, /inventory:read/);
    assert.equal(screen.queryAllByRole('table').length, 0);
  });

  it('an unauthenticated session is asked to sign in', () => {
    render(body(failureState<InventoryList>('unauthenticated', 401)));
    assert.ok(screen.getByRole('link', { name: /Sign in/ }));
  });

  it('an API error is an error, not an empty inventory', () => {
    render(body(failureState<InventoryList>('error', 500)));
    assert.match(document.body.textContent ?? '', /Unable to load data/);
    assert.equal(screen.queryAllByRole('table').length, 0);
  });

  it('NetBox not connected shows no rows and no count, and says it is not the same as none', () => {
    render(body(okState(inventoryNotOk('not-connected'))));
    const text = screen.getByRole('status').textContent ?? '';
    assert.match(text, /NetBox not connected/);
    assert.match(text, /not the same as having none/);
    assert.equal(screen.queryAllByRole('table').length, 0);
    assert.doesNotMatch(document.body.textContent ?? '', /\b0 assets\b/);
  });

  it('NetBox unreadable is unknown and nothing is estimated', () => {
    render(body(okState(inventoryNotOk('unknown'))));
    const text = screen.getByRole('status').textContent ?? '';
    assert.match(text, /NetBox state unknown/);
    assert.match(text, /Nothing is estimated/);
  });

  it('a valid empty inventory is empty, and different from a filter that matches nothing', () => {
    const empty = okState(inventoryList({ items: [], total: 0, sources: [...sources.allOk] }));
    const { unmount } = render(body(empty));
    assert.match(screen.getByRole('status').textContent ?? '', /list no assets/);
    unmount();
    render(body(empty, parseInventoryQuery({ q: 'zzz' })));
    const text = screen.getByRole('status').textContent ?? '';
    assert.match(text, /No assets match these filters/);
    assert.match(text, /not empty/);
  });
});

describe('the data surface', () => {
  it('lists each asset with its class, provenance, status and reconciliation', () => {
    render(body(okState(inventoryList())));
    const table = screen.getByRole('table');
    const rows = within(table).getAllByRole('row');
    assert.equal(rows.length, 3);
    const known = rows[1].textContent ?? '';
    assert.match(known, /core-sw-1/);
    assert.match(known, /Network device/);
    assert.match(known, /Both agree/);
    assert.match(known, /Observed:\s*healthy/);
    assert.match(known, /Reconciled/);
    const unknown = rows[2].textContent ?? '';
    assert.match(unknown, /Unknown asset/);
    assert.match(unknown, /Discovered/);
    assert.match(unknown, /Unknown to NetBox/);
    assert.match(unknown, /Intended:\s*Not reported/);
  });

  it('an asset links to its page by id', () => {
    render(body(okState(inventoryList())));
    assert.equal(screen.getByRole('link', { name: 'core-sw-1' }).getAttribute('href'), `/inventory/${DEVICE_ID}`);
    assert.equal(screen.getByRole('link', { name: 'printer-x' }).getAttribute('href'), `/inventory/${DEVICE_ID_2}`);
  });

  it('a value nobody reported reads Not reported, never zero or blank', () => {
    render(body(okState(inventoryList())));
    const unknownRow = within(screen.getByRole('table')).getAllByRole('row')[2];
    assert.match(unknownRow.textContent ?? '', /Not reported/);
    assert.doesNotMatch(unknownRow.textContent ?? '', /(^|\s)0(\s|$)/);
  });

  it('a conflict shows the NetBox value and both readings', () => {
    const item = inventoryItem({
      ip_address: { value: '10.0.0.2', provenance: 'conflict', netbox: '10.0.0.2', discovered: '10.0.0.99' },
    });
    render(body(okState(inventoryList({ items: [item], total: 1 }))));
    const text = screen.getByRole('table').textContent ?? '';
    assert.match(text, /Conflict/);
    assert.match(text, /NetBox:\s*10\.0\.0\.2/);
    assert.match(text, /Telemetry:\s*10\.0\.0\.99/);
  });

  it('every source that was not read is named, so a missing one is never invisible', () => {
    render(body(okState(inventoryList({ sources: [...sources.libreUnknown] }))));
    const notice = screen.getAllByRole('status')[0].textContent ?? '';
    assert.match(notice, /Some sources were not read/);
    assert.match(notice, /LibreNMS is configured but could not be read/);
    assert.match(notice, /Wazuh is not connected/);
    assert.match(notice, /nothing is estimated/);
  });

  it('shows no notice when every source was read', () => {
    render(body(okState(inventoryList({ sources: [...sources.allOk] }))));
    assert.equal(screen.queryAllByRole('status').length, 0);
  });

  it('shows the counts, when it was read, and the sources behind them', () => {
    render(body(okState(inventoryList())));
    const text = document.body.textContent ?? '';
    assert.match(text, /2 assets in the inventory: 1 in NetBox, 1 seen by telemetry only/);
    assert.match(text, /NetBox read 2026-10-11 12:00:00 UTC/);
    assert.match(text, /Wazuh not connected/);
  });

  it('renders hostile names as text and keeps the link target an asset id', () => {
    const item = inventoryItem({
      name: { value: HOSTILE, provenance: 'both', netbox: HOSTILE, discovered: HOSTILE },
      role: HOSTILE,
    });
    const { container } = render(body(okState(inventoryList({ items: [item], total: 1 }))));
    assert.ok((container.textContent ?? '').includes(HOSTILE));
    assert.equal(container.querySelector('img'), null);
    assert.ok(screen.getByRole('link', { name: HOSTILE }).getAttribute('href')?.startsWith('/inventory/device-'));
  });

  it('pages with the filters kept', () => {
    const state = okState(inventoryList({ total: 80, page: 2 }));
    render(body(state, parseInventoryQuery({ page: '2', asset_class: 'server' })));
    assert.equal(screen.getByRole('link', { name: /Previous/ }).getAttribute('href'), '/inventory?asset_class=server');
    assert.equal(screen.getByRole('link', { name: /Next/ }).getAttribute('href'), '/inventory?asset_class=server&page=3');
  });
});

describe('the filter form', () => {
  it('is a plain GET form with a labelled control for every server-side filter', () => {
    render(<InventoryFilters query={NONE} />);
    const form = screen.getByRole('form', { name: 'Inventory filters' });
    assert.equal(form.getAttribute('method'), 'get');
    assert.equal(form.getAttribute('action'), '/inventory');
    for (const label of [/Search name/, /Class/, /Site/, /Observed status/, /Seen by/, /Known to NetBox/]) {
      assert.ok(screen.getByLabelText(label), String(label));
    }
    assert.equal(screen.queryByRole('link', { name: 'Clear' }), null);
  });

  it('shows the current filters and a way to clear them', () => {
    render(<InventoryFilters query={parseInventoryQuery({ q: 'core', known: 'false', asset_class: 'iot' })} />);
    assert.equal((screen.getByLabelText(/Search name/) as HTMLInputElement).value, 'core');
    assert.equal((screen.getByLabelText(/Known to NetBox/) as HTMLSelectElement).value, 'false');
    assert.equal((screen.getByLabelText(/Class/) as HTMLSelectElement).value, 'iot');
    assert.equal(screen.getByRole('link', { name: 'Clear' }).getAttribute('href'), '/inventory');
  });

  it('puts a hostile search term in the control, not in markup', () => {
    const { container } = render(<InventoryFilters query={parseInventoryQuery({ q: '"><img src=x onerror=alert(1)>' })} />);
    assert.equal(container.querySelector('img'), null);
    assert.equal((screen.getByLabelText(/Search name/) as HTMLInputElement).value, '"><img src=x onerror=alert(1)>');
  });
});

describe('the asset page', () => {
  const detailBody = (state: Parameters<typeof InventoryDetailBody>[0]['state']) => <InventoryDetailBody state={state} />;

  it('shows every field with the NetBox and telemetry readings side by side', () => {
    render(detailBody(okState(inventoryDetail())));
    const table = screen.getByRole('table', { name: 'Field readings by source' });
    const rows = within(table).getAllByRole('row');
    assert.equal(rows.length, 5);
    assert.match(rows[1].textContent ?? '', /Name.*core-sw-1.*Both agree/);
    assert.match(rows[4].textContent ?? '', /MAC address.*aa:bb:cc:00:11:22.*Discovered/);
    assert.match(rows[2].textContent ?? '', /Site.*HQ.*NetBox.*Not reported/);
  });

  it('is not a dead end: links to the device, the map, flows and IPAM', () => {
    render(detailBody(okState(inventoryDetail())));
    const hrefs = screen.getAllByRole('link').map((a) => a.getAttribute('href'));
    assert.ok(hrefs.includes(`/devices/${DEVICE_ID}`));
    assert.ok(hrefs.includes(`/network/map?focus=${DEVICE_ID}`));
    assert.ok(hrefs.includes('/traffic/flows?source_ip=10.0.0.2'));
    assert.ok(hrefs.includes('/ipam'));
  });

  it('says how the class was decided, and that an unknown asset has no role or type', () => {
    const { unmount } = render(detailBody(okState(inventoryDetail())));
    assert.match(document.body.textContent ?? '', /through the operator's class map/);
    unmount();
    render(detailBody(okState(inventoryDetail(unknownAsset()))));
    const text = document.body.textContent ?? '';
    assert.match(text, /NetBox has no record of this asset/);
    assert.match(text, /NetBox role\s*Not reported/);
    assert.match(text, /Unknown to NetBox/);
  });

  it('lists where the asset is known, with its identifier in each source', () => {
    render(detailBody(okState(inventoryDetail())));
    const text = document.body.textContent ?? '';
    assert.match(text, /NetBox: 42/);
    assert.match(text, /LibreNMS: 7/);
  });

  it('every outcome of the detail read has its own surface', () => {
    const outcomes: Array<[Parameters<typeof InventoryDetailBody>[0]['state'], RegExp]> = [
      [failureState<InventoryDetail>('forbidden', 403), /not available to your role/],
      [failureState<InventoryDetail>('not_found', 404), /Asset not found/],
      [okState(inventoryDetail(null, 'not-connected')), /NetBox not connected/],
      [okState(inventoryDetail(null, 'unknown')), /NetBox state unknown/],
    ];
    for (const [state, expected] of outcomes) {
      const { unmount } = render(detailBody(state));
      assert.match(document.body.textContent ?? '', expected);
      assert.equal(screen.queryAllByRole('table').length, 0);
      unmount();
    }
  });

  it('renders hostile field text as text', () => {
    const item = inventoryItem({
      name: { value: HOSTILE, provenance: 'both', netbox: HOSTILE, discovered: HOSTILE },
      device_type: HOSTILE,
    });
    const { container } = render(detailBody(okState(inventoryDetail(item))));
    assert.ok((container.textContent ?? '').includes(HOSTILE));
    assert.equal(container.querySelector('img'), null);
  });
});
