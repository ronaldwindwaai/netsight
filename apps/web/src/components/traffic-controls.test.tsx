import '@/test/dom-setup';

import assert from 'node:assert/strict';
import { afterEach, describe, it } from 'node:test';

import { cleanup, render, screen, within } from '@testing-library/react';

import { ExplorerFilterForm } from '@/components/explorer-filter-form';
import { TimeRangePicker } from '@/components/time-range-picker';
import { TrafficNav } from '@/components/traffic-nav';
import { resolveTrafficWindow } from '@/lib/traffic-view';

afterEach(() => cleanup());

const NOW = new Date('2026-10-11T12:00:00Z');
const window24h = resolveTrafficWindow({}, NOW, 31);
const custom = resolveTrafficWindow({ from: '2026-10-10T08:30', to: '2026-10-11T08:30' }, NOW, 31);

describe('the section navigation', () => {
  it('links every section, keeping the window, and marks the current page', () => {
    render(<TrafficNav active="applications" window={window24h} />);
    const nav = screen.getByRole('navigation', { name: /Traffic sections/i });
    const links = within(nav).getAllByRole('link');
    assert.deepEqual(
      links.map((link) => link.textContent),
      ['Overview', 'Flow Explorer', 'Applications', 'Destinations', 'Anomalies'],
    );
    assert.deepEqual(
      links.map((link) => link.getAttribute('href')),
      [
        '/traffic?preset=24h',
        '/traffic/flows?preset=24h',
        '/traffic/applications?preset=24h',
        '/traffic/destinations?preset=24h',
        '/traffic/anomalies?preset=24h',
      ],
    );
    const current = links.filter((link) => link.getAttribute('aria-current') === 'page');
    assert.equal(current.length, 1);
    assert.equal(current[0].textContent, 'Applications');
  });

  it('keeps a custom window across sections', () => {
    render(<TrafficNav active="flows" window={custom} />);
    const href = screen.getByRole('link', { name: 'Destinations' }).getAttribute('href') ?? '';
    assert.match(href, /^\/traffic\/destinations\?from=2026-10-10T08%3A30%3A00Z&to=/);
  });
});

describe('the time-range picker', () => {
  it('offers the presets as links and marks the active one', () => {
    render(<TimeRangePicker section="flows" window={window24h} maxDays={31} />);
    const group = screen.getByRole('group', { name: /Time range/i });
    const links = within(group).getAllByRole('link');
    assert.deepEqual(
      links.map((link) => link.textContent),
      ['Last hour', 'Last 6 hours', 'Last 24 hours', 'Last 7 days'],
    );
    assert.equal(links[2].getAttribute('aria-current'), 'true');
    assert.equal(links[0].getAttribute('href'), '/traffic/flows?preset=1h');
  });

  it('a preset link keeps the active filters', () => {
    render(
      <TimeRangePicker section="flows" window={window24h} maxDays={31} filters={{ application: 'Zoom' }} />,
    );
    assert.equal(
      screen.getByRole('link', { name: 'Last hour' }).getAttribute('href'),
      '/traffic/flows?preset=1h&application=Zoom',
    );
  });

  it('the custom range is a plain GET form in UTC with labelled inputs', () => {
    render(<TimeRangePicker section="anomalies" window={custom} maxDays={7} />);
    const form = screen.getByRole('search', { name: /Custom time range/i });
    assert.equal(form.getAttribute('method'), 'get');
    assert.equal(form.getAttribute('action'), '/traffic/anomalies');
    const from = within(form).getByLabelText(/From \(UTC\)/);
    const to = within(form).getByLabelText(/To \(UTC\)/);
    assert.equal(from.getAttribute('type'), 'datetime-local');
    assert.equal((from as HTMLInputElement).value, '2026-10-10T08:30');
    assert.equal((to as HTMLInputElement).value, '2026-10-11T08:30');
    assert.match(form.textContent ?? '', /at most 7 days/);
    assert.equal(screen.queryAllByRole('link', { current: 'true' }).length, 0);
  });

  it('carries the filters through a custom range as hidden inputs', () => {
    render(
      <TimeRangePicker section="flows" window={window24h} maxDays={31} filters={{ port: '443', application: 'a&b' }} />,
    );
    const hidden = Array.from(document.querySelectorAll('form input[type="hidden"]')).map(
      (input) => [input.getAttribute('name'), (input as HTMLInputElement).value],
    );
    assert.deepEqual(hidden, [['application', 'a&b'], ['port', '443']]);
  });

  it('says so when the requested window was unusable and a default was used', () => {
    const adjusted = resolveTrafficWindow({ preset: '12h' }, NOW, 31);
    render(<TimeRangePicker section="flows" window={adjusted} maxDays={31} />);
    assert.match(screen.getByRole('status').textContent ?? '', /could not be used/);
  });

  it('is silent when nothing needed adjusting', () => {
    render(<TimeRangePicker section="flows" window={window24h} maxDays={31} />);
    assert.equal(screen.queryAllByRole('status').length, 0);
  });
});

describe('the Flow Explorer filters', () => {
  function form(detail: boolean, values = {}, refused: string[] = []) {
    return render(
      <ExplorerFilterForm
        window={window24h}
        values={values}
        refused={refused as never}
        detail={detail}
      />,
    );
  }

  it('is a labelled GET search form that keeps the window', () => {
    form(true);
    const search = screen.getByRole('search', { name: /Flow filters/i });
    assert.equal(search.getAttribute('method'), 'get');
    assert.equal(search.getAttribute('action'), '/traffic/flows');
    const preset = search.querySelector('input[name="preset"]') as HTMLInputElement;
    assert.equal(preset.value, '24h');
  });

  it('offers every allow-listed filter with a label when the viewer may see endpoints', () => {
    form(true);
    for (const label of [
      'Source IP',
      'Destination IP',
      'Exporter (device)',
      'VLAN',
      'Application',
      'Protocol',
      'Port',
      'Country',
      'ASN',
      'Direction',
    ]) {
      assert.ok(screen.getByLabelText(new RegExp(`^${label.replace(/[()]/g, '\\$&')}`)), label);
    }
  });

  it('does not offer address, device or VLAN filters to a viewer without endpoint access', () => {
    form(false);
    assert.equal(
      screen.queryAllByLabelText(/Source IP|Destination IP|Exporter|VLAN/).length,
      0,
    );
    assert.match(document.body.textContent ?? '', /needs the traffic:read-detail permission/);
    assert.match(document.body.textContent ?? '', /address, exporter \(device\) or VLAN/);
    for (const label of ['Application', 'Protocol', 'Port', 'Country', 'ASN', 'Direction']) {
      assert.ok(screen.getByLabelText(new RegExp(`^${label}`)), label);
    }
  });

  it('shows the current values and a way to clear them', () => {
    form(true, { source_ip: '10.0.0.1', protocol: 'tcp', port: '443' });
    assert.equal((screen.getByLabelText(/^Source IP/) as HTMLInputElement).value, '10.0.0.1');
    assert.equal((screen.getByLabelText(/^Protocol/) as HTMLSelectElement).value, 'tcp');
    assert.equal((screen.getByLabelText(/^Port/) as HTMLInputElement).value, '443');
    assert.equal(screen.getByRole('link', { name: /Clear filters/ }).getAttribute('href'), '/traffic/flows?preset=24h');
  });

  it('names the filters that were not applied without echoing their values', () => {
    form(true, {}, ['vlan', 'asn']);
    const status = screen.getByRole('status').textContent ?? '';
    assert.match(status, /VLAN/);
    assert.match(status, /ASN/);
    assert.match(status, /not applied/i);
  });

  it('a hostile current value stays in an input as a value, never markup', () => {
    const hostile = '"><img src=x onerror=alert(1)>';
    form(true, { application: hostile });
    assert.equal((screen.getByLabelText(/^Application/) as HTMLInputElement).value, hostile);
    assert.equal(document.querySelectorAll('img').length, 0);
  });

  it('constrains the inputs to what the API accepts', () => {
    form(true);
    assert.equal(screen.getByLabelText(/^VLAN/).getAttribute('max'), '4094');
    assert.equal(screen.getByLabelText(/^Port/).getAttribute('max'), '65535');
    assert.equal(screen.getByLabelText(/^Application/).getAttribute('maxlength'), '128');
    const country = screen.getByLabelText(/^Country/);
    assert.equal(country.getAttribute('maxlength'), '2');
  });
});
