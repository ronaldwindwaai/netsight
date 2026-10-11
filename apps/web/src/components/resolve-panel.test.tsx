import '@/test/dom-setup';

import assert from 'node:assert/strict';
import { afterEach, describe, it } from 'node:test';

import { cleanup, render, screen, within } from '@testing-library/react';

import { ResolvePanel } from '@/components/resolve-panel';
import type { ResolveResponse } from '@/lib/api-contracts-identity';
import type { Lookup } from '@/lib/identity-view';
import {
  HOSTILE,
  failureState,
  okState,
  resolveFixture,
  source,
  sourceNotConnected,
  sourceUnknown,
  unknownAttribution,
} from '@/test/identity-fixtures';

afterEach(() => cleanup());

const IP_LOOKUP: Lookup = { ok: true, kind: 'ip', value: '10.0.0.10' };

type State = ReturnType<typeof okState<ResolveResponse>> | ReturnType<typeof failureState<ResolveResponse>>;

function panel(lookup: Lookup | null, state: State | null) {
  return <ResolvePanel lookup={lookup} state={state} />;
}

describe('the lookup form', () => {
  it('is a plain labelled GET form with a bounded value and no hidden state', () => {
    const { container } = render(panel(null, null));
    const form = container.querySelector('form') as HTMLFormElement;
    assert.equal(form.method, 'get');
    assert.equal(form.getAttribute('action'), '/users');
    const select = screen.getByLabelText('Look up') as HTMLSelectElement;
    assert.deepEqual(
      [...select.options].map((option) => option.value),
      ['ip', 'mac', 'hostname'],
    );
    const input = screen.getByLabelText('Value') as HTMLInputElement;
    assert.equal(input.name, 'value');
    assert.equal(input.maxLength, 128);
    assert.ok(screen.getByRole('button', { name: /Look up/ }));
  });

  it('explains that an address alone never identifies a person, before any lookup', () => {
    render(panel(null, null));
    assert.match(document.body.textContent ?? '', /An address alone never identifies a person/);
  });

  it('keeps what was asked for in the form, as a value and never as markup', () => {
    render(panel({ ok: true, kind: 'hostname', value: HOSTILE }, okState(resolveFixture({ subject: { kind: 'hostname', value: HOSTILE } }))));
    const input = screen.getByLabelText('Value') as HTMLInputElement;
    assert.equal(input.value, HOSTILE);
    assert.equal((screen.getByLabelText('Look up') as HTMLSelectElement).value, 'hostname');
    assert.equal(document.querySelector('img'), null);
  });
});

describe('an unusable lookup never reaches the API', () => {
  it('an empty value asks for one', () => {
    render(panel({ ok: false, reason: 'empty' }, null));
    assert.match(document.body.textContent ?? '', /Enter an IP address, MAC address or hostname/);
  });

  it('an invalid value says so without echoing it', () => {
    render(panel({ ok: false, reason: 'invalid' }, null));
    const text = screen.getByRole('alert').textContent ?? '';
    assert.match(text, /not a valid/i);
  });
});

describe('every outcome of the read has its own surface', () => {
  it('permission denied names the permission and shows no result', () => {
    render(panel(IP_LOOKUP, failureState<ResolveResponse>('forbidden', 403)));
    const text = screen.getByRole('status').textContent ?? '';
    assert.match(text, /not available to your role/);
    assert.match(text, /users:read-limited/);
  });

  it('unauthenticated, error and rate limit are reported as such', () => {
    render(panel(IP_LOOKUP, failureState<ResolveResponse>('unauthenticated', 401)));
    assert.ok(screen.getByRole('link', { name: /Sign in/ }));
    cleanup();
    render(panel(IP_LOOKUP, failureState<ResolveResponse>('error', 500)));
    assert.match(document.body.textContent ?? '', /Unable to load data/);
    cleanup();
    render(panel(IP_LOOKUP, failureState<ResolveResponse>('rate_limited', 429)));
    assert.match(document.body.textContent ?? '', /Too many requests/);
  });

  it('not-connected says no source is configured, not that the address is unknown', () => {
    const state = okState(resolveFixture({ state: 'not-connected', endpoint: [], attribution: unknownAttribution('source-unavailable'), sources: [sourceNotConnected('wazuh')] }));
    render(panel(IP_LOOKUP, state));
    const text = screen.getByRole('status').textContent ?? '';
    assert.match(text, /not connected/i);
    assert.match(text, /not the same as/);
    assert.equal(screen.queryAllByRole('region', { name: 'Who is behind it' }).length, 0);
  });

  it('unknown says a source could not be read and estimates nothing', () => {
    const state = okState(resolveFixture({ state: 'unknown', endpoint: [], attribution: unknownAttribution('source-unavailable'), sources: [sourceUnknown('wazuh')] }));
    render(panel(IP_LOOKUP, state));
    const text = screen.getByRole('status').textContent ?? '';
    assert.match(text, /state unknown/i);
    assert.match(text, /Nothing is estimated/);
  });
});

describe('the result', () => {
  it('shows the attribution with basis and the endpoint links, as of a time', () => {
    render(panel(IP_LOOKUP, okState(resolveFixture())));
    const result = screen.getByRole('region', { name: 'Lookup result' });
    const text = result.textContent ?? '';
    assert.match(text, /IP address 10\.0\.0\.10/);
    assert.match(text, /as of 2026-10-11 12:00:00 UTC/i);
    assert.match(text, /Observed: Alice Example/);
    const endpoint = within(result).getByRole('group', { name: 'Network endpoint' });
    assert.match(endpoint.textContent ?? '', /MAC address to port/);
    assert.match(endpoint.textContent ?? '', /MAC address to VLAN/);
  });

  it('says a past-time answer from the register reflects current state, only when the server says so', () => {
    render(panel(IP_LOOKUP, okState(resolveFixture({ notes: ['register-is-current-state'] }))));
    assert.match(
      document.body.textContent ?? '',
      /register, which records current state only.*may not reflect what was assigned at that time/i,
    );
    cleanup();
    render(panel(IP_LOOKUP, okState(resolveFixture({ notes: [] }))));
    assert.doesNotMatch(document.body.textContent ?? '', /records current state/i);
  });

  it('says an address alone is not identity when only the endpoint is known', () => {
    render(panel(IP_LOOKUP, okState(resolveFixture({ attribution: unknownAttribution('ip-only') }))));
    const text = screen.getByRole('region', { name: 'Who is behind it' }).textContent ?? '';
    assert.match(text, /Not identified/);
    assert.match(text, /not identity/);
  });

  it('a restricted role sees the endpoint and is told the person is withheld', () => {
    render(panel(IP_LOOKUP, okState(resolveFixture({ attribution: unknownAttribution('restricted') }))));
    assert.match(screen.getByRole('region', { name: 'Who is behind it' }).textContent ?? '', /Person withheld/);
    assert.ok(screen.getByRole('group', { name: 'Network endpoint' }));
  });

  it('names a source that could not be read while still showing what was found', () => {
    render(panel(IP_LOOKUP, okState(resolveFixture({ sources: [source(), sourceUnknown('radius')] }))));
    assert.match(document.body.textContent ?? '', /radius: could not be read/);
    assert.ok(screen.getByRole('region', { name: 'Who is behind it' }));
  });

  it('says no network links were found without claiming the endpoint does not exist', () => {
    render(panel(IP_LOOKUP, okState(resolveFixture({ endpoint: [] }))));
    assert.match(document.body.textContent ?? '', /No network links were found/);
  });

  it('announces the result politely for assistive technology', () => {
    render(panel(IP_LOOKUP, okState(resolveFixture())));
    assert.equal(screen.getByRole('region', { name: 'Lookup result' }).getAttribute('aria-live'), 'polite');
  });
});
