import '@/test/dom-setup';

import assert from 'node:assert/strict';
import { afterEach, describe, it } from 'node:test';

import { cleanup, render } from '@testing-library/react';

import { StoreStateSurface } from '@/components/state-surface';

afterEach(() => cleanup());

describe('StoreStateSurface wording', () => {
  it('keeps a product name capitalised instead of "the netbox"', () => {
    render(<StoreStateSurface state="not-connected" noun="assets" store="NetBox" />);
    assert.match(document.body.textContent ?? '', /because NetBox is not configured/);
    assert.doesNotMatch(document.body.textContent ?? '', /netbox/);
  });

  it('still says "the incident store" for a generic store', () => {
    render(<StoreStateSurface state="not-connected" noun="incidents" store="Incident store" />);
    assert.match(document.body.textContent ?? '', /because the incident store is not configured/);
  });

  it('starts the unknown-state sentence with a capital for either kind', () => {
    render(<StoreStateSurface state="unknown" noun="assets" store="Oxidized" />);
    assert.match(document.body.textContent ?? '', /Oxidized is configured but could not be read/);
    cleanup();
    render(<StoreStateSurface state="unknown" noun="findings" store="Finding store" />);
    assert.match(document.body.textContent ?? '', /The finding store is configured but could not be read/);
  });
});
