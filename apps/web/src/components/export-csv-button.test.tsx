import '@/test/dom-setup';

import assert from 'node:assert/strict';
import { afterEach, beforeEach, describe, it } from 'node:test';

import { cleanup, fireEvent, render, screen } from '@testing-library/react';

import { ExportCsvButton, REVOKE_DELAY_MS } from '@/components/export-csv-button';

let blobs: Blob[] = [];
let revoked: string[] = [];
let clicks = 0;
const original = {
  create: URL.createObjectURL,
  revoke: URL.revokeObjectURL,
  click: window.HTMLAnchorElement.prototype.click,
};

beforeEach(() => {
  blobs = [];
  revoked = [];
  clicks = 0;
  URL.createObjectURL = (blob: Blob | MediaSource) => {
    blobs.push(blob as Blob);
    return `blob:test-${blobs.length}`;
  };
  URL.revokeObjectURL = (url: string) => void revoked.push(url);
  window.HTMLAnchorElement.prototype.click = () => void (clicks += 1);
});
afterEach(() => {
  cleanup();
  URL.createObjectURL = original.create;
  URL.revokeObjectURL = original.revoke;
  window.HTMLAnchorElement.prototype.click = original.click;
});

describe('ExportCsvButton', () => {
  it('names the action with the row count and what is exported', () => {
    render(<ExportCsvButton headers={['A']} label="devices" rows={[['x'], ['y']]} />);
    assert.ok(screen.getByRole('button', { name: 'Export CSV, 2 devices' }));
  });

  it('writes a UTF-8 BOM at the start of the Blob and declares the charset', async () => {
    render(<ExportCsvButton headers={['Name']} label="devices" rows={[['café']]} />);
    fireEvent.click(screen.getByRole('button'));
    assert.equal(blobs.length, 1);
    assert.equal(blobs[0].type, 'text/csv;charset=utf-8');
    const bytes = new Uint8Array(await blobs[0].arrayBuffer());
    assert.deepEqual(Array.from(bytes.slice(0, 3)), [0xef, 0xbb, 0xbf]);
    assert.equal(new TextDecoder().decode(bytes.slice(3)), 'Name\r\ncafé\r\n');
  });

  it('revokes the object URL after a delay, not synchronously', async () => {
    render(<ExportCsvButton headers={['A']} label="devices" rows={[['x']]} />);
    fireEvent.click(screen.getByRole('button'));
    assert.equal(clicks, 1);
    assert.ok(!revoked.includes('blob:test-1'), 'still alive right after the click');
    await new Promise((resolve) => setTimeout(resolve, REVOKE_DELAY_MS + 100));
    assert.ok(revoked.includes('blob:test-1'));
  });

  it('explains the disabled state in text and does nothing when pressed', () => {
    render(<ExportCsvButton headers={['A']} label="devices" rows={[]} />);
    const button = screen.getByRole('button', { name: 'Export CSV, 0 devices' });
    assert.equal(button.getAttribute('aria-disabled'), 'true');
    assert.equal(button.hasAttribute('disabled'), false, 'stays focusable');
    assert.match(document.getElementById(button.getAttribute('aria-describedby') ?? '')?.textContent ?? '', /Nothing to export/);
    fireEvent.click(button);
    assert.equal(blobs.length, 0);
  });
});
