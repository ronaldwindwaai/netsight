import '@/test/dom-setup';

import assert from 'node:assert/strict';
import { afterEach, describe, it } from 'node:test';

import { cleanup, render, screen } from '@testing-library/react';

import { DiagnosticsRunner } from '@/components/diagnostics-runner';

afterEach(() => cleanup());

describe('free-text warning', () => {
  it('warns next to the target and symptom inputs not to paste secrets or personal data', () => {
    render(<DiagnosticsRunner />);
    const notice = screen.getByRole('note', { name: 'Free text warning' });
    assert.match(notice.textContent ?? '', /do not (paste|enter)/i);
    assert.match(notice.textContent ?? '', /secrets?|passwords?|tokens?/i);
    assert.match(notice.textContent ?? '', /personal data/i);
    assert.match(notice.textContent ?? '', /stored/i);
  });

  it('is announced with both free-text inputs', () => {
    render(<DiagnosticsRunner />);
    const notice = screen.getByRole('note', { name: 'Free text warning' });
    for (const label of ['Target', 'Symptom (optional)']) {
      const input = screen.getByLabelText(label);
      assert.ok(input.getAttribute('aria-describedby')?.split(' ').includes(notice.id), label);
    }
  });
});
