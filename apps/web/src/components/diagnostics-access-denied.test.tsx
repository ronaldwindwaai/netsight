import '@/test/dom-setup';

import assert from 'node:assert/strict';
import { afterEach, describe, it } from 'node:test';

import { cleanup, render, screen } from '@testing-library/react';

import { DiagnosticsAccessDenied } from '@/components/diagnostics-access-denied';

afterEach(() => cleanup());

describe('diagnostics access denied', () => {
  it('explains that the role has no diagnostics access and offers no form or run control', () => {
    const { container } = render(<DiagnosticsAccessDenied />);
    const status = screen.getByRole('status');
    assert.match(status.textContent ?? '', /not available to your role/i);
    assert.equal(container.querySelector('form, input, textarea, button'), null);
  });
});
