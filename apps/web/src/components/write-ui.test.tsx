import '@/test/dom-setup';

import assert from 'node:assert/strict';
import { afterEach, beforeEach, describe, it, mock } from 'node:test';

import { act, cleanup, fireEvent, render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';

import { ActionDialog, WriteFeedback, useServerWrite } from '@/components/write-ui';
import type { ServerWrite } from '@/components/write-ui';
import { routerSpy } from '@/test/next-navigation-stub';
import { CORRELATION, FAILURES, assertAbsent, assertFocus, deferred, failedWrite } from '@/test/helpers';
import type { WriteActionResult } from '@/lib/write-result';

const PATH = '/incidents/incident-1';

beforeEach(() => routerSpy.reset());
afterEach(() => cleanup());

function Harness({ perform, label = 'Go' }: { perform: ServerWrite; label?: string }) {
  const runner = useServerWrite(perform);
  return (
    <div>
      <button type="button" onClick={() => void runner.submit({ value: 1 })}>
        {label}
      </button>
      <output data-testid="state">
        {runner.pending ? 'pending' : 'idle'}|{runner.unconfirmed ? 'unconfirmed' : 'confirmed'}
      </output>
      <WriteFeedback result={runner.result} currentPath={PATH} onReload={runner.reload} />
    </div>
  );
}

describe('useServerWrite', () => {
  it('sends one request when the control is activated twice in the same tick', async () => {
    const gate = deferred<WriteActionResult>();
    const perform = mock.fn(() => gate.promise);
    render(<Harness perform={perform} />);
    const button = screen.getByRole('button', { name: 'Go' });

    await act(async () => {
      fireEvent.click(button);
      fireEvent.click(button);
    });

    assert.equal(perform.mock.callCount(), 1);
    assert.equal(screen.getByTestId('state').textContent, 'pending|confirmed');
    await act(async () => gate.resolve({ ok: true }));
    assert.equal(screen.getByTestId('state').textContent, 'idle|confirmed');
  });

  it('allows another request once the first has finished', async () => {
    const perform = mock.fn(() => Promise.resolve<WriteActionResult>({ ok: true }));
    render(<Harness perform={perform} />);
    const button = screen.getByRole('button', { name: 'Go' });
    await act(async () => fireEvent.click(button));
    await act(async () => fireEvent.click(button));
    assert.equal(perform.mock.callCount(), 2);
  });

  it('refreshes the page once after an accepted write and not after a refused one', async () => {
    const ok = mock.fn(() => Promise.resolve<WriteActionResult>({ ok: true }));
    const view = render(<Harness perform={ok} />);
    await act(async () => fireEvent.click(screen.getByRole('button', { name: 'Go' })));
    assert.equal(routerSpy.refreshCount, 1);
    view.unmount();

    const refused = mock.fn(() => Promise.resolve(failedWrite(FAILURES.conflict.failure)));
    render(<Harness perform={refused} />);
    await act(async () => fireEvent.click(screen.getByRole('button', { name: 'Go' })));
    assert.equal(routerSpy.refreshCount, 1);
  });

  it('does not lock after a definite refusal, so the operator can correct and resend', async () => {
    const perform = mock.fn(() => Promise.resolve(failedWrite(FAILURES.invalid.failure)));
    render(<Harness perform={perform} />);
    const button = screen.getByRole('button', { name: 'Go' });
    await act(async () => fireEvent.click(button));
    await act(async () => fireEvent.click(button));
    assert.equal(perform.mock.callCount(), 2);
    assert.equal(screen.getByTestId('state').textContent, 'idle|confirmed');
  });

  it('refuses a second send after an unknown result until the page is reloaded', async () => {
    const perform = mock.fn(() => Promise.resolve(failedWrite(FAILURES.unknownResult.failure)));
    render(<Harness perform={perform} />);
    const button = screen.getByRole('button', { name: 'Go' });

    await act(async () => fireEvent.click(button));
    assert.equal(screen.getByTestId('state').textContent, 'idle|unconfirmed');
    await act(async () => fireEvent.click(button));
    await act(async () => fireEvent.click(button));
    assert.equal(perform.mock.callCount(), 1);

    await act(async () => fireEvent.click(screen.getByRole('button', { name: /Reload current state/ })));
    assert.equal(routerSpy.refreshCount, 1);
    assert.equal(screen.getByTestId('state').textContent, 'idle|confirmed');
    await act(async () => fireEvent.click(button));
    assert.equal(perform.mock.callCount(), 2);
  });

  it('treats a thrown server action as an unknown result and locks', async () => {
    const perform = mock.fn(() => Promise.reject(new Error('socket hang up')));
    render(<Harness perform={perform} />);
    const button = screen.getByRole('button', { name: 'Go' });
    await act(async () => fireEvent.click(button));
    assert.match(screen.getByRole('alert').textContent ?? '', /Result could not be confirmed/);
    assert.equal(screen.getByTestId('state').textContent, 'idle|unconfirmed');
    await act(async () => fireEvent.click(button));
    assert.equal(perform.mock.callCount(), 1);
  });
});

describe('WriteFeedback', () => {
  function feedback(result: WriteActionResult | null) {
    return render(<WriteFeedback result={result} currentPath={PATH} />);
  }

  it('renders nothing before a result or after success', () => {
    const view = feedback(null);
    assert.equal(view.container.textContent, '');
    view.unmount();
    assert.equal(feedback({ ok: true }).container.textContent, '');
  });

  it('shows the message of an input that never left the server as a warning', () => {
    feedback({ ok: false, kind: 'rejected', message: 'The comment was empty.' });
    assert.equal(screen.getByRole('alert').textContent, 'The comment was empty.');
  });

  it('409 conflict: says nothing changed and offers a reload that refreshes the page', async () => {
    feedback(failedWrite(FAILURES.conflict.failure));
    const alert = screen.getByRole('alert');
    assert.match(alert.textContent ?? '', /The record changed/);
    assert.match(alert.textContent ?? '', /Incident moved on\./);
    assert.match(alert.textContent ?? '', /Nothing was changed/);
    assert.match(alert.textContent ?? '', new RegExp(CORRELATION));
    await userEvent.setup().click(screen.getByRole('button', { name: /Reload current state/ }));
    assert.equal(routerSpy.refreshCount, 1);
    assertAbsent(screen.queryByRole('link'));
  });

  it('422 validation: tells the operator to correct the form and offers no navigation', () => {
    feedback(failedWrite(FAILURES.invalid.failure));
    const alert = screen.getByRole('alert');
    assert.match(alert.textContent ?? '', /The request was not accepted/);
    assert.match(alert.textContent ?? '', /Summary is too long\./);
    assert.match(alert.textContent ?? '', /Correct the form and try again/);
    assertAbsent(screen.queryByRole('link'));
    assertAbsent(screen.queryByRole('button'));
  });

  it('503 store unavailable: says to try later and offers no navigation', () => {
    feedback(failedWrite(FAILURES.unavailable.failure));
    const alert = screen.getByRole('alert');
    assert.match(alert.textContent ?? '', /Storage unavailable/);
    assert.match(alert.textContent ?? '', /Try again later/);
    assertAbsent(screen.queryByRole('link'));
    assertAbsent(screen.queryByRole('button'));
  });

  it('401: links to sign in and returns to the current page', () => {
    feedback(failedWrite(FAILURES.unauthenticated.failure));
    assert.match(screen.getByRole('alert').textContent ?? '', /Sign in required/);
    const link = screen.getByRole('link', { name: /Sign in/ });
    assert.equal(link.getAttribute('href'), '/login?next=%2Fincidents%2Fincident-1');
  });

  it('429: says to wait, no link', () => {
    feedback(failedWrite(FAILURES.rateLimited.failure));
    const alert = screen.getByRole('alert');
    assert.match(alert.textContent ?? '', /Too many changes/);
    assert.match(alert.textContent ?? '', /Wait a minute/);
    assertAbsent(screen.queryByRole('link'));
  });

  it('403 STEP_UP_REQUIRED: offers "Sign in again" back to this page, and warns about lost input', () => {
    feedback(failedWrite(FAILURES.stepUp.failure));
    const alert = screen.getByRole('alert');
    assert.match(alert.textContent ?? '', /Recent multi-factor sign-in required/);
    const link = screen.getByRole('link', { name: /Sign in again/ });
    assert.equal(link.getAttribute('href'), '/login?step_up=true&next=%2Fincidents%2Fincident-1');
    assert.match(alert.textContent ?? '', /discards what you have typed/);
  });

  it('403 without the step-up code is a plain refusal with no sign-in link', () => {
    feedback(failedWrite(FAILURES.forbidden.failure));
    const alert = screen.getByRole('alert');
    assert.match(alert.textContent ?? '', /Not permitted/);
    assertAbsent(screen.queryByRole('link'));
    assert.doesNotMatch(alert.textContent ?? '', /Sign in again/);
  });

  it('status unknown: says the change may have been applied and to reload before repeating', () => {
    feedback(failedWrite(FAILURES.unknownResult.failure));
    const alert = screen.getByRole('alert');
    assert.match(alert.textContent ?? '', /may or may not have been applied/);
    assert.ok(screen.getByRole('button', { name: /Reload current state/ }));
  });

  it('marks decorative icons as hidden from assistive technology', () => {
    const view = feedback(failedWrite(FAILURES.stepUp.failure));
    const icons = Array.from(view.container.querySelectorAll('i'));
    assert.ok(icons.length > 0);
    for (const icon of icons) {
      assert.equal(icon.getAttribute('aria-hidden'), 'true');
      assert.equal(icon.getAttribute('aria-label'), null);
    }
  });
});

describe('ActionDialog', () => {
  function Dialog({
    onClose,
    busy = false,
    withField = true,
  }: {
    onClose: () => void;
    busy?: boolean;
    withField?: boolean;
  }) {
    return (
      <ActionDialog title="Add a comment" onClose={onClose} busy={busy}>
        {withField ? <textarea aria-label="Comment" /> : <p>Nothing to type here.</p>}
        <button type="button">Submit</button>
      </ActionDialog>
    );
  }

  function Opener({ onClose }: { onClose: () => void }) {
    return (
      <>
        <button type="button">Opener</button>
        <Dialog onClose={onClose} />
      </>
    );
  }

  it('is a modal dialog labelled by its title', () => {
    render(<Dialog onClose={() => {}} />);
    const dialog = screen.getByRole('dialog', { name: 'Add a comment' });
    assert.equal(dialog.getAttribute('aria-modal'), 'true');
    assert.ok(document.body.classList.contains('modal-open'));
  });

  it('moves focus to the first form field when it opens', () => {
    render(<Dialog onClose={() => {}} />);
    assertFocus(screen.getByLabelText('Comment'));
  });

  it('focuses the dialog itself when it has no form field', () => {
    render(<Dialog onClose={() => {}} withField={false} />);
    assertFocus(screen.getByRole('dialog'));
  });

  it('returns focus to the control that opened it, and releases the page, when it closes', () => {
    const view = render(<Opener onClose={() => {}} />);
    view.unmount();
    const opener = render(<button type="button">Opener</button>);
    const trigger = screen.getByRole('button', { name: 'Opener' });
    trigger.focus();
    const dialog = render(<Dialog onClose={() => {}} />);
    assert.ok(document.activeElement !== trigger);
    dialog.unmount();
    assertFocus(trigger);
    assert.equal(document.body.classList.contains('modal-open'), false);
    opener.unmount();
  });

  it('closes on Escape when idle', async () => {
    const onClose = mock.fn();
    render(<Dialog onClose={onClose} />);
    await userEvent.setup().keyboard('{Escape}');
    assert.equal(onClose.mock.callCount(), 1);
  });

  it('does not close on Escape or on the close button while a request is in flight', async () => {
    const onClose = mock.fn();
    render(<Dialog onClose={onClose} busy />);
    const user = userEvent.setup();
    await user.keyboard('{Escape}');
    const close = screen.getByRole('button', { name: 'Close' }) as HTMLButtonElement;
    assert.equal(close.disabled, true);
    await user.click(close);
    assert.equal(onClose.mock.callCount(), 0);
  });

  it('keeps Tab inside the dialog, wrapping from the last control to the first', async () => {
    render(<Dialog onClose={() => {}} />);
    const user = userEvent.setup();
    const close = screen.getByRole('button', { name: 'Close' });
    const submit = screen.getByRole('button', { name: 'Submit' });
    submit.focus();
    await user.tab();
    assertFocus(close);
  });

  it('keeps Shift+Tab inside the dialog, wrapping from the first control to the last', async () => {
    render(<Dialog onClose={() => {}} />);
    const user = userEvent.setup();
    const close = screen.getByRole('button', { name: 'Close' });
    close.focus();
    await user.tab({ shift: true });
    assertFocus(screen.getByRole('button', { name: 'Submit' }));
  });

  it('keeps focus on the dialog when nothing inside is focusable', async () => {
    render(
      <ActionDialog title="Busy" onClose={() => {}} busy>
        <p>Working</p>
      </ActionDialog>,
    );
    const user = userEvent.setup();
    await user.tab();
    const dialog = screen.getByRole('dialog');
    assert.ok(dialog.contains(document.activeElement));
  });
});
