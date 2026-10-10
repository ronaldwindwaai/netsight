import '@/test/dom-setup';

import assert from 'node:assert/strict';
import { afterEach, beforeEach, describe, it, mock } from 'node:test';

import { act, cleanup, fireEvent, render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';

import { IncidentActionsPanel } from '@/components/incident-actions-panel';
import type { IncidentState } from '@/lib/api-contracts-incident';
import type { Viewer } from '@/lib/incident-actions';
import type { WriteActionResult } from '@/lib/write-result';
import { routerSpy } from '@/test/next-navigation-stub';
import { actionHandlers, resetActionHandlers } from '@/test/server-actions-stub';
import { FAILURES, VIEWERS, assertAbsent, assertFocus, deferred, failedWrite } from '@/test/helpers';

const INCIDENT_ID = 'incident-3f2b8a40-1c2d-4e5f-8a9b-0c1d2e3f4a5b';
const PATH = `/incidents/${INCIDENT_ID}`;

beforeEach(() => {
  routerSpy.reset();
  resetActionHandlers();
});
afterEach(() => cleanup());

function install(handler: (input: unknown) => Promise<WriteActionResult>) {
  const fn = mock.fn(handler);
  actionHandlers.incident = fn;
  return fn;
}

function renderPanel(
  viewer: Viewer | null,
  state: IncidentState = 'open',
  assignee: string | null = null,
) {
  return render(
    <IncidentActionsPanel
      incident={{ id: INCIDENT_ID, state, assignee_id: assignee }}
      viewer={viewer}
      currentPath={PATH}
    />,
  );
}

function button(name: string | RegExp): HTMLButtonElement {
  return screen.getByRole('button', { name }) as HTMLButtonElement;
}

function describedText(control: HTMLElement): string {
  const ids = (control.getAttribute('aria-describedby') ?? '').split(' ').filter(Boolean);
  return ids.map((id) => document.getElementById(id)?.textContent ?? '').join(' ');
}

describe('who can act', () => {
  it('technician on an incident not assigned to them: disabled with the assignment reason', () => {
    renderPanel(VIEWERS.technician, 'open', 'microsoft:someone-else');
    for (const name of [/^Acknowledge/, /^Comment/]) {
      const control = button(name);
      assert.equal(control.disabled, true, String(name));
      assert.match(describedText(control), /Technicians can only act on incidents assigned to you/);
    }
    assert.equal(button(/^Assign/).disabled, true);
    assert.match(describedText(button(/^Assign/)), /Your role does not permit this action/);
    assert.equal(button(/^Resolve/).disabled, true);
    assert.equal(button(/^Reopen/).disabled, true);
  });

  it('technician on an incident assigned to them may acknowledge and comment only', () => {
    renderPanel(VIEWERS.technician, 'open', VIEWERS.technician.identityId);
    assert.equal(button(/^Acknowledge/).disabled, false);
    assert.equal(button(/^Comment/).disabled, false);
    assert.equal(button(/^Assign/).disabled, true);
    assert.equal(button(/^Resolve/).disabled, true);
  });

  for (const role of ['management', 'auditor'] as const) {
    it(`${role} sees every control disabled, each with a reason`, () => {
      renderPanel(VIEWERS[role], 'mitigated', 'microsoft:someone');
      const controls = within(screen.getByRole('group', { name: 'Incident actions' })).getAllByRole(
        'button',
      ) as HTMLButtonElement[];
      assert.equal(controls.length, 6);
      for (const control of controls) {
        assert.equal(control.disabled, true, control.textContent ?? '');
        assert.match(describedText(control), /Your role does not permit this action/);
      }
    });
  }

  it('a signed-out viewer is told to sign in', () => {
    renderPanel(null);
    assert.equal(button(/^Acknowledge/).disabled, true);
    assert.match(describedText(button(/^Acknowledge/)), /Sign in to act on incidents/);
  });

  it('an administrator gets the controls that fit the incident state, others explain why not', () => {
    renderPanel(VIEWERS.administrator, 'open');
    assert.equal(button(/^Acknowledge/).disabled, false);
    assert.equal(button(/^Resolve/).disabled, true);
    assert.match(describedText(button(/^Resolve/)), /once it is mitigated/);
    assert.match(describedText(button(/^Reopen/)), /Only a resolved or closed incident/);
  });

  it('exposes disabled state through the disabled attribute alone and hides decorative icons', () => {
    const view = renderPanel(VIEWERS.administrator, 'mitigated');
    assert.equal(view.container.querySelectorAll('[aria-disabled]').length, 0);
    assert.equal(view.container.querySelectorAll('i[aria-label]').length, 0);
    for (const icon of Array.from(view.container.querySelectorAll('i'))) {
      assert.equal(icon.getAttribute('aria-hidden'), 'true');
    }
  });

  it('names the step-up requirement of resolve and reopen in text, not in an icon label', () => {
    renderPanel(VIEWERS.administrator, 'mitigated');
    assert.match(button(/^Resolve/).textContent ?? '', /needs recent multi-factor sign-in/);
    assert.match(button(/^Reopen/).textContent ?? '', /needs recent multi-factor sign-in/);
    assert.doesNotMatch(button(/^Acknowledge/).textContent ?? '', /multi-factor/);
  });
});

describe('one-click actions', () => {
  it('a double click sends exactly one request', async () => {
    const gate = deferred<WriteActionResult>();
    const handler = install(() => gate.promise);
    renderPanel(VIEWERS.administrator, 'open');
    const acknowledge = button(/^Acknowledge/);

    await act(async () => {
      fireEvent.click(acknowledge);
      fireEvent.click(acknowledge);
    });

    assert.equal(handler.mock.callCount(), 1);
    assert.deepEqual(handler.mock.calls[0].arguments[0], {
      action: 'acknowledge',
      incidentId: INCIDENT_ID,
    });
    await act(async () => gate.resolve({ ok: true }));
    assert.equal(routerSpy.refreshCount, 1);
    assert.match(screen.getByRole('status').textContent ?? '', /Acknowledge: saved/);
  });

  it('advances an acknowledged incident to investigating', async () => {
    const handler = install(() => Promise.resolve({ ok: true }));
    renderPanel(VIEWERS.administrator, 'acknowledged');
    await act(async () => fireEvent.click(button(/^Mark investigating/)));
    assert.deepEqual(handler.mock.calls[0].arguments[0], {
      action: 'progress',
      toState: 'investigating',
      incidentId: INCIDENT_ID,
    });
  });

  const cases: Array<[string, keyof typeof FAILURES, RegExp, 'link' | 'button' | 'none', string?]> = [
    ['409', 'conflict', /The record changed/, 'button'],
    ['422', 'invalid', /The request was not accepted/, 'none'],
    ['503', 'unavailable', /Storage unavailable/, 'none'],
    ['401', 'unauthenticated', /Sign in required/, 'link', `/login?next=${encodeURIComponent(PATH)}`],
    ['429', 'rateLimited', /Too many changes/, 'none'],
    [
      '403 STEP_UP_REQUIRED',
      'stepUp',
      /Recent multi-factor sign-in required/,
      'link',
      `/login?step_up=true&next=${encodeURIComponent(PATH)}`,
    ],
    ['403', 'forbidden', /Not permitted/, 'none'],
  ];
  for (const [label, key, title, action, href] of cases) {
    it(`${label} is explained next to the controls`, async () => {
      install(() => Promise.resolve(failedWrite(FAILURES[key].failure)));
      renderPanel(VIEWERS.administrator, 'open');
      await act(async () => fireEvent.click(button(/^Acknowledge/)));
      const alert = screen.getByRole('alert');
      assert.match(alert.textContent ?? '', title);
      assert.match(alert.textContent ?? '', /Reference:/);
      assert.equal(routerSpy.refreshCount, 0);
      const link = within(alert).queryByRole('link');
      if (action === 'link') assert.equal(link?.getAttribute('href'), href);
      else assertAbsent(link);
      const reload = within(alert).queryByRole('button', { name: /Reload current state/ });
      assert.equal(reload !== null, action === 'button');
    });
  }

  it('the step-up link is named "Sign in again"', async () => {
    install(() => Promise.resolve(failedWrite(FAILURES.stepUp.failure)));
    renderPanel(VIEWERS.administrator, 'open');
    await act(async () => fireEvent.click(button(/^Acknowledge/)));
    assert.ok(screen.getByRole('link', { name: /Sign in again/ }));
  });

  it('after an unconfirmed result no one-click action can be repeated until reload', async () => {
    const handler = install(() => Promise.resolve(failedWrite(FAILURES.unknownResult.failure)));
    renderPanel(VIEWERS.administrator, 'open');
    await act(async () => fireEvent.click(button(/^Acknowledge/)));
    assert.equal(button(/^Acknowledge/).disabled, true);
    await act(async () => fireEvent.click(button(/^Acknowledge/)));
    assert.equal(handler.mock.callCount(), 1);

    await act(async () => fireEvent.click(button(/Reload current state/)));
    assert.equal(routerSpy.refreshCount, 1);
    assert.equal(button(/^Acknowledge/).disabled, false);
  });
});

describe('comment dialog', () => {
  async function openComment() {
    const user = userEvent.setup();
    await user.click(button(/^Comment/));
    return user;
  }

  it('opens as a dialog with focus on the comment field', async () => {
    renderPanel(VIEWERS.administrator, 'open');
    await openComment();
    assert.ok(screen.getByRole('dialog', { name: 'Add a comment' }));
    assertFocus(screen.getByLabelText('Comment'));
  });

  it('submitting twice in the same tick sends one request carrying the text', async () => {
    const gate = deferred<WriteActionResult>();
    const handler = install(() => gate.promise);
    renderPanel(VIEWERS.administrator, 'open');
    const user = await openComment();
    await user.type(screen.getByLabelText('Comment'), 'Rebooted the uplink');
    const form = screen.getByRole('dialog').querySelector('form') as HTMLFormElement;

    await act(async () => {
      fireEvent.submit(form);
      fireEvent.submit(form);
    });

    assert.equal(handler.mock.callCount(), 1);
    assert.deepEqual(handler.mock.calls[0].arguments[0], {
      action: 'comment',
      message: 'Rebooted the uplink',
      incidentId: INCIDENT_ID,
    });
    await act(async () => gate.resolve({ ok: true }));
    assertAbsent(screen.queryByRole('dialog'));
    assert.match(screen.getByRole('status').textContent ?? '', /Comment: saved/);
  });

  it('cannot be dismissed while the request is in flight, and says it is working', async () => {
    const gate = deferred<WriteActionResult>();
    install(() => gate.promise);
    renderPanel(VIEWERS.administrator, 'open');
    const user = await openComment();
    await user.type(screen.getByLabelText('Comment'), 'x');
    await act(async () => {
      fireEvent.submit(screen.getByRole('dialog').querySelector('form') as HTMLFormElement);
    });

    assert.equal((within(screen.getByRole('dialog')).getByRole('button', { name: 'Close' }) as HTMLButtonElement).disabled, true);
    assert.equal((within(screen.getByRole('dialog')).getByRole('button', { name: 'Cancel' }) as HTMLButtonElement).disabled, true);
    assert.ok(within(screen.getByRole('dialog')).getByRole('button', { name: 'Working…' }));
    await user.keyboard('{Escape}');
    assert.ok(screen.getByRole('dialog'));

    await act(async () => gate.resolve({ ok: true }));
    assertAbsent(screen.queryByRole('dialog'));
  });

  it('closes on Escape and on Cancel when idle, returning focus to the Comment button', async () => {
    renderPanel(VIEWERS.administrator, 'open');
    const user = await openComment();
    await user.keyboard('{Escape}');
    assertAbsent(screen.queryByRole('dialog'));
    assertFocus(button(/^Comment/));

    await user.click(button(/^Comment/));
    await user.click(screen.getByRole('button', { name: 'Cancel' }));
    assertAbsent(screen.queryByRole('dialog'));
  });

  it('keeps the dialog and the typed text on a 422, and explains it inside the dialog', async () => {
    install(() => Promise.resolve(failedWrite(FAILURES.invalid.failure)));
    renderPanel(VIEWERS.administrator, 'open');
    const user = await openComment();
    await user.type(screen.getByLabelText('Comment'), 'keep me');
    await user.click(screen.getByRole('button', { name: 'Add comment' }));
    const dialog = screen.getByRole('dialog');
    assert.match(within(dialog).getByRole('alert').textContent ?? '', /The request was not accepted/);
    assert.equal((screen.getByLabelText('Comment') as HTMLTextAreaElement).value, 'keep me');
    assert.equal(routerSpy.refreshCount, 0);
  });

  it('cannot be submitted a second time after an unconfirmed result', async () => {
    const handler = install(() => Promise.resolve(failedWrite(FAILURES.unknownResult.failure)));
    renderPanel(VIEWERS.administrator, 'open');
    const user = await openComment();
    await user.type(screen.getByLabelText('Comment'), 'maybe sent');
    const form = screen.getByRole('dialog').querySelector('form') as HTMLFormElement;
    await act(async () => {
      fireEvent.submit(form);
    });
    assert.match(within(screen.getByRole('dialog')).getByRole('alert').textContent ?? '', /may or may not have been applied/);
    const submit = screen.getByRole('button', { name: 'Add comment' }) as HTMLButtonElement;
    assert.equal(submit.disabled, true);
    await act(async () => {
      fireEvent.submit(form);
    });
    assert.equal(handler.mock.callCount(), 1);

    await user.click(screen.getByRole('button', { name: /Reload current state/ }));
    assert.equal(routerSpy.refreshCount, 1);
    assert.equal((screen.getByRole('button', { name: 'Add comment' }) as HTMLButtonElement).disabled, false);
  });

  it('closing the dialog after an unconfirmed result does not lift the lock', async () => {
    const handler = install(() => Promise.resolve(failedWrite(FAILURES.unknownResult.failure)));
    renderPanel(VIEWERS.administrator, 'open');
    const user = await openComment();
    await user.type(screen.getByLabelText('Comment'), 'maybe sent');
    await user.click(screen.getByRole('button', { name: 'Add comment' }));
    await user.keyboard('{Escape}');
    assertAbsent(screen.queryByRole('dialog'));
    assert.equal(button(/^Comment/).disabled, true);
    assert.equal(handler.mock.callCount(), 1);
  });

  it('shows the step-up link inside the dialog when recent multi-factor sign-in is missing', async () => {
    install(() => Promise.resolve(failedWrite(FAILURES.stepUp.failure)));
    renderPanel(VIEWERS.administrator, 'open');
    const user = await openComment();
    await user.type(screen.getByLabelText('Comment'), 'x');
    await user.click(screen.getByRole('button', { name: 'Add comment' }));
    const link = within(screen.getByRole('dialog')).getByRole('link', { name: /Sign in again/ });
    assert.equal(link.getAttribute('href'), `/login?step_up=true&next=${encodeURIComponent(PATH)}`);
  });
});

describe('resolve and reopen dialogs', () => {
  it('resolve focuses the summary and sends every field, with a not-determined root cause by default', async () => {
    const handler = install(() => Promise.resolve({ ok: true }));
    renderPanel(VIEWERS.administrator, 'mitigated');
    const user = userEvent.setup();
    await user.click(button(/^Resolve/));
    assertFocus(screen.getByLabelText('Resolution summary'));

    await user.type(screen.getByLabelText('Resolution summary'), 'Replaced the optic');
    await user.type(screen.getByLabelText('Impact'), 'Floor 2 offline for 10 minutes');
    fireEvent.change(screen.getByLabelText(/Service restored at/), { target: { value: '2026-10-10T10:00' } });
    await user.click(screen.getByRole('button', { name: 'Resolve incident' }));

    assert.equal(handler.mock.callCount(), 1);
    assert.deepEqual(handler.mock.calls[0].arguments[0], {
      action: 'resolve',
      summary: 'Replaced the optic',
      rootCauseStatus: 'not-determined',
      rootCause: '',
      impact: 'Floor 2 offline for 10 minutes',
      restoredAt: '2026-10-10T10:00',
      followUps: '',
      incidentId: INCIDENT_ID,
    });
  });

  it('resolve requires the accepted root cause only when it is marked determined', async () => {
    renderPanel(VIEWERS.administrator, 'mitigated');
    const user = userEvent.setup();
    await user.click(button(/^Resolve/));
    const cause = screen.getByLabelText('Accepted root cause') as HTMLTextAreaElement;
    assert.equal(cause.disabled, true);
    await user.click(screen.getByLabelText('Determined'));
    assert.equal(cause.disabled, false);
    assert.equal(cause.required, true);
  });

  it('resolve without a recent second factor offers "Sign in again" and keeps the form', async () => {
    install(() => Promise.resolve(failedWrite(FAILURES.stepUp.failure)));
    renderPanel(VIEWERS.administrator, 'mitigated');
    const user = userEvent.setup();
    await user.click(button(/^Resolve/));
    await user.type(screen.getByLabelText('Resolution summary'), 'Fixed');
    await user.type(screen.getByLabelText('Impact'), 'None');
    fireEvent.change(screen.getByLabelText(/Service restored at/), { target: { value: '2026-10-10T10:00' } });
    await user.click(screen.getByRole('button', { name: 'Resolve incident' }));
    const dialog = screen.getByRole('dialog');
    assert.ok(within(dialog).getByRole('link', { name: /Sign in again/ }));
    assert.equal((within(dialog).getByLabelText('Resolution summary') as HTMLTextAreaElement).value, 'Fixed');
  });

  it('reopen sends the reason', async () => {
    const handler = install(() => Promise.resolve({ ok: true }));
    renderPanel(VIEWERS.administrator, 'resolved');
    const user = userEvent.setup();
    await user.click(button(/^Reopen/));
    assertFocus(screen.getByLabelText('Reason for reopening'));
    await user.type(screen.getByLabelText('Reason for reopening'), 'Flapping again');
    await user.click(screen.getByRole('button', { name: 'Reopen incident' }));
    assert.deepEqual(handler.mock.calls[0].arguments[0], {
      action: 'reopen',
      reason: 'Flapping again',
      incidentId: INCIDENT_ID,
    });
  });

  it('assign offers Unassign only when someone is assigned and sends a null assignee', async () => {
    const handler = install(() => Promise.resolve({ ok: true }));
    renderPanel(VIEWERS.administrator, 'open', 'microsoft:alice');
    const user = userEvent.setup();
    await user.click(button(/^Assign/));
    assertFocus(screen.getByLabelText('Assignee identity'));
    await user.click(screen.getByRole('button', { name: 'Unassign' }));
    assert.deepEqual(handler.mock.calls[0].arguments[0], {
      action: 'assign',
      assigneeId: null,
      incidentId: INCIDENT_ID,
    });
  });

  it('assign has no Unassign control on an unassigned incident', async () => {
    renderPanel(VIEWERS.administrator, 'open', null);
    await userEvent.setup().click(button(/^Assign/));
    assertAbsent(screen.queryByRole('button', { name: 'Unassign' }));
  });

  it('the dialog traps Tab: from the last control it returns to the first', async () => {
    renderPanel(VIEWERS.administrator, 'open');
    const user = userEvent.setup();
    await user.click(button(/^Comment/));
    const dialog = screen.getByRole('dialog');
    within(dialog).getByRole('button', { name: 'Add comment' }).focus();
    await user.tab();
    assertFocus(within(dialog).getByRole('button', { name: 'Close' }));
  });
});
