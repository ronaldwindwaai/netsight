import '@/test/dom-setup';

import assert from 'node:assert/strict';
import { afterEach, beforeEach, describe, it, mock } from 'node:test';

import { act, cleanup, fireEvent, render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';

import { UnknownDeviceActionsPanel } from '@/components/unknown-device-actions-panel';
import { UnknownDeviceScanPanel } from '@/components/unknown-device-scan-panel';
import { parseUnknownDeviceScan, type FindingState } from '@/lib/api-contracts-unknown-devices';
import type { Viewer } from '@/lib/incident-actions';
import type { WriteActionResult } from '@/lib/write-result';
import { routerSpy } from '@/test/next-navigation-stub';
import { FAILURES, assertAbsent, deferred, failedWrite } from '@/test/helpers';
import { FINDING_ID, HOSTILE, NOW, sources } from '@/test/step8-fixtures';
import { findingHandlers } from '@/test/unknown-device-actions-stub';

const PATH = `/unknown-devices/${FINDING_ID}`;

const ANALYST: Viewer = {
  identityId: 'oidc:analyst-1',
  permissions: [
    'unknown-devices:read',
    'unknown-devices:acknowledge',
    'unknown-devices:assign',
    'unknown-devices:comment',
    'unknown-devices:resolve',
    'unknown-devices:scan',
  ],
};
const AUDITOR: Viewer = { identityId: 'oidc:auditor', permissions: ['unknown-devices:read'] };

beforeEach(() => {
  routerSpy.reset();
  findingHandlers.finding = () => {
    throw new Error('No finding action handler installed for this test');
  };
});
afterEach(() => cleanup());

function install(handler: (input: unknown) => Promise<WriteActionResult>) {
  const fn = mock.fn(handler);
  findingHandlers.finding = fn;
  return fn;
}

function renderPanel(viewer: Viewer | null, state: FindingState = 'new', assignee: string | null = null) {
  return render(
    <UnknownDeviceActionsPanel
      finding={{ id: FINDING_ID, state, assignee_id: assignee }}
      viewer={viewer}
      currentPath={PATH}
    />,
  );
}

const button = (name: string | RegExp) => screen.getByRole('button', { name }) as HTMLButtonElement;

function describedText(control: HTMLElement): string {
  const ids = (control.getAttribute('aria-describedby') ?? '').split(' ').filter(Boolean);
  return ids.map((id) => document.getElementById(id)?.textContent ?? '').join(' ');
}

describe('who can act', () => {
  it('a read-only role sees every control disabled, each with a reason', () => {
    renderPanel(AUDITOR);
    const controls = within(screen.getByRole('group', { name: 'Finding actions' })).getAllByRole('button') as HTMLButtonElement[];
    assert.equal(controls.length, 5);
    for (const control of controls) {
      assert.equal(control.disabled, true);
      assert.match(describedText(control), /Your role does not permit this action/);
    }
  });

  it('a signed-out viewer is told to sign in', () => {
    renderPanel(null);
    assert.match(describedText(button(/^Acknowledge/)), /Sign in to act on findings/);
  });

  it('an analyst gets the controls that fit the state and the others explain why not', () => {
    renderPanel(ANALYST, 'new');
    assert.equal(button(/^Acknowledge/).disabled, false);
    assert.equal(button(/^Comment/).disabled, false);
    assert.equal(button(/^Resolve or dismiss/).disabled, false);
    assert.equal(button(/^Mark investigating/).disabled, true);
    assert.match(describedText(button(/^Mark investigating/)), /must be acknowledged before/);
  });

  it('a finished finding cannot be resolved again or reassigned but can be commented on', () => {
    renderPanel(ANALYST, 'resolved');
    assert.equal(button(/^Resolve or dismiss/).disabled, true);
    assert.equal(button(/^Assign/).disabled, true);
    assert.equal(button(/^Comment/).disabled, false);
  });

  it('names the step-up requirement of resolving in text and offers no isolate control', () => {
    const view = renderPanel(ANALYST);
    assert.match(button(/^Resolve or dismiss/).textContent ?? '', /needs recent multi-factor sign-in/);
    assert.equal(screen.queryAllByRole('button', { name: /isolate|quarantine/i }).length, 0);
    for (const icon of Array.from(view.container.querySelectorAll('i'))) {
      assert.equal(icon.getAttribute('aria-hidden'), 'true');
    }
  });
});

describe('one-click actions', () => {
  it('a double click sends exactly one request and refreshes once', async () => {
    const gate = deferred<WriteActionResult>();
    const handler = install(() => gate.promise);
    renderPanel(ANALYST);
    const acknowledge = button(/^Acknowledge/);
    await act(async () => {
      fireEvent.click(acknowledge);
      fireEvent.click(acknowledge);
    });
    assert.equal(handler.mock.callCount(), 1);
    assert.deepEqual(handler.mock.calls[0].arguments[0], { action: 'acknowledge', findingId: FINDING_ID });
    await act(async () => gate.resolve({ ok: true }));
    assert.equal(routerSpy.refreshCount, 1);
    assert.match(screen.getByRole('status').textContent ?? '', /Acknowledge: saved/);
  });

  it('marks an acknowledged finding as investigating', async () => {
    const handler = install(() => Promise.resolve({ ok: true }));
    renderPanel(ANALYST, 'acknowledged');
    await act(async () => fireEvent.click(button(/^Mark investigating/)));
    assert.deepEqual(handler.mock.calls[0].arguments[0], { action: 'investigate', findingId: FINDING_ID });
  });

  const cases: Array<[string, keyof typeof FAILURES, RegExp, 'link' | 'button' | 'none', string?]> = [
    ['409', 'conflict', /The record changed/, 'button'],
    ['422', 'invalid', /The request was not accepted/, 'none'],
    ['503', 'unavailable', /Storage unavailable/, 'none'],
    ['401', 'unauthenticated', /Sign in required/, 'link', `/login?next=${encodeURIComponent(PATH)}`],
    ['429', 'rateLimited', /Too many changes/, 'none'],
    ['403 STEP_UP_REQUIRED', 'stepUp', /Recent multi-factor sign-in required/, 'link', `/login?step_up=true&next=${encodeURIComponent(PATH)}`],
    ['403', 'forbidden', /Not permitted/, 'none'],
  ];
  for (const [label, key, title, action, href] of cases) {
    it(`${label} is explained next to the controls`, async () => {
      install(() => Promise.resolve(failedWrite(FAILURES[key].failure)));
      renderPanel(ANALYST);
      await act(async () => fireEvent.click(button(/^Acknowledge/)));
      const alert = screen.getByRole('alert');
      assert.match(alert.textContent ?? '', title);
      assert.equal(routerSpy.refreshCount, 0);
      const link = within(alert).queryByRole('link');
      if (action === 'link') assert.equal(link?.getAttribute('href'), href);
      else assertAbsent(link);
      assert.equal(within(alert).queryByRole('button', { name: /Reload current state/ }) !== null, action === 'button');
    });
  }

  it('after an unconfirmed result nothing is sent again until the page is reloaded', async () => {
    const handler = install(() => Promise.resolve(failedWrite(FAILURES.unknownResult.failure)));
    renderPanel(ANALYST);
    await act(async () => fireEvent.click(button(/^Acknowledge/)));
    assert.equal(button(/^Acknowledge/).disabled, true);
    await act(async () => fireEvent.click(button(/^Acknowledge/)));
    assert.equal(handler.mock.callCount(), 1);
    await act(async () => fireEvent.click(screen.getByRole('button', { name: /Reload current state/ })));
    assert.equal(routerSpy.refreshCount, 1);
    assert.equal(button(/^Acknowledge/).disabled, false);
  });
});

describe('dialogs', () => {
  it('assigns by identity and sends it with the finding id', async () => {
    const handler = install(() => Promise.resolve({ ok: true }));
    const user = userEvent.setup();
    renderPanel(ANALYST);
    await user.click(button(/^Assign/));
    const dialog = screen.getByRole('dialog', { name: 'Assign finding' });
    await user.type(within(dialog).getByLabelText('Assignee identity'), 'oidc:tech-9');
    await user.click(within(dialog).getByRole('button', { name: 'Assign' }));
    assert.deepEqual(handler.mock.calls[0].arguments[0], { action: 'assign', assigneeId: 'oidc:tech-9', findingId: FINDING_ID });
    assert.equal(screen.queryAllByRole('dialog').length, 0);
    assert.match(screen.getByRole('status').textContent ?? '', /Assign: saved/);
  });

  it('unassigns an assigned finding', async () => {
    const handler = install(() => Promise.resolve({ ok: true }));
    const user = userEvent.setup();
    renderPanel(ANALYST, 'new', 'oidc:tech-9');
    await user.click(button(/^Assign/));
    await user.click(screen.getByRole('button', { name: 'Unassign' }));
    assert.deepEqual(handler.mock.calls[0].arguments[0], { action: 'assign', assigneeId: null, findingId: FINDING_ID });
  });

  it('keeps a hostile comment as typed text and sends it unmodified', async () => {
    const handler = install(() => Promise.resolve({ ok: true }));
    const user = userEvent.setup();
    renderPanel(ANALYST);
    await user.click(button(/^Comment/));
    const dialog = screen.getByRole('dialog', { name: 'Add a comment' });
    await user.click(within(dialog).getByLabelText('Comment'));
    await user.paste(HOSTILE);
    await user.click(within(dialog).getByRole('button', { name: 'Add comment' }));
    assert.deepEqual(handler.mock.calls[0].arguments[0], { action: 'comment', message: HOSTILE, findingId: FINDING_ID });
  });

  it('resolves with a chosen outcome and a reason, and defaults to resolved', async () => {
    const handler = install(() => Promise.resolve({ ok: true }));
    const user = userEvent.setup();
    renderPanel(ANALYST);
    await user.click(button(/^Resolve or dismiss/));
    const dialog = screen.getByRole('dialog', { name: 'Resolve or dismiss finding' });
    assert.equal((within(dialog).getByLabelText(/^Resolved/) as HTMLInputElement).checked, true);
    await user.click(within(dialog).getByLabelText(/^False positive/));
    await user.type(within(dialog).getByLabelText('Reason'), 'It is the reception printer');
    await user.click(within(dialog).getByRole('button', { name: 'Finish finding' }));
    assert.deepEqual(handler.mock.calls[0].arguments[0], {
      action: 'resolve',
      outcome: 'false-positive',
      reason: 'It is the reception printer',
      findingId: FINDING_ID,
    });
  });

  it('a step-up refusal inside the dialog keeps it open with the sign-in link', async () => {
    install(() => Promise.resolve(failedWrite(FAILURES.stepUp.failure)));
    const user = userEvent.setup();
    renderPanel(ANALYST);
    await user.click(button(/^Resolve or dismiss/));
    const dialog = screen.getByRole('dialog');
    await user.type(within(dialog).getByLabelText('Reason'), 'done');
    await user.click(within(dialog).getByRole('button', { name: 'Finish finding' }));
    assert.ok(screen.getByRole('dialog'));
    assert.ok(within(screen.getByRole('dialog')).getByRole('link', { name: /Sign in again/ }));
  });

  it('Escape closes an idle dialog without sending anything', async () => {
    const handler = install(() => Promise.resolve({ ok: true }));
    const user = userEvent.setup();
    renderPanel(ANALYST);
    await user.click(button(/^Comment/));
    await user.keyboard('{Escape}');
    assert.equal(screen.queryAllByRole('dialog').length, 0);
    assert.equal(handler.mock.callCount(), 0);
  });
});

describe('scan panel', () => {
  const scan = (over: Record<string, unknown> = {}) => {
    const parsed = parseUnknownDeviceScan({
      state: 'ok',
      generated_at: NOW,
      sources: sources.wazuhNotConnected,
      created: 2,
      refreshed: 1,
      suppressed: 3,
      unverified: 0,
      truncated: false,
      ...over,
    });
    assert.ok(parsed, 'scan fixture');
    return parsed;
  };

  it('runs once per click, refreshes and reports the counts', async () => {
    const gate = deferred<{ ok: true; scan: ReturnType<typeof scan> }>();
    const handler = mock.fn(() => gate.promise);
    findingHandlers.scan = handler as never;
    render(<UnknownDeviceScanPanel />);
    const control = screen.getByRole('button', { name: /Scan for unknown devices now/ });
    await act(async () => {
      fireEvent.click(control);
      fireEvent.click(control);
    });
    assert.equal(handler.mock.callCount(), 1);
    assert.equal((screen.getByRole('button', { name: /Scanning/ }) as HTMLButtonElement).disabled, true);
    await act(async () => gate.resolve({ ok: true, scan: scan() }));
    assert.match(screen.getAllByRole('status')[0].textContent ?? '', /2 new, 1 refreshed, 3 suppressed, 0 not verified/);
    assert.equal(routerSpy.refreshCount, 1);
  });

  it('says what an unverified or truncated scan means', async () => {
    findingHandlers.scan = (() => Promise.resolve({ ok: true, scan: scan({ unverified: 4, truncated: true }) })) as never;
    render(<UnknownDeviceScanPanel />);
    await act(async () => fireEvent.click(screen.getByRole('button', { name: /Scan for unknown devices now/ })));
    const text = document.body.textContent ?? '';
    assert.match(text, /could not be checked against NetBox are not reported/);
    assert.match(text, /reached its size limit/);
  });

  it('shows a refusal with its reference and does not refresh', async () => {
    findingHandlers.scan = (() =>
      Promise.resolve({ ok: false, title: 'Too many changes', message: 'Wait a minute.', correlationId: 'corr-9' })) as never;
    render(<UnknownDeviceScanPanel />);
    await act(async () => fireEvent.click(screen.getByRole('button', { name: /Scan for unknown devices now/ })));
    const alert = screen.getByRole('alert');
    assert.match(alert.textContent ?? '', /Too many changes.*Wait a minute.*corr-9/);
    assert.equal(routerSpy.refreshCount, 0);
  });

  it('a thrown action is reported as an unknown result', async () => {
    findingHandlers.scan = (() => Promise.reject(new Error('boom'))) as never;
    render(<UnknownDeviceScanPanel />);
    await act(async () => fireEvent.click(screen.getByRole('button', { name: /Scan for unknown devices now/ })));
    assert.match(screen.getByRole('alert').textContent ?? '', /scan result is not known/);
    assert.equal((screen.getByRole('button', { name: /Scan for unknown devices now/ }) as HTMLButtonElement).disabled, false);
  });
});
