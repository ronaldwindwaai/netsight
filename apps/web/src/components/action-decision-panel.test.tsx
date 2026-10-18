import '@/test/dom-setup';

import assert from 'node:assert/strict';
import { afterEach, beforeEach, describe, it, mock } from 'node:test';

import { cleanup, render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';

import { ActionDecisionPanel } from '@/components/action-decision-panel';
import { ActionKillSwitchPanel } from '@/components/action-kill-switch-panel';
import { ProposeActionPanel } from '@/components/propose-action-panel';
import type { Viewer } from '@/lib/incident-actions';
import type { WriteActionResult } from '@/lib/write-result';
import { actionHandlers } from '@/test/actions-actions-stub';
import {
  ACTION_ID,
  DIGEST,
  FINDING,
  actionRequest,
  actionStatus,
  approvedRequest,
} from '@/test/actions-fixtures';
import { FAILURES, deferred, failedWrite } from '@/test/helpers';
import { routerSpy } from '@/test/next-navigation-stub';

const ADMIN: Viewer = {
  identityId: 'oidc:admin-1',
  permissions: ['actions:read', 'actions:approve', 'actions:execute', 'actions:propose'],
};
const ENGINEER: Viewer = {
  identityId: 'oidc:engineer',
  permissions: ['actions:read', 'actions:propose', 'actions:propose-high'],
};
const PATH = `/actions/${ACTION_ID}`;
const KEY = /^[0-9a-f-]{36}$/;

beforeEach(() => {
  routerSpy.reset();
  for (const name of ['decision', 'killSwitch', 'propose'] as const) {
    actionHandlers[name] = () => {
      throw new Error(`No ${name} handler installed for this test`);
    };
  }
});
afterEach(() => cleanup());

function install(name: 'decision' | 'killSwitch' | 'propose', handler: (input: unknown) => Promise<WriteActionResult>) {
  const fn = mock.fn(handler);
  actionHandlers[name] = fn;
  return fn;
}

const button = (name: string | RegExp) => screen.getByRole('button', { name }) as HTMLButtonElement;

function describedText(control: HTMLElement): string {
  const ids = (control.getAttribute('aria-describedby') ?? '').split(' ').filter(Boolean);
  return ids.map((id) => document.getElementById(id)?.textContent ?? '').join(' ');
}

function renderPanel(viewer: Viewer | null, request = actionRequest(), status = actionStatus()) {
  return render(<ActionDecisionPanel request={request} viewer={viewer} status={status} currentPath={PATH} />);
}

describe('who can decide', () => {
  it('an approver can approve, reject and cancel a pending request; running waits for approval', () => {
    renderPanel(ADMIN);
    assert.equal(button(/^Approve/).disabled, false);
    assert.equal(button('Reject').disabled, false);
    assert.equal(button('Cancel request').disabled, false);
    const run = button(/^Record a dry run/);
    assert.equal(run.disabled, true);
    assert.match(describedText(run), /Only an approved request can be run/);
  });

  it('the requester is told a different person must approve', () => {
    renderPanel({ ...ADMIN, identityId: 'oidc:engineer' });
    const approve = button(/^Approve/);
    assert.equal(approve.disabled, true);
    assert.match(describedText(approve), /different person must approve/);
  });

  it('an engineer cannot approve, reject or run, with the reason in words', () => {
    renderPanel(ENGINEER, actionRequest({ requester: { id: 'oidc:someone-else', kind: 'human' } }));
    for (const name of [/^Approve/, 'Reject', /^Record a dry run/]) {
      assert.equal(button(name).disabled, true);
      assert.match(describedText(button(name)), /Your role does not permit this action/);
    }
  });

  it('a signed-out viewer is told to sign in', () => {
    renderPanel(null);
    assert.match(describedText(button(/^Approve/)), /Sign in/);
  });

  it('the kill switch disables approval and says why', () => {
    renderPanel(ADMIN, actionRequest(), actionStatus({ kill_switch: { engaged: true, source: 'runtime', since: '2026-10-18T12:00:00Z' } }));
    assert.match(describedText(button(/^Approve/)), /kill switch/i);
  });

  it('marks the actions that need a recent multi-factor sign-in', () => {
    renderPanel(ADMIN);
    assert.ok(within(button(/^Approve/)).getByText(/needs recent multi-factor sign-in/));
    assert.equal(within(button('Reject')).queryByText(/multi-factor/), null);
  });
});

describe('approving', () => {
  it('shows exactly what is being approved and sends the digest and version it showed', async () => {
    const handler = install('decision', async () => ({ ok: true, state: 'approved' }));
    renderPanel(ADMIN);
    await userEvent.click(button(/^Approve/));
    const dialog = screen.getByRole('dialog', { name: 'Approve this request' });
    assert.match(dialog.textContent ?? '', /endpoint\.isolate/);
    assert.match(dialog.textContent ?? '', new RegExp(FINDING));
    assert.match(dialog.textContent ?? '', /Version 3/);
    assert.match(dialog.textContent ?? '', new RegExp(DIGEST));
    assert.match(dialog.textContent ?? '', /not the person who made this request/);
    await userEvent.click(within(dialog).getByRole('button', { name: 'Approve' }));
    assert.equal(handler.mock.callCount(), 1);
    assert.deepEqual(handler.mock.calls[0].arguments[0], {
      verb: 'approve',
      actionId: ACTION_ID,
      digest: DIGEST,
      version: 3,
    });
    assert.equal(routerSpy.refreshCount, 1);
    assert.match(screen.getByRole('status').textContent ?? '', /Approval recorded/);
  });

  it('a second approver is told how many approvals are required', async () => {
    install('decision', async () => ({ ok: true }));
    renderPanel(ADMIN, actionRequest({ risk: 'D', approvals_required: 2, action_type: 'switch.port.disable', params: {}, source: null, target_id: 'interface:sw1-gi0-1' }));
    await userEvent.click(button(/^Approve/));
    assert.match(screen.getByRole('dialog').textContent ?? '', /2 different approvers are required/);
  });

  it('a stale request is refused and the operator is told to reload, with nothing sent twice', async () => {
    const handler = install('decision', async () =>
      failedWrite({ kind: 'error', code: 'STALE_REQUEST', message: 'The request changed since you looked at it; reload and review it again', correlationId: 'corr-9', status: 409 }),
    );
    renderPanel(ADMIN);
    await userEvent.click(button(/^Approve/));
    await userEvent.click(within(screen.getByRole('dialog')).getByRole('button', { name: 'Approve' }));
    const alert = within(screen.getByRole('dialog')).getByRole('alert');
    assert.match(alert.textContent ?? '', /Nothing was changed/);
    assert.match(alert.textContent ?? '', /corr-9/);
    assert.equal(handler.mock.callCount(), 1);
  });

  it('a missing recent second factor offers a fresh sign-in', async () => {
    install('decision', async () => failedWrite(FAILURES.stepUp.failure));
    renderPanel(ADMIN);
    await userEvent.click(button(/^Approve/));
    await userEvent.click(within(screen.getByRole('dialog')).getByRole('button', { name: 'Approve' }));
    assert.ok(within(screen.getByRole('dialog')).getByRole('link', { name: /Sign in again/ }));
  });

  it('a double click sends one request', async () => {
    const gate = deferred<WriteActionResult>();
    const handler = install('decision', () => gate.promise);
    renderPanel(ADMIN);
    await userEvent.click(button(/^Approve/));
    const submit = within(screen.getByRole('dialog')).getByRole('button', { name: 'Approve' });
    await userEvent.dblClick(submit);
    assert.equal(handler.mock.callCount(), 1);
    gate.resolve({ ok: true });
  });

  it('an unconfirmed result locks further decisions until the page is reloaded', async () => {
    install('decision', async () => failedWrite(FAILURES.unknownResult.failure));
    renderPanel(ADMIN);
    await userEvent.click(button(/^Approve/));
    await userEvent.click(within(screen.getByRole('dialog')).getByRole('button', { name: 'Approve' }));
    assert.equal(within(screen.getByRole('dialog')).getByRole('button', { name: 'Approve' }).hasAttribute('disabled'), true);
  });
});

describe('rejecting and cancelling', () => {
  it('needs a reason and sends it with the digest and version', async () => {
    const handler = install('decision', async () => ({ ok: true }));
    renderPanel(ADMIN);
    await userEvent.click(button('Reject'));
    const dialog = screen.getByRole('dialog', { name: 'Reject this request' });
    await userEvent.type(within(dialog).getByLabelText('Reason'), 'Not justified by the evidence');
    await userEvent.click(within(dialog).getByRole('button', { name: 'Reject' }));
    assert.deepEqual(handler.mock.calls[0].arguments[0], {
      verb: 'reject',
      actionId: ACTION_ID,
      digest: DIGEST,
      version: 3,
      reason: 'Not justified by the evidence',
    });
  });

  it('the requester can cancel their own request', async () => {
    const handler = install('decision', async () => ({ ok: true }));
    renderPanel(ENGINEER);
    await userEvent.click(button('Cancel request'));
    const dialog = screen.getByRole('dialog');
    await userEvent.type(within(dialog).getByLabelText('Reason'), 'Raised in error');
    await userEvent.click(within(dialog).getByRole('button', { name: 'Cancel request' }));
    assert.equal((handler.mock.calls[0].arguments[0] as { verb: string }).verb, 'cancel');
  });
});

describe('running', () => {
  it('is labelled as a dry run, says nothing is contacted, and sends one key per intention', async () => {
    const handler = install('decision', async () => failedWrite(FAILURES.unavailable.failure));
    renderPanel({ ...ADMIN, identityId: 'oidc:admin-1' }, approvedRequest());
    const run = button(/^Record a dry run/);
    assert.equal(run.disabled, false);
    await userEvent.click(run);
    const dialog = screen.getByRole('dialog', { name: 'Run this request' });
    assert.match(dialog.textContent ?? '', /dry run.*records what would happen/s);
    assert.match(dialog.textContent ?? '', /does not contact or change any\s+device or network system/);
    await userEvent.click(within(dialog).getByRole('button', { name: 'Record dry run' }));
    await userEvent.click(within(dialog).getByRole('button', { name: 'Record dry run' }));
    const [first, second] = handler.mock.calls.map((c) => c.arguments[0] as { verb: string; key: string; version: number });
    assert.equal(first.verb, 'execute');
    assert.match(first.key, KEY);
    assert.equal(first.key, second.key); // a retry of one intention is the same key
    assert.equal(first.version, 4);
  });

  it('a live-capable status labels the control Run, not a dry run', () => {
    const live = actionStatus({ dry_run_only: false, executors: [{ id: 'dry-run', mode: 'dry-run', state: 'ok' }, { id: 'live', mode: 'live', state: 'ok' }] });
    renderPanel(ADMIN, approvedRequest(), live);
    assert.ok(button(/^Run/));
    assert.equal(screen.queryByRole('button', { name: /dry run/i }), null);
  });
});

describe('the kill switch panel', () => {
  it('engaging needs no step-up marker and sends the choice and the reason', async () => {
    const handler = install('killSwitch', async () => ({ ok: true }));
    render(<ActionKillSwitchPanel engaged={false} fromEnvironment={false} currentPath="/actions" />);
    const open = button(/^Engage the kill switch/);
    assert.equal(within(open).queryByText(/multi-factor/), null);
    await userEvent.click(open);
    const dialog = screen.getByRole('dialog');
    await userEvent.type(within(dialog).getByLabelText('Reason'), 'Suspected compromise');
    await userEvent.click(within(dialog).getByRole('button', { name: 'Engage' }));
    assert.deepEqual(handler.mock.calls[0].arguments[0], { engaged: true, reason: 'Suspected compromise' });
  });

  it('releasing is marked as needing a recent second factor', () => {
    render(<ActionKillSwitchPanel engaged={true} fromEnvironment={false} currentPath="/actions" />);
    assert.ok(within(button(/^Release the kill switch/)).getByText(/needs recent multi-factor sign-in/));
  });

  it('an environment switch cannot be released from here', () => {
    render(<ActionKillSwitchPanel engaged={true} fromEnvironment={true} currentPath="/actions" />);
    const release = button(/^Release the kill switch/);
    assert.equal(release.disabled, true);
    assert.match(describedText(release), /set in the environment/);
  });
});

describe('the finding proposal panel', () => {
  it('says it only proposes, and sends the finding, its evidence version, a reason and one key', async () => {
    const handler = install('propose', async () => ({ ok: true, id: ACTION_ID }));
    render(<ProposeActionPanel findingId={FINDING} evidenceVersion={3} currentPath={`/unknown-devices/${FINDING}`} />);
    assert.match(document.body.textContent ?? '', /Nothing is isolated, and nothing in\s+this release can isolate a device/);
    await userEvent.click(button('Create an action request'));
    const dialog = screen.getByRole('dialog');
    await userEvent.type(within(dialog).getByLabelText('Reason'), 'Seen on the finance VLAN');
    await userEvent.click(within(dialog).getByRole('button', { name: 'Create request' }));
    const sent = handler.mock.calls[0].arguments[0] as { findingId: string; evidenceVersion: number; reason: string; key: string };
    assert.equal(sent.findingId, FINDING);
    assert.equal(sent.evidenceVersion, 3);
    assert.equal(sent.reason, 'Seen on the finance VLAN');
    assert.match(sent.key, KEY);
    const link = await screen.findByRole('link', { name: 'Open the request' });
    assert.equal(link.getAttribute('href'), `/actions/${ACTION_ID}`);
    assert.equal(button('Create an action request').disabled, true);
  });

  it('a stale-evidence refusal tells the operator to reload', async () => {
    install('propose', async () =>
      failedWrite({ kind: 'error', code: 'STALE_EVIDENCE', message: 'The evidence changed', correlationId: 'corr-3', status: 409 }),
    );
    render(<ProposeActionPanel findingId={FINDING} evidenceVersion={3} currentPath="/unknown-devices/x" />);
    await userEvent.click(button('Create an action request'));
    const dialog = screen.getByRole('dialog');
    await userEvent.type(within(dialog).getByLabelText('Reason'), 'Seen on the finance VLAN');
    await userEvent.click(within(dialog).getByRole('button', { name: 'Create request' }));
    assert.match(within(screen.getByRole('dialog')).getByRole('alert').textContent ?? '', /evidence for this finding changed/i);
  });
});


describe('what the notice says after a run', () => {
  async function runDry(state: string) {
    install('decision', async () => ({ ok: true, state }));
    renderPanel(ADMIN, approvedRequest());
    await userEvent.click(button(/^Record a dry run/));
    await userEvent.click(within(screen.getByRole('dialog')).getByRole('button', { name: 'Record dry run' }));
  }

  it('a dry run says it was recorded and nothing was changed', async () => {
    await runDry('succeeded');
    const notice = screen.getByRole('status');
    assert.match(notice.textContent ?? '', /Dry run recorded/);
    assert.match(notice.textContent ?? '', /Nothing was changed/);
  });

  it('a failed run is a red alert, never a green "recorded"', async () => {
    await runDry('failed');
    assert.equal(screen.queryByRole('status'), null);
    const alert = screen.getByRole('alert');
    assert.match(alert.textContent ?? '', /The run failed/);
    assert.doesNotMatch(alert.textContent ?? '', /recorded/i);
  });

  it('a rolled-back run is a warning', async () => {
    await runDry('rolled-back');
    assert.match(screen.getByRole('alert').textContent ?? '', /rolled back/);
  });

  it('a first approval of two says another approver is still needed', async () => {
    install('decision', async () => ({ ok: true, state: 'pending-approval' }));
    renderPanel(ADMIN);
    await userEvent.click(button(/^Approve/));
    await userEvent.click(within(screen.getByRole('dialog')).getByRole('button', { name: 'Approve' }));
    assert.match(screen.getByRole('status').textContent ?? '', /Another approver is still needed/);
  });
});
