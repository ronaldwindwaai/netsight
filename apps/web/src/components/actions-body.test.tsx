import '@/test/dom-setup';

import assert from 'node:assert/strict';
import { afterEach, describe, it } from 'node:test';

import { cleanup, render, screen } from '@testing-library/react';

import { ActionDetailBody } from '@/components/action-detail-body';
import { ActionsBody, ActionsFilters } from '@/components/actions-body';
import { ActionsStatusCard } from '@/components/actions-status-card';
import {
  ACTION_ID,
  FINDING,
  HOSTILE,
  actionDetail,
  actionList,
  actionRequest,
  actionStatus,
  approvedRequest,
  dryRunRequest,
  failedRequest,
  failure,
  ok,
} from '@/test/actions-fixtures';

afterEach(() => cleanup());

const QUERY = { state: null, page: 1 } as const;

describe('the status card', () => {
  it('says dry run only, in words', () => {
    render(<ActionsStatusCard state={ok(actionStatus())} />);
    assert.match(screen.getByText(/Dry run only/).closest('[role="note"]')?.textContent ?? '', /does not contact or\s+change any device/);
  });

  it('a disabled engine is not connected, never an empty success', () => {
    render(<ActionsStatusCard state={ok(actionStatus({ state: 'not-connected', executors: [], definitions: [] }))} />);
    assert.ok(screen.getByText('The action engine is not enabled'));
    assert.match(document.body.textContent ?? '', /not the same as having no requests/);
  });

  it('an engaged kill switch is a prominent alert and an environment one says it cannot be released here', () => {
    const state = ok(actionStatus({ kill_switch: { engaged: true, source: 'environment', since: null } }));
    render(<ActionsStatusCard state={state} />);
    const alert = screen.getByRole('alert');
    assert.match(alert.textContent ?? '', /Kill switch engaged/);
    assert.match(alert.textContent ?? '', /cannot be released here/);
  });

  it('states that requests are held in memory and lost on restart', () => {
    render(<ActionsStatusCard state={ok(actionStatus())} />);
    assert.match(document.body.textContent ?? '', /lost when the service restarts/);
  });

  it('says requests survive a restart only when the store is durable', () => {
    render(<ActionsStatusCard state={ok(actionStatus({ store: { kind: 'postgres', durable: true } }))} />);
    assert.match(document.body.textContent ?? '', /survive a restart and are shared between workers/);
    assert.doesNotMatch(document.body.textContent ?? '', /lost when the service restarts/);
  });

  it('a failed read is an explicit failure', () => {
    render(<ActionsStatusCard state={failure('error', 500)} />);
    assert.ok(document.body.textContent?.length);
    assert.doesNotMatch(document.body.textContent ?? '', /Dry run only/);
  });
});

describe('the list', () => {
  it('shows each request with its state as a word, its risk and approvals', () => {
    render(<ActionsBody state={ok(actionList({ items: [actionRequest(), approvedRequest({ id: 'action-99999999-2222-4333-8444-555555555555' })] }))} query={QUERY} />);
    assert.ok(screen.getAllByText('Awaiting approval').length >= 1);
    assert.ok(screen.getByText('Approved, not run'));
    assert.ok(screen.getAllByText('Risk C').length === 2);
    const link = screen.getAllByRole('link', { name: 'action-11111111' })[0];
    assert.equal(link.getAttribute('href'), `/actions/${ACTION_ID}`);
    assert.ok(screen.getByText('0 of 1'));
  });

  it('a finished dry run is labelled as a dry run, not as completed', () => {
    render(<ActionsBody state={ok(actionList({ items: [dryRunRequest()] }))} query={QUERY} />);
    assert.ok(screen.getByText('Dry run recorded'));
    assert.equal(screen.queryByText('Completed'), null);
  });

  it('never labels a request as executed unless its state says it ran', () => {
    render(<ActionsBody state={ok(actionList({ items: [actionRequest(), approvedRequest({ id: 'action-99999999-2222-4333-8444-555555555555' })] }))} query={QUERY} />);
    assert.doesNotMatch(document.body.textContent ?? '', /executed|applied|isolated/i);
  });

  it('renders hostile text as text', () => {
    const request = actionRequest({ requester: { id: HOSTILE, kind: 'human' } });
    const { container } = render(<ActionsBody state={ok(actionList({ items: [request] }))} query={QUERY} />);
    assert.equal(container.querySelector('img'), null);
    assert.ok(screen.getByText(HOSTILE));
  });

  it('separates not-connected, empty, filtered-empty, permission and error', () => {
    const cases: Array<[Parameters<typeof ActionsBody>[0], RegExp]> = [
      [{ state: ok(actionList({ state: 'not-connected', items: [], total: 0 })), query: QUERY }, /controlled actions are off/],
      [{ state: ok(actionList({ items: [], total: 0 })), query: QUERY }, /Nothing has been proposed/],
      [{ state: ok(actionList({ items: [], total: 0 })), query: { state: 'failed', page: 1 } }, /Choose another state/],
      [{ state: failure('forbidden', 403), query: QUERY }, /actions:read permission/],
    ];
    for (const [props, expected] of cases) {
      const { unmount } = render(<ActionsBody {...props} />);
      assert.match(document.body.textContent ?? '', expected);
      unmount();
    }
    render(<ActionsBody state={failure('error', 500)} query={QUERY} />);
    assert.ok(document.body.textContent?.length);
  });

  it('filters are plain links that keep the current choice', () => {
    render(<ActionsFilters query={{ state: 'failed', page: 1 }} />);
    const nav = screen.getByRole('navigation', { name: 'Action request filters' });
    assert.equal(nav.querySelector('[aria-current="true"]')?.textContent, 'Failed');
    assert.equal(screen.getByRole('link', { name: 'All states' }).getAttribute('href'), '/actions');
    assert.equal(screen.getByRole('link', { name: 'Rejected' }).getAttribute('href'), '/actions?state=rejected');
  });
});

describe('the detail', () => {
  it('shows what was asked, the unknowns and a link back to the finding', () => {
    render(<ActionDetailBody state={ok(actionDetail())} status={actionStatus()} panel={null} />);
    assert.ok(screen.getByText('endpoint.isolate'));
    assert.equal(screen.getByRole('link', { name: FINDING }).getAttribute('href'), `/unknown-devices/${FINDING}`);
    assert.match(document.body.textContent ?? '', /duration_minutes = 60/);
    assert.match(document.body.textContent ?? '', /target-exists: Not known/);
    assert.match(document.body.textContent ?? '', /Not run/);
    assert.match(document.body.textContent ?? '', /hash chain verifies/);
  });

  it('a pending request has not run and says so', () => {
    render(<ActionDetailBody state={ok(actionDetail())} status={actionStatus()} panel={null} />);
    assert.match(document.body.textContent ?? '', /No executor has been asked to do anything/);
  });

  it('a dry run is described as recording what would happen and changing nothing', () => {
    render(<ActionDetailBody state={ok(actionDetail(dryRunRequest()))} status={actionStatus()} panel={null} />);
    const text = document.body.textContent ?? '';
    assert.match(text, /Dry run completed/);
    assert.match(text, /nothing was contacted/i);
    assert.match(text, /None: nothing was changed/);
    assert.match(text, /What would happen/);
    assert.match(text, /Would move the endpoint/);
    assert.doesNotMatch(text, /Applied/);
  });

  it('a failed live run says it may have changed something', () => {
    render(<ActionDetailBody state={ok(actionDetail(failedRequest()))} status={actionStatus()} panel={null} />);
    assert.match(document.body.textContent ?? '', /may have changed something/);
    assert.match(document.body.textContent ?? '', /executor-timeout/);
  });

  it('says what happens next in a labelled note, without claiming a run', () => {
    render(<ActionDetailBody state={ok(actionDetail())} status={actionStatus()} panel={null} viewer={null} />);
    const note = screen.getByRole('note', { name: 'What happens next' });
    assert.match(note.textContent ?? '', /Awaiting/);
    assert.match(note.textContent ?? '', /does not run it/);
  });

  it('a broken hash chain is a loud alert', () => {
    render(<ActionDetailBody state={ok(actionDetail(actionRequest(), { chain_intact: false }))} status={null} panel={null} />);
    assert.match(screen.getByRole('alert').textContent ?? '', /hash chain does not verify/);
  });

  it('renders the reason and history notes as text', () => {
    const request = actionRequest({ reason: HOSTILE });
    const { container } = render(<ActionDetailBody state={ok(actionDetail(request))} status={actionStatus()} panel={null} />);
    assert.equal(container.querySelector('img'), null);
    assert.ok(screen.getAllByText(HOSTILE).length >= 1);
  });

  it('the dry-run notice is hidden only when a live executor is ready', () => {
    const live = actionStatus({
      dry_run_only: false,
      executors: [{ id: 'dry-run', mode: 'dry-run', state: 'ok' }, { id: 'live', mode: 'live', state: 'ok' }],
    });
    render(<ActionDetailBody state={ok(actionDetail())} status={live} panel={null} />);
    assert.equal(screen.queryByText(/Dry run only/), null);
  });

  it('a disabled engine and a failed read are explicit', () => {
    const disabled = { kind: 'error', code: 'ACTIONS_NOT_ENABLED', message: '', correlationId: 'c', status: 503 } as const;
    render(<ActionDetailBody state={disabled} status={null} panel={null} />);
    assert.ok(screen.getByText('The action engine is not enabled'));
  });
});
