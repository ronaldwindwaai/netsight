import '@/test/dom-setup';

import assert from 'node:assert/strict';
import { afterEach, beforeEach, describe, it, mock } from 'node:test';

import { act, cleanup, fireEvent, render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';

import {
  NewRuleButton,
  NewWindowButton,
  RuleRowActions,
  WindowRowActions,
} from '@/components/alerting-write-controls';
import type { AlertRule, MaintenanceWindow } from '@/lib/api-contracts-alert-rule';
import type { Viewer } from '@/lib/incident-actions';
import type { WriteActionResult } from '@/lib/write-result';
import { routerSpy } from '@/test/next-navigation-stub';
import { actionHandlers, resetActionHandlers } from '@/test/server-actions-stub';
import {
  FAILURES,
  VIEWERS,
  assertAbsent,
  assertFocus,
  deferred,
  failedWrite,
} from '@/test/helpers';

const RULE_ID = 'alert-rule-3f2b8a40-1c2d-4e5f-8a9b-0c1d2e3f4a5b';
const WINDOW_ID = 'maintenance-3f2b8a40-1c2d-4e5f-8a9b-0c1d2e3f4a5b';
const NOW = Date.parse('2026-10-10T12:00:00Z');

const OPERATOR: Viewer = {
  identityId: 'microsoft:ana',
  permissions: ['alert-rules:read', 'alert-rules:write', 'alert-rules:disable', 'maintenance:write'],
};

function rule(overrides: Partial<AlertRule> = {}): AlertRule {
  return {
    id: RULE_ID,
    name: 'Core uplink saturated',
    status: 'draft',
    scope: { kind: 'device', ref: 'core-sw-01' },
    condition: { metric: 'interface.utilisation_percent', operator: 'gt', threshold: 90, pattern: null },
    baseline_mode: 'none',
    window_seconds: 300,
    for_seconds: 0,
    cooldown_seconds: 600,
    schedule: null,
    exceptions: { destinations: [], device_groups: [] },
    severity: 'high',
    labels: {},
    actions: ['create_alert'],
    incident_policy: 'none',
    created_by: 'microsoft:ana',
    created_at: '2026-10-01T00:00:00Z',
    updated_at: '2026-10-01T00:00:00Z',
    approved_by: null,
    approved_at: null,
    version: 3,
    ...overrides,
  };
}

function maintenanceWindow(overrides: Partial<MaintenanceWindow> = {}): MaintenanceWindow {
  return {
    id: WINDOW_ID,
    name: 'Firmware upgrade',
    scope: { kind: 'device', ref: 'core-sw-01' },
    starts_at: '2026-10-11T01:00:00Z',
    ends_at: '2026-10-11T03:00:00Z',
    evaluation: 'retain',
    status: 'scheduled',
    reason: 'Planned',
    created_by: 'microsoft:ana',
    created_at: '2026-10-01T00:00:00Z',
    cancelled_by: null,
    cancelled_at: null,
    ...overrides,
  };
}

beforeEach(() => {
  routerSpy.reset();
  resetActionHandlers();
});
afterEach(() => cleanup());

function install(handler: (input: unknown) => Promise<WriteActionResult>) {
  const fn = mock.fn(handler);
  actionHandlers.alerting = fn;
  return fn;
}

function button(name: string | RegExp): HTMLButtonElement {
  return screen.getByRole('button', { name }) as HTMLButtonElement;
}

function describedText(control: HTMLElement): string {
  const ids = (control.getAttribute('aria-describedby') ?? '').split(' ').filter(Boolean);
  return ids.map((id) => document.getElementById(id)?.textContent ?? '').join(' ');
}

async function fillRule(user: ReturnType<typeof userEvent.setup>) {
  await user.type(screen.getByLabelText('Name'), 'Core uplink saturated');
  await user.type(screen.getByLabelText('Scope reference'), 'core-sw-01');
  await user.type(screen.getByLabelText('Metric'), 'interface.utilisation_percent');
  await user.type(screen.getByLabelText('Threshold'), '90');
}

describe('who can change alerting configuration', () => {
  for (const role of ['technician', 'management', 'auditor'] as const) {
    it(`${role}: New rule and New window are disabled with a reason`, () => {
      render(
        <>
          <NewRuleButton viewer={VIEWERS[role]} />
          <NewWindowButton viewer={VIEWERS[role]} />
        </>,
      );
      for (const name of [/New rule/, /New window/]) {
        assert.equal(button(name).disabled, true, `${role} ${name}`);
        assert.match(describedText(button(name)), /Your role does not permit this action/);
      }
    });

    it(`${role}: every rule control is disabled with a reason`, () => {
      render(<RuleRowActions rule={rule()} viewer={VIEWERS[role]} />);
      for (const name of ['Edit', 'Approve', 'Disable']) {
        assert.equal(button(name).disabled, true, `${role} ${name}`);
        assert.match(describedText(button(name)), /Your role does not permit this action/);
      }
    });

    it(`${role}: Cancel window is disabled with a reason`, () => {
      render(<WindowRowActions window={maintenanceWindow()} viewer={VIEWERS[role]} nowMs={NOW} />);
      assert.equal(button('Cancel window').disabled, true);
      assert.match(describedText(button('Cancel window')), /Your role does not permit this action/);
    });
  }

  it('a signed-out viewer is told to sign in', () => {
    render(<NewRuleButton viewer={null} />);
    assert.equal(button(/New rule/).disabled, true);
    assert.match(describedText(button(/New rule/)), /Sign in to change alerting configuration/);
  });

  it('an operator may edit and disable but not approve (approval is a separate permission)', () => {
    render(<RuleRowActions rule={rule({ status: 'draft' })} viewer={OPERATOR} />);
    assert.equal(button('Edit').disabled, false);
    assert.equal(button('Approve').disabled, true);
    assert.equal(button('Disable').disabled, true);
    assert.match(describedText(button('Disable')), /Only an active rule can be disabled/);
  });

  it('an active rule cannot be edited until it is disabled', () => {
    render(<RuleRowActions rule={rule({ status: 'active' })} viewer={VIEWERS.administrator} />);
    assert.equal(button('Edit').disabled, true);
    assert.match(describedText(button('Edit')), /Disable the rule before editing it/);
    assert.equal(button('Disable').disabled, false);
  });

  it('uses the disabled attribute alone, with no ARIA duplicate', () => {
    const view = render(<RuleRowActions rule={rule()} viewer={VIEWERS.auditor} />);
    assert.equal(view.container.querySelectorAll('[aria-disabled]').length, 0);
  });
});

describe('when the store cannot take a write', () => {
  const REASON = 'The alert rule store is not connected, so rules cannot be created.';

  it('New rule is disabled and states the store reason for a permitted viewer', () => {
    render(<NewRuleButton viewer={VIEWERS.administrator} unavailableReason={REASON} />);
    assert.equal(button(/New rule/).disabled, true);
    assert.equal(describedText(button(/New rule/)), REASON);
  });

  it('a viewer without permission still gets the permission reason first', () => {
    render(<NewRuleButton viewer={VIEWERS.auditor} unavailableReason={REASON} />);
    assert.match(describedText(button(/New rule/)), /Your role does not permit this action/);
  });

  it('New window is disabled with the store reason too', () => {
    render(<NewWindowButton viewer={VIEWERS.administrator} unavailableReason="Window store down." />);
    assert.equal(button(/New window/).disabled, true);
    assert.equal(describedText(button(/New window/)), 'Window store down.');
  });
});

describe('creating a rule', () => {
  async function openCreate(viewer: Viewer = VIEWERS.administrator) {
    render(<NewRuleButton viewer={viewer} />);
    const user = userEvent.setup();
    await user.click(button(/New rule/));
    return user;
  }

  it('opens a dialog with focus on the name field', async () => {
    await openCreate();
    assert.ok(screen.getByRole('dialog', { name: 'New alert rule' }));
    assertFocus(screen.getByLabelText('Name'));
  });

  it('shows field errors and sends nothing when the form is invalid', async () => {
    const handler = install(() => Promise.resolve({ ok: true }));
    const user = await openCreate();
    await user.click(button('Create draft'));
    assert.equal(handler.mock.callCount(), 0);
    const name = screen.getByLabelText('Name');
    assert.equal(name.getAttribute('aria-invalid'), 'true');
    assert.match(screen.getByText(/Enter a name of at most 255 characters/).textContent ?? '', /Enter a name/);
  });

  it('a double submit sends one create request carrying the form values', async () => {
    const gate = deferred<WriteActionResult>();
    const handler = install(() => gate.promise);
    const user = await openCreate();
    await fillRule(user);
    const form = screen.getByRole('dialog').querySelector('form') as HTMLFormElement;

    await act(async () => {
      fireEvent.submit(form);
      fireEvent.submit(form);
    });

    assert.equal(handler.mock.callCount(), 1);
    const input = handler.mock.calls[0].arguments[0] as { action: string; values: { name: string; operand: string } };
    assert.equal(input.action, 'rule.create');
    assert.equal(input.values.name, 'Core uplink saturated');
    assert.equal(input.values.operand, '90');
    await act(async () => gate.resolve({ ok: true }));
    assertAbsent(screen.queryByRole('dialog'));
    assert.match(document.body.textContent ?? '', /Rule created as a draft/);
    assert.equal(routerSpy.refreshCount, 1);
  });

  it('the dialog cannot be closed while the request is in flight', async () => {
    const gate = deferred<WriteActionResult>();
    install(() => gate.promise);
    const user = await openCreate();
    await fillRule(user);
    await act(async () => {
      fireEvent.submit(screen.getByRole('dialog').querySelector('form') as HTMLFormElement);
    });
    await user.keyboard('{Escape}');
    assert.ok(screen.getByRole('dialog'));
    assert.equal(button('Close').disabled, true);
    assert.equal(button('Cancel').disabled, true);
    await act(async () => gate.resolve({ ok: true }));
  });

  const cases: Array<[string, keyof typeof FAILURES, RegExp]> = [
    ['409', 'conflict', /The record changed/],
    ['422', 'invalid', /The request was not accepted/],
    ['503', 'unavailable', /Storage unavailable/],
    ['401', 'unauthenticated', /Sign in required/],
    ['429', 'rateLimited', /Too many changes/],
    ['403 STEP_UP_REQUIRED', 'stepUp', /Recent multi-factor sign-in required/],
  ];
  for (const [label, key, title] of cases) {
    it(`${label} is shown inside the dialog and the typed values are kept`, async () => {
      install(() => Promise.resolve(failedWrite(FAILURES[key].failure)));
      const user = await openCreate();
      await fillRule(user);
      await user.click(button('Create draft'));
      const alert = within(screen.getByRole('dialog')).getByRole('alert');
      assert.match(alert.textContent ?? '', title);
      assert.equal((screen.getByLabelText('Name') as HTMLInputElement).value, 'Core uplink saturated');
    });
  }

  it('401 links to sign in and returns to the alerts page', async () => {
    install(() => Promise.resolve(failedWrite(FAILURES.unauthenticated.failure)));
    const user = await openCreate();
    await fillRule(user);
    await user.click(button('Create draft'));
    const link = within(screen.getByRole('dialog')).getByRole('link', { name: /Sign in/ });
    assert.equal(link.getAttribute('href'), '/login?next=%2Falerts');
  });

  it('cannot create a second rule after a result that could not be confirmed', async () => {
    const handler = install(() => Promise.resolve(failedWrite(FAILURES.unknownResult.failure)));
    const user = await openCreate();
    await fillRule(user);
    const form = screen.getByRole('dialog').querySelector('form') as HTMLFormElement;
    await act(async () => {
      fireEvent.submit(form);
    });
    assert.match(within(screen.getByRole('dialog')).getByRole('alert').textContent ?? '', /may or may not have been applied/);
    assert.equal(button('Create draft').disabled, true);
    await act(async () => {
      fireEvent.submit(form);
    });
    assert.equal(handler.mock.callCount(), 1);

    await user.click(screen.getByRole('button', { name: /Reload current state/ }));
    assert.equal(routerSpy.refreshCount, 1);
    assert.equal(button('Create draft').disabled, false);
  });

  it('closing after an unconfirmed result reloads the page so the new state is visible', async () => {
    install(() => Promise.resolve(failedWrite(FAILURES.unknownResult.failure)));
    const user = await openCreate();
    await fillRule(user);
    await user.click(button('Create draft'));
    await user.click(button('Cancel'));
    assertAbsent(screen.queryByRole('dialog'));
    assert.equal(routerSpy.refreshCount, 1);
  });

  it('closes on Escape when idle and returns focus to the New rule button', async () => {
    const user = await openCreate();
    await user.keyboard('{Escape}');
    assertAbsent(screen.queryByRole('dialog'));
    assertFocus(button(/New rule/));
  });

  it('shows a regular-expression-free hint for the matches operator', async () => {
    const user = await openCreate();
    await user.selectOptions(screen.getByLabelText('Operator'), 'matches');
    assert.ok(screen.getByLabelText('Pattern'));
    assert.match(document.body.textContent ?? '', /matched, never executed/);
  });
});

describe('editing, approving and disabling a rule', () => {
  it('editing sends the version that was loaded', async () => {
    const handler = install(() => Promise.resolve({ ok: true }));
    render(<RuleRowActions rule={rule({ version: 3 })} viewer={VIEWERS.administrator} />);
    const user = userEvent.setup();
    await user.click(button('Edit'));
    assert.ok(screen.getByRole('dialog', { name: 'Edit rule (version 3)' }));
    await user.click(button('Save draft'));
    const input = handler.mock.calls[0].arguments[0] as { action: string; ruleId: string; expectedVersion: number };
    assert.equal(input.action, 'rule.update');
    assert.equal(input.ruleId, RULE_ID);
    assert.equal(input.expectedVersion, 3);
  });

  it('approving is a confirmation: a double click sends one request bound to the version', async () => {
    const gate = deferred<WriteActionResult>();
    const handler = install(() => gate.promise);
    render(<RuleRowActions rule={rule({ version: 3, created_by: 'microsoft:ana' })} viewer={VIEWERS.administrator} />);
    const user = userEvent.setup();
    await user.click(button('Approve'));
    const dialog = screen.getByRole('dialog', { name: 'Approve version 3' });
    assert.match(dialog.textContent ?? '', /Approving activates exactly this version/);
    const confirm = within(dialog).getByRole('button', { name: 'Approve version 3' });

    await act(async () => {
      fireEvent.click(confirm);
      fireEvent.click(confirm);
    });

    assert.equal(handler.mock.callCount(), 1);
    assert.deepEqual(handler.mock.calls[0].arguments[0], {
      action: 'rule.approve',
      ruleId: RULE_ID,
      expectedVersion: 3,
    });
    await act(async () => gate.resolve({ ok: true }));
    assertAbsent(screen.queryByRole('dialog'));
    assert.match(document.body.textContent ?? '', /Rule approved and active/);
  });

  it('approval refused because the rule changed (409) says so and keeps the dialog open', async () => {
    install(() => Promise.resolve(failedWrite(FAILURES.conflict.failure)));
    render(<RuleRowActions rule={rule()} viewer={VIEWERS.administrator} />);
    const user = userEvent.setup();
    await user.click(button('Approve'));
    await user.click(within(screen.getByRole('dialog')).getByRole('button', { name: /^Approve version/ }));
    assert.match(within(screen.getByRole('dialog')).getByRole('alert').textContent ?? '', /The record changed/);
  });

  it('the confirmation takes focus when it opens', async () => {
    render(<RuleRowActions rule={rule({ status: 'active' })} viewer={VIEWERS.administrator} />);
    await userEvent.setup().click(button('Disable'));
    assertFocus(screen.getByRole('dialog'));
  });

  it('disabling an active rule sends the rule id', async () => {
    const handler = install(() => Promise.resolve({ ok: true }));
    render(<RuleRowActions rule={rule({ status: 'active' })} viewer={VIEWERS.administrator} />);
    const user = userEvent.setup();
    await user.click(button('Disable'));
    await user.click(within(screen.getByRole('dialog')).getByRole('button', { name: 'Disable rule' }));
    assert.deepEqual(handler.mock.calls[0].arguments[0], { action: 'rule.disable', ruleId: RULE_ID });
  });

  it('a confirmation cannot be repeated after an unconfirmed result', async () => {
    const handler = install(() => Promise.resolve(failedWrite(FAILURES.unknownResult.failure)));
    render(<RuleRowActions rule={rule({ status: 'active' })} viewer={VIEWERS.administrator} />);
    const user = userEvent.setup();
    await user.click(button('Disable'));
    const confirm = within(screen.getByRole('dialog')).getByRole('button', { name: 'Disable rule' }) as HTMLButtonElement;
    await user.click(confirm);
    assert.equal(confirm.disabled, true);
    await act(async () => {
      fireEvent.click(confirm);
    });
    assert.equal(handler.mock.callCount(), 1);
  });
});

describe('maintenance windows', () => {
  async function fillWindow(user: ReturnType<typeof userEvent.setup>) {
    await user.type(screen.getByLabelText('Name'), 'Firmware upgrade');
    await user.type(screen.getByLabelText('Scope reference'), 'core-sw-01');
    fireEvent.change(screen.getByLabelText(/Starts \(UTC\)/), { target: { value: '2999-01-01T01:00' } });
    fireEvent.change(screen.getByLabelText(/Ends \(UTC\)/), { target: { value: '2999-01-01T03:00' } });
    await user.type(screen.getByLabelText('Reason'), 'Planned upgrade');
  }

  it('scheduling focuses the name and sends one request on a double submit', async () => {
    const gate = deferred<WriteActionResult>();
    const handler = install(() => gate.promise);
    render(<NewWindowButton viewer={OPERATOR} />);
    const user = userEvent.setup();
    await user.click(button(/New window/));
    assertFocus(screen.getByLabelText('Name'));
    await fillWindow(user);
    const form = screen.getByRole('dialog').querySelector('form') as HTMLFormElement;

    await act(async () => {
      fireEvent.submit(form);
      fireEvent.submit(form);
    });

    assert.equal(handler.mock.callCount(), 1);
    assert.equal((handler.mock.calls[0].arguments[0] as { action: string }).action, 'window.create');
    await act(async () => gate.resolve({ ok: true }));
    assert.match(document.body.textContent ?? '', /Maintenance window scheduled/);
  });

  it('without the organisation permission, organisation scope and "stop evaluating" are unavailable', async () => {
    render(<NewWindowButton viewer={OPERATOR} />);
    await userEvent.setup().click(button(/New window/));
    const organisation = screen.getByRole('option', { name: /organisation \(needs organisation permission\)/ }) as HTMLOptionElement;
    assert.equal(organisation.disabled, true);
    const stop = screen.getByRole('option', { name: /Stop evaluating rules in scope/ }) as HTMLOptionElement;
    assert.equal(stop.disabled, true);
  });

  it('an unconfirmed schedule request cannot be repeated', async () => {
    const handler = install(() => Promise.resolve(failedWrite(FAILURES.unknownResult.failure)));
    render(<NewWindowButton viewer={OPERATOR} />);
    const user = userEvent.setup();
    await user.click(button(/New window/));
    await fillWindow(user);
    const form = screen.getByRole('dialog').querySelector('form') as HTMLFormElement;
    await act(async () => {
      fireEvent.submit(form);
    });
    assert.equal(button('Schedule window').disabled, true);
    await act(async () => {
      fireEvent.submit(form);
    });
    assert.equal(handler.mock.callCount(), 1);
  });

  it('cancelling a window asks for confirmation and sends the window id once', async () => {
    const handler = install(() => Promise.resolve({ ok: true }));
    render(<WindowRowActions window={maintenanceWindow()} viewer={OPERATOR} nowMs={NOW} />);
    const user = userEvent.setup();
    await user.click(button('Cancel window'));
    const dialog = screen.getByRole('dialog', { name: 'Cancel maintenance window' });
    await user.click(within(dialog).getByRole('button', { name: 'Cancel window' }));
    assert.deepEqual(handler.mock.calls[0].arguments[0], { action: 'window.cancel', windowId: WINDOW_ID });
    assert.match(document.body.textContent ?? '', /Window cancelled/);
  });

  it('a finished window cannot be cancelled and says why', () => {
    render(
      <WindowRowActions
        window={maintenanceWindow({ ends_at: '2026-10-09T00:00:00Z', starts_at: '2026-10-08T00:00:00Z' })}
        viewer={OPERATOR}
        nowMs={NOW}
      />,
    );
    assert.equal(button('Cancel window').disabled, true);
    assert.match(describedText(button('Cancel window')), /already ended/);
  });
});
