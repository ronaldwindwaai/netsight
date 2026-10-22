'use client';

import { useId, useState } from 'react';

import { performAlertingAction } from '@/app/(dashboard)/alerts/actions';
import { RuleFormFields } from '@/components/rule-form';
import { WindowFormFields } from '@/components/window-form';
import { ActionDialog, DisabledReason, WriteFeedback, useServerWrite } from '@/components/write-ui';
import type { WriteRunner } from '@/components/write-ui';
import {
  availableRuleActions,
  availableWindowActions,
  buildRuleDefinition,
  buildWindowRequest,
  canCreateRule,
  canCreateWindow,
  emptyRuleForm,
  emptyWindowForm,
  ruleToForm,
} from '@/lib/alerting-forms';
import type { FieldErrors, RuleActionName, RuleFormValues, WindowFormValues } from '@/lib/alerting-forms';
import { describeCondition, describeScope } from '@/lib/alerting-view';
import type { AlertRule, MaintenanceWindow } from '@/lib/api-contracts-alert-rule';
import type { Viewer } from '@/lib/incident-actions';

const PATH = '/alerts';

function FormFooter({
  pending,
  locked,
  label,
  theme = 'primary',
  onCancel,
}: {
  pending: boolean;
  /** The last result could not be confirmed: submitting again could repeat the change. */
  locked: boolean;
  label: string;
  theme?: string;
  onCancel: () => void;
}) {
  return (
    <div className="d-flex justify-content-end gap-2 mt-3">
      <button type="button" className="btn btn-outline-secondary" onClick={onCancel} disabled={pending}>
        Cancel
      </button>
      <button type="submit" className={`btn btn-${theme}`} disabled={pending || locked}>
        {pending ? 'Working…' : label}
      </button>
    </div>
  );
}

/**
 * Closing a dialog whose write could not be confirmed reloads the page: the change may have been
 * applied, and the operator must see the current state before anything is sent again.
 */
function closeAfterWrite(runner: WriteRunner, onClose: () => void): () => void {
  return () => {
    if (runner.pending) return;
    if (runner.unconfirmed) runner.reload();
    onClose();
  };
}

/** Create or edit a rule. An edit is bound to the version the operator loaded. */
function RuleEditorDialog({
  rule,
  onClose,
  onDone,
}: {
  rule: AlertRule | null;
  onClose: () => void;
  onDone: (message: string) => void;
}) {
  const [values, setValues] = useState<RuleFormValues>(rule === null ? emptyRuleForm() : ruleToForm(rule));
  const [errors, setErrors] = useState<FieldErrors>({});
  const runner = useServerWrite(performAlertingAction);
  const close = closeAfterWrite(runner, onClose);

  async function submit(event: React.FormEvent) {
    event.preventDefault();
    const built = buildRuleDefinition(values);
    if (!built.ok) {
      setErrors(built.errors);
      return;
    }
    setErrors({});
    const input =
      rule === null
        ? { action: 'rule.create', values }
        : { action: 'rule.update', ruleId: rule.id, expectedVersion: rule.version, values };
    if (await runner.submit(input)) {
      onDone(rule === null ? 'Rule created as a draft.' : 'Rule saved as a draft; it needs approval to be evaluated.');
    }
  }

  return (
    <ActionDialog
      title={rule === null ? 'New alert rule' : `Edit rule (version ${rule.version})`}
      onClose={close}
      busy={runner.pending}
    >
      <form onSubmit={submit} noValidate aria-busy={runner.pending}>
        <p className="small text-body-secondary">
          {rule === null
            ? 'A new rule starts as a draft. It is not evaluated until someone with approval permission activates this exact version.'
            : `Saving replaces the definition and returns the rule to draft. It is bound to version ${rule.version}: if someone else changed it meanwhile, nothing is saved.`}
        </p>
        {errors._form ? (
          <div className="alert alert-warning py-2" role="alert">
            {errors._form}
          </div>
        ) : null}
        <RuleFormFields values={values} errors={errors} disabled={runner.pending} onChange={setValues} />
        <div aria-live="polite">
          <WriteFeedback result={runner.result} currentPath={PATH} onReload={runner.reload} />
        </div>
        <FormFooter
          pending={runner.pending}
          locked={runner.unconfirmed}
          label={rule === null ? 'Create draft' : 'Save draft'}
          onCancel={close}
        />
      </form>
    </ActionDialog>
  );
}

function ConfirmDialog({
  title,
  confirmLabel,
  theme,
  summary,
  input,
  successMessage,
  onClose,
  onDone,
}: {
  title: string;
  confirmLabel: string;
  theme: string;
  summary: React.ReactNode;
  input: unknown;
  successMessage: string;
  onClose: () => void;
  onDone: (message: string) => void;
}) {
  const runner = useServerWrite(performAlertingAction);
  const close = closeAfterWrite(runner, onClose);
  return (
    <ActionDialog title={title} onClose={close} busy={runner.pending}>
      <div>{summary}</div>
      <div className="mt-3" aria-live="polite">
        <WriteFeedback result={runner.result} currentPath={PATH} onReload={runner.reload} />
      </div>
      <div className="d-flex justify-content-end gap-2 mt-3">
        <button type="button" className="btn btn-outline-secondary" onClick={close} disabled={runner.pending}>
          Cancel
        </button>
        <button
          type="button"
          className={`btn btn-${theme}`}
          disabled={runner.pending || runner.unconfirmed}
          onClick={async () => {
            if (await runner.submit(input)) onDone(successMessage);
          }}
        >
          {runner.pending ? 'Working…' : confirmLabel}
        </button>
      </div>
    </ActionDialog>
  );
}

function RuleSummary({ rule }: { rule: AlertRule }) {
  return (
    <dl className="row mb-0 small">
      <dt className="col-4">Rule</dt>
      <dd className="col-8 text-break">{rule.name}</dd>
      <dt className="col-4">Scope</dt>
      <dd className="col-8 text-break">{describeScope(rule.scope)}</dd>
      <dt className="col-4">Condition</dt>
      <dd className="col-8 text-break">
        <code>{describeCondition(rule.condition)}</code>
      </dd>
      <dt className="col-4">Severity</dt>
      <dd className="col-8">{rule.severity}</dd>
      <dt className="col-4">Version</dt>
      <dd className="col-8">{rule.version}</dd>
      <dt className="col-4">Created by</dt>
      <dd className="col-8 text-break">{rule.created_by}</dd>
    </dl>
  );
}

type Notify = (message: string) => void;

export function NewRuleButton({
  viewer,
  unavailableReason = null,
}: {
  viewer: Viewer | null;
  /** Set when the backing store cannot take a write; shown after the permission reason. */
  unavailableReason?: string | null;
}) {
  const [open, setOpen] = useState(false);
  const [notice, setNotice] = useState<string | null>(null);
  const permission = canCreateRule(viewer);
  const gate =
    permission.enabled && unavailableReason !== null
      ? { ...permission, enabled: false, reason: unavailableReason }
      : permission;
  const noteId = useId();
  return (
    <div>
      <button
        type="button"
        className="btn btn-sm btn-primary"
        disabled={!gate.enabled}
        aria-describedby={gate.enabled ? undefined : noteId}
        onClick={() => {
          setNotice(null);
          setOpen(true);
        }}
      >
        <i className="bi bi-plus-lg me-1" aria-hidden="true" />
        New rule
      </button>
      {!gate.enabled ? <DisabledReason id={noteId}>{gate.reason}</DisabledReason> : null}
      <span aria-live="polite">{notice !== null ? <span className="ms-2 small text-success">{notice}</span> : null}</span>
      {open ? (
        <RuleEditorDialog
          rule={null}
          onClose={() => setOpen(false)}
          onDone={(message) => {
            setOpen(false);
            setNotice(message);
          }}
        />
      ) : null}
    </div>
  );
}

/** Edit, approve and disable for one rule row. Disabled controls say why. */
export function RuleRowActions({ rule, viewer }: { rule: AlertRule; viewer: Viewer | null }) {
  const [open, setOpen] = useState<RuleActionName | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const noteId = useId();
  const actions = availableRuleActions(rule, viewer);
  const done: Notify = (message) => {
    setOpen(null);
    setNotice(message);
  };
  const ownRule = viewer !== null && rule.created_by === viewer.identityId;

  return (
    <div>
      <div className="d-flex flex-wrap gap-1" role="group" aria-label={`Actions for ${rule.name}`}>
        {actions.map((item) => (
          <button
            key={item.action}
            type="button"
            className="btn btn-outline-secondary btn-sm"
            disabled={!item.enabled}
            aria-describedby={item.enabled ? undefined : `${noteId}-${item.action}`}
            onClick={() => {
              setNotice(null);
              setOpen(item.action);
            }}
          >
            {item.label}
          </button>
        ))}
      </div>
      {actions
        .filter((item) => !item.enabled)
        .map((item) => (
          <DisabledReason key={item.action} id={`${noteId}-${item.action}`}>
            {item.label}: {item.reason}
          </DisabledReason>
        ))}
      <span aria-live="polite">{notice !== null ? <span className="d-block small text-success">{notice}</span> : null}</span>

      {open === 'edit' ? <RuleEditorDialog rule={rule} onClose={() => setOpen(null)} onDone={done} /> : null}
      {open === 'approve' ? (
        <ConfirmDialog
          title={`Approve version ${rule.version}`}
          confirmLabel={`Approve version ${rule.version}`}
          theme="success"
          successMessage="Rule approved and active."
          input={{ action: 'rule.approve', ruleId: rule.id, expectedVersion: rule.version }}
          summary={
            <>
              <p>
                Approving activates exactly this version, as shown. If the rule is edited before you
                confirm, the approval is refused and nothing is activated.
              </p>
              <RuleSummary rule={rule} />
              {ownRule ? (
                <p className="small text-body-secondary mt-3 mb-0">
                  You created this rule. Creators may approve their own rules today; the approval is
                  recorded with your identity in the audit log.
                </p>
              ) : null}
            </>
          }
          onClose={() => setOpen(null)}
          onDone={done}
        />
      ) : null}
      {open === 'disable' ? (
        <ConfirmDialog
          title="Disable rule"
          confirmLabel="Disable rule"
          theme="danger"
          successMessage="Rule disabled."
          input={{ action: 'rule.disable', ruleId: rule.id }}
          summary={
            <>
              <p>The rule stops being evaluated. It can be edited and approved again later.</p>
              <RuleSummary rule={rule} />
            </>
          }
          onClose={() => setOpen(null)}
          onDone={done}
        />
      ) : null}
    </div>
  );
}

function WindowEditorDialog({
  viewer,
  onClose,
  onDone,
}: {
  viewer: Viewer | null;
  onClose: () => void;
  onDone: Notify;
}) {
  const [values, setValues] = useState<WindowFormValues>(emptyWindowForm());
  const [errors, setErrors] = useState<FieldErrors>({});
  const runner = useServerWrite(performAlertingAction);
  const close = closeAfterWrite(runner, onClose);
  const { organisationScope } = canCreateWindow(viewer);

  async function submit(event: React.FormEvent) {
    event.preventDefault();
    const built = buildWindowRequest(values, Date.now());
    if (!built.ok) {
      setErrors(built.errors);
      return;
    }
    setErrors({});
    if (await runner.submit({ action: 'window.create', values })) onDone('Maintenance window scheduled.');
  }

  return (
    <ActionDialog title="Schedule a maintenance window" onClose={close} busy={runner.pending}>
      <form onSubmit={submit} noValidate aria-busy={runner.pending}>
        <p className="small text-body-secondary">
          Rules in scope hold their notifications (or stop evaluating, with the organisation
          permission) while the window is active. Windows are audited and can be cancelled.
        </p>
        {errors._form ? (
          <div className="alert alert-warning py-2" role="alert">
            {errors._form}
          </div>
        ) : null}
        <WindowFormFields
          values={values}
          errors={errors}
          disabled={runner.pending}
          organisationScope={organisationScope}
          onChange={setValues}
        />
        <div aria-live="polite">
          <WriteFeedback result={runner.result} currentPath={PATH} onReload={runner.reload} />
        </div>
        <FormFooter
          pending={runner.pending}
          locked={runner.unconfirmed}
          label="Schedule window"
          onCancel={close}
        />
      </form>
    </ActionDialog>
  );
}

export function NewWindowButton({
  viewer,
  unavailableReason = null,
}: {
  viewer: Viewer | null;
  /** Set when the backing store cannot take a write; shown after the permission reason. */
  unavailableReason?: string | null;
}) {
  const [open, setOpen] = useState(false);
  const [notice, setNotice] = useState<string | null>(null);
  const permission = canCreateWindow(viewer);
  const gate =
    permission.enabled && unavailableReason !== null
      ? { ...permission, enabled: false, reason: unavailableReason }
      : permission;
  const noteId = useId();
  return (
    <div>
      <button
        type="button"
        className="btn btn-sm btn-primary"
        disabled={!gate.enabled}
        aria-describedby={gate.enabled ? undefined : noteId}
        onClick={() => {
          setNotice(null);
          setOpen(true);
        }}
      >
        <i className="bi bi-plus-lg me-1" aria-hidden="true" />
        New window
      </button>
      {!gate.enabled ? <DisabledReason id={noteId}>{gate.reason}</DisabledReason> : null}
      <span aria-live="polite">{notice !== null ? <span className="ms-2 small text-success">{notice}</span> : null}</span>
      {open ? (
        <WindowEditorDialog
          viewer={viewer}
          onClose={() => setOpen(false)}
          onDone={(message) => {
            setOpen(false);
            setNotice(message);
          }}
        />
      ) : null}
    </div>
  );
}

export function WindowRowActions({
  window,
  viewer,
  nowMs,
}: {
  window: MaintenanceWindow;
  viewer: Viewer | null;
  nowMs: number;
}) {
  const [open, setOpen] = useState(false);
  const [notice, setNotice] = useState<string | null>(null);
  const noteId = useId();
  const { cancel } = availableWindowActions(window, viewer, nowMs);
  return (
    <div>
      <button
        type="button"
        className="btn btn-outline-secondary btn-sm"
        disabled={!cancel.enabled}
        aria-describedby={cancel.enabled ? undefined : noteId}
        onClick={() => {
          setNotice(null);
          setOpen(true);
        }}
      >
        Cancel window
      </button>
      {!cancel.enabled ? <DisabledReason id={noteId}>{cancel.reason}</DisabledReason> : null}
      <span aria-live="polite">{notice !== null ? <span className="d-block small text-success">{notice}</span> : null}</span>
      {open ? (
        <ConfirmDialog
          title="Cancel maintenance window"
          confirmLabel="Cancel window"
          theme="danger"
          successMessage="Window cancelled."
          input={{ action: 'window.cancel', windowId: window.id }}
          summary={
            <>
              <p>
                Cancelling ends the silencing now: rules in scope resume notifying. The window stays
                in the list as cancelled.
              </p>
              <dl className="row mb-0 small">
                <dt className="col-4">Window</dt>
                <dd className="col-8 text-break">{window.name}</dd>
                <dt className="col-4">Scope</dt>
                <dd className="col-8 text-break">{describeScope(window.scope)}</dd>
              </dl>
            </>
          }
          onClose={() => setOpen(false)}
          onDone={(message) => {
            setOpen(false);
            setNotice(message);
          }}
        />
      ) : null}
    </div>
  );
}
