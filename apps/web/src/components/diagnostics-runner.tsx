'use client';

import Link from 'next/link';
import { useState } from 'react';
import { Alert, Spinner } from '@adminlte/react';
import { AppCard } from '@/components/app-card';

import { createDiagnosticRun, type DiagnosticActionResult } from '@/app/(dashboard)/diagnostics/actions';
import { DataFailure } from '@/components/data-state';
import { DiagnosticRunView } from '@/components/diagnostic-run-view';
import { StateSurface } from '@/components/state-surface';
import { sessionHref } from '@/lib/diagnostic-session-view';
import {
  DEFAULT_DIAGNOSTIC_CHECKS,
  DIAGNOSTIC_CHECK_OPTIONS,
  checkDetail,
} from '@/lib/diagnostic-view';
import type { DiagnosticCheckKind } from '@/lib/api-contracts-diagnostic';

const FREE_TEXT_NOTICE_ID = 'diagnostic-free-text-notice';

/** The target and symptom are free text that is stored with the session and shown to its readers. */
function FreeTextNotice() {
  return (
    <p
      id={FREE_TEXT_NOTICE_ID}
      role="note"
      aria-label="Free text warning"
      className="form-text mb-0"
    >
      <i className="bi bi-exclamation-triangle me-1" aria-hidden="true" />
      Do not paste secrets (passwords, tokens, keys) or personal data into the target or symptom.
      Both are stored with the session and shown to everyone who can read diagnostics; how long
      sessions are kept has not been decided yet.
    </p>
  );
}

function NotConnectedSurface() {
  return (
    <StateSurface
      icon="bi bi-plug"
      title="Probe capability not connected"
      detail="A probe allow-list must be configured (BLACKBOX_ALLOWED_TARGETS) before Netsight can run checks. This is not the same as the target being healthy."
    />
  );
}

function UnknownSurface() {
  return (
    <StateSurface
      icon="bi bi-question-circle"
      title="Diagnostic state unknown"
      detail="The probe service could not complete this run. Nothing is estimated in its place."
    />
  );
}

function IdleSurface() {
  return (
    <StateSurface
      icon="bi bi-clipboard2-pulse"
      title="No diagnostic run yet"
      detail="Enter a target and select checks, then run a read-only diagnostic. Results are evidence from the configured probe assets and monitored sources only."
    />
  );
}

function Results({ result, running }: { result: DiagnosticActionResult | null; running: boolean }) {
  if (running) {
    return (
      <div className="p-3">
        <Spinner theme="primary" label="Running diagnostic checks" />
        <p className="mt-3 mb-0 small text-body-secondary">
          Running up to {DIAGNOSTIC_CHECK_OPTIONS.length} bounded checks… this can take around
          twenty seconds.
        </p>
      </div>
    );
  }
  if (result === null) {
    return (
      <div className="p-3">
        <IdleSurface />
      </div>
    );
  }
  if (!result.ok) {
    return (
      <div className="p-3">
        <Alert theme="danger" title="The diagnostic run could not start" icon="bi bi-exclamation-triangle">
          {' '}
          <span>{result.message}</span>
        </Alert>
      </div>
    );
  }
  if (result.state.kind !== 'ok') {
    return (
      <div className="p-3">
        <DataFailure state={result.state} />
      </div>
    );
  }
  if (result.state.data.state === 'not-connected') {
    return (
      <div className="p-3">
        <NotConnectedSurface />
      </div>
    );
  }
  if (result.state.data.state === 'unknown') {
    return (
      <div className="p-3">
        <UnknownSurface />
      </div>
    );
  }
  if (result.state.data.run === null) {
    return (
      <div className="p-3">
        <StateSurface
          icon="bi bi-exclamation-octagon"
          title="The run had no result"
          detail="The API reported an ok state without a run record; this should never happen."
        />
      </div>
    );
  }
  const run = result.state.data.run;
  const href = result.state.data.stored ? sessionHref(run.id) : null;
  return (
    <>
      <div className="px-3 pt-3">
        {href !== null ? (
          <Link className="btn btn-outline-primary btn-sm" href={href}>
            <i className="bi bi-journal-text me-1" aria-hidden="true" />
            Open stored session (probable cause, locations, path, recent changes)
          </Link>
        ) : (
          <p className="small text-body-secondary mb-0">
            This run was not stored, so it cannot be revisited: no session store is connected or it
            could not be written.
          </p>
        )}
      </div>
      <DiagnosticRunView run={run} />
    </>
  );
}

export function DiagnosticsRunner({
  initialTarget,
}: {
  initialTarget?: string | null;
}) {
  const [target, setTarget] = useState(initialTarget ?? '');
  const [symptom, setSymptom] = useState('');
  const [checks, setChecks] = useState<readonly DiagnosticCheckKind[]>(DEFAULT_DIAGNOSTIC_CHECKS);
  const [result, setResult] = useState<DiagnosticActionResult | null>(null);
  const [running, setRunning] = useState(false);

  function toggleCheck(kind: DiagnosticCheckKind) {
    setChecks((current) => {
      if (current.includes(kind)) return current.filter((item) => item !== kind);
      if (current.length >= DIAGNOSTIC_CHECK_OPTIONS.length) return current;
      return [...current, kind];
    });
  }

  async function onSubmit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setRunning(true);
    setResult(null);
    try {
      const next = await createDiagnosticRun({ target, symptom, checks: [...checks] });
      setResult(next);
    } catch {
      setResult({ ok: false, message: 'The diagnostic service did not respond.' });
    } finally {
      setRunning(false);
    }
  }

  return (
    <>
      <AppCard
        className="operational-card mb-3"
        title="Automated diagnostic"
        icon="bi bi-clipboard2-pulse"
        variant="outline"
        theme="primary"
        bodyClass="p-3"
      >
        <form onSubmit={onSubmit} aria-busy={running}>
          <div className="row g-3">
            <div className="col-md-9">
              <label className="form-label" htmlFor="diagnostic-target">
                Target
              </label>
              <input
                id="diagnostic-target"
                className="form-control"
                type="text"
                required
                maxLength={255}
                autoComplete="off"
                spellCheck={false}
                placeholder="hostname, FQDN or IP address"
                aria-describedby={FREE_TEXT_NOTICE_ID}
                value={target}
                onChange={(event) => setTarget(event.target.value)}
                disabled={running}
              />
            </div>
            <div className="col-md-3 d-flex align-items-end">
              <button type="submit" className="btn btn-primary w-100" disabled={running}>
                {running ? 'Running…' : 'Run diagnostic'}
              </button>
            </div>
            <div className="col-12">
              <label className="form-label" htmlFor="diagnostic-symptom">
                Symptom <span className="text-body-secondary">(optional)</span>
              </label>
              <textarea
                id="diagnostic-symptom"
                className="form-control"
                rows={2}
                maxLength={1000}
                placeholder="What is the failure the operator observed?"
                aria-describedby={FREE_TEXT_NOTICE_ID}
                value={symptom}
                onChange={(event) => setSymptom(event.target.value)}
                disabled={running}
              />
              <FreeTextNotice />
            </div>
          </div>

          <fieldset className="mt-3">
            <legend className="h6 fw-semibold">Checks ({checks.length} selected)</legend>
            <div className="row g-2">
              {DIAGNOSTIC_CHECK_OPTIONS.map((option) => {
                const selected = checks.includes(option.kind);
                return (
                  <div className="col-md-6" key={option.kind}>
                    <label className="form-check border rounded p-2 mb-0">
                      <input
                        className="form-check-input"
                        type="checkbox"
                        checked={selected}
                        onChange={() => toggleCheck(option.kind)}
                        disabled={running}
                      />
                      <span className="form-check-label fw-semibold">{option.label}</span>
                      <span className="d-block small text-body-secondary">{checkDetail(option.kind)}</span>
                    </label>
                  </div>
                );
              })}
            </div>
          </fieldset>
        </form>
      </AppCard>

      <p className="visually-hidden" role="status">
        {running
          ? 'Running diagnostic checks.'
          : result === null
            ? 'No diagnostic has been run.'
            : 'The diagnostic run has finished.'}
      </p>
      <Results result={result} running={running} />
    </>
  );
}