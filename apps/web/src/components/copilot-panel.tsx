'use client';

import { useRef, useState } from 'react';

import { askCopilot } from '@/app/(dashboard)/copilot/actions';
import { CopilotResult } from '@/components/copilot-result';
import type { CopilotStatus } from '@/lib/api-contracts-copilot';
import { MAX_QUESTION } from '@/lib/api-contracts-copilot';
import { validateQuestion, type AskActionResult } from '@/lib/copilot-view';

/**
 * The question form. It validates the question, sends it once through the server action (which adds
 * the session and CSRF token server-side) and shows exactly what came back: an answer with its
 * evidence, or the reason there is none. A thrown action is an unknown result, never a success.
 */
export function CopilotPanel({ status }: { status: CopilotStatus }) {
  const [text, setText] = useState('');
  const [problem, setProblem] = useState<string | null>(null);
  const [pending, setPending] = useState(false);
  const [result, setResult] = useState<AskActionResult | null>(null);
  const inFlight = useRef(false);
  const connected = status.model.state === 'ok';

  async function submit(event: { preventDefault: () => void }) {
    event.preventDefault();
    if (inFlight.current || !connected) return;
    const checked = validateQuestion(text);
    if (!checked.ok) {
      setProblem(checked.message);
      return;
    }
    setProblem(null);
    inFlight.current = true;
    setPending(true);
    setResult(null);
    try {
      setResult(await askCopilot(checked.question));
    } catch {
      setResult({
        ok: false,
        title: 'The result is not known',
        message: 'The request did not return a usable answer. Nothing was changed; you can ask again.',
        correlationId: 'not-available',
      });
    } finally {
      inFlight.current = false;
      setPending(false);
    }
  }

  return (
    <div>
      <form onSubmit={(event) => void submit(event)} noValidate>
        <label htmlFor="copilot-question" className="form-label fw-semibold">
          Question
        </label>
        <textarea
          id="copilot-question"
          className="form-control mb-2"
          rows={3}
          maxLength={MAX_QUESTION}
          value={text}
          onChange={(event) => setText(event.target.value)}
          disabled={!connected}
          aria-describedby="copilot-help"
        />
        <p id="copilot-help" className="small text-body-secondary mb-2">
          {connected
            ? 'Your question and the evidence found are sent to the configured AI model. Do not paste secrets.'
            : 'Asking is turned off because no AI model is configured for this deployment.'}
        </p>
        {problem === null ? null : (
          <p className="text-danger small" role="alert">
            {problem}
          </p>
        )}
        <button type="submit" className="btn btn-primary btn-sm" disabled={pending || !connected}>
          {pending ? 'Asking…' : 'Ask'}
        </button>
      </form>
      <div className="mt-3" aria-live="polite">
        {result === null ? null : result.ok ? (
          <CopilotResult ask={result.ask} />
        ) : (
          <div className="alert alert-danger py-2 mb-0" role="alert">
            <p className="fw-semibold mb-1">
              <i className="bi bi-exclamation-octagon me-1" aria-hidden="true" />
              {result.title}
            </p>
            <p className="mb-1">{result.message}</p>
            <small className="text-body-secondary">
              Reference: <code>{result.correlationId}</code>
            </small>
          </div>
        )}
      </div>
    </div>
  );
}
