import type { CopilotAnswer, CopilotAsk, CopilotEvidence } from '@/lib/api-contracts-copilot';
import {
  TOOL_TITLES,
  askPresentation,
  evidenceAnchor,
  freshnessLabel,
  sourceLabel,
  toolPresentation,
} from '@/lib/copilot-view';
import { formatUtcTimestamp } from '@/lib/format-time';

/**
 * One answer for every outcome. The summary, facts, inferences and recommendations come from a
 * model that read untrusted text, and the evidence excerpts come from documents and devices: all of
 * it is rendered as text, never as markup or a link. The only links are the citations, built from
 * validated evidence ids and pointing at this page.
 */
function Citations({ ids }: { ids: readonly string[] }) {
  return (
    <span className="ms-1">
      {ids.map((id) => (
        <a key={id} className="badge text-bg-light border me-1" href={`#${evidenceAnchor(id)}`}>
          {id}
        </a>
      ))}
    </span>
  );
}

function Claims({ title, claims }: { title: string; claims: CopilotAnswer['facts'] }) {
  if (claims.length === 0) return null;
  return (
    <section className="mb-3">
      <h3 className="h6">{title}</h3>
      <ul className="mb-0">
        {claims.map((claim, index) => (
          <li key={index} className="text-break">
            {claim.text}
            <Citations ids={claim.evidence_ids} />
          </li>
        ))}
      </ul>
    </section>
  );
}

function Plain({ title, items }: { title: string; items: readonly string[] }) {
  if (items.length === 0) return null;
  return (
    <section className="mb-3">
      <h3 className="h6">{title}</h3>
      <ul className="mb-0">
        {items.map((text, index) => (
          <li key={index} className="text-break">
            {text}
          </li>
        ))}
      </ul>
    </section>
  );
}

function AnswerView({ answer }: { answer: CopilotAnswer }) {
  return (
    <div>
      <p className="lead text-break">{answer.summary}</p>
      <Claims title="Facts" claims={answer.facts} />
      <Claims title="Inferences" claims={answer.inferences} />
      <Plain title="Not known" items={answer.unknowns} />
      <Plain
        title="Suggested next steps for a person"
        items={answer.recommendations.map((r) => r.text)}
      />
    </div>
  );
}

function EvidenceList({ evidence }: { evidence: readonly CopilotEvidence[] }) {
  if (evidence.length === 0) return null;
  return (
    <section className="mt-3" aria-label="Evidence">
      <h3 className="h6">Evidence</h3>
      <ol className="list-unstyled small mb-0">
        {evidence.map((item) => (
          <li key={item.id} id={evidenceAnchor(item.id)} className="border-top py-2">
            <span className="badge text-bg-light border me-1">{item.id}</span>
            <span className="badge text-bg-secondary me-1">{sourceLabel(item.source)}</span>
            <span className="fw-semibold text-break">{item.title}</span>
            <div className="text-body-secondary">
              {freshnessLabel(item.freshness)}
              {item.observed_at === null ? '' : `, ${formatUtcTimestamp(item.observed_at)}`}
              {' · '}
              <code className="text-break">{item.reference}</code>
            </div>
            {item.instruction_like ? (
              <div className="text-warning-emphasis" role="note">
                <i className="bi bi-exclamation-triangle me-1" aria-hidden="true" />
                Reads like an instruction to an AI. It was treated as data only.
              </div>
            ) : null}
            <div className="text-break">{item.excerpt}</div>
          </li>
        ))}
      </ol>
    </section>
  );
}

function ToolList({ calls }: { calls: CopilotAsk['tool_calls'] }) {
  if (calls.length === 0) return null;
  return (
    <section className="mt-3" aria-label="Sources consulted">
      <h3 className="h6">Sources consulted</h3>
      <ul className="list-unstyled small mb-0">
        {calls.map((call) => {
          const view = toolPresentation(call.state);
          return (
            <li key={call.tool} title={view.detail}>
              <i className={`bi ${view.icon} me-1`} aria-hidden="true" />
              <span className="fw-semibold">{TOOL_TITLES[call.tool]}</span>
              {': '}
              {view.label}
              {call.state === 'ok' ? ` (${call.evidence_count} items)` : ''}
            </li>
          );
        })}
      </ul>
    </section>
  );
}

export function CopilotResult({ ask }: { ask: CopilotAsk }) {
  const view = askPresentation(ask.state);
  return (
    <div aria-live="polite">
      <div className="mb-3" role="status">
        <i className={`bi ${view.icon} me-1`} aria-hidden="true" />
        <span className="fw-semibold">{view.label}</span>
        <div className="small text-body-secondary">{view.detail}</div>
      </div>
      {ask.answer === null ? null : <AnswerView answer={ask.answer} />}
      <ToolList calls={ask.tool_calls} />
      <EvidenceList evidence={ask.evidence} />
      <p className="small text-body-secondary mt-3 mb-0">
        As of {formatUtcTimestamp(ask.generated_at)}.
      </p>
    </div>
  );
}
