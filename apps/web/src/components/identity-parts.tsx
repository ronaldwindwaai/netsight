/**
 * Shared building blocks for the identity surfaces: the basis badge, evidence drill-down, a
 * correlation link, the attribution headline and the evidence-source notices.
 *
 * Every correlation is shown with its basis as a word and an icon (never colour alone), its
 * confidence, the window it holds for, the time it was computed and the evidence behind it. An
 * uncertain correlation is never worded as fact: inferred reads "possibly", unknown reads "Not
 * identified" with the reason, and an ambiguous one lists every candidate and selects none. Every
 * label (a name, a hostname) is untrusted source text and is rendered as text, never as markup.
 */
import { Alert } from '@adminlte/react';

import type {
  Attribution,
  Candidate,
  EntityRef,
  EvidenceRef,
  IdentityLink,
  SourceStatus,
  Basis,
} from '@/lib/api-contracts-identity';
import { formatUtcTimestamp } from '@/lib/format-time';
import {
  attributionHeadline,
  basisPresentation,
  confidenceText,
  entityKindLabel,
  entityText,
  evidenceKindLabel,
  reasonText,
  relationLabel,
  sourceProblems,
  validityText,
} from '@/lib/identity-view';

export function BasisBadge({ basis }: { basis: Basis }) {
  const view = basisPresentation(basis);
  return (
    <span className={`badge rounded-pill text-bg-${view.theme}`} title={view.explanation}>
      <i className={`bi ${view.icon} me-1`} aria-hidden="true" />
      {view.label}
    </span>
  );
}

export function EntityName({ entity }: { entity: EntityRef | null }) {
  if (entity === null) return <span className="fst-italic">{entityText(null)}</span>;
  return (
    <span>
      <span className="small text-body-secondary">{entityKindLabel(entity.type)}</span>{' '}
      <span className="fw-semibold">{entityText(entity)}</span>
    </span>
  );
}

function windowText(item: EvidenceRef): string {
  const from = formatUtcTimestamp(item.valid_from);
  return item.valid_to === null
    ? `valid from ${from}, no end recorded`
    : `valid ${from} to ${formatUtcTimestamp(item.valid_to)}`;
}

/** The records behind a correlation, behind a native disclosure so a page of links stays scannable. */
export function EvidenceList({ evidence }: { evidence: readonly EvidenceRef[] }) {
  if (evidence.length === 0) {
    return <p className="small text-body-secondary mb-0">No evidence recorded.</p>;
  }
  return (
    <details className="identity-evidence small">
      <summary>Evidence ({evidence.length})</summary>
      <div className="mt-1">
        {evidence.map((item) => (
          <p className="mb-1" key={item.id}>
            <strong>{evidenceKindLabel(item.kind)}</strong> from <code>{item.source}</code>,
            confidence {confidenceText(item.confidence)}, observed{' '}
            {formatUtcTimestamp(item.observed_at)}, {windowText(item)}. Record <code>{item.id}</code>
          </p>
        ))}
      </div>
    </details>
  );
}

function CandidateItems({ candidates }: { candidates: readonly Candidate[] }) {
  return (
    <ul className="list-unstyled ms-3 mb-1">
      {candidates.map((candidate) => (
        <li key={`${candidate.entity.type}:${candidate.entity.id}`} className="py-1">
          <EntityName entity={candidate.entity} /> <BasisBadge basis={candidate.basis} />{' '}
          <span className="small text-body-secondary">
            confidence {confidenceText(candidate.confidence)}
          </span>
          <EvidenceList evidence={candidate.evidence} />
        </li>
      ))}
    </ul>
  );
}

function LinkItem({ link }: { link: IdentityLink }) {
  const reason = reasonText(link.reason);
  return (
    <li className="identity-link border-bottom py-2">
      <div className="d-flex flex-wrap align-items-center gap-2">
        <span className="fw-semibold">{relationLabel(link.relation)}</span>
        <BasisBadge basis={link.basis} />
        <span className="small text-body-secondary">
          confidence {confidenceText(link.confidence)}
        </span>
      </div>
      <div className="my-1">
        <EntityName entity={link.source} /> <i className="bi bi-arrow-right mx-1" aria-hidden="true" />
        <EntityName entity={link.target} />
      </div>
      {reason.length > 0 ? <p className="small text-body-secondary mb-1">{reason}</p> : null}
      {link.ambiguous ? (
        <div className="mb-1">
          <p className="small mb-0">
            {link.candidates.length} candidates conflict; none is selected.
          </p>
          <CandidateItems candidates={link.candidates} />
        </div>
      ) : null}
      <p className="small text-body-secondary mb-1">
        {validityText(link)} · as of {formatUtcTimestamp(link.as_of)}
      </p>
      <EvidenceList evidence={link.evidence} />
    </li>
  );
}

export function LinkList({ label, links }: { label: string; links: readonly IdentityLink[] }) {
  if (links.length === 0) return null;
  return (
    <div role="group" aria-label={label}>
      <ul className="list-unstyled mb-0">
        {links.map((link, index) => (
          <LinkItem
            key={`${link.relation}:${link.source.id}:${link.target?.id ?? 'none'}:${index}`}
            link={link}
          />
        ))}
      </ul>
    </div>
  );
}

/** The answer to "who is behind this": the headline, why, and every link or candidate behind it. */
export function AttributionPanel({ attribution }: { attribution: Attribution }) {
  const headline = attributionHeadline(attribution);
  return (
    <section aria-label="Who is behind it" className="identity-attribution mb-3">
      <div className="d-flex flex-wrap align-items-center gap-2">
        <h3 className="h5 mb-0">{headline.title}</h3>
        <BasisBadge basis={attribution.basis} />
      </div>
      <p className="text-body-secondary mb-2">{headline.detail}</p>
      <LinkList label="Identity links" links={attribution.links} />
      {attribution.ambiguous ? (
        <>
          <p className="small mb-0">Each candidate is shown with its own basis; none is selected.</p>
          <CandidateItems candidates={attribution.candidates} />
        </>
      ) : null}
    </section>
  );
}

const PROBLEM_TEXT = {
  'not-connected': () => 'not connected',
  unknown: () => 'could not be read',
} as const;

/** Names the sources that were not read, or are stale: missing evidence is unknown, not absent. */
export function SourceNotices({ sources }: { sources: readonly SourceStatus[] }) {
  const problems = sourceProblems(sources);
  if (problems.length === 0) return null;
  const staleAt = new Map(sources.map((item) => [item.source, item.freshness.observed_at]));
  const describe = (problem: ReturnType<typeof sourceProblems>[number]): string => {
    if (problem.kind === 'stale') {
      const observed = staleAt.get(problem.source);
      return observed === null || observed === undefined
        ? 'last evidence is old'
        : `last evidence ${formatUtcTimestamp(observed)}`;
    }
    return PROBLEM_TEXT[problem.kind]();
  };
  return (
    <Alert theme="warning" title="Partial evidence" icon="bi bi-exclamation-triangle">
      {' '}
      <span>
        {problems.map((problem) => `${problem.source}: ${describe(problem)}`).join('; ')}. Treat the
        absence of evidence from these sources as unknown, not as proof.
      </span>
    </Alert>
  );
}
