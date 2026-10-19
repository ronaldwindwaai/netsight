import type { AskState, CopilotAsk, EvidenceSource, ToolState } from './api-contracts-copilot.ts';
import { MAX_QUESTION, MIN_QUESTION } from './api-contracts-copilot.ts';

/**
 * Pure presentation rules for the AI copilot page. Every state of an answer is a different word and
 * icon so "the model is not connected", "the model failed", "there was nothing to read" and "here is
 * an answer" can never be mistaken for one another. Text from the model, documents and devices is
 * untrusted: nothing here builds markup from it.
 */
const INVISIBLE = /[\u0000-\u001f\u007f-\u009f\u200b-\u200f\u202a-\u202e\u2066-\u2069]/g;

export type QuestionCheck = { ok: true; question: string } | { ok: false; message: string };

export function validateQuestion(raw: string): QuestionCheck {
  const question = raw.replace(INVISIBLE, ' ').replace(/\s+/g, ' ').trim();
  const length = Array.from(question).length;
  if (length < MIN_QUESTION) {
    return { ok: false, message: `Ask a question of at least ${MIN_QUESTION} characters.` };
  }
  if (length > MAX_QUESTION) {
    return { ok: false, message: `Keep the question to ${MAX_QUESTION} characters or fewer.` };
  }
  return { ok: true, question };
}

export interface StatePresentation {
  label: string;
  icon: string;
  theme: 'success' | 'secondary' | 'warning' | 'info';
  detail: string;
}

const ASK: Record<AskState, StatePresentation> = {
  ok: {
    label: 'Answer from evidence',
    icon: 'bi-check-circle',
    theme: 'success',
    detail: 'Every fact and inference below cites evidence listed on this page. Read-only: nothing was changed.',
  },
  'not-connected': {
    label: 'AI model not connected',
    icon: 'bi-plug',
    theme: 'secondary',
    detail:
      'No AI model is configured for this deployment, so there is no answer and nothing was read. This is not the same as there being nothing to find.',
  },
  unknown: {
    label: 'No usable answer',
    icon: 'bi-question-circle',
    theme: 'warning',
    detail:
      'The model did not return an answer that met the contract (it failed, timed out, or cited evidence that was not provided), so its reply is not shown. The evidence gathered is listed below.',
  },
  'no-evidence': {
    label: 'No evidence found',
    icon: 'bi-search',
    theme: 'info',
    detail:
      'The sources returned nothing relevant, so the model was not asked: an answer without evidence would be a guess.',
  },
};

export function askPresentation(state: AskState): StatePresentation {
  return ASK[state];
}

const TOOL: Record<ToolState, { label: string; detail: string; icon: string }> = {
  ok: { label: 'Read', detail: 'The source was read.', icon: 'bi-check-circle' },
  denied: {
    label: 'Not permitted',
    detail: 'Your role cannot read this source, so it was not consulted. That is a gap, not an empty result.',
    icon: 'bi-shield-lock',
  },
  'not-connected': {
    label: 'Not connected',
    detail: 'This source is not configured, so it was not consulted.',
    icon: 'bi-plug',
  },
  unknown: {
    label: 'Unreadable',
    detail: 'This source is configured but could not be read. Nothing is estimated in its place.',
    icon: 'bi-question-circle',
  },
};

export function toolPresentation(state: ToolState): { label: string; detail: string; icon: string } {
  return TOOL[state];
}

const SOURCES: Record<EvidenceSource, string> = {
  knowledge: 'Document',
  incident: 'Incident',
};

export function sourceLabel(source: EvidenceSource): string {
  return SOURCES[source];
}

export function freshnessLabel(value: 'fresh' | 'stale' | 'unknown'): string {
  return value === 'fresh' ? 'Current' : value === 'stale' ? 'Stale' : 'Age not known';
}

export const TOOL_TITLES = {
  search_knowledge: 'Documents and runbooks',
  list_open_incidents: 'Open incidents',
} as const;

/** The id is already validated as `ev-NNN` by the parser; the anchor adds a fixed prefix only. */
export function evidenceAnchor(id: string): string {
  return `evidence-${id}`;
}

/** Plain serialisable data returned by the ask server action: the answer, or why there is none. */
export type AskActionResult =
  | { ok: true; ask: CopilotAsk }
  | { ok: false; title: string; message: string; correlationId: string };
