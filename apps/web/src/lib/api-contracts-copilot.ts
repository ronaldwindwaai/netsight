import { isIntegerInRange, isOneOf, isText } from './contract-guards.ts';
import { exactRecord, isBoolean, isNullableTimestamp, type Raw } from './contract-helpers.ts';

/**
 * AI copilot contract, mirroring contracts/json-schema/copilot.schema.json (shared vectors:
 * contracts/test-vectors/copilot.vectors.json).
 *
 * Fail-closed: anything that does not satisfy the exact contract returns null and the caller renders
 * an explicit error state, never a guess. An answer is only accepted with evidence, and every
 * citation must point at an item of the same bundle. Titles, excerpts, references and every word of
 * the answer are untrusted text: bounded here and rendered as text only.
 */
export const ASK_STATES = ['ok', 'not-connected', 'unknown', 'no-evidence'] as const;
export const READ_STATES = ['ok', 'not-connected', 'unknown'] as const;
export const TOOL_STATES = ['ok', 'denied', 'not-connected', 'unknown'] as const;
export const TOOL_NAMES = ['search_knowledge', 'list_open_incidents'] as const;
export const EVIDENCE_SOURCES = ['knowledge', 'incident'] as const;
export const FRESHNESS = ['fresh', 'stale', 'unknown'] as const;

export type AskState = (typeof ASK_STATES)[number];
export type ReadState = (typeof READ_STATES)[number];
export type ToolState = (typeof TOOL_STATES)[number];
export type ToolName = (typeof TOOL_NAMES)[number];
export type EvidenceSource = (typeof EVIDENCE_SOURCES)[number];

export const MIN_QUESTION = 3;
export const MAX_QUESTION = 1000;
const MAX_EVIDENCE = 12;
const EVIDENCE_ID = /^ev-[0-9]{3}$/;
const PERMISSION = /^[a-z][a-z-]*:[a-z-]+$/;

export interface CopilotEvidence {
  id: string;
  source: EvidenceSource;
  kind: string;
  title: string;
  excerpt: string;
  reference: string;
  observed_at: string | null;
  freshness: 'fresh' | 'stale' | 'unknown';
  instruction_like: boolean;
}
export interface CopilotToolCall {
  tool: ToolName;
  state: ToolState;
  evidence_count: number;
}
export interface CopilotClaim {
  text: string;
  evidence_ids: string[];
}
export interface CopilotAnswer {
  summary: string;
  facts: CopilotClaim[];
  inferences: CopilotClaim[];
  unknowns: string[];
  recommendations: Array<{ text: string }>;
}
export interface CopilotAskRequest {
  question: string;
}
export interface CopilotAsk {
  state: AskState;
  generated_at: string;
  read_only: true;
  answer: CopilotAnswer | null;
  evidence: CopilotEvidence[];
  tool_calls: CopilotToolCall[];
}
export interface CopilotStatus {
  generated_at: string;
  read_only: true;
  model: { state: 'ok' | 'not-connected' };
  knowledge: { state: ReadState; documents: number; chunks: number };
  tools: Array<{ name: ToolName; description: string; permission: string; allowed: boolean }>;
}

// --- helpers ------------------------------------------------------------------------------------------------

function listOf<T>(value: unknown, maximum: number, parse: (item: unknown) => T | null): T[] | null {
  if (!Array.isArray(value) || value.length > maximum) return null;
  const out: T[] = [];
  for (const raw of value) {
    const parsed = parse(raw);
    if (parsed === null) return null;
    out.push(parsed);
  }
  return out;
}

const isEvidenceId = (value: unknown): value is string =>
  isText(value, 6, 6) && EVIDENCE_ID.test(value);

const isTime = (value: unknown): value is string => isNullableTimestamp(value) && value !== null;

// --- evidence, tool call, claim ----------------------------------------------------------------------------

export function parseCopilotEvidence(value: unknown): CopilotEvidence | null {
  const r = exactRecord(value, [
    'id',
    'source',
    'kind',
    'title',
    'excerpt',
    'reference',
    'observed_at',
    'freshness',
    'instruction_like',
  ]);
  if (
    r === null ||
    !isEvidenceId(r.id) ||
    !isOneOf(r.source, EVIDENCE_SOURCES) ||
    !isText(r.kind, 1, 32) ||
    !isText(r.title, 1, 200) ||
    !isText(r.excerpt, 1, 600) ||
    !isText(r.reference, 1, 200) ||
    !isNullableTimestamp(r.observed_at) ||
    !isOneOf(r.freshness, FRESHNESS) ||
    !isBoolean(r.instruction_like)
  ) {
    return null;
  }
  return r as unknown as CopilotEvidence;
}

export function parseCopilotToolCall(value: unknown): CopilotToolCall | null {
  const r = exactRecord(value, ['tool', 'state', 'evidence_count']);
  if (
    r === null ||
    !isOneOf(r.tool, TOOL_NAMES) ||
    !isOneOf(r.state, TOOL_STATES) ||
    !isIntegerInRange(r.evidence_count, 0, MAX_EVIDENCE) ||
    (r.state !== 'ok' && r.evidence_count !== 0)
  ) {
    return null;
  }
  return { tool: r.tool, state: r.state, evidence_count: r.evidence_count };
}

export function parseCopilotClaim(value: unknown): CopilotClaim | null {
  const r = exactRecord(value, ['text', 'evidence_ids']);
  if (r === null || !isText(r.text, 1, 500)) return null;
  const ids = listOf(r.evidence_ids, 8, (id) => (isEvidenceId(id) ? id : null));
  if (ids === null || ids.length < 1 || new Set(ids).size !== ids.length) return null;
  return { text: r.text, evidence_ids: ids };
}

export function parseCopilotAnswer(value: unknown): CopilotAnswer | null {
  const r = exactRecord(value, ['summary', 'facts', 'inferences', 'unknowns', 'recommendations']);
  if (r === null || !isText(r.summary, 1, 800)) return null;
  const facts = listOf(r.facts, 10, parseCopilotClaim);
  const inferences = listOf(r.inferences, 10, parseCopilotClaim);
  const unknowns = listOf(r.unknowns, 10, (u) => (isText(u, 1, 300) ? u : null));
  const recommendations = listOf(r.recommendations, 8, (item) => {
    const rec = exactRecord(item, ['text']);
    return rec !== null && isText(rec.text, 1, 400) ? { text: rec.text } : null;
  });
  if (facts === null || inferences === null || unknowns === null || recommendations === null) {
    return null;
  }
  return { summary: r.summary, facts, inferences, unknowns, recommendations };
}

export function parseCopilotAskRequest(value: unknown): CopilotAskRequest | null {
  const r = exactRecord(value, ['question']);
  if (r === null || !isText(r.question, MIN_QUESTION, MAX_QUESTION)) return null;
  return { question: r.question };
}

// --- responses -----------------------------------------------------------------------------------------------

function groundedIn(answer: CopilotAnswer, evidence: CopilotEvidence[]): boolean {
  const known = new Set(evidence.map((item) => item.id));
  return [...answer.facts, ...answer.inferences].every((claim) =>
    claim.evidence_ids.every((id) => known.has(id)),
  );
}

export function parseCopilotAsk(value: unknown): CopilotAsk | null {
  const r = exactRecord(value, ['state', 'generated_at', 'read_only', 'answer', 'evidence', 'tool_calls']);
  if (
    r === null ||
    !isOneOf(r.state, ASK_STATES) ||
    !isTime(r.generated_at) ||
    r.read_only !== true
  ) {
    return null;
  }
  const evidence = listOf(r.evidence, MAX_EVIDENCE, parseCopilotEvidence);
  const calls = listOf(r.tool_calls, 8, parseCopilotToolCall);
  if (evidence === null || calls === null) return null;
  if (new Set(evidence.map((item) => item.id)).size !== evidence.length) return null;
  const answer = r.answer === null ? null : parseCopilotAnswer(r.answer);
  if (r.answer !== null && answer === null) return null;
  if ((r.state === 'ok') !== (answer !== null)) return null;
  if (r.state === 'ok' && evidence.length === 0) return null;
  if ((r.state === 'not-connected' || r.state === 'no-evidence') && evidence.length > 0) return null;
  if (r.state === 'not-connected' && calls.length > 0) return null;
  if (answer !== null && !groundedIn(answer, evidence)) return null;
  return {
    state: r.state,
    generated_at: r.generated_at,
    read_only: true,
    answer,
    evidence,
    tool_calls: calls,
  };
}

export function parseCopilotStatus(value: unknown): CopilotStatus | null {
  const r = exactRecord(value, ['generated_at', 'read_only', 'model', 'knowledge', 'tools']);
  if (r === null || !isTime(r.generated_at) || r.read_only !== true) return null;
  const model = exactRecord(r.model, ['state']);
  if (model === null || (model.state !== 'ok' && model.state !== 'not-connected')) return null;
  const knowledge: Raw | null = exactRecord(r.knowledge, ['state', 'documents', 'chunks']);
  if (
    knowledge === null ||
    !isOneOf(knowledge.state, READ_STATES) ||
    !isIntegerInRange(knowledge.documents, 0, 5000) ||
    !isIntegerInRange(knowledge.chunks, 0, 50000) ||
    (knowledge.state !== 'ok' && (knowledge.documents !== 0 || knowledge.chunks !== 0))
  ) {
    return null;
  }
  const tools = listOf(r.tools, 8, (item) => {
    const tool = exactRecord(item, ['name', 'description', 'permission', 'allowed']);
    if (
      tool === null ||
      !isOneOf(tool.name, TOOL_NAMES) ||
      !isText(tool.description, 1, 200) ||
      !isText(tool.permission, 3, 64) ||
      !PERMISSION.test(tool.permission) ||
      !isBoolean(tool.allowed)
    ) {
      return null;
    }
    return tool as unknown as CopilotStatus['tools'][number];
  });
  if (tools === null) return null;
  return {
    generated_at: r.generated_at,
    read_only: true,
    model: { state: model.state },
    knowledge: {
      state: knowledge.state,
      documents: knowledge.documents,
      chunks: knowledge.chunks,
    },
    tools,
  };
}
