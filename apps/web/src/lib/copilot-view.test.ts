import assert from 'node:assert/strict';
import test from 'node:test';

import {
  askPresentation,
  evidenceAnchor,
  freshnessLabel,
  sourceLabel,
  toolPresentation,
  validateQuestion,
} from './copilot-view.ts';

test('a question is trimmed and must be 3 to 1000 characters of real text', () => {
  assert.deepEqual(validateQuestion('  why is sw1 down?  '), { ok: true, question: 'why is sw1 down?' });
  assert.equal(validateQuestion('hi').ok, false);
  assert.equal(validateQuestion('   ').ok, false);
  assert.equal(validateQuestion('x'.repeat(1001)).ok, false);
  assert.equal(validateQuestion('\u0000\u200b\u202e  ').ok, false);
  assert.deepEqual(validateQuestion('why\u0000 is\u202e sw1 down?'), { ok: true, question: 'why is sw1 down?' });
});

test('every ask state has its own words, icon and a note that says what is not shown', () => {
  const seen = new Set<string>();
  for (const state of ['ok', 'not-connected', 'unknown', 'no-evidence'] as const) {
    const view = askPresentation(state);
    assert.ok(view.label.length > 0 && view.icon.startsWith('bi-'));
    seen.add(view.label);
  }
  assert.equal(seen.size, 4);
  assert.match(askPresentation('not-connected').detail, /no answer/i);
  assert.match(askPresentation('unknown').detail, /not shown|no answer/i);
  assert.match(askPresentation('no-evidence').detail, /not asked|not sent/i);
});

test('tool states are words, and a denial is a gap not an empty result', () => {
  assert.match(toolPresentation('denied').label, /not permitted/i);
  assert.match(toolPresentation('denied').detail, /gap|not consulted/i);
  assert.match(toolPresentation('not-connected').label, /not connected/i);
  assert.match(toolPresentation('unknown').label, /unreadable|unknown/i);
  assert.match(toolPresentation('ok').label, /read/i);
});

test('source and freshness labels never invent a state', () => {
  assert.equal(sourceLabel('knowledge'), 'Document');
  assert.equal(sourceLabel('incident'), 'Incident');
  assert.equal(freshnessLabel('stale'), 'Stale');
  assert.equal(freshnessLabel('unknown'), 'Age not known');
});

test('an evidence anchor is the validated id and nothing else', () => {
  assert.equal(evidenceAnchor('ev-001'), 'evidence-ev-001');
});
