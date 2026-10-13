import assert from 'node:assert/strict';
import test from 'node:test';

import {
  COHORT_NOT_APPLIED,
  COHORT_SUFFICIENT,
  COHORT_TOO_FEW,
} from '../test/traffic-fixtures.ts';
import {
  cohortNotice,
  daylightSavingNotice,
  destinationScopeText,
  withheldCountText,
} from './traffic-view.ts';

test('the detail tier is told nothing about a cohort rule', () => {
  assert.equal(cohortNotice(COHORT_NOT_APPLIED, 'figures'), '');
});

test('a sufficient cohort says how many sources stand behind the figures', () => {
  const notice = cohortNotice(COHORT_SUFFICIENT, 'figures');
  assert.match(notice, /at least 5 internal endpoints/);
  assert.match(notice, /Smaller groups are never shown/);
});

test('too few sources is explained, not shown as an empty result', () => {
  const notice = cohortNotice(COHORT_TOO_FEW, 'figures');
  assert.match(notice, /fewer than 5 internal endpoints/);
  assert.match(notice, /withheld/);
  assert.match(notice, /traffic:read-detail/);
  assert.doesNotMatch(notice, /No /);
});

test('the notice uses the minimum the server stated', () => {
  assert.match(cohortNotice({ state: 'too-few-sources', minimum: 12 }, 'figures'), /fewer than 12/);
});

test('a withheld count says why instead of looking missing', () => {
  assert.equal(withheldCountText(COHORT_TOO_FEW), 'Withheld (fewer than 5)');
  assert.equal(withheldCountText({ state: 'sufficient', minimum: 5 }), 'Not reported');
  assert.equal(withheldCountText(COHORT_NOT_APPLIED), 'Not reported');
});

test('internal destinations are labelled, external ones are not', () => {
  assert.equal(destinationScopeText('internal'), 'Inside the organisation');
  assert.equal(destinationScopeText('external'), '');
});

test('a daylight-saving change in the baseline weeks is explained', () => {
  const notice = daylightSavingNotice('crossed', 'Europe/London');
  assert.match(notice, /daylight-saving change in Europe\/London/);
  assert.match(notice, /168-hour UTC weeks/);
  assert.match(notice, /scores are not affected/i);
  assert.match(notice, /outside working hours/i);
});

test('no change, or no zone, needs no notice', () => {
  assert.equal(daylightSavingNotice('none', 'Europe/London'), '');
  assert.equal(daylightSavingNotice('not-applicable', null), '');
});
