import assert from 'node:assert/strict';
import test from 'node:test';
import { reportTemplate, visibleReports } from './report-catalog.ts';
test('report listing requires both report and underlying source permissions', () => {
  for (const permissions of [null, [], ['reports:read'], ['internet:read']]) assert.equal(visibleReports(permissions).length,0);
  assert.equal(visibleReports(['reports:read','internet:read'])[0]?.id,'wan-sla');
});
test('unknown report identifiers never become source paths', () => {
  for (const id of ['../admin','https://attacker.test','wan-sla?month=secret','']) assert.equal(reportTemplate(id),null);
  assert.equal(reportTemplate('wan-sla')?.title,'Monthly WAN availability');
});
