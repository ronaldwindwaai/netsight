import '@/test/dom-setup';
import assert from 'node:assert/strict';
import { afterEach, it } from 'node:test';
import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { ReportCatalog } from '@/components/report-catalog';
import { PrintReport } from '@/components/print-report';
import { InternetSlaPanel } from '@/components/internet-sla-panel';
import { okState, slaFixture } from '@/test/internet-fixtures';
afterEach(() => cleanup());
it('only offers reports whose underlying data the caller may read', () => {
  render(<ReportCatalog permissions={['reports:read']} />);
  assert.equal(screen.queryByRole('link',{name:'Open report'}),null);
  assert.match(screen.getByRole('status').textContent ?? '',/No reports available/);
});
it('links to a real viewer rather than a placeholder or vendor UI', () => {
  render(<ReportCatalog permissions={['reports:read','internet:read']} />);
  assert.equal(screen.getByRole('link',{name:'Open report'}).getAttribute('href'),'/reports/wan-sla');
});
it('printing needs readable evidence and an explicit user click', () => {
  let calls=0; const original=window.print; window.print=()=>{calls++};
  try {
    const {rerender}=render(<PrintReport readable={false} />);
    const button=screen.getByRole('button',{name:/Print/}) as HTMLButtonElement;
    assert.equal(button.disabled,true);fireEvent.click(button);assert.equal(calls,0);
    rerender(<PrintReport readable />);fireEvent.click(screen.getByRole('button',{name:/Print/}));assert.equal(calls,1);
  } finally {window.print=original;}
});
it('report month selection stays in the report and exports keep the existing protected path', () => {
  const {container}=render(<InternetSlaPanel state={okState(slaFixture())} month="2026-09" months={['2026-09']} adjusted={false} canExport monthAction="/reports/wan-sla" />);
  assert.equal(container.querySelector('form')?.getAttribute('action'),'/reports/wan-sla');
  assert.equal(screen.getByRole('link',{name:/Download CSV/}).getAttribute('href'),'/internet/export?month=2026-09&format=csv');
});
