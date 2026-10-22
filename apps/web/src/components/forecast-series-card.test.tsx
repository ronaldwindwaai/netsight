import '@/test/dom-setup';

import assert from 'node:assert/strict';
import { afterEach, describe, it } from 'node:test';

import { cleanup, render, screen } from '@testing-library/react';

import { ForecastSeriesCard } from '@/components/forecast-series-card';
import { reasonText } from '@/lib/forecast-view';
import { offSeries } from '@/test/forecast-fixtures';

afterEach(cleanup);

describe('ForecastSeriesCard without a forecast', () => {
  it('shows a source detail that repeats the reason once', () => {
    const text = reasonText('no-source');
    render(<ForecastSeriesCard series={offSeries('traffic-volume', { reason: 'no-source', detail: text })} />);

    assert.equal(screen.getAllByText(text).length, 1);
  });

  it('keeps a detail that adds something to the reason', () => {
    render(
      <ForecastSeriesCard
        series={offSeries('traffic-volume', { reason: 'no-source', detail: 'Last read failed at 02:10 UTC.' })}
      />,
    );

    assert.ok(screen.getByText(reasonText('no-source')));
    assert.ok(screen.getByText('Last read failed at 02:10 UTC.'));
  });
});
