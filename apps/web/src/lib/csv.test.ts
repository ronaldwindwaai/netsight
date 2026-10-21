import assert from 'node:assert/strict';
import { describe, it } from 'node:test';

import { csvCell, csvFilename, toCsv } from './csv.ts';

describe('csvCell', () => {
  it('leaves plain text alone', () => {
    assert.equal(csvCell('core-sw-1'), 'core-sw-1');
  });

  it('quotes cells holding commas, quotes or line breaks and doubles inner quotes', () => {
    assert.equal(csvCell('a,b'), '"a,b"');
    assert.equal(csvCell('say "hi"'), '"say ""hi"""');
    assert.equal(csvCell('a\nb'), '"a\nb"');
    assert.equal(csvCell('a\rb'), '"a\rb"');
  });

  it('neutralises spreadsheet formulas with a leading quote', () => {
    for (const lead of ['=', '+', '-', '@']) {
      assert.equal(csvCell(`${lead}SUM(A1)`), `'${lead}SUM(A1)`);
    }
  });

  it('neutralises formulas that start with tab or carriage return', () => {
    assert.equal(csvCell('\t=1+1'), "'\t=1+1");
    assert.equal(csvCell('\r=1+1'), `"'\r=1+1"`);
  });

  it('escapes the formula prefix before quoting', () => {
    assert.equal(csvCell('=HYPERLINK("x","y")'), `"'=HYPERLINK(""x"",""y"")"`);
  });

  it('renders null and undefined as empty and numbers as digits', () => {
    assert.equal(csvCell(null), '');
    assert.equal(csvCell(undefined), '');
    assert.equal(csvCell(42), '42');
    assert.equal(csvCell(-5), '-5');
  });
});

describe('toCsv', () => {
  it('writes a header row and CRLF-terminated rows', () => {
    assert.equal(toCsv(['A', 'B'], [['1', 'x,y']]), 'A,B\r\n1,"x,y"\r\n');
  });

  it('writes only the header when there are no rows', () => {
    assert.equal(toCsv(['A'], []), 'A\r\n');
  });

  it('escapes header cells too', () => {
    assert.equal(toCsv(['=bad'], []), "'=bad\r\n");
  });
});

describe('csvFilename', () => {
  it('builds a dated, filesystem-safe name', () => {
    assert.equal(csvFilename('Devices / UK', new Date('2026-10-21T10:00:00Z')), 'devices-uk-2026-10-21.csv');
  });
});
