import type { CsvValue } from './csv.ts';
import type { ApplicationRow, DestinationRow } from './api-contracts-traffic-lists.ts';

/*
 * CSV rows for the traffic tables. They carry exactly what the page already shows: a row the server
 * withheld below the cohort minimum arrives with null values and is exported as empty cells, never
 * filled in. Source-reported text (domains, application names) goes out as data; csvCell neutralises
 * anything a spreadsheet could read as a formula.
 */

export const DESTINATION_CSV_HEADERS = [
  'Destination',
  'Domain',
  'ASN',
  'Country',
  'Visibility',
  'First seen (UTC)',
  'Last seen (UTC)',
  'Bytes',
  'Share',
  'Endpoints',
  'Reputation',
] as const;

export const APPLICATION_CSV_HEADERS = [
  'Application',
  'Category',
  'Visibility',
  'Bytes',
  'Share',
  'Endpoints',
  'Trend',
  'Risk',
  'Approval',
] as const;

export function destinationCsvRows(items: readonly DestinationRow[]): CsvValue[][] {
  return items.map((item) => [
    item.address,
    item.domain ?? '',
    item.asn === null ? '' : `AS${item.asn}`,
    item.country ?? '',
    item.visibility,
    item.first_seen ?? '',
    item.last_seen ?? '',
    item.bytes ?? '',
    item.share ?? '',
    item.endpoints ?? '',
    item.reputation,
  ]);
}

export function applicationCsvRows(items: readonly ApplicationRow[]): CsvValue[][] {
  return items.map((item) => [
    item.application,
    item.category ?? '',
    item.visibility,
    item.bytes ?? '',
    item.share ?? '',
    item.endpoints ?? '',
    item.trend.state,
    item.risk,
    item.approval,
  ]);
}
