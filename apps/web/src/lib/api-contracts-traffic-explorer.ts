/**
 * Step 7 traffic contracts, mirroring contracts/json-schema/traffic-flows.schema.json,
 * traffic-applications.schema.json, traffic-destinations.schema.json and traffic-anomalies.schema.json
 * (shared vectors: contracts/test-vectors/traffic.vectors.json). One module per surface, re-exported
 * here so callers have a single import.
 *
 * Every parser is fail-closed: anything that does not satisfy the exact contract returns null and the
 * caller must render an explicit error state, never a guess. A state that is not `ok` carries no
 * rows and no totals; a null value means "not reported", never zero. Names, domains, applications
 * and labels are untrusted source text: they are carried as data and never interpreted. A person is
 * only ever named with a basis, and an unknown or ambiguous answer names nobody.
 */
export * from './api-contracts-traffic-shared.ts';
export * from './api-contracts-traffic-cohort.ts';
export * from './api-contracts-traffic-flows.ts';
export * from './api-contracts-traffic-lists.ts';
export * from './api-contracts-traffic-anomalies.ts';
