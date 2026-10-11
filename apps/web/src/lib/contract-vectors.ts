// Test-only helper: loads the shared contract vectors that also drive the
// Python four-way agreement tests (contracts/test-vectors).
import { readFileSync } from 'node:fs';

export interface VectorCase {
  name: string;
  valid: boolean;
  set?: Record<string, unknown>;
  delete?: string[];
  jsonschema_rejects?: boolean;
}

export interface VectorBlock {
  base: Record<string, unknown>;
  cases: VectorCase[];
}

const VECTOR_URL = new URL(
  '../../../../contracts/test-vectors/incident-alert.vectors.json',
  import.meta.url,
);

const DIAGNOSTIC_VECTOR_URL = new URL(
  '../../../../contracts/test-vectors/diagnostic.vectors.json',
  import.meta.url,
);

const DIAGNOSTIC_SESSION_VECTOR_URL = new URL(
  '../../../../contracts/test-vectors/diagnostic-session.vectors.json',
  import.meta.url,
);

const INTERNET_VECTOR_URL = new URL(
  '../../../../contracts/test-vectors/internet.vectors.json',
  import.meta.url,
);

const IDENTITY_VECTOR_URL = new URL(
  '../../../../contracts/test-vectors/identity.vectors.json',
  import.meta.url,
);

const TRAFFIC_VECTOR_URL = new URL(
  '../../../../contracts/test-vectors/traffic.vectors.json',
  import.meta.url,
);

export function loadTrafficVectors(): Record<string, VectorBlock> {
  return JSON.parse(readFileSync(TRAFFIC_VECTOR_URL, 'utf-8')) as Record<string, VectorBlock>;
}

export function loadIdentityVectors(): Record<string, VectorBlock> {
  return JSON.parse(readFileSync(IDENTITY_VECTOR_URL, 'utf-8')) as Record<string, VectorBlock>;
}

export function loadInternetVectors(): Record<string, VectorBlock> {
  return JSON.parse(readFileSync(INTERNET_VECTOR_URL, 'utf-8')) as Record<string, VectorBlock>;
}

export function loadDiagnosticSessionVectors(): Record<string, VectorBlock> {
  return JSON.parse(readFileSync(DIAGNOSTIC_SESSION_VECTOR_URL, 'utf-8')) as Record<
    string,
    VectorBlock
  >;
}

export function loadVectors(): Record<string, VectorBlock> {
  return JSON.parse(readFileSync(VECTOR_URL, 'utf-8')) as Record<string, VectorBlock>;
}

export function loadDiagnosticVectors(): Record<string, VectorBlock> {
  return JSON.parse(readFileSync(DIAGNOSTIC_VECTOR_URL, 'utf-8')) as Record<string, VectorBlock>;
}

function walk(root: unknown, parts: string[]): Record<string, unknown> | unknown[] {
  let node = root;
  for (const part of parts) {
    node = Array.isArray(node) ? node[Number(part)] : (node as Record<string, unknown>)[part];
  }
  return node as Record<string, unknown> | unknown[];
}

export function buildInstance(block: VectorBlock, vector: VectorCase): unknown {
  const instance = structuredClone(block.base);
  for (const [path, value] of Object.entries(vector.set ?? {})) {
    const parts = path.split('.');
    const leaf = parts.pop() as string;
    const parent = walk(instance, parts);
    if (Array.isArray(parent)) parent[Number(leaf)] = structuredClone(value);
    else parent[leaf] = structuredClone(value);
  }
  for (const path of vector.delete ?? []) {
    const parts = path.split('.');
    const leaf = parts.pop() as string;
    delete (walk(instance, parts) as Record<string, unknown>)[leaf];
  }
  return instance;
}
