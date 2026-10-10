/**
 * Installs a jsdom window as the global DOM for component tests. Import this module first in
 * every `*.test.tsx`: React and Testing Library read `window`/`document` when they load.
 */
import { after } from 'node:test';

import { JSDOM } from 'jsdom';

const dom = new JSDOM('<!doctype html><html><body></body></html>', {
  url: 'https://noc.example.test/incidents/incident-1',
  pretendToBeVisual: true,
});

const target = globalThis as Record<string, unknown>;
for (const key of Object.getOwnPropertyNames(dom.window)) {
  if (key in target) continue;
  Object.defineProperty(target, key, {
    configurable: true,
    get: () => (dom.window as unknown as Record<string, unknown>)[key],
  });
}
for (const key of ['window', 'document', 'navigator', 'location', 'localStorage']) {
  Object.defineProperty(target, key, {
    configurable: true,
    get: () => (dom.window as unknown as Record<string, unknown>)[key],
  });
}
target.IS_REACT_ACT_ENVIRONMENT = true;

// jsdom's timers would keep the runner alive after the last test.
after(() => dom.window.close());

export { dom };
