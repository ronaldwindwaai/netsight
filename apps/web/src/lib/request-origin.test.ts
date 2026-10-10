import assert from 'node:assert/strict';
import test from 'node:test';

import { originHost, sameOrigin } from './request-origin.ts';

test('originHost extracts the lowercased host including port', () => {
  assert.equal(originHost('https://NOC.example.com'), 'noc.example.com');
  assert.equal(originHost('http://localhost:3000'), 'localhost:3000');
  assert.equal(originHost('https://noc.example.com/some/path?q=1'), 'noc.example.com');
  assert.equal(originHost(null), null);
  assert.equal(originHost(''), null);
  assert.equal(originHost('not a url'), null);
  assert.equal(originHost('javascript:alert(1)'), null);
});

test('sameOrigin accepts a matching Origin or Referer and rejects everything else', () => {
  // Origin matches.
  assert.equal(sameOrigin('noc.example.com', 'https://noc.example.com', null), true);
  // Origin missing but Referer matches (a same-site navigation that lacks Origin).
  assert.equal(
    sameOrigin('noc.example.com', null, 'https://noc.example.com/diagnostics'),
    true,
  );
  // Cross-site origin is rejected even if a matching Referer is also present.
  assert.equal(
    sameOrigin('noc.example.com', 'https://evil.example', 'https://evil.example/x'),
    false,
  );
  // Neither header: cannot be trusted.
  assert.equal(sameOrigin('noc.example.com', null, null), false);
  // No expected host: cannot be trusted.
  assert.equal(sameOrigin(null, 'https://noc.example.com', null), false);
  assert.equal(sameOrigin('  ', 'https://noc.example.com', null), false);
  // Case-insensitive host comparison.
  assert.equal(sameOrigin('NOC.Example.com', 'https://noc.example.com', null), true);
  // Port is significant.
  assert.equal(sameOrigin('noc.example.com:3000', 'https://noc.example.com', null), false);
});
