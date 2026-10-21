// Opt-in accessibility crawl: signs in to a running demo stack and runs axe-core on the main routes.
//
// NOT part of `pnpm test` and not a dependency of the repo. It needs `playwright` and
// `@axe-core/playwright`, resolved from a local, uncommitted install (never added to package.json):
//
//   mkdir ~/netsight-axe && cd ~/netsight-axe && npm init -y && npm i playwright @axe-core/playwright
//   npx playwright install chromium
//
// Then, with the demo stack (scripts/demo-local.py) and the web app running (see e2e/README.md):
//
//   NETSIGHT_AXE_TOOLS=~/netsight-axe \
//   NETSIGHT_AXE_USER=demo.admin NETSIGHT_AXE_PASSWORD=... NETSIGHT_AXE_TOTP_SECRET=... \
//   node apps/web/scripts/axe-crawl.mjs
//
// Optional: NETSIGHT_AXE_CHROMIUM (path to a chromium executable when the bundled one is not installed), NETSIGHT_AXE_BASE (default http://localhost:3000), NETSIGHT_AXE_ROUTES (comma-separated
// paths), NETSIGHT_AXE_SHOTS (directory for 1440 and 390 px screenshots, light and dark). Credentials
// come from the environment only and are never printed or written. Exit code is 1 when any
// violation is found, 2 when a prerequisite is missing, 0 otherwise.
import { createHmac } from 'node:crypto';
import { mkdirSync } from 'node:fs';
import { createRequire } from 'node:module';
import { join, resolve } from 'node:path';

const DEFAULT_ROUTES = [
  '/overview', '/devices', '/devices/1', '/alerts', '/incidents', '/security', '/users', '/internet',
  '/network/map', '/unknown-devices', '/inventory', '/ipam', '/config', '/diagnostics', '/actions',
  '/copilot', '/traffic', '/forecast', '/reports', '/this-page-does-not-exist',
];
const BASE32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
const VIEWPORTS = [{ name: '1440', width: 1440, height: 900 }, { name: '390', width: 390, height: 844 }];
const SCHEMES = ['light', 'dark'];

function skip(message) {
  console.error(`axe-crawl skipped: ${message}`);
  process.exit(2);
}

function loadTools() {
  const dir = process.env.NETSIGHT_AXE_TOOLS;
  const require = createRequire(join(resolve(dir ?? process.cwd()), 'noop.js'));
  try {
    return { playwright: require('playwright'), axe: require('@axe-core/playwright') };
  } catch {
    return skip(
      'playwright and @axe-core/playwright are not installed. Install them outside the repo and set ' +
        'NETSIGHT_AXE_TOOLS to that directory (see the header of this file).',
    );
  }
}

/** RFC 6238 TOTP (SHA-1, 6 digits, 30 s) so no extra dependency is needed. */
function totp(secret, nowMs = Date.now()) {
  const bits = [...secret.replace(/[\s=]/g, '').toUpperCase()]
    .map((c) => {
      const index = BASE32.indexOf(c);
      if (index < 0) throw new Error('NETSIGHT_AXE_TOTP_SECRET is not valid base32');
      return index.toString(2).padStart(5, '0');
    })
    .join('');
  const key = Buffer.from(bits.match(/.{8}/g).map((byte) => parseInt(byte, 2)));
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(Math.floor(nowMs / 30000)));
  const mac = createHmac('sha1', key).update(counter).digest();
  const offset = mac[mac.length - 1] & 0xf;
  const code = (mac.readUInt32BE(offset) & 0x7fffffff) % 1_000_000;
  return String(code).padStart(6, '0');
}

async function signIn(page, base, user, password, secret) {
  await page.goto(`${base}/login`);
  await page.getByLabel('Username').fill(user);
  await page.getByLabel('Password').fill(password);
  await page.locator('form button[type="submit"]').click();
  await page.locator('#local-mfa-code').waitFor();
  await page.locator('#local-mfa-code').fill(totp(secret));
  await page.locator('form button[type="submit"]').click();
  await page.waitForURL((url) => !url.pathname.startsWith('/login'), { timeout: 15000 });
}

/** Credentials are typed into the target, so a non-loopback host deserves a loud warning. */
function warnIfNotLoopback(base) {
  const host = new URL(base).hostname;
  if (!['localhost', '127.0.0.1', '[::1]', '::1'].includes(host)) {
    console.error(`WARNING: NETSIGHT_AXE_BASE host "${host}" is not loopback; this script is for the local demo stack only.`);
  }
}

async function main() {
  const { playwright, axe } = loadTools();
  const base = (process.env.NETSIGHT_AXE_BASE ?? 'http://localhost:3000').replace(/\/$/, '');
  warnIfNotLoopback(base);
  const user = process.env.NETSIGHT_AXE_USER;
  const password = process.env.NETSIGHT_AXE_PASSWORD;
  const secret = process.env.NETSIGHT_AXE_TOTP_SECRET;
  if (!user || !password || !secret) skip('set NETSIGHT_AXE_USER, NETSIGHT_AXE_PASSWORD and NETSIGHT_AXE_TOTP_SECRET.');
  const routes = (process.env.NETSIGHT_AXE_ROUTES ?? DEFAULT_ROUTES.join(',')).split(',').map((r) => r.trim()).filter(Boolean);
  const shots = process.env.NETSIGHT_AXE_SHOTS;
  if (shots) mkdirSync(shots, { recursive: true });

  const browser = await playwright.chromium.launch({ executablePath: process.env.NETSIGHT_AXE_CHROMIUM || undefined });
  const context = await browser.newContext({ viewport: { width: 1440, height: 900 } });
  const page = await context.newPage();
  await signIn(page, base, user, password, secret);

  let total = 0;
  for (const scheme of SCHEMES) {
    for (const viewport of VIEWPORTS) {
      await page.setViewportSize({ width: viewport.width, height: viewport.height });
      await page.emulateMedia({ colorScheme: scheme });
      for (const route of routes) {
        await page.goto(`${base}${route}`, { waitUntil: 'networkidle' });
        const { violations } = await new axe.AxeBuilder({ page }).analyze();
        total += violations.length;
        const label = `${scheme} ${viewport.name} ${route}`;
        console.log(violations.length === 0 ? `ok    ${label}` : `FAIL  ${label}`);
        for (const v of violations) console.log(`        ${v.id} (${v.impact}) x${v.nodes.length}: ${v.help}`);
        if (shots) {
          const name = `${scheme}-${viewport.name}-${route.replace(/[^a-z0-9]+/gi, '_')}.png`;
          await page.screenshot({ path: join(shots, name), fullPage: true });
        }
      }
    }
  }
  await browser.close();
  console.log(`\n${total} violation instance group(s) across ${routes.length} routes x ${SCHEMES.length} schemes x ${VIEWPORTS.length} viewports`);
  process.exit(total === 0 ? 0 : 1);
}

main().catch((error) => {
  console.error(`axe-crawl failed: ${error instanceof Error ? error.message : String(error)}`);
  process.exit(2);
});
