# Mobile / PWA

PWA first. Native mobile only if later requirements justify it.

Mobile home:
- overall health;
- WAN;
- critical/high incidents;
- active alerts;
- top traffic;
- Ask Netsight.

Mobile actions:
- acknowledge/assign;
- read evidence;
- run safe diagnostic;
- approve eligible action with step-up auth;
- receive push.

Do not compress full desktop configuration forms into unusable mobile screens.

## Installable/offline shell (stage 1)

The web manifest uses the existing Netsight 192/512 icons and opens the authenticated
Overview in standalone display mode. The header offers installation only when the
browser supplies a native install prompt; it never prompts automatically.

A service worker caches only the public offline document and two public icons, with
credentials omitted. It does not cache session data, API responses, authenticated
pages or operational telemetry. Offline navigation shows a generic 503 page stating
that current health is unknown, without echoing the URL or data previously read.
API/auth/login requests, writes, cross-origin requests and subresources are outside
the worker handler. Online responses remain network responses and are never added
to CacheStorage. Reconnect loads fresh content through the normal authentication
path. Only obsolete caches owned by this feature are removed on activation.

Mobile configuration history uses cards instead of shrinking a desktop table.
Push-subscription registration, browser notification permission/delivery and the
remaining mobile investigation/action workflows are subsequent stages; the manifest
and offline shell do not claim that those capabilities are complete.

Validation: five service-worker behavior tests, component tests of native-prompt/user
gesture registration, TypeScript/ESLint and production build. Chromium verified the
manifest link, exact public-only CacheStorage contents, offline protected-navigation
503/unknown state, no sensitive URL/fixture text in the offline document, mobile
width and reconnect. Isolated pnpm deployment includes the public assets; a frozen
install succeeds online (the first offline-only attempt lacked platform metadata).

No database changes. Revert the manifest/header registration/public assets together
to remove installation. To retire an already installed worker, ship a reviewed
temporary worker at the same `/sw.js` URL that clears only `netsight-offline-*`,
unregisters itself and claims no new requests; removing the file alone does not
unregister workers already installed on client devices. No such retirement or
production deployment was performed by this stage.
