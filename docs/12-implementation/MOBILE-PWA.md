# Mobile / PWA implementation (E10, Step 11)

Base: the upstream installable shell (see `docs/03-ui-ux/MOBILE-PWA.md`): `manifest.ts`, a public-only offline
service worker (`public/sw.js`: caches the offline page and two icons, answers failed navigations with a 503
offline document, never touches `/api`, `/auth` or `/login`) and the install button.

## Added on top

* **Mobile navigation** (`components/mobile-nav.tsx`, `lib/mobile-nav.ts`): bottom tab bar below `lg` for Overview,
  Incidents, Diagnostics and Internet. Diagnostics and Internet need `diagnostics:read` / `internet:read`, mirroring
  `lib/menu.ts`; the API enforces the real permission. 44 px touch targets for coarse pointers; safe-area insets.
* **Honest offline and stale states** (`components/connectivity-banner.tsx`, `lib/pwa/connectivity.ts`): an
  always-mounted live region. Offline: "not live", with the load time in UTC; there is no offline copy of
  operational data and none is implied. Stale after 5 minutes: a Reload prompt. Age is measured from the latest page
  navigation.
* **Headers** (`apps/web/next.config.mjs`, tested by `lib/pwa/headers.test.ts`): `/sw.js` and `/offline.html` are
  revalidated on every load with their own restrictive CSP and `nosniff`; all routes get `X-Frame-Options: DENY`,
  `nosniff`, a strict referrer policy and a deny-all permissions policy. There is deliberately no page CSP: it needs
  per-request nonces and is a separate decision.

## Push notifications: decision

Not built. The notification engine delivers push through a provider-agnostic gateway; the provider, subscription
store and VAPID handling have no approved design. There is no subscription endpoint, opt-in or `push` handler.

## Integration note (2026-10-19)

An independent service-worker implementation (allow-list caching of content-hashed `/_next/static/` assets, its own
manifest, icons, offline page, install prompt and cache clearing on sign-out) was dropped in favour of the reviewed
upstream shell, which caches strictly less. Nothing personal is cached, so no sign-out clearing is needed.

## Deferred / human decisions

Web Push provider; page CSP and HSTS; icon artwork; mobile acknowledge/assign and approvals (after E11 step-up);
API-reachability based offline detection; real-browser install, Lighthouse and device verification (none done here).
