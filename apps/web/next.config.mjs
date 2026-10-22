// Headers for the PWA files in public/. Everything else keeps the framework defaults.
const REVALIDATE = 'public, max-age=0, must-revalidate';

/** @type {import('next').NextConfig} */
const config = {
  // @adminlte/react renders a stock demo user menu (hidden by globals.css) whose avatar still loads
  // from this path. Serve the Netsight mark instead of a 404 on every page.
  async rewrites() {
    return [{ source: '/assets/img/user2-160x160.jpg', destination: '/icons/netsight-192.png' }];
  },
  async headers() {
    return [
      {
        // Baseline for every route. No CSP here on purpose: the per-file CSPs below must not collide
        // with it, and a page CSP needs per-request nonces (a separate decision).
        source: '/:path*',
        headers: [
          { key: 'X-Frame-Options', value: 'DENY' },
          { key: 'X-Content-Type-Options', value: 'nosniff' },
          { key: 'Referrer-Policy', value: 'strict-origin-when-cross-origin' },
          { key: 'Permissions-Policy', value: 'camera=(), microphone=(), geolocation=()' },
        ],
      },
      {
        source: '/sw.js',
        headers: [
          { key: 'Content-Type', value: 'application/javascript; charset=utf-8' },
          { key: 'Cache-Control', value: REVALIDATE },
          { key: 'X-Content-Type-Options', value: 'nosniff' },
          { key: 'Content-Security-Policy', value: "default-src 'self'; script-src 'self'" },
          { key: 'Service-Worker-Allowed', value: '/' },
        ],
      },
      {
        source: '/offline.html',
        headers: [
          { key: 'Cache-Control', value: REVALIDATE },
          { key: 'X-Content-Type-Options', value: 'nosniff' },
          { key: 'Content-Security-Policy', value: "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; frame-ancestors 'none'" },
        ],
      },
    ];
  },
};

export default config;
