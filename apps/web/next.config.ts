import type { NextConfig } from 'next';

/**
 * The Netsight API binds to loopback only. Browser-driven auth flows
 * (OIDC redirects, CSRF-protected logout) reach it through this same-origin
 * proxy so the API is never exposed publicly.
 */
const API_URL = (process.env.NETSIGHT_API_URL ?? 'http://127.0.0.1:8000').replace(/\/+$/, '');

const nextConfig: NextConfig = {
  async rewrites() {
    return [
      {
        source: '/auth/:path*',
        destination: `${API_URL}/auth/:path*`,
      },
    ];
  },
};

export default nextConfig;
