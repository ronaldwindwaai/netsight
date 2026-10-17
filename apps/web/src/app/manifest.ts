import type { MetadataRoute } from 'next';

export default function manifest(): MetadataRoute.Manifest {
  return {
    id: '/', name: 'Netsight', short_name: 'Netsight',
    description: 'Secure network operations, observability and diagnostics',
    start_url: '/overview', scope: '/', display: 'standalone',
    background_color: '#f4f7fa', theme_color: '#0b1220',
    icons: [
      {src: '/icons/netsight-192.png', sizes: '192x192', type: 'image/png', purpose: 'any'},
      {src: '/icons/netsight-512.png', sizes: '512x512', type: 'image/png', purpose: 'any'},
    ],
  };
}
