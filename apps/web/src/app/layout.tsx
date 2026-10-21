import Script from 'next/script';
import '@adminlte/react/css';
import 'bootstrap-icons/font/bootstrap-icons.css';
import './globals.css';
import './shell.css';
import './preferences.css';

import { EARLY_SCRIPT } from '@/lib/early-script';

export const metadata = {
  title: { default: 'Netsight', template: '%s · Netsight' },
  manifest: '/manifest.webmanifest',
  appleWebApp: { capable: true, title: 'Netsight', statusBarStyle: 'default' },
  icons: { apple: '/icons/apple-touch-icon.png' },
  description: 'AI-assisted Network Operations & Security Command Centre'
};

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return (
    // suppressHydrationWarning: the script below sets data-density before React hydrates.
    <html lang="en" suppressHydrationWarning>
      <body>
        {/* Density and blocked-storage handling that must run before hydration (see lib/early-script.ts). */}
        <Script id="netsight-early" strategy="beforeInteractive">
          {EARLY_SCRIPT}
        </Script>
        {children}
      </body>
    </html>
  );
}
