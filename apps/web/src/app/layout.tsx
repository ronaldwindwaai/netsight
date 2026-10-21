import Script from 'next/script';
import '@adminlte/react/css';
import 'bootstrap-icons/font/bootstrap-icons.css';
import './globals.css';
import './shell.css';
import './preferences.css';

const DENSITY_SCRIPT =
  "try{if(localStorage.getItem('netsight.density')==='compact')document.documentElement.dataset.density='compact'}catch(e){}";

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
        {/* Applies the stored table density before first paint so rows do not jump on load. */}
        <Script id="netsight-density" strategy="beforeInteractive">
          {DENSITY_SCRIPT}
        </Script>
        {children}
      </body>
    </html>
  );
}
