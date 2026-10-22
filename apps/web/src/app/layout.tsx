import '@adminlte/react/css';
import 'bootstrap-icons/font/bootstrap-icons.css';
import './globals.css';
import './shell.css';

export const metadata = {
  title: { default: 'Netsight', template: '%s · Netsight' },
  manifest: '/manifest.webmanifest',
  appleWebApp: { capable: true, title: 'Netsight', statusBarStyle: 'default' },
  icons: { apple: '/icons/apple-touch-icon.png' },
  description: 'AI-assisted Network Operations & Security Command Centre'
};

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
