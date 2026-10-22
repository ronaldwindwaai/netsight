import Link from 'next/link';

import './error-pages.css';

export const metadata = { title: 'Page not found | Netsight' };

/** Unmatched URLs. Rendered outside the dashboard shell, so it carries its own landmark and h1. */
export default function NotFound() {
  return (
    <main className="standalone-page">
      <div className="standalone-page__panel">
        <p className="standalone-page__code">404</p>
        <h1>Page not found</h1>
        <p>There is no Netsight page at this address. Check the address, or go back to the overview.</p>
        <Link href="/overview">Back to Overview</Link>
      </div>
    </main>
  );
}
