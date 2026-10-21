'use client';

import './error-pages.css';

/** Last-resort boundary: replaces the root layout, so it renders its own html and body. */
export default function GlobalError({ reset }: { error: Error & { digest?: string }; reset: () => void }) {
  return (
    <html lang="en">
      <body>
        <main className="standalone-page">
          <div className="standalone-page__panel">
            <h1>Netsight could not load</h1>
            <p>An unexpected interface error stopped this screen. No data has been inferred or changed.</p>
            <div className="standalone-page__actions">
              <button type="button" onClick={reset}>
                Try again
              </button>
              {/* A plain anchor on purpose: a full navigation recovers when client routing is broken. */}
              <a href="/overview">Back to Overview</a>
            </div>
          </div>
        </main>
      </body>
    </html>
  );
}
