import type { ReactNode } from 'react';

export interface Breadcrumb {
  label: string;
  href?: string;
}

interface AppContentProps {
  title?: string;
  breadcrumbs?: readonly Breadcrumb[];
  fluid?: boolean;
  children?: ReactNode;
}

/**
 * Page header and content area with the AdminLTE markup, but with the title as the page's single
 * level-one heading (@adminlte/react renders it as an h3, which leaves every page without an h1).
 */
export function AppContent({ title, breadcrumbs, fluid = true, children }: AppContentProps) {
  const container = fluid ? 'container-fluid' : 'container-lg';
  const hasCrumbs = breadcrumbs !== undefined && breadcrumbs.length > 0;
  return (
    <>
      {title || hasCrumbs ? (
        <div className="app-content-header">
          <div className={container}>
            <div className="row">
              <div className="col-sm-6">{title ? <h1 className="h3 mb-0">{title}</h1> : null}</div>
              {hasCrumbs ? (
                <div className="col-sm-6">
                  <nav aria-label="Breadcrumb">
                    <ol className="breadcrumb float-sm-end">
                      {breadcrumbs.map((crumb, index) => {
                        const current = index === breadcrumbs.length - 1;
                        return (
                          <li
                            key={`${crumb.label}-${index}`}
                            className={`breadcrumb-item${current ? ' active' : ''}`}
                            aria-current={current ? 'page' : undefined}
                          >
                            {crumb.href && !current ? <a href={crumb.href}>{crumb.label}</a> : crumb.label}
                          </li>
                        );
                      })}
                    </ol>
                  </nav>
                </div>
              ) : null}
            </div>
          </div>
        </div>
      ) : null}
      <div className="app-content">
        <div className={container}>{children}</div>
      </div>
    </>
  );
}
