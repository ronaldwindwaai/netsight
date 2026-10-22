import type { ReactNode } from 'react';

type CardTheme = 'primary' | 'secondary' | 'success' | 'danger' | 'warning' | 'info' | 'light' | 'dark';

export interface AppCardProps {
  title?: ReactNode;
  /** Accepted for call-site compatibility with the library card; the library does not render it either. */
  icon?: string;
  theme?: CardTheme;
  variant?: 'default' | 'outline' | 'solid';
  bodyClass?: string;
  headerClass?: string;
  footerClass?: string;
  tools?: ReactNode;
  footer?: ReactNode;
  className?: string;
  children?: ReactNode;
}

function cardClassName(theme: CardTheme | undefined, variant: AppCardProps['variant']): string {
  if (!theme) return 'card';
  if (variant === 'outline') return `card card-outline card-${theme}`;
  if (variant === 'solid') return `card text-bg-${theme}`;
  return `card card-${theme}`;
}

/**
 * Same markup and classes as the library `Card`, except the title is a level-two heading. The library
 * renders it as an h3, which sits directly under the page's h1 (AppContent) and breaks heading order.
 * Cards here are never collapsible, removable or maximisable, so none of that widget state is needed.
 * The widget props (collapsible, defaultCollapsed, removable, onRemove, maximizable) and the deprecated
 * `outline` prop are intentionally unsupported; use variant="outline" instead of `outline`.
 */
export function AppCard({
  title,
  theme,
  variant = 'default',
  bodyClass,
  headerClass,
  footerClass,
  tools,
  footer,
  className,
  children,
}: AppCardProps) {
  const hasHeader = Boolean(title) || Boolean(tools);
  return (
    <div className={`${cardClassName(theme, variant)} ${className ?? ''}`}>
      {hasHeader ? (
        <div className={`card-header ${headerClass ?? ''}`}>
          <h2 className="card-title">{title ?? ''}</h2>
          <div className="card-tools">{tools}</div>
        </div>
      ) : null}
      <div className={`card-body ${bodyClass ?? ''}`}>{children}</div>
      {footer ? <div className={`card-footer ${footerClass ?? ''}`}>{footer}</div> : null}
    </div>
  );
}
