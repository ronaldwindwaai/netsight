'use client';

import Link from 'next/link';
import { usePathname } from 'next/navigation';

import { isActiveMobileTab, mobileNavItemsFor } from '@/lib/mobile-nav';

/** Bottom tab bar for phones (hidden from the lg breakpoint up, where the sidebar is used). */
export function MobileNav({ permissions }: { permissions: readonly string[] | null }) {
  const pathname = usePathname();
  const items = mobileNavItemsFor(permissions);

  return (
    <nav className="mobile-nav d-lg-none" aria-label="Mobile navigation">
      {items.map((item) => {
        const active = isActiveMobileTab(pathname, item.href);
        return (
          <Link
            key={item.href}
            href={item.href}
            className={`mobile-nav__link${active ? ' is-active' : ''}`}
            aria-current={active ? 'page' : undefined}
          >
            <i className={`bi ${item.icon}`} aria-hidden="true" />
            <span>{item.label}</span>
          </Link>
        );
      })}
    </nav>
  );
}
