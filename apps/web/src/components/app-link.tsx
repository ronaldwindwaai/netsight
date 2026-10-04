'use client';

import Link from 'next/link';
import type { LinkProps } from '@adminlte/react';

export function AppLink({ href, children, ...props }: LinkProps) {
  return (
    <Link href={href} {...props}>
      {children}
    </Link>
  );
}
