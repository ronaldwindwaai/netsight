import 'server-only';

import { cookies } from 'next/headers';

import { PAGE_SIZE_COOKIE, parsePageSizeCookie } from './page-state.ts';

/** The reader's preferred list size from its mirror cookie (validated; the built-in default if absent). */
export async function preferredPageSize(): Promise<number> {
  return parsePageSizeCookie((await cookies()).get(PAGE_SIZE_COOKIE)?.value);
}
