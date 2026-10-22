/**
 * Page and page-size state for server-paginated lists, kept in the URL (`?page=2&page_size=100`).
 * The API paginates (`page`, `page_size` up to 100, `total`) but has no server-side filter or sort,
 * so q/status/sort filters act on the loaded page only and the UI says so with `describeRange`.
 */

export const PAGE_SIZES = [25, 50, 100] as const;
export const DEFAULT_PAGE_SIZE = 50;
/**
 * Highest page the web app will request. The API caps `page` at 1000 on the users and actions lists
 * and does not cap it on devices and alerts (only `ge=1`); one shared ceiling keeps every list
 * inside the strictest limit. At 100 rows a page that is 100,000 rows, far beyond any inventory.
 */
export const MAX_PAGE = 1000;

export interface PageParams {
  readonly page: number;
  readonly pageSize: number;
}

type Raw = string | string[] | undefined;

function first(value: Raw): string | undefined {
  return Array.isArray(value) ? value[0] : value;
}

/** Cookie that mirrors the reader's preferred size so the server can render it without a second fetch. */
export const PAGE_SIZE_COOKIE = 'netsight_page_size';
const COOKIE_MAX_AGE_SECONDS = 365 * 24 * 60 * 60;

/** A cookie value to a page size: only the offered sizes, anything else is the built-in default. */
export function parsePageSizeCookie(value: string | undefined): number {
  const size = value !== undefined && /^\d{1,3}$/.test(value) ? Number(value) : DEFAULT_PAGE_SIZE;
  return (PAGE_SIZES as readonly number[]).includes(size) ? size : DEFAULT_PAGE_SIZE;
}

/**
 * The `document.cookie` assignment that mirrors a preferred size. Not a secret and not HttpOnly (the
 * page script writes it); the default size expires the cookie instead of storing it.
 */
export function pageSizeCookie(size: number, secure: boolean): string {
  const isDefault = size === DEFAULT_PAGE_SIZE;
  const attributes = `Path=/; SameSite=Lax; Max-Age=${isDefault ? 0 : COOKIE_MAX_AGE_SECONDS}${secure ? '; Secure' : ''}`;
  return `${PAGE_SIZE_COOKIE}=${isDefault ? '' : size}; ${attributes}`;
}

/**
 * Page and size from the address. `preferredSize` (from the cookie) applies only when the address has
 * no `page_size`; any `page_size` in the address, valid or not, wins over it.
 */
export function parsePageParams(query: { page?: Raw; page_size?: Raw }, preferredSize: number = DEFAULT_PAGE_SIZE): PageParams {
  const rawPage = first(query.page);
  const parsed = rawPage !== undefined && /^\d{1,9}$/.test(rawPage) ? Number(rawPage) : 1;
  const page = parsed >= 1 && parsed <= MAX_PAGE ? parsed : 1;
  const rawSize = first(query.page_size);
  const fallback = (PAGE_SIZES as readonly number[]).includes(preferredSize) ? preferredSize : DEFAULT_PAGE_SIZE;
  const size = rawSize !== undefined && /^\d+$/.test(rawSize) ? Number(rawSize) : rawSize === undefined ? fallback : DEFAULT_PAGE_SIZE;
  const pageSize = (PAGE_SIZES as readonly number[]).includes(size) ? size : DEFAULT_PAGE_SIZE;
  return { page, pageSize };
}

export interface RangeInput extends PageParams {
  readonly total: number;
  /** Rows actually returned on this page. */
  readonly count: number;
}

export interface RangeDescription {
  readonly from: number;
  readonly to: number;
  readonly total: number;
  readonly pages: number;
  readonly partial: boolean;
  readonly hasPrevious: boolean;
  readonly hasNext: boolean;
}

export function describeRange({ page, pageSize, total, count }: RangeInput): RangeDescription {
  const pages = Math.max(1, Math.ceil(total / pageSize));
  const from = count === 0 ? 0 : (page - 1) * pageSize + 1;
  const to = count === 0 ? 0 : from + count - 1;
  return {
    from,
    to,
    total,
    pages,
    partial: count < total,
    hasPrevious: page > 1,
    hasNext: page < pages,
  };
}

/**
 * The URL for `next`, keeping every other parameter; default page and size are left out.
 * `preferredSize` is the reader's stored default size: while it differs from the built-in default,
 * `page_size` stays in the URL even at the built-in size, because a URL without it means "use my
 * preference" and an explicit choice must win over that.
 */
export function pageHref(
  pathname: string,
  current: URLSearchParams,
  next: PageParams,
  preferredSize: number = DEFAULT_PAGE_SIZE,
): string {
  const params = new URLSearchParams(current);
  params.delete('page');
  params.delete('page_size');
  if (next.page > 1) params.set('page', String(next.page));
  if (next.pageSize !== DEFAULT_PAGE_SIZE || preferredSize !== DEFAULT_PAGE_SIZE) params.set('page_size', String(next.pageSize));
  const text = params.toString();
  return text.length === 0 ? pathname : `${pathname}?${text}`;
}
