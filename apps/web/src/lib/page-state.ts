/**
 * Page and page-size state for server-paginated lists, kept in the URL (`?page=2&page_size=100`).
 * The API paginates (`page`, `page_size` up to 100, `total`) but has no server-side filter or sort,
 * so q/status/sort filters act on the loaded page only and the UI says so with `describeRange`.
 */

export const PAGE_SIZES = [25, 50, 100] as const;
export const DEFAULT_PAGE_SIZE = 50;

export interface PageParams {
  readonly page: number;
  readonly pageSize: number;
}

type Raw = string | string[] | undefined;

function first(value: Raw): string | undefined {
  return Array.isArray(value) ? value[0] : value;
}

export function parsePageParams(query: { page?: Raw; page_size?: Raw }): PageParams {
  const rawPage = first(query.page);
  const page = rawPage !== undefined && /^\d{1,9}$/.test(rawPage) && Number(rawPage) >= 1 ? Number(rawPage) : 1;
  const rawSize = first(query.page_size);
  const size = rawSize !== undefined && /^\d+$/.test(rawSize) ? Number(rawSize) : DEFAULT_PAGE_SIZE;
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

/** The URL for `next`, keeping every other parameter; default page and size are left out. */
export function pageHref(pathname: string, current: URLSearchParams, next: PageParams): string {
  const params = new URLSearchParams(current);
  params.delete('page');
  params.delete('page_size');
  if (next.page > 1) params.set('page', String(next.page));
  if (next.pageSize !== DEFAULT_PAGE_SIZE) params.set('page_size', String(next.pageSize));
  const text = params.toString();
  return text.length === 0 ? pathname : `${pathname}?${text}`;
}
