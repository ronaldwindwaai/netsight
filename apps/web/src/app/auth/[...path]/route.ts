import { proxyAuthRequest } from '@/lib/auth-proxy';

export const dynamic = 'force-dynamic';

type RouteContext = { params: Promise<{ path?: string[] }> };

async function handle(request: Request, context: RouteContext): Promise<Response> {
  const { path } = await context.params;
  const segments = Array.isArray(path) ? path : [];
  return proxyAuthRequest(segments.join('/'), request);
}

export const GET = handle;
export const POST = handle;
export const HEAD = handle;