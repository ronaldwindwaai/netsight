# syntax=docker/dockerfile:1.7
# Netsight web (Next.js, `next start`).
# The build context is the REPOSITORY ROOT (pnpm workspace, lockfile and patches live there):
#   docker build -f apps/web/Dockerfile .
# Production still deploys via systemd (infrastructure/vps); this image is additive.
#
# `output: 'standalone'` is deliberately NOT used: the systemd unit runs `next start`, and
# switching the build output would change what the default deploy produces. This image therefore
# mirrors scripts/deploy-vps.sh (`pnpm --filter @netsight/web deploy`, then `next build`).

ARG NODE_VERSION=24
ARG DEBIAN_RELEASE=bookworm
# Must equal "packageManager" in the root package.json (pnpm@12.8.1).
ARG PNPM_VERSION=12.8.1

FROM node:${NODE_VERSION}-${DEBIAN_RELEASE}-slim AS base
ARG PNPM_VERSION
ENV NEXT_TELEMETRY_DISABLED=1 \
    CI=true
RUN corepack enable && corepack prepare "pnpm@${PNPM_VERSION}" --activate

# ---- build: isolated web package (same as deploy-vps.sh), then next build ----
FROM base AS build
WORKDIR /workspace
# Lockfile, workspace config and patches first so dependency layers cache independently of source.
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
COPY patches ./patches
COPY apps/web ./apps/web
RUN --mount=type=cache,id=pnpm-store,target=/root/.local/share/pnpm/store \
    pnpm --filter @netsight/web deploy --frozen-lockfile /out
# package.json "files" limits what `pnpm deploy` copies; next.config.mjs (security headers) must be
# present for both the build and `next start`, so it is placed explicitly.
COPY apps/web/next.config.mjs /out/next.config.mjs
WORKDIR /out
RUN ./node_modules/.bin/next build \
 && pnpm prune --prod

# ---- runtime: production dependencies + build output only, non-root ----
FROM node:${NODE_VERSION}-${DEBIAN_RELEASE}-slim AS runtime
ENV NODE_ENV=production \
    NEXT_TELEMETRY_DISABLED=1
WORKDIR /app
COPY --from=build --chown=root:root /out/package.json /out/next.config.mjs ./
COPY --from=build --chown=root:root /out/node_modules ./node_modules
COPY --from=build --chown=root:root /out/public ./public
COPY --from=build --chown=root:root /out/.next ./.next
# next start writes its image/fetch cache here; the compose file mounts a tmpfs over it.
RUN mkdir -p /app/.next/cache && chown node:node /app/.next/cache
USER node
EXPOSE 2000
# /login is the unauthenticated readiness page (see apps/web/e2e/README.md).
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
  CMD ["node", "-e", "fetch('http://127.0.0.1:2000/login').then(r=>process.exit(r.ok?0:1),()=>process.exit(1))"]
# Same entry as infrastructure/vps/netsight-web.service, bound to all interfaces so a published
# port reaches it (systemd binds 127.0.0.1 behind the reverse proxy).
CMD ["node", "node_modules/next/dist/bin/next", "start", "-H", "0.0.0.0", "-p", "2000"]
