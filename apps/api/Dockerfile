# syntax=docker/dockerfile:1.7
# Netsight API (FastAPI).
# Build context is apps/api:  docker build -f apps/api/Dockerfile apps/api
# Production still deploys via systemd (infrastructure/vps); this image is additive.

ARG PYTHON_VERSION=3.12
ARG DEBIAN_RELEASE=bookworm
# Same uv release the repo's security workflow pins.
ARG UV_VERSION=0.12.23

FROM ghcr.io/astral-sh/uv:${UV_VERSION} AS uv

# ---- build: resolve the locked, production-only dependency set into a venv ----
FROM python:${PYTHON_VERSION}-slim-${DEBIAN_RELEASE} AS build
COPY --from=uv /uv /usr/local/bin/uv
ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=never \
    UV_PROJECT_ENVIRONMENT=/app/.venv
WORKDIR /app
# Dependencies first (cached layer); no dev extras, no project yet.
COPY pyproject.toml uv.lock ./
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --locked --no-dev --no-install-project
# Then install netsight-api as a real (non-editable) package, as deploy-vps.sh does.
COPY src ./src
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --locked --no-dev --no-editable

# ---- runtime: no uv, no dev dependencies, non-root ----
FROM python:${PYTHON_VERSION}-slim-${DEBIAN_RELEASE} AS runtime
RUN groupadd --system --gid 10001 netsight \
 && useradd --system --uid 10001 --gid netsight --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin netsight
ENV PATH="/app/.venv/bin:${PATH}" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1
WORKDIR /app
COPY --from=build --chown=root:root /app/.venv /app/.venv
USER 10001:10001
EXPOSE 8000
# Unauthenticated readiness endpoint GET /api/v1/health (the one deploy-vps.sh probes).
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD ["python", "-c", "import sys,urllib.request; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/api/v1/health', timeout=3).status == 200 else 1)"]
# Same app target and bind as infrastructure/vps/netsight-api.service (loopback). The web UI only
# accepts a loopback or HTTPS API URL, so the compose file shares a network namespace instead of
# widening this bind.
CMD ["uvicorn", "netsight_api.main:app", "--host", "127.0.0.1", "--port", "8000"]
