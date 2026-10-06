#!/usr/bin/env bash
# Runs ON the VPS (as the deploy user). Invoked by .github/workflows/deploy.yml after the
# release has been rsynced to ~/netsight/releases/<sha>. Builds, switches the `current`
# symlink, restarts the user service, health-checks, and rolls back on failure.
set -euo pipefail

SHA="${1:?usage: deploy-vps.sh <release-sha>}"
[[ "$SHA" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$ ]] || {
  echo "invalid release identifier" >&2
  exit 1
}
BASE="$HOME/netsight"
RELEASE="$BASE/releases/$SHA"
RUNTIME="$RELEASE/runtime"
SOURCE_WEB="$RELEASE/apps/web"
SOURCE_ARCHIVE="$RELEASE/apps/web-source"
KEEP_RELEASES=5
# Keep the bootstrap default aligned with the CloudPanel/Nginx upstream for
# netsight.sadcpf.org. The persisted shared environment remains the runtime
# source of truth after the first deployment.
PORT="${NETSIGHT_WEB_PORT:-2000}"
EXPECTED_PROXY_PORT="${NETSIGHT_EXPECTED_PROXY_PORT:-2000}"

export PATH="$HOME/.local/node/bin:$PATH"
export XDG_RUNTIME_DIR="${XDG_RUNTIME_DIR:-/run/user/$(id -u)}"

[ -d "$RELEASE" ] || { echo "release $RELEASE not found" >&2; exit 1; }
[ ! -e "$RUNTIME" ] && [ ! -e "$SOURCE_ARCHIVE" ] || {
  echo "release $RELEASE has already been prepared" >&2
  exit 1
}
mkdir -p "$BASE/shared" "$HOME/.config/systemd/user"
[ -f "$BASE/shared/web.env" ] || echo "NETSIGHT_WEB_PORT=$PORT" > "$BASE/shared/web.env"
set -a; . "$BASE/shared/web.env"; set +a
[[ "${NETSIGHT_WEB_PORT:-}" =~ ^[0-9]{1,5}$ ]] || {
  echo "NETSIGHT_WEB_PORT must be a valid TCP port" >&2
  exit 1
}
if [ "$NETSIGHT_WEB_PORT" -lt 1 ] || [ "$NETSIGHT_WEB_PORT" -gt 65535 ]; then
  echo "NETSIGHT_WEB_PORT must be a valid TCP port" >&2
  exit 1
fi
[[ "$EXPECTED_PROXY_PORT" =~ ^[0-9]{1,5}$ ]] || {
  echo "NETSIGHT_EXPECTED_PROXY_PORT must be a valid TCP port" >&2
  exit 1
}
if [ "$EXPECTED_PROXY_PORT" -lt 1 ] || [ "$EXPECTED_PROXY_PORT" -gt 65535 ]; then
  echo "NETSIGHT_EXPECTED_PROXY_PORT must be a valid TCP port" >&2
  exit 1
fi
if [ "$NETSIGHT_WEB_PORT" -ne "$EXPECTED_PROXY_PORT" ]; then
  echo "web port $NETSIGHT_WEB_PORT does not match the configured reverse-proxy port" >&2
  exit 1
fi

cd "$RELEASE"
# Create an isolated web package so root-only development tooling is not
# installed in the production release.
#
# The modern deploy implementation is used deliberately. `--legacy` forces the
# old copy-based path, which rejects the workspace-level `patchedDependencies`
# (ecc-universal, used by the OpenCode tooling and unrelated to the web app)
# with ERR_PNPM_UNUSED_PATCH because the filtered web package does not depend
# on them. The modern path carries the patch config through instead. The web
# package declares no `workspace:` dependencies, so nothing needs injecting.
pnpm --filter @netsight/web deploy --frozen-lockfile "$RUNTIME"
(
  cd "$RUNTIME"
  ./node_modules/.bin/next build
)

# Keep the service path stable across old and new releases so rollback remains
# valid while switching from workspace installs to isolated deployments.
mv "$SOURCE_WEB" "$SOURCE_ARCHIVE"
ln -s ../runtime "$SOURCE_WEB"

install -m 0644 infrastructure/vps/netsight-web.service "$HOME/.config/systemd/user/netsight-web.service"
install -m 0644 infrastructure/vps/netsight-api.service "$HOME/.config/systemd/user/netsight-api.service"
systemctl --user daemon-reload
systemctl --user enable netsight-web.service >/dev/null
systemctl --user enable netsight-api.service >/dev/null

# Install the API virtualenv into the shared runtime location. netsight-api is
# a real installable package (hatchling), so the service resolves it from the
# venv and needs no PYTHONPATH side-channel.
if [ -f "$RELEASE/apps/api/pyproject.toml" ]; then
  (
    cd "$RELEASE/apps/api"
    UV_PROJECT_ENVIRONMENT="$HOME/netsight/shared/api-venv" \
      "$HOME/.local/bin/uv" sync --frozen --no-dev
  )
fi

PREVIOUS="$(readlink -f "$BASE/current" 2>/dev/null || true)"
ln -sfn "$RELEASE" "$BASE/current"
systemctl --user restart netsight-web.service
systemctl --user restart netsight-api.service

healthy=0
for _ in $(seq 1 30); do
  if curl -fsS -o /dev/null --max-time 3 "http://127.0.0.1:${NETSIGHT_WEB_PORT}/"; then healthy=1; break; fi
  sleep 2
done

if [ "$healthy" -ne 1 ]; then
  echo "health check failed for $SHA" >&2
  journalctl --user -u netsight-web.service -n 30 --no-pager >&2 || true
  if [ -n "$PREVIOUS" ] && [ -d "$PREVIOUS" ]; then
    echo "rolling back to $PREVIOUS" >&2
    ln -sfn "$PREVIOUS" "$BASE/current"
    systemctl --user restart netsight-web.service
  fi
  exit 1
fi

# Prune old releases, keeping the newest $KEEP_RELEASES and whatever `current` points to.
CURRENT="$(readlink -f "$BASE/current")"
ls -1dt "$BASE"/releases/*/ 2>/dev/null | tail -n +$((KEEP_RELEASES + 1)) | while read -r old; do
  [ "$(readlink -f "$old")" = "$CURRENT" ] || rm -rf "$old"
done
echo "deployed $SHA on port ${NETSIGHT_WEB_PORT}"
