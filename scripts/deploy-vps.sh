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
PORT="${NETSIGHT_WEB_PORT:-4310}"

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

cd "$RELEASE"
# Create an isolated web package so root-only development tooling is not
# installed in the production release. The legacy deploy mode is required
# because this workspace does not use injected workspace dependencies.
pnpm --filter @netsight/web deploy --legacy --frozen-lockfile "$RUNTIME"
(
  cd "$RUNTIME"
  ./node_modules/.bin/next build
)

# Keep the service path stable across old and new releases so rollback remains
# valid while switching from workspace installs to isolated deployments.
mv "$SOURCE_WEB" "$SOURCE_ARCHIVE"
ln -s ../runtime "$SOURCE_WEB"

install -m 0644 infrastructure/vps/netsight-web.service "$HOME/.config/systemd/user/netsight-web.service"
systemctl --user daemon-reload
systemctl --user enable netsight-web.service >/dev/null

PREVIOUS="$(readlink -f "$BASE/current" 2>/dev/null || true)"
ln -sfn "$RELEASE" "$BASE/current"
systemctl --user restart netsight-web.service

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
