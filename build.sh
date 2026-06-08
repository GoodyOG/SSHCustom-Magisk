#!/usr/bin/env bash
#
# Reproducible SSHCustom-Magisk build:
#   1. Read the canonical version from the VERSION file at the repo root.
#      Override with VERSION=x.y.z ./build.sh for local experiments.
#   2. Sync the canonical webroot/index.html into internal/webui/ so the
#      go:embed directive picks up exactly what users will see.
#   3. Stamp module.prop with the version.
#   4. Build a host validator and run it against the bundled config to
#      catch JSON regressions before we ship.
#   5. Cross-compile the daemon for arm64 and armv7, statically linked.
#   6. Package the module ZIP with deterministic timestamps and POSIX perms.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"

# Single source of truth for the version. The VERSION file flows from here
# into module.prop, the daemon binary (via -ldflags), and the release zip
# filename. There is exactly one place to edit when bumping a release.
if [ -z "${VERSION:-}" ]; then
  if [ ! -f "$ROOT/VERSION" ]; then
    echo "VERSION file missing at repo root" >&2
    exit 1
  fi
  VERSION="$(cat "$ROOT/VERSION" | tr -d '[:space:]')"
fi
echo "==> Building SSHCustom-Magisk v${VERSION}"

DIST="$ROOT/dist"
MODULE="$ROOT/src/module"
ARM64_BIN="$MODULE/bin/arm64/sshcustomd"
ARMV7_BIN="$MODULE/bin/arm/sshcustomd"
HOST_BIN="$DIST/sshcustomd-host"
ZIP_OUT="$DIST/SSHCustom-Magisk-v${VERSION}.zip"
WEBROOT_SRC="$MODULE/webroot/index.html"
WEBROOT_EMBED="$ROOT/internal/webui/index.html"
FAVICON_SRC="$MODULE/webroot/favicon.svg"
FAVICON_EMBED="$ROOT/internal/webui/favicon.svg"
LDFLAGS="-s -w -buildid= -X github.com/GoodyOG/SSHCustom_Magisk/internal/version.Version=${VERSION}"

mkdir -p "$DIST" "$(dirname "$ARM64_BIN")" "$(dirname "$ARMV7_BIN")"
export GOFLAGS="${GOFLAGS:--mod=mod}"

echo "==> Go toolchain"
go version

echo "==> Syncing embedded webroot from $WEBROOT_SRC"
# go:embed pulls from disk at compile time. Keeping internal/webui/index.html
# always identical to src/module/webroot/index.html means we have one HTML
# source of truth — the module package and the binary fallback are the same
# bytes. Differences would mean the dashboard looks one way during install
# and another way after a fresh install with no on-disk webroot.
cp "$WEBROOT_SRC" "$WEBROOT_EMBED"
cp "$FAVICON_SRC" "$FAVICON_EMBED"

echo "==> Stamping src/module/module.prop with version=${VERSION}"
# The module.prop file is what Magisk and KernelSU display in their module
# list. We rewrite the version line in place; everything else is left alone.
sed -i.bak -E "s|^version=.*|version=v${VERSION}|" "$MODULE/module.prop"
rm -f "$MODULE/module.prop.bak"

echo "==> Running unit tests"
# Tests are cheap and fence in pure helpers (DNS extraction, mode parsing,
# slug generation). Run them on every build so a broken test fails fast
# instead of waiting for CI.
go test ./... >/dev/null

echo "==> Building host validation binary"
CGO_ENABLED=0 go build \
  -trimpath \
  -buildvcs=false \
  -ldflags="$LDFLAGS" \
  -o "$HOST_BIN" \
  ./cmd/sshcustomd/

echo "==> Validating bundled config/profile JSON"
"$HOST_BIN" validate -c "$MODULE/config/config.json" -p "$MODULE/config/profiles.json"

echo "==> Building Android/Linux ARM64 daemon"
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build \
  -trimpath \
  -buildvcs=false \
  -ldflags="$LDFLAGS" \
  -o "$ARM64_BIN" \
  ./cmd/sshcustomd/

echo "==> Building Android/Linux ARMv7 daemon"
GOOS=linux GOARCH=arm GOARM=7 CGO_ENABLED=0 go build \
  -trimpath \
  -buildvcs=false \
  -ldflags="$LDFLAGS" \
  -o "$ARMV7_BIN" \
  ./cmd/sshcustomd/

echo "==> Packaging Magisk module"
python3 "$ROOT/scripts/package_module.py" "$MODULE" "$ZIP_OUT"

echo "$ZIP_OUT"
