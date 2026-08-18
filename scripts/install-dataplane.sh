#!/usr/bin/env bash
# install-dataplane.sh — download and install the pinned data-plane adapter
# binary from its upstream release archive.
#
# Behavior:
#   1. download the x86_64-unknown-linux-gnu prebuilt archive;
#   2. verify integrity against the official .sha256 sidecar published with it;
#   3. install only the adapter binary to ~/.local/share/causeway/bin/ (all
#      CAUSEWAY needs).
#
# Environment variables:
#   SSLOCAL_VERSION  override the pinned upstream version (default v1.24.0)
#   GH_PROXY         mirror prefix for the download host (optional; normally
#                    unnecessary when the host is directly reachable)
#
# Fallback (when this script fails; requires a Rust toolchain on the host,
# ~5-10 minutes of compilation):
#   cargo install shadowsocks-rust --locked --root ~/.local/share/causeway
#   # the artifact lands at the same path this script installs to
set -euo pipefail

VERSION="${SSLOCAL_VERSION:-v1.24.0}"
ASSET="shadowsocks-${VERSION}.x86_64-unknown-linux-gnu.tar.xz"
BASE_URL="https://github.com/shadowsocks/shadowsocks-rust/releases/download/${VERSION}"
DEST="${XDG_DATA_HOME:-$HOME/.local/share}/causeway/bin"

if [ "$(uname -m)" != "x86_64" ] || [ "$(uname -s)" != "Linux" ]; then
    echo "error: this script supports Linux x86_64 only; on other platforms use cargo install shadowsocks-rust --locked" >&2
    exit 1
fi

url() {
    if [ -n "${GH_PROXY:-}" ]; then
        echo "${GH_PROXY}$1"
    else
        echo "$1"
    fi
}

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

echo ">> downloading ${ASSET}"
curl -fL --retry 3 --connect-timeout 15 -o "$TMP/$ASSET" "$(url "$BASE_URL/$ASSET")"
curl -fL --retry 3 --connect-timeout 15 -o "$TMP/$ASSET.sha256" "$(url "$BASE_URL/$ASSET.sha256")"

echo ">> verifying sha256"
( cd "$TMP" && sha256sum -c "$ASSET.sha256" )

echo ">> extracting and installing to $DEST"
tar -xJf "$TMP/$ASSET" -C "$TMP" sslocal
mkdir -p "$DEST"
install -m 0755 "$TMP/sslocal" "$DEST/sslocal"

echo ">> verifying"
"$DEST/sslocal" --version
echo "OK: $DEST/sslocal"
