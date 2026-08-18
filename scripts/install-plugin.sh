#!/usr/bin/env bash
# install-plugin.sh — place and verify the transport-plugin binary
#
# Division of labor: the plugin is built by the maintainer from upstream
# sources inside a container (no toolchain required on the host); this script
# does exactly two things —
#   1. install the build artifact to ~/.local/share/causeway/bin/obfs-local;
#   2. when run without arguments, verify the installed binary exists and is
#      executable.
#
# Usage:
#   scripts/install-plugin.sh /path/to/obfs-local   # install from a build artifact
#   scripts/install-plugin.sh                        # verify only
set -euo pipefail

DEST="${XDG_DATA_HOME:-$HOME/.local/share}/causeway/bin/obfs-local"

if [ $# -ge 1 ]; then
    SRC="$1"
    if [ ! -x "$SRC" ]; then
        echo "error: $SRC does not exist or is not executable" >&2
        exit 1
    fi
    mkdir -p "$(dirname "$DEST")"
    install -m 0755 "$SRC" "$DEST"
    echo ">> installed $DEST"
fi

if [ ! -x "$DEST" ]; then
    echo "error: $DEST does not exist." >&2
    echo "  build the plugin from upstream sources inside a container first, then run:" >&2
    echo "  scripts/install-plugin.sh /path/to/obfs-local" >&2
    exit 1
fi

# The plugin binary has no standard --version; print the first help lines to
# confirm executability
echo ">> executability check"
"$DEST" --help 2>&1 | head -3 || true
echo "OK: $DEST"
