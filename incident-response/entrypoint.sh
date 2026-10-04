#!/bin/sh
set -eu

# Keep host credentials/config read-only while allowing container-local runtime state.
umask 077
mkdir -p "$CODEX_HOME"
for name in auth.json config.toml; do
    if [ -f "$HOME/.codex/$name" ]; then
        ln -sf "$HOME/.codex/$name" "$CODEX_HOME/$name"
    fi
done

exec "$@"
