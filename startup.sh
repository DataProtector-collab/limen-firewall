#!/bin/sh
# Optional local browser lab. Real Windows rules require the desktop application.
cd "$(dirname "$0")" || exit 1
if curl --fail --silent http://127.0.0.1:8080/ >/dev/null 2>&1; then exit 0; fi
mkdir -p artifacts
npm run dev >artifacts/dev.log 2>&1 &
