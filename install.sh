#!/usr/bin/env bash
# Thin bootstrap: verify prerequisites, then hand off to the TypeScript installer.
# The installer is the source of truth for provisioning; see AGENTS.md.
set -euo pipefail
cd "$(dirname "$0")"

need() {
	command -v "$1" >/dev/null 2>&1 || { echo "error: '$1' not found. $2" >&2; exit 1; }
}

need bun "Install: https://bun.sh"
need node "The cf CLI requires Node.js 22.18 or later."
need cf "Install: npm install --global cf"

node -e 'const [a,b]=process.versions.node.split(".").map(Number);process.exit(a>22||(a===22&&b>=18)?0:1)' \
	|| { echo "error: Node.js 22.18 or later is required by the cf CLI." >&2; exit 1; }

bun install --frozen-lockfile
exec bun run installer/src/index.ts "$@"
