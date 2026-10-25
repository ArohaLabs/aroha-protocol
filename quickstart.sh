#!/usr/bin/env bash
# Copyright (c) 2026 Aroha Labs
# SPDX-License-Identifier: Apache-2.0

# Aroha Quickstart — first agent-to-agent transaction in under 60 seconds
#
# Prerequisites: Node.js 22+ and npm 10+
# Run: bash quickstart.sh

set -euo pipefail

CYAN='\033[36m'
TEAL='\033[38;5;51m'
GREEN='\033[32m'
YELLOW='\033[33m'
GRAY='\033[90m'
BOLD='\033[1m'
RESET='\033[0m'

step() { echo -e "\n${TEAL}${BOLD}▶ $1${RESET}"; }
ok()   { echo -e "  ${GREEN}✓${RESET}  $1"; }
info() { echo -e "  ${GRAY}$1${RESET}"; }

echo -e "\n${TEAL}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo -e "${TEAL}${BOLD}  Aroha — Aroha Protocol  ·  Quickstart${RESET}"
echo -e "${TEAL}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}\n"

# ── Step 1: Check Node.js ──────────────────────────────────────────────────────
step "Checking prerequisites"

NODE_VERSION=$(node --version 2>/dev/null || echo "none")
if [[ "$NODE_VERSION" == "none" ]]; then
  echo -e "  ${YELLOW}Node.js not found. Install v22+ from https://nodejs.org${RESET}"
  exit 1
fi

MAJOR=$(echo "$NODE_VERSION" | sed 's/v\([0-9]*\).*/\1/')
if [[ "$MAJOR" -lt 22 ]]; then
  echo -e "  ${YELLOW}Node.js $NODE_VERSION found, but v22+ is required.${RESET}"
  echo -e "  ${GRAY}Run: nvm install 22 && nvm use 22${RESET}"
  exit 1
fi

ok "Node.js $NODE_VERSION"
ok "npm $(npm --version)"

# ── Step 2: Install dependencies ──────────────────────────────────────────────
step "Installing dependencies"
info "This may take 30–60 seconds on first run…"
npm install --silent 2>/dev/null || npm install
ok "All workspace packages installed"

# ── Step 3: Build all packages ────────────────────────────────────────────────
step "Building Aroha packages"
info "Compiling the TypeScript packages…"
npm run build --silent 2>/dev/null || npm run build
ok "Build complete"

# ── Step 4: Run the protocol test suite ───────────────────────────────────────
step "Running the protocol conformance suite"
npx vitest run --config vitest.conformance.config.ts 2>&1 | tail -3
ok "Conformance suite passing"

# ── Step 5: Run the VC terminal demo ──────────────────────────────────────────
step "Running live agent-to-agent transaction demo"
echo ""
node scripts/demo-vc-terminal.mjs

# ── Done ───────────────────────────────────────────────────────────────────────
echo -e "\n${TEAL}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo -e "\n  ${GREEN}${BOLD}Quickstart complete.${RESET}\n"
echo -e "  ${CYAN}Next steps:${RESET}"
echo -e "  ${GRAY}  npm run demo:vc         — re-run the terminal demo${RESET}"
echo -e "  ${GRAY}  npm run demo:browser    — browser UI with SSE trace  (port 3040)${RESET}"
echo -e "  ${GRAY}  npm run demo:chat       — full chat demo + blockchain  (port 3051)${RESET}"
echo -e "  ${GRAY}  docs/spec/aroha-1.0.md              — protocol specification${RESET}"
echo ""
