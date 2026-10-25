#!/usr/bin/env bash
# Copyright (c) 2026 Aroha Labs
# SPDX-License-Identifier: Apache-2.0
#
# Push spec-public/ → the public ArohaLabs/aroha-spec repo, or --check for drift.
#
# spec-public/ (inside the private monorepo) is the SOURCE OF TRUTH.
# NEVER edit the public repo directly — edit here, then run this script.
# Internal-only files (PUBLISH.md, sync.sh, w3c-registration/SUBMIT.md) are
# excluded from the public mirror.
#
#   ./sync.sh --check   # report drift, exit 1 if any (use in CI / pre-launch)
#   ./sync.sh --push    # mirror to the public repo and push
#
# The spec exists in THREE places: here, ../docs/spec (referenced by README,
# CONTRIBUTING, CHARTER and CODEOWNERS), and the public GitHub repo. Only two of
# them were ever compared, so docs/spec quietly fell a whole section behind
# without anything noticing. Both mirrors are now checked in one pass — if you
# add a fourth copy, add it here too.

set -euo pipefail
REPO="https://github.com/ArohaLabs/aroha-spec.git"
HERE="$(cd "$(dirname "$0")" && pwd)"
DOCS_SPEC="$(cd "$HERE/.." && pwd)/docs/spec"
TMP="$(mktemp -d)"
EXCLUDE=(PUBLISH.md sync.sh w3c-registration/SUBMIT.md w3c-registration/pr-body.md)

git clone -q --depth 1 "$REPO" "$TMP"

# Build the set of files the public repo should contain.
mirror() {
  cd "$HERE"
  find . -type f -not -path './.git/*' | sed 's|^\./||' | while read -r f; do
    skip=0
    for e in "${EXCLUDE[@]}"; do [ "$f" = "$e" ] && skip=1; done
    [ "$skip" = 1 ] && continue
    echo "$f"
  done
}

drift=0
while read -r f; do
  # --strip-trailing-cr: ignore CRLF/LF differences (Windows working trees)
  if ! diff -q --strip-trailing-cr "$HERE/$f" "$TMP/$f" >/dev/null 2>&1; then
    echo "DRIFT: $f"
    drift=1
    [ "${1:-}" = "--push" ] && { mkdir -p "$TMP/$(dirname "$f")"; cp "$HERE/$f" "$TMP/$f"; }
  fi
done < <(mirror)

# ── docs/spec mirror ────────────────────────────────────────────────────────
# Every file in spec/ must appear identically in ../docs/spec. Extra files in
# docs/spec (cncf-sandbox-proposal.md and other internal drafts) are fine —
# the rule is one-directional.
docs_drift=0
for f in "$HERE"/spec/*; do
  b="$(basename "$f")"
  if ! diff -q --strip-trailing-cr "$f" "$DOCS_SPEC/$b" >/dev/null 2>&1; then
    echo "DOCS DRIFT: docs/spec/$b"
    docs_drift=1
    [ "${1:-}" = "--push" ] && cp "$f" "$DOCS_SPEC/$b"
  fi
done

if [ "${1:-}" = "--check" ]; then
  if [ "$drift" = 0 ] && [ "$docs_drift" = 0 ]; then
    echo "in sync ✓"
  else
    echo "^ run ./sync.sh --push to reconcile"
  fi
  rm -rf "$TMP"
  [ "$drift" = 0 ] && [ "$docs_drift" = 0 ] && exit 0 || exit 1
fi

if [ "${1:-}" = "--push" ]; then
  # docs/spec was already reconciled above; report it so a run that only fixed
  # the local mirror doesn't look like a no-op.
  [ "$docs_drift" = 1 ] && echo "docs/spec reconciled ✓"
  if [ "$drift" = 0 ]; then
    echo "public repo already in sync ✓"
    rm -rf "$TMP"; exit 0
  fi
  cd "$TMP"
  git add -A
  git commit -q -m "sync from spec-public source of truth"
  git push -q origin main
  echo "pushed ✓"
  rm -rf "$TMP"; exit 0
fi

echo "usage: ./sync.sh --check | --push"; rm -rf "$TMP"; exit 2
