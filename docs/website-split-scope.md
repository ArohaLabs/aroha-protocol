<!-- Copyright (c) 2026 Aroha Labs -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Splitting the website out of the monorepo — scope

Written 2026-08-23, against `feat/unified-app-foundation`. This is a scope,
not a plan of record: nothing here has been executed.

---

## Recommendation: two repos, not three

The original question was whether to split into **protocol / website /
runtime**. The commit history says two of those three belong together.

Of the 400 commits examined, **6.8% touch more than one** of the three areas:

| | commits |
|---|---|
| runtime only | 143 |
| website only | 88 |
| protocol only | 40 |
| **protocol + runtime** | **21** |
| protocol + website | 6 |

A repository boundary is cheap where changes don't cross it and expensive
where they do. Website changes almost never reach the protocol; runtime
changes reach it constantly — 21 of the 27 spanning commits are exactly the
seam that a protocol/runtime split would cut. Splitting there converts a
one-commit change into a publish, a version bump, and a second PR, twenty-one
times over the same period.

So: **extract the website, keep protocol and runtime together.**

---

## Precondition: the declared version ranges are currently fiction

This is the one thing that should be fixed **before** any split, and it is
worth fixing even if no split ever happens.

Every consumer in the workspace declares a semver range that is behind the
local package, and npm's workspace symlinks mean the range is never exercised
— the working tree is what actually resolves. The declared range is
documentation that nothing checks.

The sharpest case is not a range at all but a **same-version content drift**:

```
@aroha-sdk/audit  published 1.3.0   → no invite_* event types
@aroha-sdk/audit  working tree 1.3.0 → has invite_* event types
```

The version was not bumped when the events were added. Anything installing
`@aroha-sdk/audit@^1.2.0` from the registry today gets a 1.3.0 that is missing
types the runtime uses. Inside the monorepo this is invisible, because the
symlink wins. Outside it, it is a type error.

**This affects the runtime, not the website** — but it is the same class of
defect, and the website split is a good moment to establish the discipline:
bump on publish, and have CI install from the registry at least once.

---

## What the website actually depends on

Smaller than it first appears. A naive grep suggests 14 protocol packages;
**ten of those are inside `<CodeBlock code={`…`}>` documentation template
literals** — sample code shown to readers, not imports. The real surface is
**4 packages across 4 files**, which matches `apps/website/package.json`
exactly:

| File | Imports |
|---|---|
| `src/app/api/v1/signals/route.ts` | `createSignalsHandler` (reputation) |
| `src/lib/orchestrator.ts` | `ArohaClient`, `generateDID` (core); `SagaEngine`, `AlwaysApproveGate` (orchestrator); `StripeSettlement`, `NullSettlement`, `IReputationRecorder`, `ReputationRecordContext`, `SettlementOutcome` (settlement) |
| `src/lib/reputation.ts` | `BayesianReputationEngine`, `InMemoryReputationStore` |
| `src/lib/saga-store.ts` | `SagaLog` (type, orchestrator) |

### Verified: it compiles against the published pins

All four declared versions are published, and a probe importing all thirteen
symbols typechecks clean (`tsc --strict`, `moduleResolution: NodeNext`) against
exactly those versions:

```
@aroha-sdk/core@1.3.1  @aroha-sdk/orchestrator@1.2.3
@aroha-sdk/reputation@1.3.2  @aroha-sdk/settlement@1.3.0   → tsc exit 0
```

Two of the four already behave as they would post-split. `reputation` and
`settlement` are pinned exactly, so npm could not satisfy them from the
workspace and installed real tarballs — `apps/website/node_modules/@aroha-sdk/settlement`
is published 1.3.0, not a symlink. **The website is already building against
published settlement code today.**

The other two are ranges and do resolve to the working tree:

| package | declared | resolves to now | would resolve to post-split |
|---|---|---|---|
| core | `^1.3.1` | 1.8.0 (symlink) | 1.3.1 |
| orchestrator | `^1.2.3` | 1.3.0 (symlink) | 1.2.3 |

That five-minor gap on `core` is the only genuine behavioural risk in the
split. It is small in practice: the website's entire use of `core` is
`new ArohaClient()` and `generateDID(id, url)`, and both declarations are
byte-identical between 1.3.1 and 1.8.0. `PROTOCOL_VERSION` is `"1.0"` in both.

**Still, do not ship the split on a typecheck.** Before cutting over, either
bump the pins to current (`core@^1.8.0`, `orchestrator@^1.3.0`) or run the
site's own tests against 1.3.1. A clean compile proves the shapes match; it
does not prove the wire behaviour does.

---

## What moves

- `apps/website/` — **186 tracked files**, self-contained.
- **211 commits** touch only the website; `git filter-repo --path apps/website`
  preserves that history in the new repo.
- It already has its own `package-lock.json`, `.env.example` and
  `next.config.mjs`. There is no `.vercel/` directory in the tree.

## What does *not* move (and needs no change)

- `tsconfig.base.json` — the website's `tsconfig.json` does **not** extend it.
  It declares its own `paths: { "@/*": ["./src/*"] }` and nothing else.
- Root `package.json` has **no website-specific scripts**; the coupling is
  only the `apps/*` workspace glob.

## What breaks in the monorepo when the directory leaves

Each of these is a one-line edit, listed so none is discovered in CI:

| File | Change |
|---|---|
| `.gitignore:3-5` | drop the three `apps/website/*` lines |
| `.github/workflows/deploy.yml` | **delete** — it is the website's Vercel deploy; it moves with the site (carry `VERCEL_ORG_ID` / `VERCEL_PROJECT_ID` and the token secret across) |
| `.github/workflows/ci.yml:18,26` | drop the `apps/website/public/**` path filters |
| `scripts/build-ordered.mjs:86` | `["apps/website", "apps/aroha-runtime"]` → `["apps/aroha-runtime"]` |
| `README.md:179` | the directory listing line |
| `docs/infrastructure.md:233-284` | the website section — move it to the new repo |
| `package-lock.json` | regenerates on the next `npm install` |

Stale-but-harmless references that can stay: `CHANGELOG.md` (history),
`docs/superpowers/specs/…` (a dated design doc), and two source comments —
`apps/aroha-runtime/src/hub/publish.ts:6` and
`apps/aroha-runtime/src/engine/hosted.ts:6` — which point at website routes
for context. The second is worth keeping accurate: it notes that the runtime's
hosted-inference behaviour mirrors `apps/website/src/app/api/chat/route.ts`.
That is a **behavioural coupling with no compiler behind it**, and the split
removes the last thing making it visible. Either extract the shared provider
union into a package, or write the expectation into a test.

---

## Order of work

1. Fix the version discipline: bump `@aroha-sdk/audit` (its 1.3.0 is already
   published with different content) and reconcile every declared range with
   what is actually published.
2. Bump the website's `core` / `orchestrator` pins to current, so the split
   does not silently roll it back five minors.
3. `git filter-repo --path apps/website` into the new repo; move `deploy.yml`
   and the `docs/infrastructure.md` website section with it.
4. Apply the seven monorepo edits above; confirm `build-ordered.mjs` and CI
   are green without the directory.
5. Address the `hosted.ts` ↔ `chat/route.ts` coupling before the comment
   becomes the only record of it.
