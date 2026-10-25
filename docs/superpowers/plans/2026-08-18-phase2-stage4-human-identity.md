# Phase 2 Stage 4: Human Identity (Phase 1 — Named Local Users)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give the runtime a concept of *which person* is acting, so an audit record can name an approver. This is Phase 1 of the human-identity spec — named local users with per-person tokens — and it is what the action-request path (the next stage) is gated on for any regulated deployment.

**Architecture:** A `UserStore` (JSON under the workspace, same shape as `AgentStore`) plus one change to `checkRequest`: it stops returning a boolean-ish verdict and starts returning *who*. The single-token path is preserved exactly, because the spec is explicit that a personal install must never see a login screen — authentication is an opt-in deployment mode, not a universal upgrade.

**Tech Stack:** TypeScript, vitest, `node:crypto` (already used by `ensureToken`).

**Spec:** [../specs/2026-08-18-human-identity-design.md](../specs/2026-08-18-human-identity-design.md) §3 Phase 1, §4

## Global Constraints

- Copyright header on every new file.
- **`guard.test.ts` must pass completely untouched.** The spec names this as the strongest regression signal that personal use has not regressed. If a test in it needs changing, the change is wrong.
- **Anonymous mode stays the default.** With no users defined, behaviour is byte-identical to today.
- **Constant-time token comparison for users too.** A per-user token is a bearer credential; comparing it with `===` reintroduces the timing oracle `safeEqual` exists to close.
- **Tokens are stored hashed, not in plaintext.** `ensureToken` stores the install token in plaintext because it is the credential the launch URL must reproduce; a user token is only ever *checked*, never re-displayed, so there is no reason to keep the original — and a user file that leaks should not hand over every employee's credential.
- **Disclosed, not hidden:** the install token keeps working when users exist, resolving to an explicit *unattributed* identity rather than silently masquerading as a person. Locking it out would strand an operator who set up users and then lost their own token; pretending it is a person would corrupt the attribution the stage exists to establish. It is visible in the audit record either way.

---

## File Structure

| File | Responsibility |
|---|---|
| `apps/aroha-runtime/src/host/users.ts` | *Create* — `UserStore`: add/list/revoke, token→identity |
| `apps/aroha-runtime/src/workspace/paths.ts` | *Modify* — `usersFile` |
| `apps/aroha-runtime/src/gateway/guard.ts` | *Modify* — resolve credential → identity |
| `apps/aroha-runtime/src/gateway/server.ts` | *Modify* — thread identity to admin routes |
| `apps/aroha-runtime/src/gateway/admin-api.ts` | *Modify* — attribute a kill-switch flip to the person |
| `apps/aroha-runtime/src/main.ts` | *Modify* — `aroha user add/list/revoke` |

---

## Task 1: UserStore

**Files:** Create `src/host/users.ts` + `src/host/users.test.ts`; modify `paths.ts` (`usersFile: join(root, "users.json")`).

**Interfaces:**
- Produces: `class UserStore { add(displayName): {user, token}; list(): User[]; revoke(id): boolean; resolve(token): Identity | null; isEmpty(): boolean }`
- `interface User { id: string; displayName: string; tokenHash: string; createdAt: string }`
- `interface Identity { userId: string; displayName: string }`

- [ ] **Step 1: Write the failing test**

```ts
// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { resolveWorkspace, ensureWorkspace } from "../workspace/paths.js";
import { UserStore } from "./users.js";

let root: string;
let store: UserStore;
beforeEach(() => {
  root = mkdtempSync(join(tmpdir(), "aroha-users-"));
  store = new UserStore(ensureWorkspace(resolveWorkspace(root)));
});
afterEach(() => rmSync(root, { recursive: true, force: true }));

describe("UserStore", () => {
  it("is empty on a fresh install — that is what keeps personal mode anonymous", () => {
    expect(store.isEmpty()).toBe(true);
    expect(store.list()).toEqual([]);
  });

  it("issues a distinct token per person and resolves it back to them", () => {
    const dana = store.add("Dana");
    const sam = store.add("Sam");
    expect(dana.token).not.toBe(sam.token);
    expect(store.resolve(dana.token)).toEqual({ userId: dana.user.id, displayName: "Dana" });
    expect(store.resolve(sam.token)).toEqual({ userId: sam.user.id, displayName: "Sam" });
  });

  it("never stores the token itself, only a hash", () => {
    const { token } = store.add("Dana");
    const raw = JSON.stringify(store.list());
    // A user file that leaks must not hand over every employee's credential.
    expect(raw).not.toContain(token);
  });

  it("returns null for an unknown token", () => {
    store.add("Dana");
    expect(store.resolve("f".repeat(64))).toBe(null);
  });

  it("refuses a token that resolves after revocation", () => {
    const { user, token } = store.add("Dana");
    expect(store.resolve(token)).not.toBe(null);
    expect(store.revoke(user.id)).toBe(true);
    expect(store.resolve(token)).toBe(null);
  });

  it("revoking an unknown id reports it rather than silently succeeding", () => {
    expect(store.revoke("nope")).toBe(false);
  });

  it("persists across instances — a restart must not forget who exists", () => {
    const { token } = store.add("Dana");
    const reopened = new UserStore(ensureWorkspace(resolveWorkspace(root)));
    expect(reopened.resolve(token)?.displayName).toBe("Dana");
  });
});
```

- [ ] **Step 2: Run to verify it fails. Step 3: Implement.**

Hash with `sha256`; the token is 32 random bytes hex-encoded, matching `ensureToken`'s shape. Write with `{ mode: 0o600 }` and `restrictToOwner`, same as the token file.

- [ ] **Step 4: Run. Step 5: Commit.**

---

## Task 2: The guard resolves an identity

**Files:** `src/gateway/guard.ts` + a NEW `src/gateway/guard-identity.test.ts` (leave `guard.test.ts` untouched — that is the regression signal).

- [ ] **Step 1: Write the failing test** covering:
  - no `resolveUser` configured → `{ ok: true }`, `identity` undefined (today's behaviour)
  - `resolveUser` configured, user token supplied → `identity` is that user
  - `resolveUser` configured, install token supplied → `identity` is the explicit unattributed sentinel, NOT a person
  - `resolveUser` configured, unknown token → `invalid_token`, 401
  - a revoked user's token is refused immediately

- [ ] **Step 2–3: Implement.** `GuardConfig` gains an optional resolver; `GuardResult`'s ok branch gains `identity`:

```ts
export interface Identity {
  userId: string;
  displayName: string;
}

/**
 * Resolves a supplied bearer token to a person, or null if it is not a
 * user token. Injected rather than imported so the guard stays a pure
 * function with no I/O — the property its whole test suite depends on.
 */
export type ResolveUser = (token: string) => Identity | null;

export interface GuardConfig {
  token: string;
  port: number;
  resolveUser?: ResolveUser;
}

export type GuardResult =
  | { ok: true; identity?: Identity }
  | { ok: false; status: number; reason: GuardRejection };
```

Stage 4 becomes: try `resolveUser` first (a user token is the common case in a shared deployment), then fall back to the install token.

```ts
  const supplied = bearerToken(headers["authorization"]) ?? req.query?.token ?? null;
  if (supplied === null) {
    return { ok: false, status: 401, reason: "missing_token" };
  }

  // A user token identifies a person. Checked first: in a shared deployment
  // it is the ordinary case, and the install token is the exception.
  const user = cfg.resolveUser?.(supplied) ?? null;
  if (user !== null) {
    return { ok: true, identity: user };
  }

  if (!safeEqual(supplied, cfg.token)) {
    return { ok: false, status: 401, reason: "invalid_token" };
  }

  // The install token is valid but names nobody. When users exist it is
  // reported as explicitly unattributed rather than left to look like a
  // person — see this module's note on why it is not simply locked out.
  return cfg.resolveUser
    ? { ok: true, identity: UNATTRIBUTED }
    : { ok: true };
```

with

```ts
/**
 * What the install token resolves to once named users exist.
 *
 * Not locked out: an operator who added users and then lost their own token
 * would otherwise be stranded with no way back in. Not silently treated as a
 * person either: an audit record naming a human who did not act is worse
 * than one that says plainly nobody was named.
 */
export const UNATTRIBUTED: Identity = {
  userId: "unattributed",
  displayName: "Unattributed (install token)",
};
```

- [ ] **Step 4: Run BOTH `guard.test.ts` and the new file.** `guard.test.ts` passing untouched is the deliverable, not a formality.

- [ ] **Step 5: Commit.**

---

## Task 3: Attribute operator actions

**Files:** `server.ts`, `admin-api.ts`, `admin.ts` (+ tests)

- [ ] Thread `verdict.identity` from `handle()` into `handleAdminApi`.
- [ ] `POST /v1/admin/consults/{disable,enable}` passes the identity's `userId` to `admin.setConsultsDisabled(disabled, actor)`, so the audit entry names who flipped it rather than the constant `"operator"`.
- [ ] `GET /v1/admin/status` reports `identity`, so an operator can see who the runtime thinks they are.
- [ ] Test: with a user token, the toggle's audit entry carries that user's id; with the install token, it carries `unattributed`.

---

## Task 4: `aroha user` subcommands

**Files:** `main.ts` (+ `main.test.ts` if one exists — check first)

There is no subcommand registry; `main()` is a flat `if` chain on `argv[0]`. Follow that pattern rather than inventing a framework for three commands.

```
aroha user add <name>     Issue a token for a person
aroha user list           Who has access
aroha user revoke <id>    Immediately invalidate a person's token
```

- [ ] `add` prints the token ONCE with a plain warning that it is not recoverable — it is stored hashed.
- [ ] Update `HELP`.
- [ ] Wire `new UserStore(ws)` into `up()`, passing `resolveUser: (t) => users.resolve(t)` to `startGateway` **only when users exist** — so a personal install's guard config is unchanged, not merely equivalent.

---

## Task 5: Full verification

- [ ] `guard.test.ts` untouched and green.
- [ ] Full runtime suite, `npm run build`, `npm test`, push, CI green.

---

## Disclosed limitations (carry into the spec's §6)

- **Phase 1 tokens are bearer credentials.** Anyone holding one is that user. Sufficient for a pilot, not for non-repudiation — that is Phase 3 (per-user signing keys).
- **No roles.** Every authenticated user has identical rights; this establishes *who*, not *what they may do*.
- **The install token remains an unattributed path** when users exist (see Task 2's rationale). A deployment wanting strict attribution needs a config switch that does not exist yet.
