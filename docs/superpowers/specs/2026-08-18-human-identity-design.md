<!-- Copyright (c) 2026 Aroha Labs
     SPDX-License-Identifier: Apache-2.0 -->

# Human Identity in the Runtime — Design

**Date:** 2026-08-18
**Status:** Draft for review
**Scope:** Give the runtime a concept of *which person* is acting, so audit records can name an approver and org deployments can meet compliance requirements — without breaking the zero-friction single-user experience that works today.

**Blocks:** the action-request path in [2026-08-18-internal-consult-design.md](./2026-08-18-internal-consult-design.md) §5 for any regulated deployment.

---

## 1. The gap

Verified, not assumed: `ensureToken()` generates one 32-byte token into `~/.aroha/token`, and `gateway/guard.ts` checks that single value. There is no user model, no per-person session, and no role anywhere in the runtime.

For a personal tool that is correct design — the person at the keyboard *is* the user, and asking them to log in to their own laptop would be friction with no security benefit. The problem appears only when the audit log must answer **"which employee approved this action?"**, which is the central question in any compliance review of the action-request path.

## 2. The scoping insight

Identity is not universally required. It is required by **deployment shape**:

| Shape | Who uses it | Identity needed? |
|---|---|---|
| **Personal** — one human, one laptop | The owner | **No.** The token *is* the identity. |
| **Shared/departmental** — one agent host, many employees | A team | **Yes.** Actions are attributable to a person. |

So authentication is an **opt-in deployment mode**, never a universal upgrade. The current no-account experience is a genuine product strength for individual users and must not regress — a personal install should never see a login screen.

---

## 3. Three phases

### Phase 1 — Named local users

The smallest change that unblocks `approvedBy`.

- `aroha user add <name>` issues a distinct token per person; `aroha user list` / `aroha user revoke <name>`.
- `guard.ts` resolves token → `{ userId, displayName }` instead of a boolean match, and attaches it to the request context.
- Audit records the resolved `userId`.
- The existing single anonymous token keeps working unchanged when no users are defined — that is the personal-mode path.

**Good for:** small teams, pilots, anywhere without an IdP.
**Not good enough for:** enterprises — provisioning is manual, and offboarding depends on someone remembering to revoke.

### Phase 2 — OIDC / SSO

What enterprises actually require: no second user directory, and offboarding that follows the IdP.

- The runtime acts as an OIDC relying party against the org's IdP (Entra ID, Okta, Google Workspace).
- **Authorization Code + PKCE**, not a client secret — a publicly distributed binary cannot hold a secret. Redirect to `http://127.0.0.1:<port>/auth/callback`, the standard native-app pattern.
- Session cookie replaces the bearer token for browser traffic; the token path stays for programmatic callers.
- `userId` becomes the IdP `sub` claim, with email/name for display.
- Enabled by config (`auth = "oidc"` plus issuer/client id). Absent that config, nothing changes.

**Design constraint:** the local gateway is loopback-bound by default. OIDC must work without exposing the runtime publicly — which the native-app loopback redirect flow already assumes, so no conflict.

**Status: built** (2026-08-19). Authorization Code + PKCE (S256 only), `state` and `nonce` both required and single-use, ID tokens verified against the IdP's JWKS with the algorithm pinned to RS256. No dependency — `node:crypto` imports a JWK and verifies RS256 directly.

`/auth/*` is exempt from the bearer-token stage, because a person signing in does not yet have a credential. The exemption is narrow and deliberate: Host, Origin and Sec-Fetch-Site are still enforced; `/auth/login` only redirects to the configured IdP; and `/auth/callback` does nothing without a `state` this runtime issued moments earlier, single-use, plus a PKCE verifier only this process holds.

**Limitations:**
- **Sessions are in-memory** — a restart signs everyone out. For a local runtime that is arguably correct rather than merely tolerable, but it is a real property.
- **No refresh-token handling.** A session lasts its own TTL (12h) regardless of what the IdP thinks; revoking a user at the IdP does not end an established Aroha session before it expires.
- **No back-channel logout.** Same consequence as above, from the other direction.
- **The install token still works in OIDC mode**, for scripts, the CLI and `--relay`. Enabling SSO does not close that path, and it resolves to `unattributed` exactly as in Phase 1.

### Phase 3 — Per-user approval keys

Turns an approval from *logged* into *non-repudiable*.

Today `signInvariants(invariants, signerDid, privateKey)` signs with the **agent's** key, so the audit proves "agent A asserted a human approved." With a per-user keypair the approver signs directly, and the consulted agent verifies that a *specific person* authorised the action — not that an agent claimed so.

- Each user gets a keypair at first login, stored via the §9.7 keystore.
- `signerDid` becomes the user's DID; approver identity is bound into the signed invariants.
- Receiving agents verify against the org's user directory.

**Status: partially built** (2026-08-18). Each user now gets an Ed25519 keypair at creation, private half in the OS keystore (§9.7), and an action-request approval is signed by that key rather than the agent's. What it changes: an agent claiming "Dana approved" while Dana did not must now steal Dana's key, not merely write her name in a field.

The receiver cannot resolve a person DID on its own — there is no org-wide user directory — so the request carries the user's public key and the *agent* counter-signs the binding. The receiver verifies the agent's attestation first (its key is recoverable from its content-addressed DID), then the person's signature against the key that attestation vouches for.

**What is still NOT proved, and must not be claimed:**
- **That the human was present.** A session bearer token still triggers the signing; the key signs on that session's behalf. Phase 1's limitation is narrowed, not eliminated.
- **That the key really is that person's**, to anyone outside this runtime. The agent remains the only attester. A genuine org directory, or an issuer the receiver independently trusts, is what would close this — and neither exists.
- **Non-repudiation in a legal sense.** A holder of the runtime's OS keystore can sign as any of its users.

---

## 4. What changes where

| Component | Change |
|---|---|
| `workspace/paths.ts` | User store alongside the token file |
| `gateway/guard.ts` | Resolve credential → identity; keep anonymous-token path |
| `gateway/server.ts` | Auth routes for OIDC (Phase 2); user CRUD routes |
| Audit record | Populate `approvedBy` |
| `main.ts` | `aroha user …` subcommands |
| `config.toml` | `auth = "none" \| "users" \| "oidc"`, issuer, client id |

`auth = "none"` is the default and is exactly today's behaviour.

---

## 5. Testing

- Anonymous mode unchanged — the full existing `guard.test.ts` suite passes untouched (the strongest regression signal that personal use has not regressed).
- A revoked user's token is refused immediately.
- Two users' tokens resolve to different `userId`s and produce distinguishable audit records.
- OIDC: callback with a valid code establishes a session; a mismatched PKCE verifier is refused; an expired session re-challenges.
- An approval recorded under one user cannot be attributed to another.

---

## 6. Disclosed limitations

- **Phase 1 tokens are bearer credentials.** Anyone holding one is that user. Acceptable for a pilot, insufficient where non-repudiation matters — that is Phase 3.
- **No roles or permissions.** Every authenticated user has the same rights. Per-user capability limits (who may approve *what*) are a separate design; this only establishes *who*.
- **A per-user key proves less than it appears to.** See Phase 3's status note: it binds an approval to a key this runtime holds for a person, not to the person. Overstating this in a compliance conversation would be worse than not having built it.
- **The install token remains an unattributed path once users exist.** As built, it is still accepted and resolves to an explicit `unattributed` identity rather than being locked out. Locking it out would strand an operator who added users and then lost their own token; treating it as a person would corrupt the attribution this phase exists to establish. It is visible as not-a-person in every audit record, but a deployment wanting *strict* attribution needs a config switch that does not exist yet.
- **Loopback assumption.** OIDC via the native-app loopback redirect assumes the user has a browser on the same machine. Headless/SSH sessions need device-code flow, which the platform-sync design (§5.6) already contemplates but this does not yet implement.
