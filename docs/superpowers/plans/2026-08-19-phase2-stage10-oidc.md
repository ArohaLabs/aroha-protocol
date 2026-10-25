# Phase 2 Stage 10: OIDC / SSO

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let a deployment authenticate people against the org's existing identity provider, so there is no second user directory to provision and offboarding follows the IdP. Human-identity spec Phase 2 — the gap in the middle, with Phase 1 (named local users) and Phase 3 (per-user approval keys) already built.

**Architecture:** The runtime acts as an OIDC relying party using **Authorization Code + PKCE**, never a client secret — a publicly distributed binary cannot hold one. The redirect lands on the loopback gateway itself (`http://127.0.0.1:<port>/auth/callback`), the standard native-app pattern, which is why this works without exposing the runtime publicly. A session cookie carries browser identity; the bearer-token path stays for programmatic callers.

**Tech Stack:** TypeScript, vitest, `node:crypto` only — verified that it imports a JWK and verifies RS256 directly, so ID-token verification needs no new dependency (which matters under `bun build --compile`, the same constraint that shaped the keystore and mcp-guard decisions).

**Spec:** [../specs/2026-08-18-human-identity-design.md](../specs/2026-08-18-human-identity-design.md) §3 Phase 2

## Global Constraints

- Copyright header on new files.
- **`guard.test.ts` must pass with an empty diff**, exactly as in Phase 1. A personal install must never see a login screen, and that suite is the proof.
- **Verify the ID token's signature.** The token arrives from a server-to-server call we made over TLS, so a forged one is already hard — but "we fetched it ourselves" is an argument about the channel, not about the token. Accepting an unverified assertion of identity and calling the feature OIDC would be overclaiming.
- **PKCE is mandatory, S256 only.** `plain` is permitted by the RFC and defeats the point; refuse it.
- **The `state` parameter is not optional.** Without it the callback is a CSRF sink — an attacker can complete a login flow in a victim's browser and bind the victim's session to the attacker's account.
- **Nonce binding.** The ID token's `nonce` must match the one this runtime generated for that authorization request, or a token minted for a different request could be replayed into this one.
- A session must expire. An indefinite session is a bearer credential with no revocation path.

---

## File Structure

| File | Responsibility |
|---|---|
| `apps/aroha-runtime/src/gateway/oidc.ts` | *Create* — discovery, PKCE, code exchange, ID-token verification |
| `apps/aroha-runtime/src/gateway/sessions.ts` | *Create* — session store, cookie parsing |
| `apps/aroha-runtime/src/gateway/guard.ts` | *Modify* — resolve a session cookie to an identity |
| `apps/aroha-runtime/src/gateway/server.ts` | *Modify* — `/auth/login`, `/auth/callback`, `/auth/logout` |
| `apps/aroha-runtime/src/workspace/config.ts` | *Modify* — `authMode`, `oidcIssuer`, `oidcClientId` |

---

## Task 1: PKCE and ID-token verification

**Files:** Create `src/gateway/oidc.ts` + test.

```ts
export function createPkcePair(): { verifier: string; challenge: string };
export async function discover(issuer: string): Promise<OidcEndpoints>;
export async function exchangeCode(opts): Promise<{ idToken: string }>;
export async function verifyIdToken(idToken, opts: {
  jwksUri: string; issuer: string; clientId: string; nonce: string;
}): Promise<{ ok: true; claims: IdTokenClaims } | { ok: false; reason: string }>;
```

Verification checks, all of them, in this order:
1. Structure — three base64url segments, `alg: RS256` (refuse `none` and HS256 outright: `none` is the classic bypass, and HS256 with a public key as the HMAC secret is the classic key-confusion attack)
2. Signature against the JWKS key matching `kid`
3. `iss` exactly equals the configured issuer
4. `aud` contains the configured client id
5. `exp` in the future, `iat` not absurdly far in the future
6. `nonce` matches the one issued for this request

- [ ] **Tests** against a locally generated RSA keypair acting as the IdP — real signing, real verification, no mocks:
  - a well-formed token verifies and yields `sub`
  - `alg: none` is refused
  - `alg: HS256` signed with the public key as secret is refused (key confusion)
  - a signature from a different key is refused
  - wrong `iss`, wrong `aud`, expired `exp`, mismatched `nonce` each refused with a distinct reason
  - an unknown `kid` is refused rather than falling back to any available key

- [ ] Commit.

---

## Task 2: Sessions

**Files:** Create `src/gateway/sessions.ts` + test.

```ts
export class SessionStore {
  create(identity: Identity, ttlMs?: number): string;   // returns opaque id
  resolve(sessionId: string): Identity | null;          // null when absent or expired
  destroy(sessionId: string): void;
}
export function parseCookie(header: string | undefined, name: string): string | null;
```

- 32 bytes of CSPRNG, same shape as the install token. Default TTL 12 hours.
- In-memory, and say so: a restart logs everyone out. For a local runtime that is acceptable and arguably correct; it is a disclosed limitation, not an oversight.
- Cookie flags: `HttpOnly`, `SameSite=Lax`, `Path=/`. **Not `Secure`** — the gateway is plain HTTP on loopback, and setting `Secure` would stop the cookie being sent at all. Worth a comment, since a reviewer should be able to see that was a decision rather than an omission.

- [ ] Tests: round-trip; expiry; destroy; unknown id; cookie parsing including multiple cookies and absent header.

- [ ] Commit.

---

## Task 3: Guard resolves a session

**Files:** `guard.ts` + `guard-identity.test.ts` additions.

`GuardConfig` gains `resolveSession?: (sessionId: string) => Identity | null`. Stage 4 order applies: user token → session cookie → install token. A browser in OIDC mode presents a cookie and no Authorization header, so the token stages must not reject before the cookie is consulted.

**Important:** in OIDC mode the install token must still work for programmatic callers — otherwise enabling SSO breaks every script and the `--relay`/CLI paths. It resolves to `UNATTRIBUTED` exactly as in Phase 1.

- [ ] Tests: cookie resolves to a person; expired/unknown cookie falls through to the token stages; `guard.test.ts` still empty-diff.

- [ ] Commit.

---

## Task 4: Routes and config

- `GET /auth/login` → generate PKCE + state + nonce, store them, 302 to the IdP
- `GET /auth/callback?code&state` → validate state, exchange, verify, create session, set cookie, redirect to `/`
- `POST /auth/logout` → destroy session, clear cookie

Config: `authMode = "none" | "oidc"`, `oidcIssuer`, `oidcClientId`. Absent → nothing changes, and `/auth/*` returns 404 rather than existing-but-broken.

**Pending authorization requests expire** (10 minutes) and are single-use — a state value that survives its exchange is replayable.

- [ ] Tests through a real gateway against a fake IdP served from `node:http`, matching how `relay-client.test.ts` fakes the relay broker: full round trip, state mismatch refused, replayed state refused, callback without a pending request refused.

- [ ] Commit.

---

## Task 5: Verification

- [ ] Runtime suite, `guard.test.ts` empty diff, build, monorepo tests, push, CI.
- [ ] Update the spec: Phase 2 built, with limitations (in-memory sessions; no refresh-token handling, so a session ends at TTL regardless of IdP session state; no back-channel logout).
