# @aroha-sdk/credentials

![Stable](https://img.shields.io/badge/status-stable-brightgreen) ![npm](https://img.shields.io/npm/v/@aroha-sdk/credentials)

Issue, attenuate, and verify cryptographically signed spending mandates — the bounded-authority primitive for Aroha agent chains.

## Install

```bash
npm install @aroha-sdk/credentials
```

## Quick example

```typescript
import {
  issueIntentMandate, attenuateToCart, attenuateToPayment,
  verifyMandateChain, redeemPaymentMandate, httpRedemptionStore, httpRevocationCheck,
} from "@aroha-sdk/credentials";

// Step 1: the human issues the root intent mandate to their agent.
const intent = await issueIntentMandate(
  humanDID, agentDID,
  { spendLimitUsd: 500, requireHumanApprovalAboveUsd: 100, allowedMerchants: [airlineDID, hotelDID] },
  humanPrivateKey,
  3_600_000,            // TTL: 1 hour
);

// Step 2: the agent narrows to a cart for one provider. Fields it omits
// (here requireHumanApprovalAboveUsd) are inherited from the parent.
const cart = await attenuateToCart(intent, providerDID,
  { spendLimitUsd: 300, allowedMerchants: [airlineDID] }, agentPrivateKey);

// Step 3: the provider narrows to a single payment.
const payment = await attenuateToPayment(cart, processorDID,
  { spendLimitUsd: 250, allowedMerchants: [airlineDID] }, providerPrivateKey);

// Step 4: the payee verifies the WHOLE chain back to the human…
const result = await verifyMandateChain(payment.token, resolveKey, {
  expectedRoot: humanDID,          // the human you expect to be paying
  expectedGrantee: processorDID,   // yourself
  isRevoked: httpRevocationCheck(registryUrl),   // GET /v1/mandates/:id/revoked
});
if (!result.valid) throw new Error(result.reason);

// …and records the spend so the same mandate cannot be spent twice.
// httpRedemptionStore shares one cumulative cap across every payee on the registry.
await redeemPaymentMandate(httpRedemptionStore(registryUrl, apiKey), result.mandate!, 249.99, airlineDID,
  { token: payment.token });
```

`resolveKey(did)` returns the Ed25519 public key for a DID. For content-addressed
DIDs (`did:aroha:z<base58btc(pubkey)>`) you can omit it — the default,
`resolveContentAddressedKey`, derives the key from the DID itself. Namespaced DIDs
(`did:aroha:acme.agent`) need a registry-backed resolver.

## What each check guarantees

| Property | Where it is enforced |
|---|---|
| Every link signed by its grantor, back to a root intent | `verifyMandateChain` |
| `child.grantor === parent.grantee`, `child.parentMandateId === parent.mandateId` | `verifyMandateChain` |
| Tier order intent → cart → payment (never broader) | `verifyMandateChain` (and at attenuation) |
| Each child's constraints narrow its parent's | `verifyMandateChain` on every link (attenuation-time check is advisory only) |
| `expiresAt`, `validFrom`, `validUntil`, child never outlives parent | `verifyMandateChain` / `verifyMandate` |
| Revocation of any link | `isRevoked` hook (`httpRevocationCheck`; revoke with `revokeMandate`) |
| Parent cannot hand out more than its limit in total | `SpendingLedger` at attenuation |
| A payment mandate cannot be spent beyond its limit in total | `redeemPaymentMandate` + a shared `RedemptionStore` (`D1RedemptionStore` / `httpRedemptionStore`) |
| An HTTP request's amount is within every link's constraints and running total | `verifyHttpSpendRequest` + an `ISpendingLedger` |

Narrowing rule: if a parent sets a constraint, the child must set it to an equal
or narrower value — omitting it is a widening and is rejected by the verifier.

## Token format

v2 tokens are `base64url(JSON({ v: 2, mandate, signature, chain }))`, where `chain`
is the signed ancestry, root first, excluding the mandate itself. A v2 signature is
Ed25519 over the RFC 8785 (JCS) canonical form of `{ "mandate": <body>, "v": 2 }`.
Cross-SDK conformance vectors live in [`test-vectors/mandate-v2.json`](./test-vectors/mandate-v2.json)
(regenerate with `npx vite-node scripts/gen-test-vectors.ts`; output must not change).

Amounts (`*Usd`) are JSON numbers: finite, non-negative, integers or decimals with
at most cent precision. Non-finite values are rejected.

Legacy v1 tokens (`{ mandate, signature }`, no chain) still verify with
`verifyMandate`, but a v1 token that is not itself a root carries no ancestry and
**cannot** prove that a human authorised it (`chainVerified: false`).

## Presenting a mandate to an HTTP API

A mandate token on its own is a bearer credential: whoever copies it can use it.
A REST server must never accept the token alone. The holder (the token's grantee)
signs each request into one `Aroha-Mandate` header, bound to the server
(`audience`), the method, the path and query exactly as sent, the SHA-256 of the
exact body bytes, a single-use nonce and an expiry of at most 5 minutes
(spec §6.9.2; vectors in [`test-vectors/http-presentation-v1.json`](./test-vectors/http-presentation-v1.json)).

```ts
// Client (the mandate's grantee)
const body = JSON.stringify({ item: "widget", qty: 2 });
const headers = await presentMandateHttp({
  token, holderDid: myDid, holderPrivateKey: myKey,
  audience: "https://api.example.com", method: "POST",
  url: "https://api.example.com/v1/orders", body,
});
await fetch("https://api.example.com/v1/orders", { method: "POST", headers: { ...headers, "content-type": "application/json" }, body });

// Server (raw body bytes, before JSON parsing)
const nonces = new InMemoryHttpPresentationNonces(); // one per process; use Redis/DB when you run several
async function handle(req, res, rawBody) {
  const r = await verifyHttpMandateRequest(req.headers["aroha-mandate"], {
    audience: "https://api.example.com", method: req.method, url: req.url, body: rawBody,
    nonces, expectedRoot: HUMAN_DID, isRevoked: httpRevocationCheck(REGISTRY_URL),
  });
  if (!r.ok) return res.status(r.status).json({ error: r.code, reason: r.reason });
  // r.mandate is the verified leaf: check r.mandate.constraints before acting.
}
```

`verifyHttpMandateRequest` refuses to run without a root pin option (`expectedRoot` or
`trustedRoots`; a supplied but empty value is a `ROOT_NOT_PINNED` refusal, see below)
and an explicit `isRevoked` (a hook, or `null`). `isRevoked: null`
is a quiet, explicit opt-out: no warning is printed, and the result says
`revocationChecked: false`. For task mandates,
use `verifyHttpPresentation` and then the task-mandate verifier with
`expectedGrantee: result.holder`. Sign the bytes you send: a body that a client
library re-serialises, or a URL it rewrites, will not verify.

### Spending: `verifyHttpSpendRequest`

`verifyHttpMandateRequest` never sees the amount. If the endpoint spends money
("send an invoice up to what the customer authorised"), use
`verifyHttpSpendRequest` instead. It does everything above and then:

- refuses a task mandate (`NOT_A_SPENDING_MANDATE`);
- checks the amount (`INVALID_AMOUNT`, 400: finite and greater than 0) before it
  looks at the presentation, so a bad amount does not use up the client's nonce;
- checks **every link** of the chain: `currency` (default `"USD"` on both sides),
  `allowedMerchants` against `merchant`, `merchantCategory`,
  `requireHumanApprovalAboveUsd` against `humanApproved`, and the amount against
  `min(spendLimitUsd, sessionLimitUsd)`. If a mandate sets a constraint and you did
  not pass the input it needs (for example `allowedMerchants` with no `merchant`), the
  request is refused. Validity windows and expiry are checked by the chain verifier;
- adds the amount to a **running total for every link**, keyed by
  `mandateRedemptionKey(link)` (`grantor#mandateId`). It charges all links or none: if
  one link would go over, the links already charged are released (`OVER_LIMIT`).
  Two sibling carts under one $500 intent cannot spend more than $500 between them,
  and two concurrent requests cannot both take the last of a budget.

```ts
import { verifyHttpSpendRequest, MapSpendingLedger, InMemoryHttpPresentationNonces } from "@aroha-sdk/credentials";

const nonces = new InMemoryHttpPresentationNonces();
const ledger = new MapSpendingLedger(); // per process, empty after a restart: use a shared ISpendingLedger in production

async function sendInvoice(req, res, rawBody) {
  const invoice = JSON.parse(rawBody); // the body the holder signed
  const r = await verifyHttpSpendRequest(req.headers["aroha-mandate"], {
    audience: "https://api.example.com", method: req.method, url: req.url, body: rawBody, nonces,
    expectedRoot: CUSTOMER_DID, isRevoked: null, ledger, amountUsd: invoice.amountUsd,
  });
  if (!r.ok) {
    res.status(r.status).json({ error: r.code, reason: r.reason });
    return;
  }
  try {
    await billing.send(invoice);
  } catch (e) {
    await r.charge.release(); // the side effect failed: give the money back to every link
    throw e;
  }
  res.status(201).end();
}
```

Result: `{ ok: true, holder, token, mandate, chain, rootGrantor, revocationChecked, charge: { amountUsd, allocations, release() } }`
or `{ ok: false, code, reason, status }`. Codes: the presentation codes (401),
`MANDATE_INVALID`, `NOT_A_SPENDING_MANDATE`, `CURRENCY_MISMATCH`,
`MERCHANT_NOT_ALLOWED`, `MERCHANT_CATEGORY_NOT_ALLOWED`, `HUMAN_APPROVAL_REQUIRED`,
`OVER_LIMIT` (403), `INVALID_AMOUNT` (400), `LEDGER_UNAVAILABLE` (503).
`humanApproved: true` means your own approval flow approved this spend; never take it
from the client. Cross-SDK vectors: [`test-vectors/http-spend-v1.json`](./test-vectors/http-spend-v1.json).

**The ledger is required.** `MapSpendingLedger` keeps totals in memory: per process,
and reset on restart (anything already spent can be spent again). With more than
one process, or across restarts, pass a shared ledger: `D1SpendingLedger`, or your
own `ISpendingLedger` whose `allocate` is atomic. Use a ledger instance for request
spending only — not the one you pass to `issueIntentMandate` / `attenuateToCart`,
which counts what a parent hands out to children, not what is spent.

**`verifyHttpSpendRequest` or `redeemPaymentMandate`?** Both keep a running total
under `grantor#mandateId` with the limit `min(spendLimitUsd, sessionLimitUsd)`.
`verifyHttpSpendRequest` is for a server that receives the mandate over HTTP: it
accepts intent, cart and payment leaves and charges every link of the chain, with a
release for a failed side effect. `redeemPaymentMandate` is the settlement call for a
payee that verified a payment mandate itself (or shares a cap with other payees through
`httpRedemptionStore`); it charges the payment mandate only and has no release. Use one
of them for a given population of mandates, not both: their stores are separate, so a
payment mandate charged through both could be spent twice its limit.

**An empty pin is a refusal, not a crash.** If you pass `expectedRoot` (or
`trustedRoots`) but its value is empty — `undefined`, `null`, `""` or `[]`, as when
you look up a customer who never enrolled — `verifyHttpMandateRequest` and
`verifyHttpSpendRequest` return `{ ok: false, code: "ROOT_NOT_PINNED", status: 403 }`
without consuming the nonce. They still throw when you supply neither option at all
(a misconfiguration), or a value of the wrong type.

**One clock.** `now` (Unix ms) governs the presentation's expiry, the nonce store's
expiry and every mandate's validity window, so a test can check mandate expiry
without sleeping: issue a mandate with a 60-second TTL, then present and verify with
`now: Date.now() + 120_000` and the result is `MANDATE_INVALID` ("Mandate expired").

### Enrollment: which DID speaks for which customer

`expectedRoot` must come from a table you keep: your customer account → their DID.
Whatever fills that table decides whose mandates you honour, so an enrollment must
prove two things together:

- the **account**: the customer is signed in to *this* account with your own login.
  The library cannot check a login. You pass the account your authentication
  established as **`authenticatedAccountId`** — never an id from the request body.
- the **key**: the DID's private key signed a fresh, single-use, expiring challenge
  you issued *to that account*, for *this* service (`audience`).

```ts
import {
  InMemoryEnrollmentStore, issueEnrollmentChallenge, completeEnrollment, enrolledDid, signEnrollment,
} from "@aroha-sdk/credentials";

const AUDIENCE = "https://invoices.example.com";
const enrollments = new InMemoryEnrollmentStore(); // one process; implement EnrollmentStore on your DB otherwise

// Server, POST /enroll/challenge — requires your login.
async function enrollChallenge(session: { accountId: string }) {
  return issueEnrollmentChallenge(enrollments, { authenticatedAccountId: session.accountId });
  // → { challenge, expiresAt, accountId }   (5 minutes, single use)
}

// Customer's device: the key never leaves it.
async function proveKey(c: { challenge: string; accountId: string }, myDid: string, myKey: Uint8Array) {
  const proof = await signEnrollment({ accountId: c.accountId, did: myDid, challenge: c.challenge, audience: AUDIENCE, privateKey: myKey });
  return { did: myDid, challenge: c.challenge, proof };
}

// Server, POST /enroll — requires your login.
async function enroll(session: { accountId: string }, body: { did: unknown; challenge: unknown; proof: unknown }) {
  const r = await completeEnrollment(enrollments, {
    authenticatedAccountId: session.accountId, audience: AUDIENCE,
    did: body.did, challenge: body.challenge, proof: body.proof,
  });
  if (!r.ok) {
    return { status: r.status, body: { error: r.code, reason: r.reason } };
  }
  return { status: 200, body: { did: r.did, replaced: r.replaced } };
}

// Per spending request: the customer id only CHOOSES which enrolled DID to pin.
async function rootFor(customerId: string) {
  return enrolledDid(enrollments, customerId); // undefined → ROOT_NOT_PINNED (403), not a crash
}
```

`completeEnrollment` spends the challenge first, whatever the outcome, then refuses
with `MALFORMED` (400, not a challenge string), `CHALLENGE_UNKNOWN` (400, never issued
or already used), `CHALLENGE_ACCOUNT_MISMATCH` (403, issued to another account),
`CHALLENGE_EXPIRED` (400), `BAD_DID` (400, not a content-addressed `did:aroha:z…` DID —
or a `did:aroha:E…` DID resolvable through `kelSource`, or one your `resolvePublicKey`
vouches for), `BAD_PROOF` (403) or `STORE_UNAVAILABLE` (503). Otherwise it records
account → DID; a later enrollment replaces it (key rotation) and reports the old DID
as `replaced`. It throws only for a server misconfiguration (no store, no
`authenticatedAccountId`, no `audience`).

The proof is an Ed25519 signature (base64url) by the DID's key over the UTF-8 bytes of
the JCS canonicalisation of
`{ "purpose": "aroha.enrollment/v1", "audience", "accountId", "did", "challenge" }`,
so a proof made for one account, challenge, DID or service is useless for any other.
An `EnrollmentStore` keeps challenges and bindings; its `consumeChallenge` must be
atomic (return and delete in one step: `DELETE … RETURNING`, Redis `GETDEL`). Python:
`issue_enrollment_challenge`, `complete_enrollment`, `enrolled_did`, `sign_enrollment` in
`aroha.enrollment`. Cross-SDK vectors: [`test-vectors/enrollment-v1.json`](./test-vectors/enrollment-v1.json).

### Negative tests: `@aroha-sdk/credentials/testing`

Test-only builders for presentations a correct client would never send. Not
exported from the package root or `/mandates`; do not import it in production code.

```ts
import { presentMandateHttpUnchecked, buildHttpPresentationHeader } from "@aroha-sdk/credentials/testing";

// A presenter who is not the token's grantee (presentMandateHttp would refuse to build this):
const notGrantee = await presentMandateHttpUnchecked({
  token, holderDid: strangerDid, holderPrivateKey: strangerKey,
  audience: "https://api.example.com", method: "POST", url: "https://api.example.com/v1/invoices", body,
});
// Any field, signed with any key; extraMembers / omitMembers / proof tamper with the header itself:
const wrongKey = await buildHttpPresentationHeader({
  token, holder: agentDid, signerPrivateKey: strangerKey,
  audience: "https://api.example.com", method: "POST", url: "/v1/invoices", body,
});
```

## API

- `issueIntentMandate(grantorDID, granteeDID, constraints, privateKey, ttlMs?, { ledger? })` — root intent mandate. Returns `SignedMandate` (`{ mandate, signature, token, v: 2, chain: [] }`).
- `attenuateToCart(parent, granteeDID, constraints, grantorPrivateKey, ttlMs?, { ledger? })` — narrower cart mandate carrying the parent's chain.
- `attenuateToPayment(parent, granteeDID, constraints, grantorPrivateKey, ttlMs?, { ledger? })` — narrower payment mandate carrying the parent's chain.
- `verifyMandateChain(token, resolveKey?, { expectedRoot?, expectedGrantee?, isRevoked?, clockToleranceMs?, now?, maxDepth? })` — **the check to gate money on.** Returns `{ valid, mandate?, reason?, chainVerified?, chain?, rootGrantor? }`.
- `verifyMandate(token, leafGrantorPublicKey, expectedGrantee?, { keyRotatedAt?, resolveKey?, isRevoked?, expectedRoot?, clockToleranceMs?, now? })` — checks the leaf against one caller-supplied key; for v2 tokens also verifies the chain. **On its own it does not prove human authorisation** for legacy v1 child tokens — check `chainVerified`.
- `enforceSpendingConstraints(token, leafGrantorPublicKey, { proposedAmountUsd, merchantDID?, requireChain?, … })` — verify + amount/merchant gate.
- `redeemPaymentMandate(store, verifiedMandate, amountUsd, merchantDID, { token?, now? })` — cumulative redemption up to `min(spendLimitUsd, sessionLimitUsd)`. `InMemoryRedemptionStore` is per-process only. For a cap shared across processes or payees use `D1RedemptionStore(db)` (your own D1/SQLite; schema in `redemption-d1.ts`) or `httpRedemptionStore(registryUrl, apiKey)` (the registry's `POST /v1/mandates/:id/redeem`, which re-verifies the token and derives the limit itself — pass `{ token }`). Stores key a mandate's total by `mandateRedemptionKey(mandate)` (`<grantor>#<mandateId>`), not the bare id: the id is the minter's choice, so a stranger could otherwise mint a look-alike and spend your cap. Read totals back with `store.redeemedMicros(mandateRedemptionKey(mandate))`.
- `verifyHttpSpendRequest(header, { ...verifyHttpMandateRequest options, amountUsd, currency?, merchant?, merchantCategory?, humanApproved?, ledger })` — holder proof, chain, every link's spending constraints, and an all-or-nothing running-total charge of every link (see above).
- `issueEnrollmentChallenge(store, { authenticatedAccountId, ttlMs?, now? })`, `completeEnrollment(store, { authenticatedAccountId, audience, did, challenge, proof, now?, resolvePublicKey?, kelSource?, kelStore? })`, `enrolledDid(store, accountId)`, `signEnrollment({ accountId, did, challenge, audience, privateKey })`, `InMemoryEnrollmentStore` — account → DID enrollment (see above).
- `checkSpendAgainstConstraints(constraints, { amountUsd, currency?, merchant?, merchantCategory?, humanApproved? })`, `checkSpendAmount(amountUsd)`, `mandateCumulativeLimitUsd(constraints)` — the per-spend checks the spending gates share.
- `httpRevocationCheck(registryUrl, { cacheMs?, failOpen?, onError? })` — a `MandateRevocationCheck` for `isRevoked`, backed by `GET /v1/mandates/:id/revoked?grantor=…`. The hook is called as `isRevoked(mandateId, grantor)`; revocations are per (grantor, mandateId). Fails closed (throws → chain rejected) when the registry cannot be reached unless `failOpen: true`.
- `revokeMandate(registryUrl, token, grantorPrivateKey, { revokerDid? })` — revoke the token's mandate as its grantor or any ancestor grantor (`POST /v1/mandates/:id/revoke`). Revoking a mandate invalidates every mandate beneath it.
- `decodeMandateToken(token)` — decode (without verifying) into a `SignedMandate` you can attenuate.
- `checkNarrowing(parent, child, parentTier, childTier)` — returns the reason a child widens its parent, or `null`.
- `canonicalizeJcs(value)`, `mandateSigningPayloadV2(mandate)` — canonicalisation primitives.

## License

Apache-2.0 — see [LICENSE](../../LICENSE).