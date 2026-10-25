<!-- Copyright (c) 2026 Aroha Labs
     SPDX-License-Identifier: Apache-2.0 -->

# Invoice API — an agent may only spend what a customer authorised

A REST tool that AI agents call to send invoices for your customers. An agent may send one only if **that customer** authorised **that agent**, only **up to the amount** they allowed (as a running total), and only **before it expires**. Everything else is refused.

This example exists to answer the three questions people get stuck on:

1. **Where does the customer's key live?** On the customer's side — never with the agent or your server.
2. **How does the server know which customer to trust?** Enrollment: the customer proves their account *and* their key once.
3. **How does the agent get the authorisation?** The customer signs it on their device and hands back a token; the agent presents it with a proof of its own on every call.

## Who holds what

| Party | Holds | Never holds |
|---|---|---|
| **Customer** (your app or wallet on their device) | Their private key, created on the device (`customer.mjs init`) | The agent's key |
| **Agent** (wherever it runs) | Its own private key; the customer's *token* | The customer's private key |
| **Invoice service** (`server.mjs`) | Customer id → DID (from enrollment); presentation nonces; the spending ledger | Anyone's private key |

Here each key is a file readable only by its owner (`lib/keystore.mjs`). In production: the customer's key in the OS keychain, a passkey-backed wallet, or a key service you run for them; the agent's key in its host's KMS or vault. A `did:aroha:z…` DID contains its public key, so the service needs no key directory.

## The flow

```text
customer device                         invoice service                         agent
───────────────                         ───────────────                         ─────
init → key + DID
enroll ── account login ───────────────▶ challenge (single use, 5 min)
       ── login + signature(challenge) ─▶ verify → record customerId ↔ DID
                                                                           ◀── "please authorise did:aroha:z…"
authorise(agent DID, $500, 1 h) ── token ────────────────────────────────▶
                                         ◀── POST /tools/send_invoice ────── body + Aroha-Mandate
                                             (token + agent's proof over this exact request)
                                         pin the ENROLLED DID for this customer
                                         verify proof + chain + limits, charge the running total
                                         send → on failure, give the money back
```

**Enrollment needs both proofs.** The account login stops anyone enrolling a DID for someone else's account; the signature over a fresh challenge stops anyone enrolling a DID whose key they do not hold. A later enrollment replaces the DID (key rotation). Losing the device key means re-enrolling through the account — in a product, behind your normal account recovery.

**The customer id in the request only chooses which enrolled DID to pin.** A mandate signed by anyone else — another customer, or a key the agent made up — fails verification against it.

## Run it

```bash
npm install            # @aroha-sdk/core and @aroha-sdk/credentials 2.x
npm test               # the whole flow, end to end, including every refusal
```

By hand, with a server from `server.mjs` running:

```bash
node customer.mjs init
node customer.mjs enroll http://127.0.0.1:3005 acme-login
node agent.mjs did                                         # send this to the customer
node customer.mjs authorise <agentDid> 500 1               # prints the token
node agent.mjs invoice http://127.0.0.1:3005 acme 120 <token>
```

## What the tests prove

| Case | Result |
|---|---|
| Authorised agent, within the limit (and as a running total) | sent |
| One invoice over the limit; the running total over the limit | `OVER_LIMIT` |
| Another agent presenting the token | refused (holder proof) |
| Another customer's authorisation used for this customer | refused (root pinned to the enrolled DID) |
| A mandate the agent signed itself | refused |
| Expired, tampered or missing authorisation | refused |
| The send fails after the charge | the amount is given back |
| Enrolling for someone else's account, or without the key, or replaying a challenge | refused |

## Before production

- Make accounts, enrollments, challenges, presentation nonces and the spending ledger **durable and shared** — here they are in memory and reset on restart.
- Turn on **revocation** (`httpRevocationCheck` against your registry) so a customer can withdraw an authorisation before it expires.
- Record a **signed receipt** for every executed and refused invoice (`@aroha-sdk/core` action receipts).
- Use your real login for enrollment, not an API key in a config object.
