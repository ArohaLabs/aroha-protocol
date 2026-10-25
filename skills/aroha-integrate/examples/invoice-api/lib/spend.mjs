// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

// The whole authorisation check for one invoice, in one library call.
//
// verifyHttpSpendRequest checks, in order: the amount is a real, positive
// number; the agent's proof over THIS request (method, path, body, audience,
// single-use nonce, ≤5-minute expiry); the mandate chain back to the pinned
// customer DID with the agent as grantee; every link's constraints (currency,
// merchants, approval threshold, limits); and then charges the amount as a
// running total against every link — or charges nothing at all.

import { verifyHttpSpendRequest } from "@aroha-sdk/credentials";

export async function authoriseSpend({ header, audience, method, url, body, nonces, ledger, customerDid, amountUsd, now }) {
  const r = await verifyHttpSpendRequest(header, {
    audience, method, url, body, nonces, ledger,
    expectedRoot: customerDid,   // from enrollment — never from the request
    isRevoked: null,             // explicit opt-out for the example; use httpRevocationCheck(registryUrl) in production
    amountUsd,                   // from the signed body
    currency: "USD",
    now,                         // one clock for the presentation, the nonce and mandate expiry
  });
  if (!r.ok) return r;
  return { ok: true, holder: r.holder, release: () => r.charge.release() };
}
