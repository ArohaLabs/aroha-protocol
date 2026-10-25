// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Regression tests for three problems found in the published 1.3.0 SDK:
 *   (a) a spend gate must check the chain's root against the root the caller
 *       expects, not only "the signature is valid under the key I was handed";
 *   (b) a task mandate must not be accepted where a spending mandate is expected;
 *   (c) enforceSpendingConstraints must refuse NaN, negative, infinite and
 *       non-number amounts.
 */

import { describe, it, expect, beforeAll, vi } from "vitest";
import * as ed from "@noble/ed25519";
import { generateDid } from "@aroha-sdk/core";
import {
  enforceSpendingConstraints,
  issueIntentMandate,
  issueTaskMandate,
  verifyMandate,
  verifyMandateChain,
  SpendingConstraintViolation,
} from "./mandate.js";

interface Key { priv: Uint8Array; pub: Uint8Array; did: string }
async function key(): Promise<Key> {
  const priv = ed.utils.randomPrivateKey();
  const pub = await ed.getPublicKeyAsync(priv);
  return { priv, pub, did: generateDid(pub) };
}

function sortKeys(x: unknown): unknown {
  if (Array.isArray(x)) return x.map(sortKeys);
  if (x && typeof x === "object") {
    return Object.fromEntries(Object.keys(x).sort().map((k) => [k, sortKeys((x as Record<string, unknown>)[k])]));
  }
  return x;
}

let human: Key, agent: Key, mallory: Key;
let token: string;

beforeAll(async () => {
  vi.spyOn(console, "warn").mockImplementation(() => {});
  human = await key();
  agent = await key();
  mallory = await key();
  token = (await issueIntentMandate(human.did, agent.did, { spendLimitUsd: 50 }, human.priv, 600_000)).token;
});

const code = (p: Promise<unknown>) => p.then(() => "ACCEPTED", (e: unknown) => (e instanceof SpendingConstraintViolation ? e.code : String(e)));

describe("(a) the root is checked against what the caller expects", () => {
  it("a self-minted chain signed by its own key is refused once the root is pinned", async () => {
    const forged = (await issueIntentMandate(mallory.did, agent.did, { spendLimitUsd: 1e6 }, mallory.priv, 600_000)).token;
    // Signature is valid under the key passed — that alone is not authority.
    expect(await code(enforceSpendingConstraints(forged, mallory.pub, { proposedAmountUsd: 10, expectedRoot: human.did }))).toBe("MANDATE_INVALID");
    expect(await code(enforceSpendingConstraints(forged, mallory.pub, { proposedAmountUsd: 10, trustedRoots: [human.did] }))).toBe("MANDATE_INVALID");
    expect(await code(enforceSpendingConstraints(forged, mallory.pub, { proposedAmountUsd: 10, trustedRoots: [] }))).toBe("MANDATE_INVALID");
    expect(await code(enforceSpendingConstraints(token, human.pub, { proposedAmountUsd: 10, expectedRoot: human.did }))).toBe("ACCEPTED");
    expect((await verifyMandateChain(forged, undefined, { expectedRoot: human.did })).valid).toBe(false);
  });

  it("a caller key that disagrees with the grantor's self-certifying DID is refused", async () => {
    const r = await verifyMandate(token, mallory.pub, undefined, {});
    expect(r.valid).toBe(false);
    expect(await code(enforceSpendingConstraints(token, mallory.pub, { proposedAmountUsd: 1 }))).toBe("MANDATE_INVALID");
  });
});

describe("(b) a task mandate is not a spending mandate", () => {
  it("a v2 task token is refused by spending enforcement and chain verification", async () => {
    const task = await issueTaskMandate(human.did, agent.did, ["payments.send"], {} as never, human.priv, 600_000, {
      spendingConstraints: { spendLimitUsd: 1000 },
    });
    expect(await code(enforceSpendingConstraints(task.token, human.pub, { proposedAmountUsd: 10, expectedRoot: human.did }))).toBe("MANDATE_INVALID");
    expect((await verifyMandateChain(task.token, undefined, { expectedRoot: human.did })).valid).toBe(false);
  });

  it("a legacy v1 body carrying mandateType is refused even when it also carries spending constraints", async () => {
    // v1 task and v1 spending signatures cover the same bytes (sorted JSON of
    // the body), so the type marker is the only thing telling them apart.
    const body = {
      mandateType: "hybrid",
      mandateTier: "intent",
      constraints: { spendLimitUsd: 1000 },
      grantee: agent.did,
      grantor: human.did,
      issuedAt: new Date(Date.now() - 1000).toISOString(),
      expiresAt: new Date(Date.now() + 600_000).toISOString(),
      parentMandateId: null,
      mandateId: "00000000-0000-4000-8000-0000000000aa",
    };
    const sig = await ed.signAsync(new TextEncoder().encode(JSON.stringify(sortKeys(body))), human.priv);
    const v1 = Buffer.from(JSON.stringify({ mandate: body, signature: Buffer.from(sig).toString("base64url") })).toString("base64url");
    const r = await verifyMandate(v1, human.pub);
    expect(r.valid).toBe(false);
    expect(r.reason).toMatch(/mandateType/);
    expect(await code(enforceSpendingConstraints(v1, human.pub, { proposedAmountUsd: 10, expectedRoot: human.did }))).toBe("MANDATE_INVALID");
  });
});

describe("(c) proposed amounts must be finite, non-negative numbers", () => {
  it.each([
    ["NaN", NaN],
    ["negative", -1],
    ["negative zero is fine", -0],
    ["Infinity", Infinity],
    ["-Infinity", -Infinity],
    ["string", "10"],
    ["null", null],
    ["undefined", undefined],
    ["bigint", 10n],
    ["boxed number", new Number(10)],
  ])("%s", async (name, amount) => {
    const got = await code(enforceSpendingConstraints(token, human.pub, { proposedAmountUsd: amount as number }));
    expect(got).toBe(name === "negative zero is fine" ? "ACCEPTED" : "INVALID_AMOUNT");
  });

  it("an amount over the limit is LIMIT_EXCEEDED, and the limit itself is accepted", async () => {
    expect(await code(enforceSpendingConstraints(token, human.pub, { proposedAmountUsd: 50.01 }))).toBe("LIMIT_EXCEEDED");
    expect(await code(enforceSpendingConstraints(token, human.pub, { proposedAmountUsd: 50 }))).toBe("ACCEPTED");
  });
});
