---
name: aroha-mandates
description: Issue, attenuate and verify Aroha spending and task mandates with @aroha-sdk/credentials, including the governed verifier profile, guest grants (onBehalfOf/roomId) and the PSD3 actingFor side. Use when code must delegate spending or task authority from a person to an agent, or must check such authority before acting.
license: Apache-2.0
compatibility: Node.js 22+, TypeScript or JavaScript, @aroha-sdk/credentials 2.x and @aroha-sdk/core 2.x.
metadata:
  project: Aroha (https://github.com/ArohaLabs/aroha-protocol)
  spec: aroha-1.0 §6.5–§6.8
---

# Aroha mandates

A mandate is a signed, narrowing grant of authority. A person issues a root mandate to an agent; each delegate can only pass on a narrower one. The verifier checks the whole chain back to a root it trusts. Install: `npm install @aroha-sdk/credentials @aroha-sdk/core`.

## Rules to follow

- Verify the whole chain with `verifyMandateChain`. Do not rely on a single link: any agent can sign itself a root.
- Always pin the root: `expectedRoot`, `expectedRootPerson` or `trustedRoots`.
- Always pass a revocation hook (`isRevoked`) in production. It fails closed when the source is unreachable.
- Never take the caller's identity, room or on-behalf-of member from the request body. Take them from your transport authentication and your own records.
- Never put private keys in prompts, logs or tool arguments.

## Spending mandates

```ts
import { issueIntentMandate, attenuateToCart, verifyMandateChain, httpRevocationCheck } from "@aroha-sdk/credentials";

// Person → agent. actingFor (optional) declares the payment side; children inherit it.
const intent = await issueIntentMandate(personDid, agentDid, { spendLimitUsd: 200, currency: "USD" }, personKey, 3_600_000, { actingFor: "payer" });
// Agent → provider, narrower. Omitting a limit the parent sets is a widening, and is refused.
const cart = await attenuateToCart(intent, providerDid, { spendLimitUsd: 50 }, agentKey);

const result = await verifyMandateChain(cart.token, undefined, {
  expectedRoot: personDid,
  expectedGrantee: providerDid,
  isRevoked: httpRevocationCheck(registryUrl, { registryKeys }), // registryKeys: pin the signed revocation status
});
if (!result.valid) throw new Error(result.reason);
```

## Governed verifier profile (production gates)

`governedVerification()` turns on every protective check: a person root with a Key Event Log, a revocation hook, a required chain and a pinned root. It throws `GovernedProfileError` if a prerequisite is missing.

```ts
import { governedVerification, verifyMandateChain } from "@aroha-sdk/credentials";

const governed = governedVerification({ kelSource, isRevoked, expectedRootPerson: personDid });
const r = await verifyMandateChain(token, undefined, governed);
```

## Task mandates and guest grants

```ts
import { issueTaskMandate, enforceTaskConstraints } from "@aroha-sdk/credentials";

// Host person lends a strict subset of authority to their agent, for one guest in one room.
const grant = await issueTaskMandate(hostDid, agentDid, ["search", "draft-email"], {
  onBehalfOf: guestDid, roomId, reversibleOnly: true, humanGates: ["draft-email"],
}, hostKey);

// At the capability gate. Throws TaskConstraintViolation (code CONTEXT_MISMATCH for a wrong room or member).
await enforceTaskConstraints(grant.token, hostPublicKey, {
  expectedGrantee: agentDid,
  requestedCapability: "search",
  capabilityReversibility: "full",
  roomId: roomIdFromYourRoomRecord,
  onBehalfOf: memberDidFromYourRoomRecord,
});
```

A child of a guest grant must keep `onBehalfOf` and `roomId`. `attenuateTaskMandate` copies them when you leave them out.

## Checks before you finish

- Run `npx vitest run` in the package that uses this. The conformance vectors are in `packages/aroha-credentials/test-vectors/mandate-v2.json` and `spec-public/vectors/conversation-v1.json`.
- A `valid: false` result or a thrown violation means: do not act. Report the `reason` to the caller and do not retry with a wider mandate.
