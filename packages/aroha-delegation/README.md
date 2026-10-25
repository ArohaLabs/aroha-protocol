# @aroha-sdk/delegation

![Beta](https://img.shields.io/badge/status-beta-blue) ![npm](https://img.shields.io/npm/v/@aroha-sdk/delegation)

**Turnkey multi-hop delegation for agent networks.** Build webs of agents — A delegates to B, which delegates to C and D — where every hop carries signed, verifiable, shrinking authority, and a receipt tree comes back to whoever started it.

The cryptographic primitives live in `@aroha-sdk/credentials`; the single-agent server lives in `@aroha-sdk/run`. This package is the composition layer that turns "multi-hop agent web" from a custom verify/attenuate/call pipeline in every node into a few lines per node.

```
A (root issuer) ──► B (orchestrator) ──► C (searcher)
                                     └─► D (summariser)
```

## A node in the web

```typescript
import { serveDelegated, staticResolver } from "@aroha-sdk/delegation";

serveDelegated("orchestrator", {
  identity: { did: "did:aroha:acme:orchestrator", privateKey: myKey },
  trustAnchors: { "did:aroha:human:alice": alicePublicKeyB64 },
  resolvePublicKey: registryResolver(),   // or staticResolver({...}) for closed networks
}, async (ctx) => {
  ctx.assertCapability("research");        // throws unless the verified mandate allows it

  // Delegate onward — authority is attenuated automatically:
  // subset scope, depth − 1, blocked list carried forward, same correlationId
  const search  = await ctx.delegate(searcherDidHash, ctx.message,
                                     { allowed: ["web-search"] });
  const summary = await ctx.delegate(summariserDidHash, search.message,
                                     { allowed: ["summarise"] });
  return summary.message;
}).start(8000);
```

Every request to this agent **must** carry a valid mandate chain or it is rejected with 400 before your handler runs. Fail closed, always.

## Starting a chain (the root issuer)

```typescript
import { issueDelegation, callDelegated } from "@aroha-sdk/delegation";

const { envelope } = await issueDelegation(
  { did: "did:aroha:human:alice", privateKey: aliceKey },
  orchestratorDid,
  {
    allowed: ["research", "web-search", "summarise"],
    constraints: { maxDelegationDepth: 1 },  // B may delegate once; C/D may not
    ttlMs: 60_000,
  },
);

const res = await callDelegated(orchestratorEndpoint, "history of agent protocols", envelope);

console.log(res.message);
console.log(res.receipts[0]);          // B's receipt, with C's and D's nested in .children
```

## What the chain guarantees

Each hop appends one signed mandate to the envelope riding `context.aroha`. `verifyTaskMandateChain()` — run automatically by every `serveDelegated` node — checks the whole path, root → leaf:

| Check | Attack it stops |
|---|---|
| Every link's Ed25519 signature | Forged or tampered mandates |
| Root key pinned to `trustAnchors` | An attacker minting their own "root" |
| `grantor(i) === grantee(i−1)` + `parentMandateId` linkage | Splicing a mandate from another chain |
| `allowed(i) ⊆ allowed(i−1)` | Scope widening mid-chain |
| `blocked` list must survive every hop | Laundering a ban through a sub-agent |
| Child expiry ≤ parent expiry | Zombie authority outliving its grant |
| **`maxDelegationDepth` strictly decrements** | Runaway agent-spawns-agent recursion |
| Chain length ≤ `maxDepth` (default 8), even with no `maxDelegationDepth` | Unbounded sub-agent depth |
| `isRevoked(mandateId, grantor)` on every link (option; a throwing hook rejects) | A revoked grant living on until expiry |
| `kelSource` (option): E-DID grantors checked against their current key; revoked identities refused | A revoked or rotated identity's grants |

Depth is enforced here, at the chain level — `maxDelegationDepth: 0` means the mandate is a dead end, and `ctx.delegate()` refuses with `DELEGATION_DEPTH_EXCEEDED` before a child token is even signed.

## Enforcing the leaf's constraints

A verified chain says what was granted; the serving path must also check what the request does. Pass `requestScope` so the leaf mandate's `allowed`/`blocked`, `actionLimits`, `dataAccess`, `reversibleOnly` and `humanGates` are enforced **before your handler runs**:

```typescript
serveDelegated("records", {
  identity, trustAnchors,
  isRevoked: myTaskRevocationCheck,
  // YOUR code decides what a request touches — never the caller's claim.
  requestScope: (req) => ({ capability: "lookup", dataAccess: { "customer-db": "read" }, reversibility: "full" }),
}, async (ctx) => {
  ctx.assertDataAccess("drafts", "write");                      // per-action data checks
  ctx.assertCapability("send", { reversibility: "irreversible", approval: await ctx.requestApproval("send") });
  return "...";
});
```

`createDelegationMiddleware` does the same for `ArohaServer`, defaulting the capability to the request body's `capability` (403 when none can be determined). Action counts are kept per process.

## Receipts come back as a tree

Every node builds a `TaskReceipt` automatically (actions, violations, timings) and returns it as a response artifact. `ctx.delegate()` collects downstream receipts and nests them, so the root issuer receives the **whole execution tree** under one `correlationId`:

```
orchestrator (complete)
 ├─ searcher   (complete) — actions: web-search
 └─ summariser (complete) — actions: summarise
```

## Runnable example

A full A → B → (C, D) web on localhost — including a blocked over-delegation, a rejected forged root, and an out-of-grant refusal — ships in the repo at `examples/delegation-web/demo.mjs`.

## Mandate verification without @aroha-sdk/run

`serveDelegated` above wraps `@aroha-sdk/run`'s `serve()` end to end — the
right choice when you want its streaming/approval/receipt machinery too. If
you're hosting with a raw `ArohaServer` from `@aroha-sdk/core` instead and
just need mandate-chain verification, mount it directly as middleware — the
same composability pattern `@aroha-sdk/credentials`'
`createRbacMiddleware()` already uses:

```typescript
import { ArohaServer } from "@aroha-sdk/core";
import { createDelegationMiddleware, getVerifiedMandate } from "@aroha-sdk/delegation";

const server = new ArohaServer({
  agentDID: "did:aroha:acme:orchestrator",
  didDocument,
  port: 8000,
  resolvePublicKey,
  middleware: [
    createDelegationMiddleware({
      did: "did:aroha:acme:orchestrator",
      trustAnchors: { "did:aroha:human:alice": alicePublicKeyB64 },
    }),
  ],
  onMessage: async (envelope, respond) => {
    const verified = getVerifiedMandate(envelope); // undefined only if require:false and none was sent
    // ...
  },
});
```

No `@aroha-sdk/run` dependency in this path. You lose `serveDelegated`'s
automatic receipt stitching and `ctx.delegate()` convenience — this only
answers "is there a valid mandate chain granting the caller access," the
same boundary RBAC draws around permission checks.

## Wire format

No new protocol: the envelope rides the existing `RunRequest.context` under the `aroha` key, so any `/v1/run`-speaking agent can participate.

```jsonc
{ "message": "…", "context": { "aroha": {
  "v": 1,
  "chain": ["<rootToken>", "<childToken>", …],
  "rootKeyB64": "<root issuer's Ed25519 public key>",
  "correlationId": "…"
}}}
```

## License

Apache-2.0 — see [LICENSE](../../LICENSE).