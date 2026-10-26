<!-- Copyright (c) 2026 Aroha Labs
     SPDX-License-Identifier: Apache-2.0 -->

# Wrap Any REST API as a Aroha Agent in ~50 Lines

Any service with a REST API can become a Aroha-capable agent. This guide shows the repeatable pattern used by `@aroha-sdk/stripe-agent`, `@aroha-sdk/salesforce-agent`, and `@aroha-sdk/zendesk-agent`.

---

## The pattern

A Aroha proxy agent does three things:

1. **Validates** the inbound signed envelope (handled by `ArohaServer` automatically)
2. **Translates** the Aroha capability + params into a REST API call
3. **Signs and returns** the result as a `ArohaResponse`

That's it. Here it is in ~50 lines for a fictional `HubSpot` contact lookup:

```typescript
// agents/aroha-hubspot-agent/src/server.ts
import { ArohaServer, generateDID } from "@aroha-sdk/core";
import { InMemoryRegistry } from "@aroha-sdk/registry";
import { buildEnvelope } from "@aroha-sdk/core";
import type { ArohaEnvelope, ArohaRequestBody, ArohaResponseBody } from "@aroha-sdk/core";

// ── 1. Identity ──────────────────────────────────────────────────────────────

const PORT = Number(process.env.PORT ?? 3070);
const ENDPOINT = `http://localhost:${PORT}/aroha/v1`;
const { did, privateKey, publicKey, document: didDocument } = await generateDID("hubspot-agent", ENDPOINT);

// ── 2. Registry (so other agents can discover this agent) ───────────────────

const registry = new InMemoryRegistry();
await registry.register(did, MANIFEST_CID, publicKey, {   // MANIFEST_CID: CID of your published manifest
  capabilityIds: ["get-contact", "search-contacts", "create-contact"],
});

// ── 3. REST helper ───────────────────────────────────────────────────────────

async function hubspot(method: string, path: string, body?: unknown) {
  const res = await fetch(`https://api.hubapi.com${path}`, {
    method,
    headers: {
      Authorization: `Bearer ${process.env.HUBSPOT_ACCESS_TOKEN}`,
      "Content-Type": "application/json",
    },
    body: body ? JSON.stringify(body) : undefined,
  });
  if (!res.ok) throw new Error(`HubSpot ${res.status}: ${await res.text()}`);
  return res.json();
}

// ── 4. Message handler ───────────────────────────────────────────────────────

async function onMessage(envelope: ArohaEnvelope, respond: (r: ArohaEnvelope) => void) {
  if (envelope.type !== "ArohaRequest") return;
  const { capability, params } = envelope.body as ArohaRequestBody;

  try {
    let result: Record<string, unknown>;
    if (capability === "get-contact") {
      result = await hubspot("GET", `/crm/v3/objects/contacts/${params.contactId}`);
    } else if (capability === "search-contacts") {
      result = await hubspot("POST", "/crm/v3/objects/contacts/search", {
        filterGroups: [{ filters: [{ propertyName: "email", operator: "EQ", value: params.email }] }],
      });
    } else if (capability === "create-contact") {
      result = await hubspot("POST", "/crm/v3/objects/contacts", { properties: params });
    } else {
      throw new Error(`Unknown capability: ${capability}`);
    }

    const reply = await buildEnvelope("ArohaResponse", did, envelope.from,
      { capability, result } satisfies ArohaResponseBody, envelope.correlationId, privateKey);
    respond(reply);
  } catch (err) {
    const errReply = await buildEnvelope("ArohaError", did, envelope.from,
      { code: "Aroha_INTERNAL_ERROR" as never, message: String(err), retryable: true },
      envelope.correlationId, privateKey);
    respond(errReply);
  }
}

// ── 5. Start ─────────────────────────────────────────────────────────────────

const server = new ArohaServer({
  agentDID: did, didDocument, port: PORT,
  resolvePublicKey: async (senderDID) => {
    const rec = await registry.resolveByDID(senderDID);
    return rec ? new Uint8Array(Buffer.from(rec.publicKeyB64, "base64url")) : null;
  },
  onMessage,
});
await server.start();
console.log(`[HubSpot Agent] ${did} listening on port ${PORT}`);
```

That's 52 lines. **Any REST API. Same pattern.**

---

## Adding saga support (Reserve → Commit → Cancel)

For write operations that need atomic rollback, extend the handler with three extra cases:

```typescript
// In-memory reservation store
const reservations = new Map<string, { capability: string; params: Record<string, unknown> }>();

async function onMessage(envelope: ArohaEnvelope, respond: (r: ArohaEnvelope) => void) {
  const { type, body, correlationId: cid, from } = envelope;

  if (type === "ArohaRequest") {
    // ... read operations as above
  }

  if (type === "ArohaReserve") {
    const { capability, params, holdDurationMs } = body as ArohaReserveBody;
    // Validate params before committing
    if (capability === "create-deal" && !params.dealName) throw new Error("dealName required");
    const token = `res-${Date.now()}`;
    reservations.set(token, { capability, params });
    const expiresAt = new Date(Date.now() + holdDurationMs).toISOString();
    respond(await buildEnvelope("ArohaReserveAck", did, from,
      { reservationToken: token, expiresAt }, cid, privateKey));
    return;
  }

  if (type === "ArohaCommit") {
    const { reservationToken } = body as ArohaCommitBody;
    const res = reservations.get(reservationToken);
    if (!res) throw new Error("Unknown token");
    // Now do the actual write
    const result = await hubspot("POST", "/crm/v3/objects/deals", { properties: res.params });
    reservations.delete(reservationToken);
    respond(await buildEnvelope("ArohaCommitAck", did, from,
      { reservationToken, result }, cid, privateKey));
    return;
  }

  if (type === "ArohaCancel") {
    const { reservationToken } = body as ArohaCancelBody;
    reservations.delete(reservationToken); // nothing was created yet
    respond(await buildEnvelope("ArohaCancelAck", did, from,
      { reservationToken }, cid, privateKey));
  }
}
```

The saga pattern adds ~25 lines. Total: **~75 lines** for a fully atomic, Aroha-capable proxy agent.

---

## Checklist for any new proxy agent

- [ ] `generateDID(agentName, endpoint)` — identity
- [ ] `InMemoryRegistry` with `capabilityIds` — discovery
- [ ] `REST helper` — fetch wrapper with auth header
- [ ] `onMessage` switch on `envelope.type` — dispatcher
- [ ] `ArohaServer` with `resolvePublicKey` — transport
- [ ] For write ops: in-memory `reservations` Map, `ArohaReserve/Commit/Cancel` cases

---

## Scaffold with the CLI

```bash
aroha create-bridge --name hubspot --sdk HubSpot -y
cd aroha-hubspot-bridge
# Implement handleCapability() in src/bridge.ts
npm run build
# The scaffold names the package @aroha-sdk/hubspot-bridge: rename it to a scope you own, then
npm publish --access public
```

---

## Existing proxy agents

Published on npm (1.0.0); their source is not in this repository.

| Agent | Capabilities | Port |
|-------|-------------|------|
| `@aroha-sdk/stripe-agent` | get-customer, list-invoices, create-payment-intent (saga), create-invoice (saga) | 3060 |
| `@aroha-sdk/salesforce-agent` | get-account, search-leads, create-lead (saga), create-opportunity (saga) | 3061 |
| `@aroha-sdk/zendesk-agent` | get-ticket, search-tickets, create-ticket (saga), add-comment (saga) | 3062 |
| `@aroha-sdk/github-agent` | list-issues, create-issue (saga), merge-pull-request (saga) | — |
| `@aroha-sdk/jira-agent` | search-issues, create-issue (saga), transition-issue (saga) | — |

Submit your own to the [Aroha ecosystem registry →](ecosystem.md)
