<!-- Copyright (c) 2026 Aroha Labs
     SPDX-License-Identifier: Apache-2.0 -->

# Recipe: Converting an A2A Agent to Aroha

The A2A (Agent2Agent) protocol — an open Linux Foundation project — uses JSON message passing with `taskId`/`messageId`
fields and `role: "ROLE_USER" | "ROLE_AGENT"` semantics (A2A 1.0). Aroha adds Ed25519 identity, replay protection,
atomic sagas, and registry discovery on top of the same JSON-over-HTTP foundation.

The `@aroha-sdk/a2a-bridge` package handles the message format translation.

---

## Option A — CLI sidecar (fastest, 2 minutes)

Generate a Aroha wrapper that proxies to your existing A2A agent over HTTP.
Your A2A agent keeps running unchanged.

```bash
# Install the CLI
npm install -g @aroha-sdk/cli

# Generate the wrapper (interactive)
aroha convert --from a2a --endpoint http://localhost:8080

# Or non-interactive:
aroha convert \
  --from a2a \
  --name my-flight-agent-aroha \
  --port 3001 \
  --endpoint http://localhost:8080 \
  --out ./my-flight-agent-aroha

cd my-flight-agent-aroha
npm install && npm run dev
```

The generated agent:
- Accepts signed Aroha envelopes on port 3001
- Verifies Ed25519 signatures and enforces RBAC
- Converts each envelope to an A2A message using `arohaToA2a()`
- Forwards to your A2A agent as a JSON-RPC `SendMessage` call (`sendMessage()` from `@aroha-sdk/a2a-bridge`)
- Converts the A2A response back using `a2aToAroha()` + re-signs

**Limitation:** The bridge runs at Trust Level 1 (no Ed25519 proof on A2A messages).
Use Option B for Trust Level 2+.

---

## Option B — Native conversion (full compliance)

Rewrite the A2A handler to speak Aroha natively. This is the path to saga support and
higher trust levels.

### Step 1 — Scaffold a new provider

```bash
aroha init my-flight-agent --type provider --port 3001
cd my-flight-agent
npm install
```

### Step 2 — Map A2A fields to Aroha

| A2A concept | Aroha equivalent |
|-------------|----------------|
| `taskId` | `envelope.correlationId` |
| `messageId` | `envelope.id` |
| `role: "ROLE_USER"` → sends requests | `ArohaRequest` |
| `role: "ROLE_AGENT"` → sends responses | `ArohaResponse` |
| `parts[].data` | `envelope.body` (unwrapped) |
| `metadata.capability` | `envelope.body.capability` |
| No saga | `ArohaReserve` / `ArohaCommit` / `ArohaCancel` |

### Step 3 — Migrate your A2A handler

**Before (A2A):**

```typescript
app.post("/message", async (req, res) => {
  const { taskId, parts } = req.body as A2AMessage;
  const data = parts.find(p => p.data !== undefined)?.data ?? {};

  if (data.capability === "search-flights") {
    const results = await flightService.search(data.params);
    res.json({
      messageId: crypto.randomUUID(),
      taskId,
      role: "ROLE_AGENT",
      parts: [{ data: { result: results } }],
    });
  }
});
```

**After (Aroha — in `src/handlers.ts`):**

```typescript
case "ArohaRequest": {
  const { capability, params } = envelope.body as { capability: string; params: Record<string, unknown> };
  if (capability === "search-flights") {
    const result = await flightService.search(params);
    return buildEnvelope("ArohaResponse", agentDID, from,
      { capability, result },
      correlationId, privateKey);
  }
  // unknown capability → ArohaError (see default case)
}
```

### Step 4 — Add saga handlers (optional but recommended)

A2A has no reservation concept. To make bookings atomic, add reserve/commit/cancel:

```typescript
case "ArohaReserve": {
  const { capability, params, holdDurationMs } = envelope.body;
  if (capability === "book-flight") {
    const token = `RES-${crypto.randomUUID()}`;
    reservations.set(token, { params, expiresAt: new Date(Date.now() + holdDurationMs) });
    return buildEnvelope("ArohaReserveAck", agentDID, from,
      { reservationToken: token, expiresAt: reservations.get(token)!.expiresAt.toISOString() },
      correlationId, privateKey);
  }
}

case "ArohaCommit": {
  const res = reservations.get(envelope.body.reservationToken);
  if (!res?.committed) {
    res!.committed = true;
    res!.result = await flightService.book(res!.params);
  }
  return buildEnvelope("ArohaCommitAck", agentDID, from,
    { reservationToken: envelope.body.reservationToken, result: res!.result },
    correlationId, privateKey);
}

case "ArohaCancel": {
  const res = reservations.get(envelope.body.reservationToken);
  if (res?.committed) await flightService.refund(res.result);
  reservations.delete(envelope.body.reservationToken);
  return buildEnvelope("ArohaCancelAck", agentDID, from,
    { reservationToken: envelope.body.reservationToken },
    correlationId, privateKey);
}
```

### Step 5 — Update the capability manifest

Set `sagaRole: "participant"` for transactional capabilities:

```typescript
// In src/manifest.ts, update the capability definition:
{
  id: "book-flight",
  sagaRole: "participant",
  reserveCapabilityId: "book-flight",
  cancelCapabilityId: "book-flight",
  // ...
}
```

---

## Migration reference

### A2A error → Aroha error

```typescript
// A2A:
res.status(404).json({ error: "Not found" });

// Aroha:
return buildEnvelope("ArohaError", agentDID, from,
  { code: ArohaErrorCode.NoInventory, message: "Not found", retryable: false },
  correlationId, privateKey);
```

### A2A streaming → Aroha streaming

```typescript
// A2A: SSE or long-poll
res.write(`data: ${JSON.stringify({ progress: 50 })}\n\n`);

// Aroha: WebSocket stream via `stream` callback in onMessage
stream(await buildEnvelope("ArohaStream", agentDID, from,
  { progressPct: 50, message: "Processing..." },
  correlationId, privateKey));
```

### Trust level upgrade path

Trust levels are defined in [§4.4 of the specification](../spec/aroha-1.0.md#44-trust-levels):

| Trust Level | Requirement (spec §4.4) |
|-------------|---------------|
| 1 | Registered with a Layer 2 registry |
| 2 | Verifiable credential from a trust anchor |
| 3 | Reputation ≥ 8000 |
| 4 | Explicit user authorization |

---

## See also

- [A2A bridge source](../../packages/aroha-a2a-bridge/src/index.ts)
- [General conversion recipe](./converting-existing-agents.md)
- [Aroha spec](../spec/aroha-1.0.md)
