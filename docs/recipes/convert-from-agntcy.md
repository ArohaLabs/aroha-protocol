<!-- Copyright (c) 2026 Aroha Labs
     SPDX-License-Identifier: Apache-2.0 -->

# Recipe: Converting an Agntcy Agent to Aroha

Agntcy (agntcy.ai) uses the Open Agent Specification (OAS) — a YAML-based capability manifest
and a JSON-over-HTTP `POST /invoke { capability, input }` call convention. Aroha adds
Ed25519 identity, atomic sagas, and decentralized registry discovery.

---

## Option A — CLI sidecar (fastest, ~5 minutes)

Generate a Aroha wrapper that proxies to your existing Agntcy agent.

```bash
aroha convert \
  --from agntcy \
  --name my-agent-aroha \
  --port 3001 \
  --endpoint http://localhost:8080 \
  --out ./my-agent-aroha

cd my-agent-aroha
npm install
```

Then edit **`src/capability-map.ts`** to map your Agntcy capability IDs and schemas
to Aroha format (the file has inline comments explaining each mapping).

```bash
npm run dev
```

---

## Option B — Native conversion

### Step 1 — Scaffold

```bash
aroha init my-agent --type provider --port 3001
cd my-agent
npm install
```

### Step 2 — Map the Agntcy manifest to Aroha

Agntcy uses a YAML manifest like:

```yaml
# agntcy.yaml
name: my-search-agent
version: 1.0.0
capabilities:
  - id: search_documents
    description: Search across indexed documents
    input:
      properties:
        query: { type: string }
        limit: { type: integer, default: 10 }
    output:
      properties:
        results: { type: array }
```

The equivalent Aroha capability in `src/manifest.ts`:

```typescript
{
  id: "search-documents",          // kebab-case (Aroha convention)
  version: "1.0.0",
  description: "Search across indexed documents",
  inputSchema: {
    type: "object",
    properties: {
      query: { type: "string" },
      limit: { type: "integer" },
    },
    required: ["query"],
  },
  outputSchema: {
    type: "object",
    properties: { results: { type: "array" } },
  },
  async: false,
  maxResponseMs: 5000,
  requiredTrustLevel: 1,
  pricing: { model: "free" },
  sagaRole: "none",
}
```

### Step 3 — Migrate the handler

**Before (Agntcy HTTP handler):**

```python
# Python Agntcy agent
@app.post("/invoke")
async def invoke(request: InvokeRequest):
    if request.capability == "search_documents":
        results = await search(request.input["query"], request.input.get("limit", 10))
        return InvokeResponse(output={"results": results})
```

**After (Aroha TypeScript handler in `src/handlers.ts`):**

```typescript
case "ArohaRequest": {
  const { capability, params } = envelope.body as { capability: string; params: Record<string, unknown> };

  if (capability === "search-documents") {
    // Call your existing search logic (HTTP, gRPC, in-process, etc.)
    const results = await searchService.search(
      params.query as string,
      (params.limit as number) ?? 10
    );
    return buildEnvelope("ArohaResponse", agentDID, from,
      { capability, result: { results } },
      correlationId, privateKey);
  }
}
```

### Step 4 — Capability ID convention

Agntcy uses `snake_case`; Aroha uses `kebab-case`. Handle the translation in one place:

```typescript
// src/capability-map.ts
const AGNTCY_TO_Aroha: Record<string, string> = {
  search_documents: "search-documents",
  summarize_text:   "summarize-text",
  // add more as needed
};

export function agntcyCapToAroha(id: string): string {
  return AGNTCY_TO_Aroha[id] ?? id.replace(/_/g, "-");
}
```

### Step 5 — Saga emulation for write capabilities

Agntcy `POST /invoke` is stateless — there's no native hold. For write capabilities
that need atomicity in multi-agent sagas, implement the Aroha saga pattern:

```typescript
case "ArohaReserve": {
  const { capability, params, holdDurationMs } = envelope.body;
  // Pre-run the Agntcy invoke and cache the result
  const output = await agntcyInvoke(capability, params);
  const token = `AGN-${crypto.randomUUID()}`;
  cache.set(token, { output, expiresAt: new Date(Date.now() + holdDurationMs) });
  return buildEnvelope("ArohaReserveAck", agentDID, from,
    { reservationToken: token, expiresAt: cache.get(token)!.expiresAt.toISOString() },
    correlationId, privateKey);
}
case "ArohaCommit": {
  const entry = cache.get(envelope.body.reservationToken);
  if (!entry?.committed) { entry!.committed = true; }
  return buildEnvelope("ArohaCommitAck", agentDID, from,
    { reservationToken: envelope.body.reservationToken, result: entry!.output },
    correlationId, privateKey);
}
case "ArohaCancel": {
  cache.delete(envelope.body.reservationToken);
  return buildEnvelope("ArohaCancelAck", agentDID, from,
    { reservationToken: envelope.body.reservationToken },
    correlationId, privateKey);
}
```

---

## Agntcy OAS manifest → Aroha manifest checklist

| OAS field | Aroha field | Notes |
|-----------|-----------|-------|
| `name` | `name` | Direct |
| `version` | `version` | semver |
| `capabilities[].id` | `capabilities[].id` | Convert `snake_case` → `kebab-case` |
| `capabilities[].input` | `inputSchema` | JSON Schema (OAS input is already compatible) |
| `capabilities[].output` | `outputSchema` | JSON Schema |
| `capabilities[].description` | `description` | Direct |
| _(none)_ | `sagaRole` | Set `"participant"` for write capabilities |
| _(none)_ | `requiredTrustLevel` | Set `1` for public, `2` for authenticated |
| _(none)_ | `pricing` | Set pricing model |

---

## See also

- [General conversion recipe](./converting-existing-agents.md)
- [Generated sidecar source](../../packages/aroha-cli/src/templates/converters/agntcy.ts)
- [Aroha spec](../spec/aroha-1.0.md)
