<!-- Copyright (c) 2026 Aroha Labs
     SPDX-License-Identifier: Apache-2.0 -->

# @aroha-sdk/a2a-bridge

Adapter between [A2A (Agent2Agent)](https://a2a-protocol.org/) — the open agent-to-agent protocol governed under the Linux Foundation — and Aroha. Targets the **A2A 1.0** wire shapes. Stability: **experimental** (see [COMPATIBILITY.md](https://github.com/ArohaLabs/aroha-protocol/blob/main/COMPATIBILITY.md)).

```bash
npm install @aroha-sdk/a2a-bridge
```

Aroha is complementary to A2A: A2A is the transport, Aroha adds authority. The bridge carries an Aroha mandate token in `message.metadata["aroha.mandate"]`, lists the extension URI `https://aroha-labs.com/a2a/extensions/mandate/v1` in `message.extensions`, and lets an agent declare the extension in `AgentCard.capabilities.extensions`.

!!! note "No envelope proof"
    A2A messages carry no Aroha Ed25519 envelope proof. An envelope produced by
    `a2aToAroha` is unsigned. Authority comes from verifying the mandate chain
    (`a2aToArohaVerified` / `verifyA2aMandate`, with `verifyMandateChain` from
    `@aroha-sdk/credentials`); caller identity comes from
    the A2A transport's own authentication. For full envelope signing, convert
    the agent natively with the [A2A conversion recipe](../recipes/convert-from-a2a.md).

---

## sendMessage — JSON-RPC client

```typescript
import { sendMessage } from "@aroha-sdk/a2a-bridge";

const result = await sendMessage(agentJsonRpcUrl, {
  messageId: crypto.randomUUID(),
  role: "ROLE_USER",
  parts: [{ data: { capability: "book-flight", params: { from: "AKL", to: "NRT" } } }],
}, { mandateToken });

// result: { kind: "task", task } | { kind: "message", message }
```

Sends JSON-RPC 2.0 method `SendMessage` with header `A2A-Version: 1.0` (and `A2A-Extensions` when the mandate is attached). Throws `A2AJsonRpcError` on a JSON-RPC error.

## Mandate carriage

```typescript
import { attachMandate, extractMandate, withArohaMandateExtension } from "@aroha-sdk/a2a-bridge";

const outbound = attachMandate(message, mandateToken);
const token = extractMandate(inbound);              // string | undefined
const card = withArohaMandateExtension(agentCard, true);
```

## a2aToAroha / arohaToA2a

| A2A 1.0 | Aroha |
|-----|------|
| `messageId` | `envelope.id` (`urn:a2a:<messageId>`) and `nonce` |
| `taskId` (else `contextId`) | `envelope.correlationId` |
| `role: "ROLE_USER"` | `ArohaRequest` (and `ArohaReserve` outbound) |
| `role: "ROLE_AGENT"` | `ArohaResponse` and other types |
| first `data` part, or JSON in a `text` part | `envelope.body` |
| `metadata["aroha.mandate"]` | `envelope.body.credentialToken` |

`arohaToA2a(envelope, { mandateToken? })` emits a single `{ data, mediaType: "application/json" }` part and records `aroha.type`, `aroha.from`, `aroha.to` in metadata. `arohaStreamToA2aStatus` maps progress to `TASK_STATE_WORKING` / `TASK_STATE_COMPLETED`.

## Not implemented

Streaming (`SendStreamingMessage`, `SubscribeToTask`), `ListTasks` and push notifications; the server answers them with `UnsupportedOperationError` (-32004) or `PushNotificationNotSupportedError` (-32003). The A2A server side (`createA2aRequestHandler`: a signed Agent Card at `/.well-known/agent-card.json`, JSON-RPC `SendMessage` with mandate verification, and `GetTask` / `CancelTask` for tasks the handler returned), the `getTask` / `cancelTask` client calls and card signature verification (`verifyAgentCardSignature`, `fetchAgentCard`) are implemented, and CI runs them against the official A2A JavaScript SDK (`@a2a-js/sdk`) in both directions. See the package README.

## Full conversion guide

See [Converting from A2A →](../recipes/convert-from-a2a.md).
