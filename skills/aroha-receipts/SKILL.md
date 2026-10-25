---
name: aroha-receipts
description: Sign and verify Aroha action receipts (v2) with @aroha-sdk/core, covering executed and denied actions, the four identities (requester, principal, approver, executor), presentedHash binding to what an approver saw, and traceparent links. Use when an agent takes or refuses a consequential action and a downstream party must be able to check who asked, who approved and on what basis.
license: Apache-2.0
compatibility: Node.js 22+, @aroha-sdk/core 2.x; optional @aroha-sdk/telemetry for trace links.
metadata:
  project: Aroha (https://github.com/ArohaLabs/aroha-protocol)
  spec: aroha-1.0 §12.6
---

# Aroha action receipts

A receipt is a statement signed by the acting agent's Ed25519 key. It records the action, a hash of its arguments, whether untrusted content shaped it (`tainted`), who approved it, and the outcome. It proves the agent made these claims. It does not prove they are true.

## Issue a receipt

```ts
import { signActionReceipt, hashReceiptArgs, hashPresentedContent } from "@aroha-sdk/core";

const presented = { action: "send-email", to: "ben@example.com", preview: "Three options attached." };
const receipt = await signActionReceipt({
  agentDid, action: "send-email", argsSha256: hashReceiptArgs(args),
  tainted: true, provenance: ["user", "peer"],
  requesterDid: guestDid, principalDid: hostDid, executorDid: agentDid,
  approval: { approverDid: hostDid, approvedAt, approvalId, presentedHash: hashPresentedContent(presented) },
  presentedHash: hashPresentedContent(presented),
  roomId, onBehalfOf: guestDid,
}, agentPrivateKey);
```

Receipt refusals too. A denied receipt requires `denialReason`:

```ts
await signActionReceipt({ agentDid, action: "pay", argsSha256: hashReceiptArgs(args), tainted: true,
  outcome: "denied", denialReason: "guest-origin request for a host-only capability" }, agentPrivateKey);
```

## Verify a receipt

```ts
import { verifyActionReceipt, receiptMatches, requireApprovalIfTainted, verifyPresentedHash } from "@aroha-sdk/core";

const v = await verifyActionReceipt(receipt, resolveAgentKey); // accepts v1 and v2
if (!v.ok) throw new Error(v.reason);
const mismatch = receiptMatches(v.receipt, { agentDid, action: "send-email", args })
  ?? requireApprovalIfTainted(v.receipt)
  ?? verifyPresentedHash(v.receipt, presentedContentYouHold);
if (mismatch) throw new Error(mismatch);
```

`resolveAgentKey` must be your own resolver: from a content-addressed `did:aroha:z…` DID, or from a verified Key Event Log. Never use a key that came with the receipt.

## Link to a trace (optional)

```ts
import { withReceiptTraceparent, annotateSpanWithReceipt, OtlpHttpExporter } from "@aroha-sdk/telemetry";
import { actionReceiptHash } from "@aroha-sdk/core";

const r = await signActionReceipt(withReceiptTraceparent(input, span), agentPrivateKey);
// annotateSpanWithReceipt(record, actionReceiptHash(r)) before exporting the span record.
```

## Rules

- Hash exactly what the approver was shown, and nothing else, for `presentedHash`. JCS canonicalisation makes key order irrelevant.
- Keep `tainted` truthful. A false "untainted" receipt is signed evidence against the agent that made it.
- Vectors: `spec-public/vectors/conversation-v1.json` (`receipts.v1`, `receipts.v2Executed`, `receipts.v2Denied`).
