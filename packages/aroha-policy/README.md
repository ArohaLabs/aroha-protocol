# @aroha-sdk/policy

Pre-LLM policy guardrails for Aroha agents — declarative per-capability rules, payload checks and
content screening that run before the model is called, complementing cryptographic mandate bounds.

## Install

```bash
npm install @aroha-sdk/policy
```

## Quick example

```typescript
import {
  ArohaPolicyEngine, createPolicyMiddleware, createStructuredPayloadMiddleware,
  createContentScreener, createOutboundScreener,
} from "@aroha-sdk/policy";
import { ArohaServer } from "@aroha-sdk/core";

const engine = new ArohaPolicyEngine();
engine.addPolicy({
  capabilityId: "book-flight",
  maxSpendPerCall: { amount: 300, currency: "USD", paramKey: "amount" },
  requiredParamKeys: ["from", "to", "amount"],
  allowedParamKeys: ["from", "to", "date", "amount"],
  rateLimitPerMinute: 30,
});
engine.addPolicy({ capabilityId: "*", paramAllowedValues: [{ key: "action", allowedValues: ["read", "list"] }] });

// Direct evaluation
const decision = await engine.evaluate("book-flight", { from: "AKL", to: "SYD", amount: 250 }, callerDID);
// decision.outcome === "allow"

// Or as server middleware: denied requests get a 403 before your handler runs
const server = new ArohaServer({
  agentDID, didDocument, port: 3001, resolvePublicKey, onMessage,
  middleware: [createPolicyMiddleware(engine), createStructuredPayloadMiddleware({ maxStringLength: 1024 })],
});

// Screen untrusted free text before it reaches the model, and redact what goes out
const inbound = createContentScreener().screen(userMessage, "untrusted"); // { blocked, reason? }
const outbound = createOutboundScreener().screen(modelReply);             // { text, redactions, redacted }
```

## Why this exists in the mandate chain

Cryptographic mandate bounds enforce what an agent is *authorised* to do. Policy rules enforce
what it *should* do — spend-per-call caps, parameter allow-lists, rate limits and content
screening that run before the LLM ever sees the request.

## API

- `ArohaPolicyEngine` — `addPolicy(CapabilityPolicy)`, `removePolicy(capabilityId)`, `evaluate(capability, params, senderDID)` → `{ outcome: "allow" | "deny", violatedRule?, reason? }`.
- `CapabilityPolicy` — `{ capabilityId ("*" = default), maxSpendPerCall?, allowedParamKeys?, blockedParamValues?, requiredParamKeys?, paramAllowedValues?, rateLimitPerMinute?, requiresHITLApproval? }`.
- `createPolicyMiddleware(engine)` / `createStructuredPayloadMiddleware({ maxStringLength?, maxParamDepth? })` — `ArohaServer` middleware.
- `ContentScreener` / `createContentScreener(opts)` — pattern and length screening of untrusted text (`screen`, `screenHistory`).
- `OutboundScreener` / `createOutboundScreener(opts)` — redaction of sensitive values in outbound text; `DEFAULT_OUTBOUND_RULES`, `passesLuhn`.

## License

Apache-2.0 — see [LICENSE](../../LICENSE).
