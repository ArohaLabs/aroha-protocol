# @aroha-sdk/a2a-bridge

![Experimental](https://img.shields.io/badge/status-experimental-orange)

Adapter between [A2A (Agent2Agent)](https://a2a-protocol.org/) — the open agent-to-agent protocol governed under the Linux Foundation — and Aroha. Targets the **A2A 1.0** wire shapes.

Aroha is complementary to A2A: A2A carries the conversation, Aroha adds **authority**. This package carries an Aroha mandate token inside A2A messages and declares it in the Agent Card, so an A2A peer that understands Aroha can verify what the caller is allowed to do, and one that does not can ignore it.

```bash
npm install @aroha-sdk/a2a-bridge
```

## Call an A2A agent with a mandate

```typescript
import { sendMessage } from "@aroha-sdk/a2a-bridge";

const result = await sendMessage(
  "https://flights.example/a2a",          // JSON-RPC url from the agent's Agent Card
  {
    messageId: crypto.randomUUID(),
    role: "ROLE_USER",
    parts: [{ data: { capability: "book-flight", params: { from: "AKL", to: "NRT" } } }],
  },
  { mandateToken },                       // placed in message.metadata["aroha.mandate"]
);

if (result.kind === "task") console.log(result.task.status.state);
else console.log(result.message.parts);
```

`sendMessage` sends a JSON-RPC 2.0 `SendMessage` request with the `A2A-Version: 1.0` header, and `A2A-Extensions` when the mandate extension is in use. It returns `{ kind: "task", task }` or `{ kind: "message", message }`, and throws `A2AJsonRpcError` on a JSON-RPC error.

## Receive: verify the mandate

```typescript
import { a2aToArohaVerified } from "@aroha-sdk/a2a-bridge";
import { verifyMandateChain, httpRevocationCheck } from "@aroha-sdk/credentials";

// Walks every link back to a root you trust, checks revocation, the grantee
// and (optionally) the amount; throws A2AMandateError otherwise.
const { envelope, mandate } = await a2aToArohaVerified(a2aMessage, callerDid, myDid, {
  verifyMandateChain,                    // the verifier is passed in; this package has no credentials dependency
  expectedRoot: trustedHumanDID,         // a root policy is REQUIRED (or trustedRoots / person root / governed profile)
  expectedGrantee: callerDid,            // the caller as authenticated by your A2A transport
  isRevoked: httpRevocationCheck(REGISTRY),
  proposedAmountUsd: 12,                 // rejected when above the leaf's spendLimitUsd
});
// The mandate is copied to body.credentialToken. The envelope has NO proof —
// do not treat it as signed.
```

`verifyA2aMandate(message, policy)` is the non-throwing form. Pass a
`governedVerification()` profile as `policy.verifierOptions` to run every
check. The plain `a2aToAroha` copies the token without verifying it; use it
only when you verify the mandate yourself with `verifyMandateChain` (not the
single-link `verifyMandate`, which cannot tell a human-rooted chain from a
root an agent signed for itself).

## Declare the extension in your Agent Card

```typescript
import { withArohaMandateExtension } from "@aroha-sdk/a2a-bridge";

const card = withArohaMandateExtension(myAgentCard, /* required */ true);
// card.capabilities.extensions now includes
// { uri: "https://aroha-labs.com/a2a/extensions/mandate/v1", required: true, params: { metadataKey: "aroha.mandate" } }
```

## Serve an A2A endpoint (signed Agent Card + `SendMessage`)

```typescript
import { createServer } from "node:http";
import { createA2aRequestHandler, withArohaMandateExtension } from "@aroha-sdk/a2a-bridge";
import { verifyMandateChain } from "@aroha-sdk/credentials";

const handler = await createA2aRequestHandler({
  card: withArohaMandateExtension(myAgentCard, true), // signed at startup (EdDSA JWS)
  agentDid, privateKey: agentPrivateKey,
  // The caller DID comes from YOUR transport authentication, never the message.
  resolveCaller: (req) => authenticatedDidFor(req),
  mandatePolicy: { verifyMandateChain, expectedRoot: humanDid, isRevoked },
  handle: async (envelope, ctx) => ({ answer: await answer(envelope.body, ctx.rootGrantor) }),
});
createServer(handler).listen(8080);
```

It serves the signed card at `/.well-known/agent-card.json` and JSON-RPC at `/a2a`. Every `SendMessage` goes through `a2aToArohaVerified` first; a mandate that does not verify is answered with JSON-RPC error `-32010` (`AROHA_MANDATE_REJECTED_RPC_CODE`) and never reaches `handle`. When `handle` returns a task (`{ kind: "task", task }`), the server remembers it (the latest `maxTasks`, default 1000) so that the caller that created it can `GetTask` and `CancelTask` it. Another caller gets `TaskNotFoundError`. `CancelTask` calls your `onCancel(task)` hook, then marks the task `TASK_STATE_CANCELED`. Cancelling a task that is already canceled returns it unchanged, and cancelling any other finished task returns `TaskNotCancelableError` (-32002). A request without `A2A-Version: 1.0` gets `VersionNotSupportedError` (-32009), because A2A 1.0 §3.6.2 says a missing header means 0.3.

Card signatures are detached JWS with the protected header `{ alg: "EdDSA", typ: "JOSE", kid }`. The payload is the A2A 1.0 §8.4.1 canonical form: RFC 8785 JCS of the card without `signatures`, leaving out any field that holds its proto default (`required: false`, `tenant: ""`, an empty `securitySchemes`, …) unless the field is REQUIRED or explicitly `optional`. Versions up to 2.0.0 signed the card as-is. `verifyAgentCardSignature` still accepts those signatures.

On the client side, `fetchAgentCard(baseUrl)` downloads the card and verifies its signature. It throws when the card is unsigned or no signature verifies. `verifyAgentCardSignature(card, resolveKey?)` checks a card you already have. By default it resolves only content-addressed `did:aroha:z…` kids. `getTask(url, id)` and `cancelTask(url, id)` call the matching JSON-RPC methods.

## Interop with the official A2A SDK (tested in CI)

`src/interop-a2a-js.test.ts` runs this package against the official A2A JavaScript SDK, [`@a2a-js/sdk`](https://github.com/a2aproject/a2a-js) 1.3.0. That SDK implements A2A 1.0.0 and is a devDependency only. The test runs in-process over HTTP on 127.0.0.1, with no network:

- **SDK client → this server:** discovery through `ClientFactory.createFromUrl` and the card signature checked by the SDK's `verifyAgentCardSignature`. It covers `SendMessage` with a mandate, `sendMessageStream`, `GetTask`, `CancelTask`, cancelling a finished task, `TaskNotFound` for an unknown id or another caller's task, and `-32010` for a missing or self-rooted mandate. `sendMessageStream` falls back to `SendMessage` because the card says `streaming: false`, and a raw `SendStreamingMessage` gets -32004.
- **This client → SDK server:** the SDK's `DefaultRequestHandler` runs behind its Express `jsonRpcHandler` and `agentCardHandler`, and signs its card with the SDK's `generateAgentCardSignature` (EdDSA). `fetchAgentCard` verifies that signature, and pinning a different kid fails. With a mandate, `sendMessage` reaches an SDK agent that checks the mandate with `verifyA2aMandate`. An untrusted mandate gets `TASK_STATE_REJECTED`. `getTask` and `cancelTask` run against the SDK's task store.
- **Signatures both ways:** the SDK verifies cards this package signed, including cards with default-valued fields, and this package verifies cards the SDK signed. Each side rejects a tampered card.

Bugs on this package's side that the interop test found and fixed after 2.0.0. Each was checked against the A2A 1.0 specification:

| What | Spec | Was | Now |
|---|---|---|---|
| Card signing payload | §8.4.1: omit default-valued fields | JCS of the card as-is, so the SDK rejected a bridge card with `required: false`, and the bridge rejected the SDK's served card (`tenant: ""`, empty lists) | §8.4.1 form; the old form is still accepted when verifying |
| Absent `A2A-Version` | §3.6.2: absent means 0.3 | treated as 1.0 | `VersionNotSupportedError` -32009 (was -32600 for a wrong version) |
| `SendStreamingMessage` without streaming | §3.3.4: MUST return `UnsupportedOperationError` | -32601 method not found | -32004 |
| `GetTask` / `CancelTask` | §3.1 core methods | -32601 | implemented |
| `configuration.blocking` | 1.0 renamed it `returnImmediately` | only `blocking` typed | `returnImmediately`; `blocking` deprecated |

Behaviour on the SDK's side (`@a2a-js/sdk` 1.3.0) to know about:

- **It enforces required extensions.** When a card marks an extension `required: true`, the SDK server answers `ExtensionSupportRequiredError` (-32008) to a request whose `A2A-Extensions` header does not list it. The specification allows this but does not require it. This client sends `A2A-Extensions` only when a mandate is attached, so a call without a mandate to such an agent is refused before the agent runs.
- **It serves the card with defaults spelled out** (`tenant: ""`, `description: ""`, empty lists and maps) and canonicalizes before verifying. That works with this package in versions after 2.0.0.
- **It canonicalizes more aggressively than §8.4.1** (a deviation). Its `canonicalizeAgentCard` drops every empty value, including REQUIRED fields that are empty (an empty `skills` list, `capabilities: {}`) and empty values inside an extension's `params`. It also drops fields outside the 1.0 schema. A card with any of these does not cross-verify. Do not sign such cards.
- **It rejects a missing `A2A-Version` header** with -32009 unless its v0.3 compatibility layer is on. This client always sends `A2A-Version: 1.0`.

## API

| Export | Purpose |
|---|---|
| `sendMessage(url, message, opts?)` | JSON-RPC `SendMessage` client; `opts.mandateToken`, `opts.headers`, `opts.fetch` |
| `parseSendMessageResult(result)` | Interpret a `SendMessage` result (`{task}` / `{message}`) |
| `attachMandate(message, token)` / `extractMandate(message)` | Carry a mandate in `metadata["aroha.mandate"]` and list the extension URI in `message.extensions` |
| `arohaMandateExtension(required?)` / `withArohaMandateExtension(card, required?)` / `cardSupportsArohaMandate(card)` | Agent Card extension declaration |
| `verifyA2aMandate(message, policy)` / `a2aToArohaVerified(message, fromDID, toDID, policy)` | Verify the carried mandate with `verifyMandateChain` (root policy required); reject unverifiable, untrusted, revoked or over-limit mandates |
| `a2aToAroha(message, fromDID, toDID)` | A2A message → unsigned Aroha envelope; copies the mandate unverified (also accepts pre-1.0 messages) |
| `arohaToA2a(envelope, opts?)` | Aroha envelope → A2A 1.0 message (body as a `data` part) |
| `arohaStreamToA2aStatus(envelope)` | `ArohaStream` progress → `TASK_STATE_WORKING` / `TASK_STATE_COMPLETED` |
| `getTask(url, id, opts?)` / `cancelTask(url, id, opts?)` | JSON-RPC `GetTask` / `CancelTask` clients |
| `createA2aRequestHandler(opts)` | node:http handler: signed card at `/.well-known/agent-card.json`, JSON-RPC `SendMessage` with mandate verification before your handler, `GetTask` / `CancelTask` (`opts.onCancel`) for tasks it returned |
| `A2A_RPC_ERROR` | The A2A 1.0 JSON-RPC error codes the server uses (-32001, -32002, -32003, -32004, -32009) |
| `signAgentCard(card, key, kid)` / `verifyAgentCardSignature(card, resolveKey?)` / `fetchAgentCard(baseUrl, opts?)` | EdDSA JWS Agent Card signatures (detached JCS payload) |
| Types | `A2AMessage`, `A2APart`, `A2ATask`, `A2AAgentCard` (incl. `signatures`), `A2AAgentExtension`, … |

**Mapping:** `messageId` ↔ `id` (`urn:a2a:<messageId>`); `taskId` (else `contextId`) ↔ `correlationId`; `ROLE_USER` ↔ `ArohaRequest`/`ArohaReserve`; `ROLE_AGENT` ↔ other types.

## Not implemented

- Streaming (`SendStreamingMessage`, `SubscribeToTask`), `ListTasks` and `GetExtendedAgentCard`: the server answers `UnsupportedOperationError` (-32004). Push notification config methods: `PushNotificationNotSupportedError` (-32003). The client has no streaming call.
- The task store behind `GetTask` / `CancelTask` is in memory and only holds tasks `handle` returned. Your handler cannot yet push later status changes into it.
- Card signature keys other than content-addressed `did:aroha:z…` need a caller-supplied `resolveKey` (no JWKS / `jku` fetching).
- Transport authentication: the server takes the caller DID from your `resolveCaller`; it does not implement any A2A security scheme itself.

## Breaking changes in 2.0.0 (from 1.2.x)

A2A 1.0 changed the wire format, so this package did too:

- `role` is `"ROLE_USER" | "ROLE_AGENT"`, not `"user" | "agent"`.
- Parts have no `type`/`kind` discriminator: `{ text }`, `{ data }`, `{ url }` or `{ raw }`.
- Task states are `TASK_STATE_*`; `A2ATask.messages` became `history`.
- `arohaToA2a` metadata keys are now `aroha.type`, `aroha.from`, `aroha.to` (were `arohaType`, `fromDID`, `toDID`).
- `a2aToAroha` still accepts pre-1.0 input.

The functions this README used to describe (`createA2AArohaAgent`, `callA2AWithMandate`, `wrapA2ATask`) never existed.

## License

Apache-2.0 — see [LICENSE](../../LICENSE).