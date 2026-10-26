---
name: aroha-integrate
description: Add Aroha bounded authority to an existing AI agent, tool server or API — pick the smallest integration path (wrap an MCP server with mcp-guard, verify mandates in a handler, present a mandate over MCP, or run the Aroha runtime), apply it, and prove it refuses what it should. Use when asked to "add Aroha", "limit what this agent can do", "require approval before tool calls", "verify who authorised this call", or to make an agent's permissions deny-by-default.
license: Apache-2.0
compatibility: Node.js 22+ (TypeScript/JavaScript) or Python 3.11+. Path A needs only @aroha-sdk/mcp-guard (published, 0.2.x) and an MCP client that speaks stdio. Paths B and C need @aroha-sdk/credentials >=2.0.0 and @aroha-sdk/core >=2.0.0 (published 2026-10-19), or Python aroha >=2.0.0.
metadata:
  project: Aroha (https://github.com/ArohaLabs/aroha-protocol)
  related-skills: aroha-mandates, aroha-receipts, aroha-python-sdk
---

# Integrate Aroha into an existing agent

Aroha bounds what an agent may do: a person signs a mandate, each agent can pass on only a narrower one, the tool verifies the chain before acting, and every action leaves a signed receipt. Do not rebuild the agent. Add the smallest piece that puts a check at the boundary.

## Step 1 — Pick the path (ask the user only if two apply equally)

| The code you are changing is… | Path | Code needed |
|---|---|---|
| An MCP client config (Claude Desktop, Cursor, Windsurf, Cline, Zed, any stdio MCP client) | **A. Wrap with mcp-guard** | None — config only |
| A tool server or API that agents call, which you own | **B. Verify mandates in the handler** | ~10 lines |
| An agent that calls tools on a person's behalf | **C. Issue and present a mandate** | ~15 lines |
| A person's local assistant (chat UI, approvals, memory) | **D. Run the Aroha runtime** | None — install |

Paths B and C usually go together: C on the caller, B on the callee.

## Path A — wrap an MCP server (config only)

**Step A1 — list the server's real tool names. Do not skip this.** Rules are glob deny-lists over tool names, and every server names things its own way: the GitHub server pushes with `push_files` and comments with `add_issue_comment`; the filesystem server overwrites with `write_file` and `edit_file`. A rule written from guesses lets those through without asking. List them with the MCP SDK (`npm i @modelcontextprotocol/sdk`):

```js
// list-tools.mjs — node list-tools.mjs npx -y @modelcontextprotocol/server-github
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
const [command, ...args] = process.argv.slice(2);
const client = new Client({ name: "list-tools", version: "1.0.0" });
await client.connect(new StdioClientTransport({ command, args, env: { ...process.env } }));
for (const t of (await client.listTools()).tools) console.log(t.name);
await client.close();
```

Sort every name into **block** (never), **gate** (ask the person) or **allow** (reads). Anything that writes, sends, moves, merges, pushes, publishes, shares or spends is at least gated.

**Step A2 — wrap each server entry.** `--block` always refuses, `--gate` asks the person, `--limit glob:n` caps calls per session, `--name` labels the audit log:

```json
{
  "mcpServers": {
    "github": {
      "command": "npx",
      "args": ["-y", "@aroha-sdk/mcp-guard",
               "--name",  "github",
               "--block", "*delete*,*remove*",
               "--gate",  "merge_*,push_*,create_*,update_*,fork_*,add_*,send_*",
               "--limit", "*:50",
               "--",
               "npx", "-y", "@modelcontextprotocol/server-github"]
    },
    "filesystem": {
      "command": "npx",
      "args": ["-y", "@aroha-sdk/mcp-guard",
               "--name",  "filesystem",
               "--block", "*delete*,*remove*",
               "--gate",  "write_*,edit_*,move_*,create_*",
               "--limit", "*:200",
               "--",
               "npx", "-y", "@modelcontextprotocol/server-filesystem", "/path/to/allowed/dir"]
    }
  }
}
```

Pin the guard version (`@aroha-sdk/mcp-guard@0.2.x`) for reproducible behaviour. Keep the original config as a backup. Restart the client afterwards. On Windows some clients need `"command": "cmd", "args": ["/c", "npx", …]`.

**Limits of path A — tell the user:**
- **It is a deny-list, not deny-by-default.** A tool added to the server later with a verb you did not list is allowed. Re-run step A1 when a server updates.
- **A gate only asks if the client can show approval prompts** (MCP elicitation, or the 2026-07-28 multi round-trip). If it cannot, every gated tool is refused and the person is never asked; the refusal says the client could not ask. Support varies by client and version — public reports disagree for Claude Desktop — so have the user try one harmless gated tool and confirm they see a prompt.
- Limits count per server process (one client session), not per day.

**Step A3 — prove it.** Drive the wrapped command over stdio from a script, exactly as the client would, and check each rule. Point the filesystem server at a scratch directory, and for servers with external effects (GitHub) put a local stand-in with the same tool names behind the guard so nothing real happens:

```js
// verify.mjs — the same Client as above, connected to the WRAPPED command from the config
const r = await client.callTool({ name: "delete_file", arguments: { path: "x" } });
console.assert(r.isError && /blocked/.test(r.content[0].text), "delete must be blocked");
// Gates: declare elicitation and answer "decline" — the call must be refused and never reach the server.
// Limits: call any allowed tool n+1 times — the last must be refused with "session limit".
```

The guard also writes every decision to `~/.aroha/mcp-guard.jsonl` (override with `--log`), which is the evidence to show the user.

## Path B — verify a mandate before acting

A mandate is never accepted on its own: whoever copies a token would be able to use it. The agent presents it with a **holder proof** — its own signature over this request — and the server checks both in one call.

**Plain HTTP API that spends money (TypeScript, `node:http`)** — one call does everything: the agent's proof over this exact request, the chain back to the customer you pinned, every limit on every link, and the charge as a running total (all links or none):

```ts
import { createServer } from "node:http";
import { verifyHttpSpendRequest, MapSpendingLedger, InMemoryHttpPresentationNonces, httpRevocationCheck, enrolledDid } from "@aroha-sdk/credentials";

const AUDIENCE = "https://invoices.example.com";     // see "Choosing the audience" below
const nonces = new InMemoryHttpPresentationNonces();  // production: PostgresNonceStore / RedisNonceStore (@aroha-sdk/store-postgres, store-redis)
const ledger = new MapSpendingLedger();               // per process, resets on restart: production uses PostgresSpendingLedger / RedisSpendingLedger
const reply = (res, status, body) => { res.writeHead(status, { "content-type": "application/json" }); res.end(JSON.stringify(body)); };

createServer(async (req, res) => {
  if (req.method !== "POST" || req.url !== "/tools/send_invoice") return reply(res, 404, {});
  const chunks = []; for await (const c of req) chunks.push(c);
  const rawBody = Buffer.concat(chunks);               // the EXACT bytes received — verify these, never a re-serialised copy
  let invoice; try { invoice = JSON.parse(rawBody.toString("utf8")); } catch { return reply(res, 400, { error: "BAD_JSON" }); }
  const r = await verifyHttpSpendRequest(req.headers["aroha-mandate"], {
    audience: AUDIENCE, method: req.method, url: req.url, body: rawBody, nonces, ledger,
    expectedRoot: await enrolledDid(enrollments, String(invoice.customerId ?? "")),  // enrollment (below) — never from the request; unknown → 403
    isRevoked: httpRevocationCheck(REGISTRY_URL),     // or null to opt out explicitly
    amountUsd: invoice.amountUsd,                     // from the signed body
    currency: "USD",                                  // the currency you charge in; a mandate in another currency is refused
  });
  if (!r.ok) return reply(res, r.status, { error: r.code, reason: r.reason });   // THIS line is the gate — never continue past a refusal
  try { await billing.send(invoice); } catch { await r.charge.release(); return reply(res, 502, { error: "SEND_FAILED" }); }  // give it back
  reply(res, 201, { ok: true });
}).listen(3005);
```

With Express or Fastify the call is the same; take `rawBody` from a raw-body parser (e.g. `express.raw({ type: "*/*" })`), not from the parsed JSON.

**Why the raw bytes.** The agent signs a hash of the exact body it sent. If your server parses the JSON and then serialises it again before verifying, the bytes can differ (key order, spacing, number formatting) — and worse, a test whose client happens to produce identical bytes will pass while production fails or, if you verify one copy and act on another, acts on bytes nobody signed. Verify the bytes you received and act on what you parsed from those same bytes.

**Choosing the audience.** The audience is the name of YOUR service that the agent signs into its proof, so a proof made for another service cannot be replayed at yours. Use one stable public identifier — normally the public origin agents call (`https://invoices.example.com`), not `localhost`, not an internal host behind your proxy, and not something taken from the request's `Host` header. Configure it once (env var) and give the same value to agents. A mismatch is refused as `BAD_PROOF`.

**Refusals and their HTTP status** (`r.status` carries it; return it as-is):

| Status | Codes | Meaning |
|---|---|---|
| 400 | `INVALID_AMOUNT` | The amount in the request is not a positive, finite number |
| 401 | `MISSING`, `MALFORMED`, `EXPIRED`, `LIFETIME_TOO_LONG`, `MALFORMED_TOKEN`, `BAD_REQUEST`, `UNKNOWN_HOLDER`, `HOLDER_NOT_GRANTEE`, `BAD_PROOF`, `REPLAYED`, `NONCE_STORE_UNAVAILABLE` | No valid proof that THIS agent sent THIS request (a failed nonce store also lands here — it cannot rule out a replay) |
| 403 | `MANDATE_INVALID` (bad signature, expired, wrong root), `ROOT_NOT_PINNED` (unknown customer), `NOT_A_SPENDING_MANDATE`, `CURRENCY_MISMATCH`, `MERCHANT_NOT_ALLOWED`, `MERCHANT_CATEGORY_NOT_ALLOWED`, `HUMAN_APPROVAL_REQUIRED`, `OVER_LIMIT` | The agent is who it says, but the customer did not authorise this |
| 503 | `LEDGER_UNAVAILABLE` | Your spending ledger failed — nothing was charged |

If the mandate constrains merchant, merchant category or a human-approval threshold, pass `merchant`, `merchantCategory` or `humanApproved` — the last only from your own approval flow, never from the client. Not spending money (any other action)? Use `verifyHttpMandateRequest` with the same options minus `amountUsd`/`ledger`/`currency`.

**Python server** (Starlette/FastAPI; same checks, identical bytes):

```python
from aroha import verify_http_spend_request, InMemorySpendingLedger, InMemoryHttpPresentationNonces
from aroha.enrollment import InMemoryEnrollmentStore, enrolled_did
NONCES, LEDGER, ENROLLMENTS = InMemoryHttpPresentationNonces(), InMemorySpendingLedger(), InMemoryEnrollmentStore()   # production: aroha.stores.postgres / aroha.stores.redis
raw = await request.body()
url = request.scope["raw_path"].decode() + ("?" + request.scope["query_string"].decode() if request.scope["query_string"] else "")
invoice = json.loads(raw)
r = verify_http_spend_request(request.headers.get("aroha-mandate"), audience="https://api.example.com",
    method=request.method, url=url, body=raw, nonces=NONCES, ledger=LEDGER,
    expected_root=enrolled_did(ENROLLMENTS, invoice["customerId"]), is_revoked=None, amount_usd=invoice["amountUsd"])
if not r.ok: return JSONResponse({"error": r.code, "reason": r.reason}, status_code=r.status)
try: billing.send(invoice)
except Exception: r.charge.release(); raise
```

**MCP tool server.** The mandate arrives in `_meta["aroha/mandate"]` with a holder proof bound to the tool, its arguments and this server:

```ts
import { verifyPresentation, PresentationNonces } from "@aroha-sdk/mcp-bridge";
import { verifyMandateChain } from "@aroha-sdk/credentials";

const nonces = new PresentationNonces();
const p = await verifyPresentation(request.params._meta?.["aroha/mandate"], {
  audience: MY_DID, tool: request.params.name, args: request.params.arguments ?? {}, resolvePublicKey, nonces,
});
if (!p.ok) return deny(403, p.reason);
const r = await verifyMandateChain(p.token, undefined, { expectedRoot: customerDid, expectedGrantee: p.holder, isRevoked });
if (!r.valid || !r.chainVerified) return deny(403, r.reason);
```

## Path C — act on a person's behalf (issue, narrow, present)

```ts
import { generateKeyPair, generateDid } from "@aroha-sdk/core";
import { issueIntentMandate, presentMandateHttp } from "@aroha-sdk/credentials";

// Identities. The PERSON's key lives on their device or in a key service you provide —
// never on the agent's side, never in prompts or logs.
const agent = await generateKeyPair();
const agentDid = generateDid(agent.publicKey);

// The PERSON signs: up to $500 for one hour, for this agent only.
const grant = await issueIntentMandate(personDid, agentDid, { spendLimitUsd: 500 }, personPrivateKey, 3_600_000);

// The AGENT presents it on each call, signed with its own key, bound to this exact request.
const url = "https://api.example.com/tools/send_invoice";
const body = JSON.stringify({ customer: "acme", amountUsd: 120 });
const headers = await presentMandateHttp({
  token: grant.token, holderDid: agentDid, holderPrivateKey: agent.privateKey,
  audience: "https://api.example.com", method: "POST", url, body,
});
await fetch(url, { method: "POST", headers: { ...headers, "content-type": "application/json" }, body });
```

Over MCP, present with `presentMandate` from `@aroha-sdk/mcp-bridge` and pass the result as `_meta` on `callTool`. Non-spending limits (which tools, how many calls, reversible only, human gates): `issueTaskMandate`, verified with the task-mandate verifier. Delegating further? Attenuate — a child can only narrow (see the `aroha-mandates` skill). Spending: `issueIntentMandate` → `attenuateToCart` → `attenuateToPayment`.

## Path D — the Aroha runtime (a person's assistant)

The runtime already does deny-by-default: known-safe reads run, everything else asks; the person can keep an answer for this conversation, 24 hours or always (a year), optionally at most N times, as a signed standing permission they can revoke under Settings → Permissions. Point the user at the runtime install instead of re-implementing approvals.

## Always

- Record what happened: sign an action receipt for every executed **and denied** action (`aroha-receipts` skill).
- Pass a revocation hook in production; it fails closed when the source is unreachable.
- Take caller identity from transport authentication, never from the request body.
- Never put private keys in prompts, tool arguments, logs or committed config.

## Step 2 — Prove it works (do not skip)

Write tests for the cases that match the path you used, run them, and report each result. Done means every refusal fails closed — not just that the happy path works.

**Path A (wrapped MCP server)** — drive the wrapped command over stdio (Step A3):
1. A read runs without a prompt.
2. A blocked tool is refused even if the person would approve.
3. A gated tool is refused when the person declines, and runs when they approve.
4. The (limit + 1)th call in a session is refused.

**Paths B/C — spending (an amount per call, as with invoices or payments):**
1. An authorised call within the limit **succeeds**; a later call that takes the running total over the limit is **refused** (`OVER_LIMIT`), and so is a single call over it.
2. **Another agent** presenting the token is refused (`HOLDER_NOT_GRANTEE`) — build it with `presentMandateHttpUnchecked` from `@aroha-sdk/credentials/testing`, because the honest client will not.
3. **Another customer's** authorisation used for this customer is refused (root pinned to the enrolled DID), and so is a mandate the agent signed itself.
4. An **expired** mandate is refused — pass `now` to the verifier to move the clock instead of sleeping.
5. A **tampered** token (limit raised after signing), a **changed body** after signing, and the **same request replayed** are refused.
6. A mandate in **another currency** is refused (`CURRENCY_MISMATCH`) — issue one with `currency: "EUR"` in the test.
7. **No** authorisation is refused (401), and an **unknown customer** is refused as `ROOT_NOT_PINNED` (403) — never a 500.
8. A side effect that **fails** after the charge gives the amount back (`charge.release()`).
9. A **revoked** mandate is refused once revocation is published (needs your registry).

**Paths B/C — task permissions (which tools, how many calls):**
1. An allowed tool within its call limit succeeds.
2. A tool not in the mandate is refused; the (limit + 1)th call is refused.
3. An irreversible tool under `reversibleOnly` is refused; a `humanGates` tool is refused until approved.
4. Expired, tampered, other-holder and replayed presentations are refused, as above.

**Enrollment:** enrolling without a login, into another account, with a key you do not hold, or with a used or expired challenge is refused.

A complete, runnable version of the spending path — enrollment, the customer's and the agent's keys in separate places, every case above tested — is bundled with this skill in `examples/invoice-api/` (`npm install && npm test`).

## Keys and trust (paths B and C)

- **Creating identities:** `generateKeyPair()` then `generateDid(publicKey)` from `@aroha-sdk/core`. A `did:aroha:z…` DID contains its public key, so verifiers need no lookup.
- **Where a person's key lives:** on their device or in a wallet / key service your product provides — never on the agent's side, never in prompts or logs. In an enterprise, the person's identity can come from the identity provider instead (see the remote MCP connector's enterprise-managed authorization).
- **Which people a server trusts — enrollment.** Keep a binding customer → DID, written only by the library's enrollment, which proves two things together: the customer's existing **account login** (so nobody enrolls a key into someone else's account) and a **signature by the DID's own key** over a fresh, single-use challenge issued to that account for this service (so nobody enrolls a key they do not hold, or replays a proof made for another service):

```ts
import { InMemoryEnrollmentStore, issueEnrollmentChallenge, completeEnrollment, enrolledDid, signEnrollment } from "@aroha-sdk/credentials";

const enrollments = new InMemoryEnrollmentStore();   // a DB-backed EnrollmentStore in production
// Server, POST /enroll/challenge — the account id comes ONLY from your own login:
const c = await issueEnrollmentChallenge(enrollments, { authenticatedAccountId: accountFromLogin });   // { challenge, expiresAt, accountId }
// Customer's device:
const proof = await signEnrollment({ accountId: c.accountId, did: customerDid, challenge: c.challenge, audience: AUDIENCE, privateKey: customerKey });
// Server, POST /enroll (logged in), body { did, challenge, proof }:
const r = await completeEnrollment(enrollments, { authenticatedAccountId: accountFromLogin, audience: AUDIENCE, did, challenge, proof });
// r.ok → bound (a later enrollment replaces the DID: key rotation). Otherwise r.code: CHALLENGE_UNKNOWN (used/never issued),
// CHALLENGE_ACCOUNT_MISMATCH, CHALLENGE_EXPIRED, BAD_DID, BAD_PROOF.
// Per request: expectedRoot: await enrolledDid(enrollments, customerId) — an unknown customer is refused as ROOT_NOT_PINNED (403).
```

  The customer id in a request then only CHOOSES which enrolled DID to pin — a mandate from anyone else fails against it. A lost key goes through your normal account recovery, then re-enrollment. Python: `aroha.enrollment` has the same functions in snake_case.
- **How the agent gets the authorisation.** The agent shows its DID; the customer, on their own device, signs `issueIntentMandate(customerDid, agentDid, { spendLimitUsd, currency }, customerKey, ttlMs)` and hands back only the token (your app's consent screen, an API, a redirect).
- **Running totals** are the library's job when you use `verifyHttpSpendRequest`: it charges every link of a delegated chain, keyed by grantor + id, all or nothing, and `charge.release()` returns the money if your side effect fails. Bring a durable ledger for production: `@aroha-sdk/store-postgres` / `@aroha-sdk/store-redis` (TypeScript) or `pip install "aroha[postgres]"` / `"aroha[redis]"` (Python); both use one layout, so a mixed fleet can share a database.
- **Testing refusals:** `@aroha-sdk/credentials/testing` (test-only) builds hostile presentations — `presentMandateHttpUnchecked` for an agent presenting someone else's token, `buildHttpPresentationHeader` for arbitrary fields.
- Runnable reference: `examples/invoice-api/` in this skill's folder.

## Versions

Install `@aroha-sdk/core@^2 @aroha-sdk/credentials@^2` (or `pip install "aroha>=2"`). The functions in paths B and C (`verifyHttpSpendRequest`, `verifyHttpMandateRequest`, `presentMandateHttp`, the enrollment functions, `verifyMandateChain`, `httpRevocationCheck`, `presentMandate`, `verifyPresentation`) do not exist in the 1.x line, whose single-link `verifyMandate` also does not check who signed, the mandate type, or non-numeric amounts. If a project is pinned to 1.x, upgrade it rather than hand-building a substitute.
