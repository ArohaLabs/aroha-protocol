<!-- Copyright (c) 2026 Aroha Labs
     SPDX-License-Identifier: Apache-2.0 -->

# aroha — Aroha Protocol Python SDK

Build agents that register on the Aroha Hub and are callable by any client through the standard `/v1/run` protocol.

```
pip install aroha
```

## Quick start

```python
from aroha.agent import serve

@serve(
    name="My Agent",
    system_prompt="You are a helpful assistant.",
    provider="anthropic",
    model="claude-sonnet-4-6",
    memory="session",
)
async def my_agent(message: str, session_id: str, history: list, context: dict) -> str:
    import anthropic
    client = anthropic.Anthropic()
    resp = client.messages.create(
        model="claude-sonnet-4-6",
        max_tokens=1024,
        system="You are a helpful assistant.",
        messages=[{"role": "user", "content": message}],
    )
    return resp.content[0].text

if __name__ == "__main__":
    my_agent.start(port=8000)
```

This starts a FastAPI server with:
- `POST /v1/run` — the Aroha Protocol invocation endpoint
- `GET /.well-known/aroha-agent.json` — agent manifest
- `GET /health` — liveness check
- `GET /docs` — Swagger UI

### Security defaults (2.0)

- **Signed callers by default.** `auth="aroha-sig"` is the default: every
  request must be Ed25519-signed by the calling agent's DID key (see
  `aroha.hub.call_agent(..., sign_as=...)`). Pass `auth="none"` explicitly for
  an open agent, or `auth="bearer"` for a shared secret.
- **Loopback bind.** `start()` binds `127.0.0.1`. Pass `host="0.0.0.0"` (or an
  interface address) to accept connections from other machines.
- **No CORS by default.** Pass `cors_origins=["https://app.example"]` (or
  `["*"]`) to let browsers on other origins call the agent.
- **1 MiB request cap.** Larger bodies are rejected with HTTP 413 before
  parsing (`max_body_bytes=` to change it).
- **HTTPS-only clients.** `ArohaClient`, `aroha.client.ArohaClient`,
  `aroha.hub.*` and `registry_key_resolver` refuse `http://` URLs unless the
  host is loopback (`127.0.0.0/8`, `::1`, `localhost`) or you pass
  `allow_insecure_http=True` for a network you control.
- **Dev mode needs `AROHA_DEV_MODE=1`.** `ArohaServer(dev_mode=True)` and
  `validate_envelope(skip_signature=True)` disable signature checks. Both are
  refused unless the environment sets `AROHA_DEV_MODE=1` (a warning is printed
  to stderr once). `skip_signature=True` may instead be paired with
  `acknowledge_unauthenticated=True`, which states that a transport-level
  check (mTLS, a private link, a signed-request layer) authenticates the peer.

## Register on the Aroha Hub

```python
import os
result = my_agent.register(
    endpoint_url="https://my-agent.fly.dev",
    api_key=os.environ["AROHA_API_KEY"],
    private_key=agent_key,          # the agent's 32-byte Ed25519 seed (or Ed25519PrivateKey)
    manifest_cid="bafy...",         # the pinned manifest CID
)
print(result["didHash"])  # chat URL: https://aroha-labs.com/chat/<didHash>
```

The registry requires proof of key possession: `register` asks
`POST /v1/agents/challenge` for a one-time nonce and signs
`{"action":"prove-ownership","did":…,"nonce":…}` with `private_key`. Without a
DID in the manifest the agent registers as the content-addressed
`did:aroha:z…` of that key. A rotatable `did:aroha:E…` agent skips the
challenge and sends its Key Event Log instead
(`aroha.hub.register_agent(..., kel=...)`).

## Framework bridges

### LangChain / LangGraph

```bash
pip install aroha[langchain]
```

```python
from langchain_anthropic import ChatAnthropic
from langchain_core.prompts import ChatPromptTemplate
from aroha.bridges.langchain_v1 import from_chain

llm = ChatAnthropic(model="claude-sonnet-4-6")
prompt = ChatPromptTemplate.from_messages([
    ("system", "You are a helpful assistant."),
    ("human", "{message}"),
])
chain = prompt | llm

agent = from_chain(chain, name="LangChain Agent")
agent.start(port=8000)
```

### CrewAI

```bash
pip install aroha[crewai]
```

```python
from crewai import Agent, Task, Crew
from aroha.bridges.crewai_v1 import from_crew

researcher = Agent(
    role="Researcher",
    goal="Research the given topic thoroughly",
    backstory="Expert researcher",
    llm="anthropic/claude-sonnet-4-6",
)

def make_crew(message: str) -> Crew:
    task = Task(description=message, agent=researcher, expected_output="Research findings")
    return Crew(agents=[researcher], tasks=[task])

agent = from_crew(make_crew, name="Research Agent")
agent.start(port=8000)
```

### Google ADK

```bash
pip install aroha[google-adk]
```

```python
from google.adk.agents import LlmAgent
from google.adk.runners import Runner
from google.adk.sessions import InMemorySessionService
from aroha.bridges.google_adk import from_runner

adk_agent = LlmAgent(
    name="assistant",
    model="gemini-2.0-flash",
    instruction="You are a helpful assistant.",
)
session_service = InMemorySessionService()
runner = Runner(agent=adk_agent, app_name="my-app", session_service=session_service)

agent = from_runner(runner, name="Gemini Agent", memory="session")
agent.start(port=8000)
```

### OpenAI SDK

```bash
pip install aroha[openai]
```

```python
from openai import OpenAI
from aroha.bridges.openai_v1 import from_openai_client

client = OpenAI()
agent = from_openai_client(
    client,
    model="gpt-4o",
    system_prompt="You are a helpful assistant.",
    name="GPT Agent",
    memory="session",
)
agent.start(port=8000)
```

`AsyncOpenAI` works too. For the OpenAI Agents SDK use
`from_openai_agent(Agent(...))` (`pip install aroha[openai-agents]`).

### Aroha capabilities as framework tools

The other direction: give a framework agent tools that call Aroha providers
with signed `ArohaRequest` envelopes. Each tool's parameters are the
capability's `inputSchema`.

```python
from aroha.bridges.langchain_bridge import aroha_tools_for_agent   # LangChain / LangGraph
from aroha.bridges.crewai_bridge import aroha_tools_for_crew       # CrewAI
from aroha.bridges.autogen_bridge import aroha_tools_for_autogen   # AutoGen 0.4+ (autogen-core)

tools = await aroha_tools_for_agent(discovered, ["search-flights"], me.did, me.private_key, ArohaClient())
```

Tested against langchain-core 1.6 / langgraph 1.2, crewai 1.15, autogen
0.7.5, google-adk 2.12, openai 2.54 and openai-agents 0.20, with fake models
and no network (`tests/test_bridges_<framework>.py`, skipped when the
framework is not installed; `tests/test_bridges_fakes.py` runs the same
mapping logic everywhere). The AutoGen bridge targets the 0.4+ packages,
not legacy `pyautogen` 0.2.

## Hub client

```python
from aroha.hub import register_agent, resolve_agent, call_agent, list_agents

# Resolve by didHash
agent = resolve_agent("abc123def")

# Call an agent by didHash (resolves endpoint automatically)
reply = call_agent("abc123def", "What is the weather in London?")
print(reply["message"])

# List all agents
agents = list_agents(limit=20)
```

## Advanced: A2A envelope transport

The SDK also includes the full Aroha cryptographic envelope protocol for
zero-trust agent-to-agent messaging:

```python
from aroha import generate_did, ArohaServer, ArohaClient, build_envelope, validate_envelope, NonceRegistry

env = build_envelope("ArohaRequest", sender_did, receiver_did, body, correlation_id, private_key)
ok, reason = validate_envelope(env, sender_public_key_or_did_document, my_did, NonceRegistry())
```

`aroha.messages.validate_envelope` is the only envelope verifier and applies
the same rules, in the same order, as the TypeScript SDK: recipient →
timestamps (unparseable rejected; `created` at most max(tolerance, 30 s) in the
future; `expires - created` ≤ 5 min by default, `max_ttl_ms` to raise it) →
signature (`proof.verificationMethod` must belong to `from`) → nonce, recorded
only after the signature verified and keyed per sender. `aroha.envelope` is a
deprecated shim over it. Envelope signatures cover a byte-exact port of the
TypeScript `JSON.stringify(sortKeysDeep(envelope))`, so envelopes cross between
the SDKs in both directions. `build_envelope` accepts all 19 message types.
Nonces longer than 128 characters are rejected.

Replay protection is pluggable: `NonceRegistry(store)` takes any
`aroha.nonce_store.NonceStore` (`set_if_absent(key, expiry_ms)`,
`evict_expired()`). The default `MapNonceStore` forgets every nonce on restart;
a single instance should use `FileNonceStore("/var/lib/aroha/nonces.jsonl")`
(same JSON Lines format as the TypeScript `FileNonceStore`), and several
instances need a shared store (e.g. Redis `SET key NX PXAT expiry`).
`ArohaServer(..., nonce_registry=NonceRegistry(FileNonceStore(path)))` wires it
into the server.

## Spending mandates (v2 wire format)

```python
from aroha.mandate import (
    SpendingConstraints, issue_intent_mandate, attenuate_to_cart, verify_mandate_chain,
)

intent = issue_intent_mandate(human_did, agent_did, SpendingConstraints(500, allowed_merchants=[m]), human_key)
cart = attenuate_to_cart(intent, provider_did, SpendingConstraints(42.07, allowed_merchants=[m]), agent_key)

result = verify_mandate_chain(cart.token, expected_root=human_did)   # before moving money
assert result.valid and result.chain_verified
```

Tokens are `base64url(JSON({"v": 2, "mandate", "signature", "chain"}))`, with
camelCase fields (including `issuedAt`), the signature over the RFC 8785 (JCS)
form of `{"mandate": <body>, "v": 2}`, and the signed ancestry embedded
root-first. A verifier walks the chain offline: each link's signature,
grantor = parent's grantee, `parentMandateId`, tier order (intent → cart →
payment), narrowing re-checked on every link (`check_narrowing`), time
windows, and optional revocation (`is_revoked(mandate_id, grantor)`, fails
closed; a revocation list must be keyed by `(grantor, mandateId)` because a
mandate id alone is chosen by its minter and names nothing). Ancestor keys
come from `resolve_key` (default: content-addressed `did:aroha:z…` DIDs);
pass `kel_source=` to resolve rotatable `did:aroha:E…` DIDs through their Key
Event Logs, and `require_person_root=True` to insist the root is a person.

## Durable stores

`verify_http_spend_request` and the enrollment helpers keep three kinds of
state: single-use presentation nonces (replay protection), enrollment
challenges and account → DID bindings, and spending running totals. The
`InMemory…` stores lose all of it on restart — every nonce can be replayed
and every dollar spent again — and are not shared between processes. A
production server uses a shared, durable store:

```bash
pip install "aroha[postgres]"   # psycopg 3
pip install "aroha[redis]"      # redis-py 5+
```

PostgreSQL:

```python
import psycopg
from aroha.stores.postgres import (
    migrate, PostgresHttpPresentationNonces, PostgresEnrollmentStore, PostgresSpendingLedger,
)

conn = psycopg.connect(DATABASE_URL, autocommit=True)   # or a psycopg_pool.ConnectionPool
migrate(conn)                                           # once per deploy; idempotent
NONCES = PostgresHttpPresentationNonces(conn)
ENROLLMENT = PostgresEnrollmentStore(conn)
LEDGER = PostgresSpendingLedger(conn)
r = verify_http_spend_request(header, amount_usd=10, ledger=LEDGER, nonces=NONCES, audience=AUD, method="POST",
                              url=path, body=raw, expected_root=enrolled_did(ENROLLMENT, account_id), is_revoked=None)
```

Redis:

```python
import redis
from aroha.stores.redis import RedisHttpPresentationNonces, RedisEnrollmentStore, RedisSpendingLedger

client = redis.Redis.from_url(REDIS_URL)          # run Redis with appendonly yes
NONCES = RedisHttpPresentationNonces(client)
ENROLLMENT = RedisEnrollmentStore(client)
LEDGER = RedisSpendingLedger(client)
c = issue_enrollment_challenge(ENROLLMENT, authenticated_account_id=session.account_id)
r = verify_http_spend_request(header, amount_usd=10, ledger=LEDGER, nonces=NONCES, audience=AUD, method="POST",
                              url=path, body=raw, expected_root=enrolled_did(ENROLLMENT, account_id), is_revoked=None)
```

Semantics are those of the in-memory stores: amounts are integer micro-USD;
`init` is idempotent; `allocate` is atomic and raises `BudgetExhaustedError`
past the limit (or for an unknown key); `release` is safe to repeat; a nonce
claim succeeds once while it is live; a challenge is consumed (read and
deleted) by exactly one caller; outstanding challenges are bounded
(`max_challenges`, default 100 000). Store errors are not caught by the
stores: the verifiers refuse with `NONCE_STORE_UNAVAILABLE`,
`STORE_UNAVAILABLE` or `LEDGER_UNAVAILABLE` (503).

**PostgreSQL layout** — tables `<table_prefix><name>`, prefix default
`aroha_`, validated against `^[a-z_][a-z0-9_]{0,40}$`; `schema_sql()` returns
the DDL for your own migration tool. All inputs are bound parameters.

| Table | Columns | Atomic operation |
|---|---|---|
| `aroha_http_nonces` | `key TEXT PK`, `expires_at_ms BIGINT` | claim: `INSERT … ON CONFLICT (key) DO UPDATE … WHERE expires_at_ms < now RETURNING` (a live row wins) |
| `aroha_enrollment_challenges` | `challenge TEXT PK`, `account_id TEXT`, `expires_at_ms BIGINT` | consume: `DELETE … RETURNING` |
| `aroha_enrollment_bindings` | `account_id TEXT PK`, `did TEXT`, `updated_at TIMESTAMPTZ` | upsert |
| `aroha_spending_budgets` | `key TEXT PK`, `limit_micros BIGINT`, `allocated_micros BIGINT`, `expires_at_ms BIGINT NULL` | init: `INSERT … ON CONFLICT DO NOTHING`; allocate: `UPDATE … WHERE allocated_micros + amt <= limit_micros AND (expires_at_ms IS NULL OR expires_at_ms >= now) RETURNING` |
| `aroha_spending_allocations` | `key TEXT`, `allocation_id TEXT` (PK together), `amount_micros BIGINT` | release: `DELETE … RETURNING amount_micros`, then subtract, one transaction |

Expired nonce rows are deleted every 64 claims per instance; expired
challenges on every issue. Under concurrent issuance the challenge bound may
be overshot by the number of parallel callers (it caps storage only).

**Redis layout** — key prefix default `aroha:` (on Redis Cluster use a hash
tag such as `{aroha}:` so each script's keys share a slot):

| Key | Type | Written by |
|---|---|---|
| `aroha:nonce:<holder> <nonce>` | string `"1"` | `SET NX PX` until the presentation expires (inclusive) |
| `aroha:enroll:challenge:<challenge>` | string JSON `{"accountId","expiresAtMs"}` | Lua (exists check + bound + `SET PX` + index); consume is Lua `GET`+`DEL` |
| `aroha:enroll:challenges` | sorted set challenge → expiresAtMs | the same scripts (bounds outstanding challenges exactly) |
| `aroha:enroll:binding:<accountId>` | string DID | `SET` |
| `aroha:ledger:budget:<key>` | hash `limit`, `allocated` (micro-USD), optional `expires` (Unix ms) | Lua init (only if absent) / allocate (check-and-`HINCRBY`) / release |
| `aroha:ledger:alloc:<key>` | hash allocationId → micro-USD | the same allocate / release scripts |

Ledger keys are `grantor#mandateId` (`mandate_redemption_key`).

**Shared with TypeScript.** The tables, keys, migration lock and Lua
semantics match `@aroha-sdk/store-postgres` and `@aroha-sdk/store-redis`, so
Python and TypeScript servers can use one database or one Redis (same
`table_prefix` / `key_prefix`). Either language's `migrate` can run first.
The Python `init` sets no expiry; a budget expiry written by the TypeScript
stores (`init(key, limit, expiresAt)`) is honoured: past it, `allocate`
raises `BudgetExhaustedError` with nothing remaining. Python never deletes
budgets; reclaim space with the TypeScript `prune()` or your own job.

Tests: `tests/test_durable_stores.py` runs one contract suite over the
in-memory, PostgreSQL and Redis stores (parallel claims, allocations and
challenge consumption from separate connections; persistence across new
clients; expiry; an enrollment + `verify_http_spend_request` flow). Set
`AROHA_TEST_POSTGRES_URL` and/or `AROHA_TEST_REDIS_URL`; without them (or
without the driver) those cases are skipped.

## Task mandates (v2 wire format)

Non-monetary delegation: which capabilities an agent may invoke, how often,
with what compute and data access, optionally bound to one conversation room
and one room member (`room_id` / `on_behalf_of`).

```python
from aroha.task_mandate import (
    TaskConstraints, TaskActionRequest, issue_task_mandate, attenuate_task_mandate,
    enforce_task_constraints, check_task_narrowing,
)

grant = issue_task_mandate(host_did, agent_did, ["web-search", "send-email"], TaskConstraints(
    action_limits={"send-email": 2}, human_gates=["send-email"],
    data_access={"email": "read-write"}, room_id=room_id, on_behalf_of=guest_did,
), host_key)
sub = attenuate_task_mandate(grant, vendor_did, ["web-search"], TaskConstraints(
    data_access={"email": "read"}), agent_key, ttl_seconds=600)    # room / member binding inherited

mandate = enforce_task_constraints(sub.token, agent_public_key, TaskActionRequest(
    "web-search", room_id=room_id, on_behalf_of=guest_did))         # raises TaskConstraintViolation
```

Tokens are `base64url(JSON({"v": 2, "mandate", "signature"}))`, signed over
the JCS form of `{"mandate": <body>, "purpose": "aroha.task-mandate/v2", "v": 2}`.
A task token is one link; `check_task_narrowing(parent, child)` is the rule a
verifier holding the parent must apply (a widening child still has a valid
signature).

### Breaking change in this release

* **Mandate wire format.** Python used to issue snake_case tokens with no
  `issuedAt`, no chain, and a signature over `json.dumps(sort_keys=True)` —
  tokens no other SDK could verify. Everything is issued as v2 now. Old
  Python tokens and TypeScript v1 tokens are still accepted **for
  verification only**: a legacy root verifies as a one-link chain; a legacy
  child carries no ancestry, so `verify_mandate` reports
  `chain_verified=False` and `verify_mandate_chain` rejects it. Old Python
  tokens cannot be attenuated — re-issue them.
* `verify_mandate` returns a `MandateVerificationResult` (it still unpacks as
  `valid, mandate, reason`). Ancestors of a v2 token are resolved with
  `resolve_key`, so chains with named (non-self-certifying) DIDs need a
  resolver.
* `SpendingConstraints.currency` defaults to `None` (absent on the wire, read
  as USD) instead of `"USD"`; `merchant_category` is no longer inherited by
  attenuation (restate it, as in TypeScript); the approval-threshold error
  reads "approval threshold".
* Envelope timestamps are now `2026-01-01T00:00:00.000Z` (TypeScript format),
  and `validate_envelope` enforces the max TTL and future-`created` checks.
  Envelopes signed by earlier Python releases over bodies containing floats
  such as `10.0` or non-ASCII text used the old canonical form and will not
  verify.

## Parity with the TypeScript reference

| Area | Status |
|---|---|
| RFC 8785 JCS (`aroha.jcs`) | Byte-identical; tested against the RFC samples in `mandate-v2.json` and ~27k numbers formatted by node |
| Spending mandates v2 | Wire-identical; every vector in `packages/aroha-credentials/test-vectors/mandate-v2.json` passes (payloads, signatures, verdicts); live round trips both ways when node + built packages are available |
| Envelopes | Same validation order and rules; byte-identical canonical form; live round trips both ways |
| E-DIDs / KELs (`aroha.kel`) | Verification ported (inception/rotate/recover/revoke/anchor, controller seals, stale/duplicity store); reproduces the L0-KEL-01 pinned vector. Issuing helpers included |
| Message types / error codes | All 19 types, all 28 `ArohaErrorCode` values |
| Task mandates v2 (`aroha.task_mandate`) | Wire-identical; every vector in `packages/aroha-credentials/test-vectors/task-mandate-v2.json` passes (payloads, signatures, verdicts, reasons, narrowing reasons, violation codes and messages); live round trips both ways |
| Not ported | Spending ledger / redemption store (cumulative budget enforcement), multi-hop task-chain verifier (`verifyTaskMandateChain` in `@aroha-sdk/delegation`), task receipts, file-backed nonce store |

Timestamps are parsed as ISO 8601 only; an offset-less timestamp is read as
UTC (JavaScript's `Date.parse` reads it as local time and accepts some
non-ISO formats). Every SDK emits explicit `Z` timestamps, so this only
matters for hand-written input.

Conformance tests: `tests/test_mandate_vectors.py` and
`tests/test_task_mandate_vectors.py` (skipped with a message when the
monorepo's vector files are not present) and `tests/test_cross_language.py` /
`tests/test_task_mandate_interop.py` (marked `integration`; need `node` and built
`packages/aroha-core` + `packages/aroha-credentials`, or `AROHA_TS_PACKAGES`).

## /v1/run protocol

Any compliant agent must implement:

```
POST /v1/run
Content-Type: application/json

{
  "message":   "user message",
  "sessionId": "uuid (optional, echoed back)",
  "history":   [{"role": "user"|"assistant", "content": "..."}],
  "context":   {}
}
```

Response:

```json
{
  "message":   "agent reply",
  "sessionId": "uuid",
  "artifacts": [],
  "usage":     {}
}
```

The `@serve` decorator handles all of this automatically.
