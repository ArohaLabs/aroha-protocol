<!-- Copyright (c) 2026 Aroha Labs
     SPDX-License-Identifier: Apache-2.0 -->

# Python SDK

**Package:** `aroha` (2.0.0 on PyPI, beta) · **Module:** `aroha` · **Requires:** Python ≥ 3.11

## Installation

```bash
pip install aroha

# Optional framework bridges
pip install "aroha[langchain]"   # LangChain
pip install "aroha[crewai]"      # CrewAI
pip install "aroha[autogen]"     # AutoGen
pip install "aroha[all]"         # All bridges
```

## Quick Start

```python
from aroha.identity import generate_did
from aroha.transport import ArohaServer, ArohaClient
from aroha.messages import build_envelope, new_correlation_id

# 1. Generate a DID + Ed25519 keypair — returns a plain dict
identity = generate_did("my-agent", "http://localhost:3001")

# 2. Build a server
async def on_message(envelope):
    print(f"Received: {envelope['type']} from {envelope['from']}")
    return None  # 202 Accepted (async)

server = ArohaServer(
    agent_did=identity["did"],
    did_document=identity["document"],
    on_message=on_message,
    resolve_public_key=lambda did: None,  # add real key resolution
    dev_mode=True,                         # disable for production; refused unless AROHA_DEV_MODE=1
)

server.run(host="0.0.0.0", port=3001)
```

## High-level API — `@serve`

The simplest way to expose a Python function as an Aroha agent (wraps FastAPI + SSE automatically):

```python
from aroha.agent import serve

@serve(
    name="My Pricing Agent",
    system_prompt="You provide FX rates.",
    provider="anthropic",
    model="claude-sonnet-4-6",
    auth="bearer",                    # default is "aroha-sig" (Ed25519-signed callers)
    bearer_tokens={"secret-token"},
    expose_mcp=True,                  # expose /mcp endpoint
)
async def pricing_agent(message: str, session_id, history, context, **kw) -> str:
    return f"Current rate: 1 USD = 0.92 EUR"

if __name__ == "__main__":
    pricing_agent.start(port=8000)
```

**Streaming (async generator):**

```python
@serve(name="Streaming Agent")
async def streaming_agent(message: str, session_id, history, context, **kw):
    yield "Thinking..."
    yield " done!"
```

**Endpoints exposed:**

| Route | Description |
|---|---|
| `POST /v1/run` | Invoke the agent (`{"message":"...", "stream":true}`) |
| `POST /v1/resume` | Resolve a pending HITL approval |
| `POST /mcp` | MCP JSON-RPC endpoint (if `expose_mcp=True`) |
| `GET /health` | Liveness probe |
| `GET /.well-known/aroha-agent.json` | Agent manifest |

**ASGI deployment (Gunicorn / Uvicorn workers):**

```python
# asgi.py
app = pricing_agent.app()   # returns the FastAPI instance
```

```bash
uvicorn asgi:app --host 0.0.0.0 --port 8000
```

---

## `aroha.identity`

### `generate_did(agent_id, endpoint, *, namespace=None) → dict`

Generates a `did:aroha:` DID, an Ed25519 keypair, and a conformant DID Document. Returns a plain `dict` (JSON-serialisable except for the crypto key objects).

```python
from aroha.identity import generate_did

identity = generate_did("pricing-agent", "https://agents.example.com/pricing")
print(identity["did"])       # did:aroha:pricing-agent
print(identity["document"])  # W3C DID Document as a plain dict

# Optional namespace — scopes the DID to your organisation
identity = generate_did("pricing-agent", "https://agents.example.com/pricing",
                        namespace="acme-corp")
print(identity["did"])       # did:aroha:acme-corp.pricing-agent
```

**Return value:**

| Key | Type | Description |
|---|---|---|
| `"did"` | `str` | The agent's DID, e.g. `did:aroha:my-agent` |
| `"document"` | `dict` | Full W3C DID Document (plain dict, ready for JSON) |
| `"private_key"` | `Ed25519PrivateKey` | Ed25519 private key — **keep secret, never serialise** |
| `"public_key"` | `Ed25519PublicKey` | Ed25519 public key (safe to share) |
| `"public_key_bytes"` | `bytes` | Raw 32-byte public key (for `verify_envelope`) |

### Helpers

```python
from aroha.identity import (
    extract_public_key,       # revocation-aware — use this in production
    extract_public_key_bytes, # raw bytes from a DIDDocument dataclass (internal)
    extract_endpoint,
    to_multibase, from_multibase,
)

# extract_public_key checks for revoked keys and raises ValueError if revoked
pub_bytes = extract_public_key(identity["document"])   # → bytes (32)

# Encoding helpers
encoded = to_multibase(raw_bytes)    # → "z<base58>"
decoded = from_multibase(encoded)    # → bytes
```

**Revocation checking:**

```python
from aroha.identity import extract_public_key

doc = identity["document"]
# If the key has been revoked, extract_public_key raises:
# ValueError: Key z<prefix>… was revoked at <date>: <reason>
pub = extract_public_key(doc)
```

---

## `aroha.crypto`

### `sign_message(message, private_key, verification_method_id) → dict`

Canonicalises the message (lexicographically sorted keys), signs with Ed25519, and returns a proof dict. Called automatically by `build_envelope`.

```python
from aroha.crypto import sign_message, verify_message_signature, canonicalize_message

key_id = f'{identity["did"]}#key-1'
proof = sign_message(envelope, identity["private_key"], key_id)
valid = verify_message_signature(envelope, sender_public_key)  # → bool
canon = canonicalize_message(envelope)                         # → str
```

### Body Encryption (DIDComm-style)

```python
from aroha.crypto import encrypt_body, decrypt_body

encrypted = encrypt_body({"secret": "value"}, recipient_pub_bytes)
# → { "alg": "ECDH-ES+A256GCM", "epk": ..., "iv": ..., "ciphertext": ..., "tag": ... }

plaintext = decrypt_body(encrypted, recipient_private_key_bytes)
```

---

## `aroha.messages`

### `build_envelope(...) → ArohaEnvelope`

Builds and signs an outbound Aroha message envelope.

```python
from aroha.messages import build_envelope, new_correlation_id

envelope = build_envelope(
    type_="ArohaRequest",
    from_did=identity["did"],
    to_did="did:aroha:target-agent",
    body={"capability": "convert", "amount": 100, "from": "USD", "to": "EUR"},
    correlation_id=new_correlation_id(),
    private_key=identity["private_key"],
    ttl_seconds=300,          # optional, default 300
    traceparent="00-...",     # optional W3C trace context
    routing_hint={"complexity": "standard"},  # optional
)
```

| Parameter | Type | Default | Description |
|---|---|---|---|
| `type_` | `str` | required | One of the 19 Aroha message type strings |
| `from_did` | `str` | required | Sender DID |
| `to_did` | `str` | required | Recipient DID |
| `body` | `dict` | required | Message payload |
| `correlation_id` | `str` | required | Saga/session ID (use `new_correlation_id()`) |
| `private_key` | `Ed25519PrivateKey` | required | Sender's signing key |
| `ttl_seconds` | `int` | `300` | Message validity window |
| `traceparent` | `str` | `None` | W3C Trace Context header |
| `routing_hint` | `dict` | `None` | Orchestrator model routing suggestion |

### `validate_envelope(...) → tuple[bool, str | None]`

Validates an inbound envelope: recipient match → timestamps → signature → nonce replay (the nonce is recorded only after the signature verifies).

```python
from aroha.messages import validate_envelope, NonceRegistry

nonces = NonceRegistry()

valid, reason = validate_envelope(
    envelope=inbound,
    sender_key=resolved_pub_key,   # public key, raw bytes, or the sender's DID document
    my_did=identity["did"],
    nonce_registry=nonces,
    skip_signature=False,   # True only with acknowledge_unauthenticated=True (mTLS/VPC trusted mesh)
)

if not valid:
    print(f"Rejected: {reason}")
```

### `NonceRegistry`

Replay attack prevention. Stores seen nonces with their expiry times; automatically evicts expired entries on each check.

```python
from aroha.messages import NonceRegistry

nonces = NonceRegistry()
is_fresh = nonces.check(nonce="abc123", expires_at="2026-04-29T12:00:00+00:00")
# → True first time, False on replay
```

### Message Types

```python
from aroha.messages import MESSAGE_TYPES   # Aroha_MESSAGE_TYPES is a backward-compatible alias

# Set of all 19 valid type strings:
# {"ArohaRequest", "ArohaResponse", "ArohaStream", "ArohaNegotiate",
#  "ArohaCounterOffer", "ArohaAccept", "ArohaReserve", "ArohaReserveAck",
#  "ArohaCommit", "ArohaCommitAck", "ArohaCancel", "ArohaCancelAck",
#  "ArohaDelegate", "ArohaError", "ArohaSatisfactionSignal",
#  "ArohaSpendingMandate", "ArohaTaskMandate",
#  "ArohaDispute", "ArohaDisputeResolution"}
```

### `ArohaErrorCode`

```python
from aroha.messages import ArohaErrorCode

# Auth
ArohaErrorCode.UNAUTHORIZED              # "Aroha_UNAUTHORIZED"
ArohaErrorCode.FORBIDDEN                 # "Aroha_FORBIDDEN"
# Protocol
ArohaErrorCode.INVALID_SIGNATURE         # "Aroha_INVALID_SIGNATURE"
ArohaErrorCode.EXPIRED_MESSAGE           # "Aroha_EXPIRED_MESSAGE"
ArohaErrorCode.REPLAY_DETECTED           # "Aroha_REPLAY_DETECTED"
ArohaErrorCode.UNKNOWN_CAPABILITY        # "Aroha_UNKNOWN_CAPABILITY"
ArohaErrorCode.TRUST_LEVEL_INSUFFICIENT  # "Aroha_TRUST_LEVEL_INSUFFICIENT"
# Saga
ArohaErrorCode.RESERVATION_FAILED        # "Aroha_RESERVATION_FAILED"
ArohaErrorCode.RESERVATION_EXPIRED       # "Aroha_RESERVATION_EXPIRED"
ArohaErrorCode.COMMIT_FAILED             # "Aroha_COMMIT_FAILED"
ArohaErrorCode.CANCEL_FAILED             # "Aroha_CANCEL_FAILED"
ArohaErrorCode.INVALID_TOKEN             # "Aroha_INVALID_TOKEN"
# Availability
ArohaErrorCode.NO_INVENTORY              # "Aroha_NO_INVENTORY"
ArohaErrorCode.CAPACITY_EXCEEDED         # "Aroha_CAPACITY_EXCEEDED"
ArohaErrorCode.SERVICE_UNAVAILABLE       # "Aroha_SERVICE_UNAVAILABLE"
# Generic
ArohaErrorCode.INTERNAL_ERROR            # "Aroha_INTERNAL_ERROR"
ArohaErrorCode.INVALID_PARAMS            # "Aroha_INVALID_PARAMS"
```

---

## `aroha.transport`

### `ArohaServer`

FastAPI-based HTTP server. Handles `GET /.well-known/aroha-agent.json` and `POST /aroha/v1`.

```python
from aroha.transport import ArohaServer

server = ArohaServer(
    agent_did=identity["did"],
    did_document=identity["document"],
    on_message=my_handler,       # async (envelope) → envelope | None
    resolve_public_key=resolver, # async (did: str) → Ed25519PublicKey | None
    dev_mode=False,              # True = skip all crypto (dev/hackathon only)
)

# Blocking — call from a thread or use server.app with uvicorn directly
server.run(host="0.0.0.0", port=3001)

# For async use:
import uvicorn
await uvicorn.Server(uvicorn.Config(server.app, host="0.0.0.0", port=3001)).serve()
```

**`on_message` signature:**

```python
async def on_message(envelope: dict) -> dict | None:
    if envelope["type"] == "ArohaRequest":
        # process and return a response envelope, or None for async (202)
        return build_envelope("ArohaResponse", ...)
    return None
```

### `ArohaClient`

Async HTTP client.

```python
from aroha.transport import ArohaClient, ArohaTransportError

client = ArohaClient(timeout=30.0)

# Send and await synchronous response (None → 202 Accepted)
reply = await client.send(
    endpoint="http://localhost:3001/aroha/v1",
    envelope=signed_envelope,
    timeout=10.0,  # optional override
)

# Fetch a peer's DID Document
doc = await client.fetch_did_document("http://localhost:3001")

# Handle errors
try:
    reply = await client.send(endpoint, envelope)
except ArohaTransportError as e:
    print(e.status_code, e.body)
```

---

## `aroha.orchestrator`

### `SagaEngine`

Coordinates atomic 3-phase transactions across multiple agents.

```python
from aroha.orchestrator import SagaEngine, SagaStep

engine = SagaEngine(
    client=ArohaClient(),
    orchestrator_did=identity["did"],
    private_key=identity["private_key"],
)

result = await engine.execute([
    SagaStep(
        agent_did="did:aroha:flight-agent",
        agent_endpoint="https://flights.example.com/aroha/v1",
        capability="book-flight",
        params={"origin": "JFK", "dest": "NRT", "date": "2026-06-01"},
        hold_duration_ms=30_000,
    ),
    SagaStep(
        agent_did="did:aroha:hotel-agent",
        agent_endpoint="https://hotels.example.com/aroha/v1",
        capability="book-hotel",
        params={"city": "Tokyo", "nights": 5},
        hold_duration_ms=30_000,
    ),
])

if result.success:
    print(result.results)   # {0: {pnr: ...}, 1: {ref: ...}}
else:
    print(result.failures)  # list of failure dicts; all reservations auto-cancelled
```

**Saga phases:**
1. **Reserve** — all steps in parallel; any failure aborts
2. **Commit** — steps in order; failure triggers LIFO cancellation of committed steps
3. **Compensate** — cancelled in reverse order if commit fails mid-way

### `AgentSelector`

Fan-out ArohaRequests to multiple candidate agents and select the best response.

```python
from aroha.orchestrator import AgentSelector, SagaStep

selector = AgentSelector(
    client=ArohaClient(),
    orchestrator_did=identity["did"],
    private_key=identity["private_key"],
)

result = await selector.select(
    capability="sentiment-analysis",
    params={"ticker": "BTC", "window": "1h"},
    candidates=[
        {"did": "did:aroha:feed-a", "endpoint": "https://feed-a.example.com/aroha/v1"},
        {"did": "did:aroha:feed-b", "endpoint": "https://feed-b.example.com/aroha/v1"},
    ],
    weights={"price": 0.5, "reputation": 0.3, "latency": 0.2},
)

print(result.winner.agent_did)   # did:aroha:feed-a (or feed-b)
print(result.winner.score)       # 0.87
print(result.ranked)             # all candidates, scored and sorted
```

**Default scoring weights:**

| Factor | Default weight |
|---|---|
| Price | 0.35 |
| Reputation | 0.30 |
| Latency | 0.15 |
| Preference | 0.15 |
| Availability | 0.05 |

---

## Framework Bridges

### LangChain

```python
from aroha.bridges.langchain_bridge import aroha_tools_for_agent

tools = await aroha_tools_for_agent(
    agents=[
        {"did": "did:aroha:fx-agent", "endpoint": "https://fx.example.com/aroha/v1", "capabilities": ["convert"]},
    ],
    capability_ids=["convert"],
    orchestrator_did=identity["did"],
    private_key=identity["private_key"],
    client=ArohaClient(),
)

# Use like any LangChain tool
from langchain.agents import AgentExecutor, create_openai_functions_agent
executor = AgentExecutor(agent=agent, tools=tools)
```

### CrewAI / AutoGen

`aroha.bridges.crewai_bridge.aroha_tools_for_crew` (CrewAI ≥ 0.80) and `aroha.bridges.autogen_bridge.aroha_tools_for_autogen` (AutoGen 0.4+, `autogen-core`) build the same tools for those frameworks. See the [SDK README](https://github.com/ArohaLabs/aroha-protocol/blob/main/sdks/aroha-py/README.md#framework-bridges) for the inbound bridges (`from_chain`, `from_crew`, `from_runner`, `from_openai_client`).

---

## `aroha.web_did`

Two-factor DNS-anchored identity. See [did:aroha-web: spec →](../spec/web-did.md)

Since 2.0 this is a port of the TypeScript resolver: same document shape
(`verificationMethod[]` with base58 `publicKeyMultibase`, `arohaWeb.keyHistory`
newest first, v2 DID-bound rotation records) and the same resolution rules.

```python
from aroha.web_did import generate_web_agent, rotate_key, resolve_web_did, select_web_did_key

agent = generate_web_agent("stripe.com", "payments-agent")
# agent.did == "did:aroha-web:stripe.com:payments-agent"

# Publish agent.document (JSON) at agent.well_known_url and the TXT value
# agent.dns_txt_record at _aroha.stripe.com.

rotated = rotate_key(agent, cool_down_hours=24)  # v2 record signed by the old key

result = resolve_web_did("did:aroha-web:stripe.com:payments-agent")
key = select_web_did_key(result)  # raises when no key is accepted (fail closed)
```

`resolve_web_did` refuses DIDs whose domain is not a hostname (IP literals need
`allow_ip_literal=True`) or whose path does not match
`^[a-z0-9-]+(/[a-z0-9-]+)*$`; fetches over https without following redirects,
with a timeout and a 64 KiB cap; hashes the served key itself and requires the
rotation chain to link it to a key `_aroha.{domain}` commits to. With no DNS
resolver (pass `dns_resolver=`, or install dnspython) it raises unless
`allow_no_dns=True`; `dns_verified` is `False` whenever DNS was not checked.

---

## `aroha.csn`

Capability Schema Negotiation — deterministic structural matching before LLM fallback.
See [CSN guide →](../spec/csn.md)

```python
from aroha.csn import (
    CapabilityRegistry, CapabilityEntry, CSNHandler,
    CapabilityNegotiator, DiscoveryRequest,
)

# ── Provider ──────────────────────────────────────────────────────────────────
registry = CapabilityRegistry()
registry.register(CapabilityEntry(
    name="fx-convert",
    description="Convert between two currencies",
    input_schema={
        "type": "object",
        "properties": {
            "amount": {"type": "number"},
            "from":   {"type": "string"},
            "to":     {"type": "string"},
        },
        "required": ["amount", "from", "to"],
    },
))
handler = CSNHandler(registry, agent_did=did, private_key=key)

async def on_message(envelope, respond, stream):
    if envelope["type"] == "ArohaNegotiate" and "csn" in envelope["body"]:
        reply = await handler.handle(envelope, envelope["from"])
        respond(reply)

# ── Requestor ─────────────────────────────────────────────────────────────────
negotiator = CapabilityNegotiator(send=http_send, orchestrator_did=my_did, private_key=key)
result = await negotiator.discover(
    agent_endpoint="https://fx.example.com/aroha/v1",
    agent_did="did:aroha-web:fx.example.com:agent",
    request=DiscoveryRequest(
        capability_intent="convert currency from USD to JPY",
        desired_schema={"input": {"type": "object", "properties": {
            "amount": {"type": "number"}, "from": {"type": "string"}, "to": {"type": "string"},
        }, "required": ["amount", "from", "to"]}},
    ),
)
# result.resolved_capability == "fx-convert"
# result.match_method == "schema"   (no LLM used)
# result.rounds == 0                (cache hit on repeat)
```

---

## `aroha.reputation`

Bayesian Beta reputation engine with 11 signals and Thompson Sampling.
See [Reputation Model →](../reputation-model.md)

```python
from aroha.reputation import BayesianReputationEngine

engine = BayesianReputationEngine()
engine.record_event({
    "agent_did": "did:aroha:fx-agent",
    "domain":    "fx",
    "signal":    "saga_complete",
    "success":   True,
    "response_ms": 120,
})

score  = engine.composite_score("did:aroha:fx-agent", "fx")
ranked = engine.thompson_select(["did:aroha:fx-a", "did:aroha:fx-b"], "fx")
```

---

## `aroha.mandate`

Spending mandate delegation — Intent → Cart → Payment with monotonic constraint narrowing.
See [@aroha-sdk/credentials →](../packages/credentials.md)

```python
from aroha.mandate import (
    issue_intent_mandate, attenuate_to_cart, attenuate_to_payment,
    verify_mandate, SpendingConstraints,
)
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

user_key = Ed25519PrivateKey.generate()

intent = issue_intent_mandate(
    grantor_did="did:aroha:personal-agent-alice",
    grantee_did="did:aroha:personal-agent",
    constraints=SpendingConstraints(spend_limit_usd=500.0),
    private_key=user_key,
    ttl_seconds=3600,   # 1 hour; default is 3600
)

# Attenuate to a cart-level mandate (constraints can only narrow, never widen)
cart = attenuate_to_cart(
    parent=intent,
    grantee_did="did:aroha:shopping-orchestrator",
    narrowed=SpendingConstraints(
        spend_limit_usd=79.99,
        allowed_merchants=["merchant-a"],
    ),
    grantor_private_key=user_key,
)

# verify_mandate returns a 3-tuple: (valid: bool, mandate | None, reason: str | None)
valid, mandate, reason = verify_mandate(cart.token, user_key.public_key())
if valid:
    print(mandate.constraints.spend_limit_usd)   # 79.99
else:
    print(f"Rejected: {reason}")
```

