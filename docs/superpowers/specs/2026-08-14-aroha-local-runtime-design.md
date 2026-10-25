<!-- Copyright (c) 2026 Aroha Labs
     SPDX-License-Identifier: Apache-2.0 -->

# Aroha Local Runtime — Design

**Date:** 2026-08-14
**Status:** Draft for review
**Scope:** A single-binary, cross-platform local runtime that installs in one command, manages a local inference engine, creates and hosts agents, serves a chat UI, and connects to other agents — including agents on other people's devices — to complete real transactions. Includes the discovery, naming, and injection-defense protocol work required to make that safe.

---

## 1. Goal

Today, standing up an Aroha agent requires Node 22+, `npm`, a scaffolder, manual inference configuration, and a hand-rolled UI. That is a developer workflow. This design collapses it to:

```
curl -fsSL https://aroha.sh/install | sh
aroha up
```

…after which the user has a running inference engine, a working agent, and a browser chat UI — with no Node, no API key, and no account. From there the agent can discover and call other agents, and can itself become callable.

### 1.1 Non-goals

- **Not** a replacement for the SDK. The runtime is a host, not a framework.
- **Not** a model training or fine-tuning tool.
- **Not** bundling model weights.
- **Not** a hosted multi-tenant service.

---

## 2. What already exists

**Most of what this needs is already built.** The runtime is largely an orchestrator over existing packages.

| Need | Provided by | Notes |
|---|---|---|
| Agent host, SSE streaming, HITL approvals, sessions | `@aroha-sdk/run` → `serve()` | |
| Call & stream to remote agents | `@aroha-sdk/run` → `callAgent`, `streamAgent` | Incl. attenuated variant |
| Discovery / resolution | `@aroha-sdk/run` → `resolveAgent`, `listAgents` | Registry-backed |
| MCP + skill register/resolve/list | `@aroha-sdk/run` | Registry-side live |
| MCP ⇄ Aroha adaptation | `@aroha-sdk/mcp-bridge` | Bidirectional |
| MCP tool-call policy | `@aroha-sdk/mcp-guard` → `GuardEngine`, `GuardProxy` | Rules + stdio proxy |
| Signing / verification / replay | `@aroha-sdk/run/signing`, `@aroha-sdk/core` | Ed25519, `NonceRegistry` |
| **Body encryption** | `@aroha-sdk/core` → `encryptBody`/`decryptBody` | X25519 ECDH + AES-256-GCM, ephemeral key per message |
| **Self-certifying DIDs** | `@aroha-sdk/core` → `generateDid` | `did:aroha:<base58btc(publicKey)>` — see §2.1 |
| Domain-anchored identity | `did:aroha-web` | DNS TXT + HTTPS proof |
| Org → agent delegation | `@aroha-sdk/commerce` → `org-identity.ts` | `AgentDelegationCredential` |
| Mandates, attenuation, chains, receipts | `@aroha-sdk/credentials`, `/delegation` | `TaskReceiptBuilder` |
| Saga: negotiate → reserve → commit → compensate | `@aroha-sdk/orchestrator` | LIFO compensation, DLQ, recovery |
| Escrow bound to saga lifecycle | `@aroha-sdk/settlement` → `escrow.ts` | open/approveSplit/release/refund |
| Settlement adapters | `@aroha-sdk/settlement` | stripe, wallet, ap2, quota, api-key |
| Intent confirmation before funds lock | `@aroha-sdk/orchestrator` → `intent-gate.ts` | Paraphrase-and-confirm |
| Capability taxonomy (reversibility + risk tier) | `@aroha-sdk/core` → `capabilities/taxonomy.ts` | |
| Visibility + grants | `apps/registry-server` | Grants by DID **and** key hash |
| Per-firm subdomain provisioning | `apps/registry-server` → `provision.ts`, `cloudflare-dns.ts` | Signed requests, license check, audit log |

### 2.1 The most consequential existing property

```ts
// The DID is content-addressed: did:aroha:<base58btc(publicKey)>
export function generateDid(publicKey: Uint8Array): string {
  return "did:aroha:" + toMultibase(publicKey);
}
```

**An Aroha DID contains its own public key.** Key resolution is therefore *self-certifying*: any party can derive and verify the key offline, with no trusted third party. This single property is the foundation for federated discovery (§7) and it dissolves most of the registry-as-root-of-trust risk (§9.2).

**Exception:** the namespaced form `did:aroha:<namespace>.<agentId>` is **not** content-addressed and does require a trusted resolver. Two DID forms with materially different trust models — this must be stated normatively in the spec, and code must branch on it rather than assume.

---

## 3. Key decisions

| Decision | Choice | Rationale |
|---|---|---|
| Distribution | Single native binary + browser UI | Ollama-class UX; headless-capable; no Node on user machines |
| Build toolchain | `bun build --compile` | Reuses every `@aroha-sdk/*` package — no second protocol implementation to keep in cryptographic lockstep |
| Inference | Detect existing engine, else offer managed install | Small download; never bundles weights |
| Identity | Local DID immediately; claim on publish | Zero-friction first run; offline-capable |
| Local store | SQLite via `bun:sqlite` | Avoids native-module compilation in a compiled binary |
| Transport security | **Message-layer (Layer 2), not transport-layer** | Enables device hosting with no TLS certificate (§6) |
| Connectivity | **Outbound-first; LAN → P2P → relay ladder** | Consuming needs zero infra; inbound degrades gracefully |
| Discovery | **Federated, verifiable records; indexes untrusted** | Enabled by §2.1; avoids recreating a central root of trust (§7) |
| Naming | **Subdomain is an alias, never an identity** | Preserves self-certifying identity (§7.7) |

---

## 4. Architecture

```
                         ┌─────────────────────────────────┐
   aroha CLI ──────────► │        aroha supervisor         │
   (same binary)         │                                 │
                         │  ┌───────────────────────────┐  │
   browser ──:7777─────► │  │  Gateway (HTTP + WS)      │  │
                         │  │  embedded UI + local API  │  │
                         │  │  origin + Host + token    │  │
                         │  └───────────┬───────────────┘  │
                         │              │                  │
                         │  ┌───────────┴───────┐          │
                         │  │  Agent host       │──────────┼──► serve()  [dual-context §9.1]
                         │  ├───────────────────┤          │
                         │  │  Engine manager   │──────────┼──► ollama / vLLM
                         │  ├───────────────────┤          │
                         │  │  MCP manager      │──────────┼──► MCP servers (guarded)
                         │  ├───────────────────┤          │
                         │  │  Transport layer  │──────────┼──► LAN / P2P / relay  (§6)
                         │  ├───────────────────┤          │
                         │  │  Discovery client │──────────┼──► SAR indexes  (§7)
                         │  ├───────────────────┤          │
                         │  │  Platform sync    │──────────┼──► registry /v1/*
                         │  └───────────────────┘          │
                         │       ~/.aroha/ (SQLite, keys)  │
                         └─────────────────────────────────┘
```

### 4.1 Workspace layout

```
~/.aroha/
  config.toml           engine, port, transport prefs, telemetry opt-in
  aroha.db              agents, sessions, messages, mcps, peers, pinned keys
  token                 gateway auth token (0600)
  keys/                 Ed25519 private keys (0600 or OS keychain)
  agents/<slug>/        manifest.json + optional handler source
  mcp/<name>/           installed MCP payloads
  logs/supervisor.log
```

---

## 5. Subsystems

### 5.1 Installer

`install.sh`, `install.ps1`, Homebrew tap, Scoop/winget. Detect OS/arch → fetch versioned binary → **verify checksum and signature** → install to PATH → verify `aroha --version`.

Targets: `darwin-arm64`, `darwin-x64`, `linux-x64`, `linux-arm64`, `windows-x64`.

**Code signing is a procurement dependency, not polish.** Gatekeeper blocks unsigned macOS binaries; SmartScreen flags unsigned Windows ones. Apple Developer ID and an Authenticode certificate both carry lead time and recurring cost — start acquisition at M0 though it lands in M11.

### 5.2 Engine manager

**Detection order:** running Ollama `:11434` → Ollama on PATH → vLLM `:8000` → LM Studio `:1234` → configured hosted key → none.

**If none:** offer managed Ollama install (download, verify, supervise). Never silent; always show size.

**Model selection:** probe RAM/VRAM and recommend (e.g. `llama3.1:8b` at 16GB, `qwen2.5:3b` at 8GB). Pull with progress; user may override.

**Responsibilities:** health polling, crash restart with backoff, graceful shutdown, uniform completion interface so the host is engine-agnostic.

**Hosted fallback:** Anthropic/OpenAI/Google key. Mirror the provider union in `apps/website/src/app/api/chat/route.ts`.

**Secrets:** OS keychain (Keychain / DPAPI / libsecret), never `config.toml`.

### 5.3 Agent host

Wraps `serve()`. Agents are **declarative** (manifest + prompt + model + MCP tools — the default and the only kind the UI exposes) or **code-backed**.

Minted via `mintLocalIdentity()`: real DID, real keypair, usable offline. Nothing contacts the network at creation.

The execution loop is **dual-context** from the outset (§9.1) — retrofitting that boundary later is impractical.

### 5.4 Gateway and local UI

One server on `127.0.0.1:7777` serving embedded UI assets plus a local JSON/SSE API.

**UI:** agent list/status, streaming chat with inline HITL approvals, creation wizard, MCP browser, model manager, peer/connection view, publish flow, settings, logs.

Embedded at compile time. No CDN calls; must work fully offline.

### 5.5 MCP manager

Browse via `listMcps()`, install locally, attach to agents. Servers run supervised (stdio) or remote (http), exposed through `mcp-bridge.fromMcp()`.

**All MCP traffic routes through `mcp-guard`'s `GuardProxy` by default**, not opt-in. Install requires explicit confirmation showing source and command.

### 5.6 Platform sync

**Publish:** device-code OAuth (works headless and over SSH) → bind the existing local DID to the account by signing a server-issued challenge (private key never leaves the machine) → manifest → IPFS → `/v1/agents`.

Two modes, genuinely different products:

- **Definition publish** — manifest, prompt, model binding, MCP bindings. Consumers instantiate on *their* runtime. No hosting or uptime obligation. Right for **templates and starter agents**; mirrors how MCPs and skills already distribute.
- **Endpoint publish** — registered as a live callable service addressed by DID, reachable per §6.

Sequencing: at M6, endpoint publish works only for agents reachable at ladder rung 1 (deployed, public endpoint). Endpoint-publishing a *device-hosted* agent additionally requires M9 (LAN/P2P) or M10 (relay). Until then device-hosted agents publish as definitions.

**Consume:** browse Hub locally, resolve, call with signed requests. Private agents via `/v1/grants`.

---

## 6. Transport and connectivity

Resolves: **how do agents on individual devices connect, with no public IP and no HTTPS certificate?**

### 6.1 HTTPS is not required

Layer 0 currently reads "Transport (HTTPS + WebSocket)," which makes device hosting look impossible — a NAT'd laptop cannot obtain a CA certificate for a private, rotating address.

TLS provides two properties, authentication and confidentiality, bound to a *hostname* via a CA. Aroha already has both bound to a *DID*:

- **Authentication** — Ed25519 envelope signatures against a key the DID itself commits to (§2.1).
- **Confidentiality** — `encryptBody`/`decryptBody`: X25519 ECDH + AES-256-GCM, DIDComm v2 JWE style, **fresh ephemeral keypair per message** (forward secrecy). X25519 keys derive from the existing Ed25519 key, so every agent already has encryption material.
- **Replay protection** — `NonceRegistry` / `createNonceGuard`.

For agent-to-agent this is *stronger* than TLS: the identity that matters is the key, not the host that served the bytes. This is the Signal / Noise / libp2p model.

**Required changes:**

1. **Amend Layer 0** to: *any bidirectional byte transport; security is provided by Layer 2, not the transport.*
2. **Encryption becomes mandatory off-TLS.** Current guidance is that senders *SHOULD* encrypt sensitive fields. Off-TLS this hardens to **full-body encryption REQUIRED**. Signature-over-cleartext is fine on TLS, unacceptable on a LAN socket or relay.

### 6.2 The transport ladder

| Rung | Mechanism | When | Infra |
|---|---|---|---|
| 1 | **Direct HTTPS** | Callee has a public endpoint | None |
| 2 | **LAN direct** | Same network — mDNS/DNS-SD (`_aroha._tcp.local`), plain TCP/WS | None |
| 3 | **P2P** | Across networks — ICE/STUN, hole punch over WebRTC data channel or QUIC | STUN |
| 4 | **Relay** | Hole punch fails (symmetric NAT, corporate networks) | Broker |

Rung 2 works with **no internet at all**.

Because every envelope is signed and encrypted end to end, **the relay is untrusted at every rung** — which is what keeps the vendor-neutrality claim intact.

### 6.3 The relay broker

The runtime holds a persistent **outbound** WebSocket; inbound calls for that DID are pushed down it. NAT is never traversed because nothing connects inward — the pattern GitHub Actions runners and Slack Socket Mode use.

**Implementation: Cloudflare Durable Objects.** One DO per agent DID holds the socket and routes to it. **WebSocket Hibernation** evicts the object from memory while the socket stays open, so idle agents cost almost nothing — decisive, since most laptops are asleep.

This deliberately avoids Cloudflare Tunnel: per `wrangler.toml`, `*.cfargotunnel.com` routing requires proxying inside a Cloudflare-authoritative zone, which forced a Business/Enterprise subdomain delegation — a wall this team already hit. Durable Objects need only the standard Workers paid plan.

### 6.4 Presence: DID documents cannot hold your address

A laptop's address changes per network and is unreachable while asleep.

- **DID document — stable facts.** Keys, supported transports, relay address. `DIDDocument.service` is already `ServiceEndpoint[]`, so the model supports this today.
- **Presence record — volatile facts.** Current ICE candidates, online status, timestamp. Published on connect, expired on disconnect, TTL-bounded. **New registry concept:** today the registry knows an agent is *registered*, never whether it is *presently reachable*.

**Resolver change:** `getArohaEndpoint()` currently does `.find()`, returns one string, and throws when absent:

```ts
const svc = doc.service.find((s) => s.type === "ArohaEndpoint");
if (!svc) throw new Error(`DID ${doc.id} has no ArohaEndpoint service`);
```

This becomes an ordered **candidate list** merging DID-document transports with the live presence record, consumed by §6.2.

### 6.5 Build order

Rungs 1–2 plus presence records give working device-to-device agents on a shared network with **zero infrastructure**, proving the transport-agnostic model before any NAT-traversal work. Build them first.

---

## 7. Discovery, naming, and addressing

### 7.1 The gap

- **MCP** has no discovery — every server is hand-configured.
- **A2A** uses `/.well-known/agent.json` — requires a domain, no cross-domain index.
- **Registries**, including Aroha's today, are centralized: single point of trust, failure, and censorship.

Nobody has **federated, verifiable capability discovery**. That is the standardizable gap, and it is coherent with a W3C vendor-neutrality claim in a way a central registry never will be.

### 7.2 Three separable layers

Conventionally conflated; separating them is the design:

| Layer | Question | Trust required |
|---|---|---|
| **Resolution** | DID → keys | **None** — self-certifying (§2.1) |
| **Discovery** | "who can book flights?" → candidate DIDs | **None** — every result independently verifiable |
| **Reachability** | where is it *right now* | None — signed, short TTL (§6.4) |

Once resolution is self-certifying, **discovery need not be trusted** — which is precisely what makes federation possible.

### 7.3 Signed Agent Records

The unit of discovery is a self-signed record, not a registry row:

```
SAR {
  did,                    // content-addressed; commits to the signing key
  capabilities[],         // capability IDs from the taxonomy
  transports[],           // ladder candidates, incl. "via parent DID" (§7.8)
  settlementRails[],      // §8.1
  terms { pricing, sla },
  issuedAt, ttl,
  signature               // by the agent's own key
}
```

Because the DID commits to the key, **any party can verify a SAR offline**, with no network call and no trusted third party.

Agents publish their SAR to any number of indexes — competing, replaceable, untrusted caches. Clients query, verify every result locally, and apply their own trust policy.

**Security property, stated precisely: an index can omit, but cannot forge.** The same guarantee as Certificate Transparency. Omission is mitigated by querying several indexes — which is why federation is the point rather than a nicety.

### 7.4 Interop surfaces

Free, internet-native publication paths:

- `/.well-known/aroha-agent.json` for domain-having agents — also gives **A2A interop**
- DNS TXT for `did:aroha-web`
- mDNS for LAN (§6.2)
- The Aroha registry as **one index among many**, not *the* index

### 7.5 Human-readable addressing

DIDs are unforgeable but unreadable. Subdomains give browser-friendly HTTPS URLs and interop with non-Aroha clients (curl, webhooks, A2A). Target shape:

```
agentname.firmname.aroha-labs.app
```

### 7.6 The binding constraint is TLS

**X.509 wildcards match exactly one label** (CA/Browser Forum policy, not a Cloudflare limit):

- `*.aroha-labs.app` validates `firmname.aroha-labs.app` ✅
- `*.aroha-labs.app` does **not** validate `agentname.firmname.aroha-labs.app` ❌

Serving that name requires a cert for `*.firmname.aroha-labs.app`; multi-level wildcards (`*.*.`) do not exist. Free Universal SSL covers apex plus one label — one level short of the target shape. DNS resolves fine; the **handshake** is what fails.

### 7.7 Resolution: provision per firm, route per agent

```
per firm  (provisioned once):
   *.firmname.aroha-labs.app  ──proxied──►  Worker
   + cert for *.firmname.aroha-labs.app

per agent (no infrastructure):
   research.acme.aroha-labs.app
        └─► Worker reads Host → firm + agent → DID → Durable Object (§6.3)
```

Adding a **firm** is one DNS write plus one cert. Adding an **agent** is a database insert. Firms are bounded and revenue-generating; agents are unbounded and ephemeral — the cost model lands on the right side of that line.

This reuses the existing flow closely: `upsertProxiedCname`, `verifyProvisionSignature`, the license check, rate limiting, and the audit log in `provision.ts` were written for *per-firm* provisioning. Change the zone, add cert issuance; the auth model transfers unchanged.

**The naming hierarchy mirrors the identity hierarchy:**

```
acme.aroha-labs.app            ↔  did:aroha:org:acme     (generateOrgIdentity)
research.acme.aroha-labs.app   ↔  did:aroha:<pubkey>     (agent, delegated via
                                    AgentDelegationCredential)
```

**Normative rule: the subdomain is an alias, never an identity.** `research.acme.aroha-labs.app` *resolves to* a DID; it is not the DID. If a hostname became identity, whoever controls the domain would control every firm's identity — recentralizing exactly the property §2.1 provides, and inverting `did:aroha-web`, which is meant to anchor to the *agent owner's* domain.

**Implementation rule: the Worker routes on (firm, agent) independent of URL encoding.** Then the URL shape is configuration, and the fallbacks in §7.9 can ship first without touching routing, identity, or the relay.

### 7.8 Agents behind agents

Sub-agents are addressed **by DID and routed through their parent** — no DNS record, no certificate, no public exposure. Benefits: no DNS sprawl, no per-child TLS cost, smaller public attack surface, private-by-default children via the existing `/v1/grants` model.

This is already modelled: `attenuateTaskMandate` grants bounded authority downward, and `verifyMandateChain` lets a caller verify the entire path. A child's SAR declares its transport as *"via parent DID X"* (§7.3) — verifiable, and requiring no infrastructure. Nesting depth becomes a policy limit rather than an infrastructure problem.

**Confused-deputy hazard.** When A fronts B and A also holds its own authority, a caller may induce A to act with *A's* authority instead of the caller's delegated authority. The chain must make **"acting as the caller"** versus **"acting for itself"** explicit and verifiable at B. Absent that distinction, fronting silently becomes privilege escalation. See §9.5.

### 7.9 Must verify before committing

The last attempt broke on exactly this class of assumption — `provision.ts` records that the Business/Enterprise requirement was "verified directly against the API, not assumed." Same discipline:

1. **Advanced Certificate Manager** — can it issue `*.firmname.aroha-labs.app`, and how many certs are included?
2. **Cloudflare for SaaS / Custom Hostnames** — purpose-built for this; confirm whether *wildcard* custom hostnames require Enterprise. That detail decides the cost model.
3. Proxied-wildcard behaviour at that depth.

Confidence in the X.509 single-label rule is high. Confidence in current Cloudflare plan gating is **not** — verify against the API before designing around it.

**Fallbacks that work on free Universal SSL today:**

- **Flattened** — `research--acme.aroha-labs.app`. One label, free cert, firm namespace still visible. Zero per-firm provisioning.
- **Path-based** — `acme.aroha-labs.app/research`. Firm gets a real subdomain under the free wildcard; agents are paths. Agents aren't distinct origins — which *helps* browser isolation but prevents per-agent CORS/cookies.

### 7.10 Personal agents: key-derived names

Most runtime users have no firm. They still need a callable name, and it must not require an allocator.

**Do not randomize — derive from the key.** A random label needs allocation state, collision handling, expiry rules, and a name→DID lookup that clients must *trust* — quietly recentralizing the property §2.1 provides for free.

Since the DID already commits to the public key:

```
label = wordlist(argon2id(publicKey))
      → otter-brass-canyon-vivid-ledger-amber.aroha-labs.app
```

The name is now **self-verifying**: any client derives from the key in the DID and confirms the hostname matches. No registry, no trusted mapping, no allocation table. The same principle as onion addresses and IPFS CIDs. The choice of a wordlist alphabet and a memory-hard KDF — rather than the obvious `base32(sha256(pk))` — is load-bearing anti-abuse, explained in "Vanity grinding" below.

Consequences, all of which fall out for free:

- **Squatting is impossible** — a label cannot be claimed without a key that produces it.
- **No allocation state** — minting is a pure function; it scales infinitely at zero marginal cost.
- **One label deep** — covered by the free `*.aroha-labs.app` Universal SSL wildcard. Individuals cost nothing; only firms (§7.7) need the paid cert path, which puts the cost where the revenue is.

**Namespace disambiguation.** Personal and firm labels share the first level, so the *format* must decide between them:

| Kind | Form | Routing rule |
|---|---|---|
| Personal | Exactly 6 hyphen-separated tokens, all from the wordlist (~66 bits) | Parses as derived → verify against the DID's key, then route |
| Firm | Allocated human-readable name, **barred from matching the derived format** | Otherwise → look up allocated firm |

Anything that is neither is rejected. Collision management never arises — at 66 bits, birthday collisions appear around 8 billion agents.

**Mint lazily.** Outbound calls need no name (§6.2 rung 1 is the caller's problem, not the callee's). Mint only when an agent is first made *callable* — otherwise the namespace materializes DNS-visible names for millions of agents that will never receive a request.

**Firm migration.** An individual at `otter-brass-canyon-vivid-ledger-amber.aroha-labs.app` who later joins or founds a firm becomes `research.acme.aroha-labs.app`. **The DID does not change** — only the alias. Mandates, delegation chains, grants, and reputation all survive, because none of them ever referenced a hostname. This is the concrete payoff of the alias-never-identity rule in §7.7; had the hostname been identity, migration would break every relationship the agent had.

#### Vanity grinding

An attacker can brute-force keypairs until the derived label contains a chosen substring, exactly as vanity `.onion` and Bitcoin addresses are produced.

Two facts make the naive mitigations useless:

- **Label length does not help.** Grinding cost is exponential in the length of the *prefix being mined*, not the total label. In base32 (`A–Z2–7`), `paypal` is 6 characters → 32⁶ ≈ 1.07 billion candidates, which a GPU exhausts in seconds. A 16-character label is no harder to attack than a 12-character one.
- **"Never truncate in UI" is unenforceable.** Mobile Safari and Chrome elide long hostnames in the URL bar and we have no say. Notification titles, OS share sheets, chat previews, CLI columns, and log formatters all truncate too. A control requiring every surface to behave cannot hold.

So the design goal is not to forbid truncation but to **make truncation harmless**. Three layers:

**Layer 1 — Wordlist encoding (structural).** Encode the derived hash as tokens from a curated wordlist rather than base32. The decisive property: **`paypal` is not in the wordlist and therefore cannot be produced at any cost.** Grinding stops being expensive and becomes impossible for the strings that matter. Truncation is then safe by construction — `otter-brass-can…` still reads as nonsense, not as a brand. A plain-ASCII wordlist also eliminates Unicode homograph attacks for free.

*Known residual weakness:* an attacker may still grind tokens that **concatenate** into a brand-like string — if `pay` and `pal` are both present, `pay-pal-…` is minable. The wordlist must therefore be curated against brand-forming fragments and visually confusable pairs. This narrows the attack substantially but does not close it, which is why Layer 3 exists.

**Layer 2 — Memory-hard derivation (economic).** Derive through Argon2id rather than raw SHA-256. The asymmetry is the point: **a legitimate user derives once, ever**, so ~100 ms is invisible, while an attacker attempting 2³⁰ candidate keys pays roughly 3.4 CPU-years instead of seconds. This is the password-hashing argument applied to name derivation. It does not by itself prevent brand-grinding, so it functions as belt-and-braces behind Layer 1 — but it is nearly free and raises the floor on every grinding attack, including Layer 1's concatenation gap.

**Layer 3 — Trust never derives from the name (systemic).** Anti-phishing that depends on users reading strings correctly has never worked — not for TLD homographs, not for punycode, not for lookalike domains. Trust must bind to a verifiable claim and the UI must display *that*, per §9.6. With Layer 3 in place, even a perfectly ground `pay-pal-…` label buys the attacker nothing, because the surface a user reads for trust is not the surface being ground.

With all three, "never truncate" downgrades from a load-bearing control to a nice-to-have.

---

## 8. Protocol gaps for completing a transaction

Covered today: discovery, identity, replay protection, mandate issuance and attenuation, negotiate/counter-offer/accept with price and SLA and schema, reserve/commit/cancel with LIFO compensation and DLQ and saga recovery, escrow bound to the saga, signed task receipts, capability risk tiers, intent-gate confirmation, reputation signals.

Five gaps remain.

### 8.1 Settlement rail negotiation — hard blocker

`ArohaNegotiateBody.proposedTerms` carries `price: { amount, currency }`. **Currency is not a rail.** One agent holds USDC on Base; the counterparty settles via Stripe. They can agree on price, sign mandates, and reserve — and still be unable to pay each other.

Adapters exist (`stripe`, `wallet`, `ap2`, `quota`, `api-key`); nothing advertises which an agent accepts, and nothing converges on one.

**Needed:** accepted rails in the capability manifest and SAR (§7.3); a `settlement` field in `proposedTerms` (rail + asset + destination); a defined failure when the sets don't intersect. Smallest change here, and nothing completes without it.

### 8.2 Verifiable outcome and a challenge window — trust blocker

```ts
export interface ArohaCommitAckBody {
  reservationToken: string;
  result: Record<string, unknown>;
}
```

An unstructured blob, self-asserted by the provider — and it drives saga success, which drives `escrow.release()`. **The party receiving the money controls the signal that releases it,** with no evidence structure and no window to object. Task receipts prove an agent *claims* it acted; nothing proves the booking exists.

**Needed:** a structured evidence field (confirmation identifiers, provider-signed artifacts, third-party attestation where available), plus a **challenge window** between CommitAck and release. Even a buyer-ack-or-timeout gate turns escrow from theater into a guarantee.

### 8.3 Dispute and arbitration — absent

`"disputed"` exists only as an invoice status string. No dispute message type, no arbiter role, no resolution outcome, no path binding a resolution back to escrow. Escrow can `release()` or `refund()` but nothing says **who decides when parties disagree** — the exact case escrow exists for.

**Needed:** `ArohaDispute` / `ArohaDisputeResolution`, an arbiter DID agreed at negotiation time, and an escrow path honoring a signed resolution. The arbiter can start as "a third party both sides accepted."

### 8.4 Durable delivery for offline agents

Saga recovery handles *orchestrator* crashes, not: agent reserves, provider confirms six hours later, laptop is closed. No mailbox, no store-and-forward, no resumable correlation.

Every realistic latency-bearing task — bookings, approvals, human-in-the-loop — hits this.

**Needed:** durable inbox semantics, at-least-once delivery, correlation-based resumption. This is the protocol requirement the §6.3 broker satisfies, arguing for designing them together.

### 8.5 Legal-entity binding

`generateOrgIdentity()` mints a keypair and names itself `did:aroha:org:<name>` — **self-asserted**; nothing prevents minting `did:aroha:org:Stripe`. `did:aroha-web` solves this for domain owners; org DIDs have no equivalent, and monetary disputes eventually need a legal entity.

**Needed:** require org DIDs to chain to a `did:aroha-web` proof (cheaper, reuses existing machinery), or add a verified-issuer credential. Note this interacts with §7.7 — a firm's subdomain must not be mistaken for entity verification.

---

## 9. Security and threat model

Three properties change the posture: execution moves to **untrusted user devices**, TLS stops being the transport authenticator, and agents hold **both tools and money**. Ranked by blast radius.

### 9.1 Prompt injection against an agent holding authority — Tier 1

The defining risk, and **mandates do not defend against it.**

```ts
allowed: string[];                      // capability IDs
taskConstraints: TaskConstraints;
spendingConstraints?: SpendingConstraints;
```

These are **class-level**: which *kinds* of action, how much in *total*. Nothing binds *this specific transaction*. "book-flights ≤ $500" is fully satisfied by booking the attacker's flight for $500. Attenuation prevents **escalation**, not **misuse within grant**. The mandate isn't broken — it answers a different question.

The local runtime amplifies this by inviting connections to arbitrary published agents, piping untrusted text into a loop holding real credentials and real money.

Three layers, independently useful:

**Layer 1 — Instance-bound invariants (cryptographic).** Extend mandates from class constraints to instance invariants, bound at intent time:

```
invariants: {
  payee:      ["did:aroha:<verified-airline>", ...],
  parameters: { destination: "JFK", passenger: <hash> },
  maxAmount:  { amount: 500, currency: "USD" },
  expiry:     "..."
}
```

Signed by the principal **before untrusted content enters the loop**, verified at commit. Injection may steer the conversation but cannot alter the bound outcome — a redirected payee or mutated parameter fails verification. Invariants narrow monotonically through attenuation, so `assertNarrowing` extends to cover them rather than needing new machinery.

`intent-gate` already paraphrases and confirms before funds lock. **Make that confirmation emit a signed plan** — the ceremony exists; it just produces no binding artifact.

**Layer 2 — Dual-context agent loop (structural).** Split execution into two contexts that never merge:

- **Planner** — sees user intent and the mandate, holds tools and authority, **never sees untrusted content directly**.
- **Worker** — processes remote responses and tool output, **no tool access, no mandate**, returns *structured data*, never instructions.

The planner operates on symbolic references ("the flight number the worker extracted"), not raw text. This is the CaMeL / dual-LLM pattern — the only defense that holds when the model itself is fallible, because it removes the model's *ability* to be the vulnerability rather than asking it to resist. **This must land with the agent loop (M2); retrofitting the boundary later is impractical.**

**Layer 3 — Provenance and risk gates (policy).** Taint every value with origin. Enforce: any parameter to a capability with `hasFinancialImplication` or tier ≥ 3 that derives from untrusted content requires explicit human confirmation. The taxonomy supplies the metadata; `mcp-guard`'s `GuardEngine` is the natural enforcement point.

**Why all three:** Layer 1 stops the attack succeeding, Layer 2 stops it starting, Layer 3 catches the remainder at the cost of a prompt. Any one alone leaves a real hole.

### 9.2 Key resolution — an implementation flaw, not a protocol flaw

`registryKeyResolver` fetches `publicKeyB64` over HTTPS, caches in memory, and trusts it unconditionally — no pinning, no continuity check, no signature beyond TLS. As written, whoever controls the registry controls every identity: serving an attacker's key means E2E encryption silently encrypts *to the attacker* and forged signatures verify.

But per §2.1 the DID **already contains the key**. The resolver is fetching over the network something it can compute locally.

**Fix, in priority order:**

1. For content-addressed DIDs, **derive the key from the DID**; never fetch. If a record is fetched for other reasons, **verify it matches** and hard-fail on mismatch.
2. For namespaced/`did:aroha-web` DIDs where resolution is genuinely required: **key continuity (TOFU)** — pin on first contact, hard-fail and alert on change — plus a **transparency log** making key changes publicly auditable.
3. Add a **TTL**; the current cache has none, so legitimate key rotation never propagates within a process.

Fix (1) converts the registry from a root of trust into a cache and is a small, contained change.

### 9.3 The localhost gateway — Tier 1

Any webpage the user visits can request `127.0.0.1:7777`; Ollama shipped CVEs of this shape. The commonly-missed variant is **DNS rebinding** — the attacker re-resolves their own domain to `127.0.0.1`, after which the browser treats requests as same-origin. A bearer token alone does not prevent this.

**Required, all:**

1. Loopback-only bind by default; wider exposure needs an explicit flag and a printed warning.
2. Per-install bearer token, first-run generated, `0600`, required on every route.
3. **Strict `Origin` validation** plus a **`Host` header allowlist** — this is what actually stops rebinding and cross-site POSTs.
4. No wildcard CORS; explicit allowlist.
5. `Sec-Fetch-Site` enforcement as defense in depth.

Blast radius otherwise is total: tool execution, chat history, key access.

### 9.4 Tier 2

**Keys at rest without hardware backing.** A `0600` file means malware running as the user achieves full agent impersonation — and because keys authorize spending, **keys are money**. OS keychain helps; passphrase-wrapped or TPM/Secure-Enclave-backed keys are the answer for any agent holding a spending mandate.

**Supply chain — MCP servers and published agents.** MCP install is arbitrary code execution. `mcp-guard` already provides tool-call policy, so **enforce by default**. Published agents need signed manifests, visible publisher identity, and typosquatting protection.

**Self-attested completion releasing escrow.** See §8.2.

### 9.5 Confused deputy in nested agents

Per §7.8: when A fronts B and holds its own authority, a caller may induce A to act with A's authority rather than the caller's delegated authority.

**Mitigation:** every forwarded call carries an explicit **"acting as"** assertion naming the principal, verified at B against the mandate chain. B must reject a call whose claimed principal isn't provable from the chain. Fronting without this is silent privilege escalation.

### 9.6 Namespace operation

Running `*.aroha-labs.app` makes Aroha Labs a registrar, with a registrar's obligations: **squatting and impersonation** (`stripe.aroha-labs.app`, `openai.aroha-labs.app`), abuse, and takedown. Needed: reserved names, verification for brand-adjacent claims, and a dispute path. The signed-provisioning + license-check model in `provision.ts` is a sound starting point — it was built for this kind of gatekeeping.

**This burden applies to firm names only.** Per §7.10, personal names are key-derived and therefore **structurally squat-proof** — the holder does not choose the string, so free self-serve minting cannot be turned into `paypal-login.aroha-labs.app`. Residual risk is vanity grinding, addressed by the three layers in §7.10. Registrar effort concentrates on the firm tier, already gated by signed provisioning and a license check.

**Identity display rule (required — this is §7.10 Layer 3).** No UI surface may present a hostname or label as evidence of identity. Specifically:

1. Trust indicators derive **only** from a verifiable claim — a `did:aroha-web` DNS+HTTPS proof, or a verified-issuer credential per §8.5 — never from the name.
2. Unverified agents are labelled **explicitly unverified**. Absence of a badge is not a signal; users reliably miss it.
3. The label is rendered as an *address*, visually distinct from the *identity*, so the two are not read interchangeably.

Rule 2 is the one most often dropped in implementation, and dropping it silently reinstates the entire attack.

### 9.7 Tier 3

- **Metadata to the relay.** E2E encryption hides content, not the social graph. Mitigate with padding, batching, and making direct/LAN transports the default.
- **LAN discovery.** mDNS announces presence to the whole network and is trivially spoofed. **Discovery must never imply trust** — require explicit pairing before invocation.
- **P2P deanonymization.** Hole punching reveals the user's IP. Surface it; offer relay-only mode.
- **Local data at rest.** `~/.aroha/aroha.db` holds plaintext chat history — the richest single target on the machine. Consider encryption keyed from the OS keychain.
- **Sybil reputation.** Cheap DIDs plus self-issued satisfaction signals allow fabricated reputation. Weight by verified identity and settled-transaction history.
- **Installer/update supply chain.** `curl | sh` and any auto-update must verify signatures before execution or binary replacement.

### 9.8 Security testing

Regression tests present from M0: cross-origin POST rejected; forged `Host` rejected; missing/invalid token rejected; non-loopback bind refused without flag; unencrypted body rejected on non-TLS transport; unexpected key change halts the session; SAR with an invalid signature discarded; forwarded call with an unprovable "acting as" rejected; derived-name hostname not matching the DID's key rejected; firm name matching the reserved derived-label format refused at allocation.

---

## 10. First-run data flow

```
aroha up
  ├─ ensure ~/.aroha, generate gateway token
  ├─ engine manager: detect → none found
  │    └─ prompt: "Install Ollama (~600MB) and pull llama3.1:8b (~4.7GB)?"
  ├─ no agents exist → create default "assistant"
  │    └─ mintLocalIdentity() → DID + keypair → ~/.aroha/keys
  ├─ agent host: serve() behind the gateway
  ├─ gateway: listen 127.0.0.1:7777
  └─ open browser to http://127.0.0.1:7777/?token=…

User chats immediately. No account. No network beyond the model pull.
```

---

## 11. Open questions

- **Bun compile maturity** — M0 spike must confirm `bun:sqlite`, embedded assets, subprocess supervision, and `@noble/curves` in a compiled binary across all five targets.
- **Binary size** — 60–90MB is acceptable but should be measured early.
- **Cloudflare cert path** — §7.9. Blocks the target URL shape, not the architecture.
- **Moderation** — public publishing invites abuse; the 48h new-agent hiding helps, but a reporting/takedown path is needed before public publish opens broadly. Note E2E encryption means a relay operator *cannot* inspect traffic — deliberate, but it constrains what moderation can mean.
- **Index ecosystem** (§7.3) — who runs SAR indexes besides Aroha Labs, and what makes the federation real rather than nominal.
- **Arbiter ecosystem** (§8.3) — who arbitrates, and what makes a resolution binding.
- **Update channel** — package managers only is cheaper and avoids self-updating-binary risk.
- **Telemetry** — reuse `aroha-cli`'s existing opt-in prompt and posture.

---

## 12. Milestones

Each ends at something demonstrable. Sizes are relative, not calendar commitments.

| # | Milestone | Outcome | Size |
|---|---|---|---|
| **M0** | **Foundations & spike** | Bun-compiled binary on 5 targets; `bun:sqlite`, embedded assets, subprocess spawn, Ed25519/X25519 verified in-binary. Workspace, config, gateway skeleton **with §9.3 controls and §9.8 tests**. Signing certificates ordered. | M |
| **M1** | Engine manager | Detect/install/supervise Ollama; hardware probe; model pull; uniform completion interface; hosted fallback. | L |
| **M2** | Agent host + chat UI | Declarative agents; embedded streaming UI with HITL approvals; agent CRUD. **Includes §9.1 Layer 2 dual-context loop.** End of M2 = full local loop, offline. | L |
| **M3** | MCP manager | Browse/install/attach; supervised stdio; `mcp-guard` by default; install consent. **Includes §9.1 Layer 3 provenance tainting.** | M |
| **M4** | Outbound connectivity | Consume remote agents; Hub browsing; grants UI. **Includes §9.2 self-certifying key resolution fix.** Zero new infrastructure. | M |
| **M5** | Federated discovery | SAR schema, signing, verification, publication to multiple indexes; `/.well-known` + DNS TXT interop. | M |
| **M6** | Publish & claim | Device-code auth; DID→account binding; manifest → IPFS → `/v1/agents`; definition vs endpoint publish. | L |
| **M7** | Naming & subdomain routing | Wildcard Worker routing on (firm, agent); **key-derived personal names (§7.10) with lazy minting** — free-tier TLS, no allocator; per-firm provisioning reusing `provision.ts`; alias→DID mapping; §9.6 controls. Ships flattened if §7.9 unresolved. | M |
| **M8** | Transaction protocol additions | §8.1 settlement rails, §8.2 verifiable outcome + challenge window, §8.3 dispute types. **Includes §9.1 Layer 1 instance-bound invariants.** | L |
| **M9** | Device-to-device transport | §6 Layer 0 amendment, mandatory off-TLS encryption, candidate/presence records, resolver change, **LAN/mDNS first**, then ICE/STUN P2P. | L |
| **M10** | Relay broker | Durable Object rendezvous with Hibernation; durable inbox (§8.4); abuse controls; §7.8 sub-agent routing. | L |
| **M11** | Distribution | Installers, Homebrew tap, Scoop/winget, notarization, release automation, docs. | M |

**Critical path:** M0 → M1 → M2 delivers the entire local experience and is where the product becomes real. **M4 makes it a network participant with no infrastructure at all.** M5 makes discovery federated. M9/M10 make devices mutually reachable.

**Security is not a milestone.** §9.3 lands in M0; §9.1 Layer 2 in M2; Layer 3 in M3; §9.2 in M4; Layer 1 in M8; §9.5 in M10.

---

## 13. Testing strategy

- **Unit** — engine detection matrix, config parsing, DID/key handling, manifest construction, SAR signing/verification, candidate ordering, Host→(firm, agent) routing, key-derived label generation and verification, personal-vs-firm format disambiguation.
- **Integration** — supervisor lifecycle, gateway API against real SQLite, MCP subprocess supervision, transport fallback across all four rungs.
- **Security** — §9.8, from M0.
- **Injection** — a corpus of adversarial agent responses asserting the planner never ingests untrusted text, and that bound invariants reject redirected payees and mutated parameters.
- **End-to-end** — scripted first run per target in CI: install → up → create agent → chat → shutdown, stubbed engine to keep CI offline.
- **Two-device** — automated pair exercising LAN, P2P, and relay rungs, asserting E2E encryption holds and the relay never sees plaintext.
- **Cross-platform** — matrix build and smoke-run per target on every release.

---

## 14. Package layout

```
apps/aroha-runtime/           the binary: supervisor, gateway, CLI entry
  src/engine/                 detection, install, supervision
  src/host/                   agent lifecycle; dual-context loop
  src/mcp/                    MCP install + supervision (guarded)
  src/transport/              candidate resolution, mDNS, ICE, relay client
  src/discovery/              SAR build/sign/verify, index clients
  src/sync/                   device auth, publish, consume
  src/gateway/                HTTP/WS, auth, static serving
  src/store/                  bun:sqlite schema + migrations
apps/aroha-runtime-ui/        UI bundle, embedded into the binary
apps/aroha-relay/             Durable Object rendezvous broker (M10)
apps/aroha-edge/              wildcard Worker: Host → (firm, agent) → DID (M7)
```

Reused unchanged: `@aroha-sdk/core`, `/run`, `/registry`, `/mcp-bridge`, `/mcp-guard`, `/credentials`, `/delegation`, `/settlement`, `/orchestrator`, `/commerce`.

Protocol additions modify `@aroha-sdk/core` (message types, SAR, invariants), `/settlement` (escrow state machine), `/credentials` (invariant narrowing), `/orchestrator` (negotiation).

`scripts/build-ordered.mjs` must gain the new packages in the correct layer — it is hand-maintained and alphabetical builds break on it.

---

## 15. Summary of what to build

1. A Bun-compiled single binary for 5 targets, signed, with installers.
2. An engine manager that detects, installs, and supervises Ollama/vLLM, with hosted fallback.
3. An agent host over `serve()`, with declarative agents, local DIDs, and a **dual-context execution loop**.
4. A gateway serving an embedded UI, hardened against localhost and DNS-rebinding attacks from day one.
5. An MCP manager with consent-gated install and `mcp-guard` on by default.
6. Outbound consumption of remote agents — no new infrastructure.
7. **Federated discovery via Signed Agent Records**, verifiable offline, with untrusted indexes.
8. Publish with both definition and endpoint modes.
9. **Subdomain addressing** — wildcard Worker routing, per-firm provisioning for firms, **key-derived self-verifying names for individuals**, alias-never-identity throughout.
10. Transaction protocol additions: settlement rails, verifiable outcome with challenge window, dispute types, and **instance-bound mandate invariants**.
11. Device-to-device transport: Layer 0 amendment, mandatory off-TLS encryption, presence records, LAN → P2P ladder.
12. A Durable Object relay with a durable inbox for offline delivery and sub-agent routing.
13. **Self-certifying key resolution** — the smallest change with the largest security return.
