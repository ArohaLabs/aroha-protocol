<!-- Copyright (c) 2026 Aroha Labs
     SPDX-License-Identifier: Apache-2.0 -->

# Aroha Threat Model

**Owner:** Security Agent  
**Version:** 1.0 — 2026-05-28  
**Status:** Initial draft — not yet reviewed by auditor  
**Scope:** Aroha 1.0 reference implementation, Layers 0–4

---

## Assets to Protect

| Asset | Confidentiality | Integrity | Availability |
|-------|----------------|-----------|--------------|
| Agent private keys (Ed25519) | Critical | Critical | High |
| DID documents | Low | Critical | High |
| Saga state (in-progress transactions) | Medium | Critical | High |
| Payment/settlement records | High | Critical | High |
| Capability registry entries | Low | High | High |
| Agent-to-agent message payloads | Medium | Critical | Medium |

---

## Trust Boundaries

```
[ External Internet ]
        |
        | (TLS 1.3+, signed envelopes)
        v
[ Aroha Agent Endpoint ]
        |
        | (internal — same process or local network)
        v
[ Registry / Orchestrator / Settlement ]
        |
        | (key material — HSM or environment variable)
        v
[ Ed25519 Keypair ]
```

---

## Threat Actors

| Actor | Capability | Motivation |
|-------|------------|------------|
| Malicious external agent | Can send arbitrary signed/unsigned messages | Steal value, disrupt sagas, impersonate |
| Compromised participant agent | Valid keys, can sign messages | Abort sagas selectively, double-spend |
| Network attacker (MitM) | Can observe/modify unencrypted traffic | Replay attacks, eavesdrop |
| Malicious registry | Controls discovery results | Redirect agents to attacker-controlled endpoints |
| Compromised orchestrator | Controls saga coordination | Force partial commits, selectively cancel |

---

## Threat Scenarios

### T1 — Replay Attack
**Threat:** Attacker captures a valid signed envelope and replays it later.  
**Impact:** Duplicate saga steps, duplicate payments.  
**Controls:** Envelope `expires` freshness check (receiver rejects envelopes whose `expires` is in the past) + nonce uniqueness check, with nonces retained until `expires` (L1-03, L1-04).  
**Status:** Controlled — nonce validation implemented in `aroha-core`.

### T2 — Identity Impersonation
**Threat:** Agent sends messages claiming to be a different DID.  
**Impact:** Unauthorised capability access, payment fraud.  
**Controls:** All envelopes signed with sender's Ed25519 key; receiver verifies against DID document (L0-04, L1-02).  
**Status:** Controlled — signature verification mandatory.

### T3 — Partial Commit Exploit
**Threat:** Malicious participant sends `Commit` without prior `Reserve`, or ACKs `Reserve` but never processes it.  
**Impact:** Inconsistent saga state; one party delivers, counterparty does not.  
**Controls:** Coordinator enforces `Reserve → Commit` ordering; TTL on reserve locks (L3-01, L3-05).  
**Status:** Partially controlled — TTL enforcement needs audit verification.

### T4 — Registry Poisoning
**Threat:** Attacker registers a capability with a legitimate-looking name, hijacking discovery.  
**Impact:** Agents route requests to attacker-controlled endpoint.  
**Controls:** DID-based registration (attacker must control DID); capability quality tiers in ecosystem registry.  
**Status:** Partial — no cryptographic proof of capability authenticity in v1 spec.  
**ASSUMPTION:** This is a known v1 limitation. Mitigated by reputation/quality tier system in ecosystem layer.

### T5 — Key Compromise
**Threat:** Agent's Ed25519 private key is exfiltrated.  
**Impact:** Attacker can impersonate the agent indefinitely.  
**Controls:** Key rotation (L0-03); rotation invalidates old key for future messages.  
**Status:** Controlled for forward-looking messages; historical messages signed with old key cannot be retroactively invalidated (by design — audit logs remain valid).

### T6 — DID Document Tampering
**Threat:** Attacker modifies a DID document to replace the public key with their own.  
**Impact:** Attacker can sign messages that verify against the tampered document.  
**Controls:** DID documents are integrity-protected by the registry; InMemoryRegistry has no persistent attack surface; on-chain registry is immutable.  
**Status:** Controlled for on-chain deployments. InMemoryRegistry (dev/test use only) is not hardened.

### T7 — Saga Timeout DoS
**Threat:** Participant deliberately delays `Reserve` acknowledgement to hold coordinator locks.  
**Impact:** Other sagas queue behind blocked locks; throughput degradation.  
**Controls:** Coordinator-side timeout + cancellation on TTL expiry (L3-05).  
**Status:** Partially controlled — timeout values are configurable and must be tuned per deployment.

### T8 — Credential Exposure to the Model
**Risk:** a model (or content injected into its context) gets an agent's credentials and uses them outside the agent's controls.  
**Rule:** the model never has access to credentials. Credentials are held by the runtime and attached to outbound requests outside the model. This matches the requirement in IETF draft-ietf-wimse-aims that the language model must not have access to an agent's credentials.  
**Controls (Aroha runtime, checked against the source on 2026-10-15):**
- MCP server credentials (API keys, OAuth tokens) live in the OS keystore (`host/keystore.ts`, `host/mcp-credentials.ts`). The runtime reads them when it opens the connection. For a remote server they become an HTTP header on the transport (`mcp/client.ts` `authHeadersFor`); for a local (stdio) server they become environment variables of the server subprocess. Neither path puts them in a prompt, a tool schema or a tool argument.
- Model-provider API keys are in the same keystore (`host/credentials.ts`) and are used only by the engine's HTTP calls to the provider.
- Agent and person private keys sign envelopes, approvals and receipts inside the runtime process. No tool exposes them.
- Only `status()` leaves the credential store: connected, expiry and a four-character hint.
- The memory extractor refuses to store credential-shaped text, and log lines that quote external text are redacted (`host/secret-patterns.ts`).

**Residual risk:** a local MCP server process does receive its own credential (it is the tool, not the model). A tool whose result echoes a secret would put that secret into the model's context: there is no general secret filter on tool results. An operator who pastes a secret into a chat gives it to the model.  
**Status:** Partially controlled. See [Production Hardening §11](hardening.md#11-credential-vault-rule).  
**Verification:** in a test workspace, capture the requests sent to the model provider (for example through a logging proxy) and search them for each configured credential's value (expected: no match). Confirm `config.toml` contains no `registryApiKey` or `mcpOauthSecret` after a start.

---

## Out-of-Scope Threats (v1)

- Side-channel attacks on Ed25519 implementation (deferred to cryptographic audit)
- Physical access to agent host
- Supply chain attacks on npm dependencies
- Bridge security (MCP bridge, A2A bridge, LangChain bridge)

---

## Incident Response (Summary)

Full playbook: [docs/security/incident-response.md](incident-response.md).

**If you discover a vulnerability:**
1. Do NOT open a public GitHub issue.
2. Report it privately, as described in [SECURITY.md](../../SECURITY.md): email contact@aroha-labs.com with the subject "SECURITY", or use [GitHub private vulnerability reporting](https://github.com/ArohaLabs/aroha-protocol/security/advisories/new).
3. Expect acknowledgement within 48 hours and a severity assessment within 5 business days.

---

*This threat model is a living document. Update whenever the protocol or implementation changes.*
