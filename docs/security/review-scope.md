<!-- Copyright (c) 2026 Aroha Labs
     SPDX-License-Identifier: Apache-2.0 -->

# Security Review Scope

**Owner:** Security Agent  
**Version:** 1.0 — 2026-05-28  
**Status:** Draft — auditor not yet selected  
**Target start:** not scheduled  
**Verification:** This document is complete when an auditor is selected and a statement of work is signed.

---

## Objective

Execute an independent security review of the Aroha 1.0 reference implementation to:
1. Surface unknown vulnerabilities before ecosystem growth increases attack surface.
2. Produce a public audit status bulletin for the trust page.
3. Build a remediation backlog with severity, owner, and SLA for every finding.

---

## Scope

### In Scope

| Component | Why |
|-----------|-----|
| `packages/aroha-core` | Core protocol: envelope signing, DID operations, saga state machine |
| `packages/aroha-credentials` | Verifiable credential issuance and verification |
| `packages/aroha-registry` | Agent registration and capability discovery |
| `aroha-extensions/packages/aroha-orchestrator` | Saga coordinator logic — most complex failure mode surface |
| `packages/aroha-policy` | Access control and policy enforcement |
| `aroha-extensions/packages/aroha-settlement` | Payment and escrow — financial risk surface |
| `packages/aroha-trusted-mesh` | Trust mesh composition |
| Cryptographic primitives | Ed25519 key generation, signing, verification; nonce/replay prevention |
| DID method implementation | Key rotation, DID document integrity |
| Transport security | TLS enforcement, header validation |
| Saga rollback correctness | Cancel idempotency, partial commit handling |

### Out of Scope (v1 audit)

- `packages/aroha-langchain-bridge`, `aroha-a2a-bridge`, `aroha-mcp-bridge` — bridge security deferred to v2 audit
- Demo scripts in `scripts/`
- Frontend apps in `apps/`
- Third-party ecosystem packages in `community/`

---

## Review Areas

### 1. Cryptographic Implementation

- Ed25519 key generation entropy
- Signature verification completeness (no short-circuit paths)
- Nonce uniqueness and replay window enforcement
- Key rotation: old key invalidation, version tracking

### 2. DID & Identity

- DID resolution: SSRF risks if resolving external DID documents
- DID document tampering detection
- Identity binding: can a malicious agent impersonate another's DID?

### 3. Saga Pattern

- Partial commit attack: can a participant commit without reserving?
- Cancel race condition: what happens if Cancel and Commit arrive simultaneously?
- Timeout manipulation: can a slow participant hold a lock indefinitely?
- Saga ID collision: entropy and uniqueness guarantees

### 4. Registry

- Capability spoofing: can an agent register capabilities it doesn't have?
- Registry poisoning: can a malicious agent deregister a legitimate one?
- Rate limiting and DoS surface
- Stale entry expiry correctness

### 5. Commerce / Settlement

- Double-spend prevention
- Refund correctness on rollback
- Payment receipt forgery
- Integer overflow / currency precision handling

### 6. Transport & API

- Injection via message payloads (DID, capability names, saga IDs)
- Overly permissive CORS or missing auth on internal endpoints
- Log injection

---

## Deliverables Expected from Auditor

| Deliverable | Format | Due |
|-------------|--------|-----|
| Audit kickoff scope confirmation | Email/signed SoW | Before start |
| Preliminary findings (mid-audit check-in) | Draft report | Week +2 |
| Final report | PDF + machine-readable findings (JSON or CSV) | Week +4 |
| Public audit status bulletin | Short summary for trust page | Week +4 |
| Remediation verification (if patch-and-retest in scope) | Addendum | Week +6 |

---

## Auditor Candidates

**ASSUMPTION:** No auditor has been contacted. The following are candidate categories — specific firms must be identified and contacted by Week 7.

| Type | Notes |
|------|-------|
| Specialised crypto/protocol firms | Preferred for L0–L1 cryptographic review |
| Smart contract audit firms with Rust/TS experience | Familiar with distributed systems, atomicity, and financial logic |
| Open source security firms | May offer reduced rate for open-source (Apache-2.0-licensed) projects |
| Academic security groups | Possible for W3C credibility, longer timeline |

---

## Remediation Backlog Template

Findings will be tracked here once the audit is complete:

| ID | Severity | Component | Description | Owner | SLA | Status |
|----|----------|-----------|-------------|-------|-----|--------|
| — | — | — | — | — | — | — |

**SLA by severity:**
- Critical: patch within 72 hours
- High: patch within 7 days
- Medium: patch within 30 days
- Low: patch within 90 days or next release

---

## Public Audit Status Bulletin (Template)

> **Aroha 1.0 Security Review — Status as of [DATE]**
>
> Auditor: [FIRM]  
> Scope: Core protocol, credentials, registry, orchestrator, settlement  
> Status: [In progress / Complete]  
> Critical findings: [N] open / [N] resolved  
> High findings: [N] open / [N] resolved  
> Full report: [Link or "Available on request"]

This bulletin will be published in [docs/trust.md](../trust.md).
