<!-- Copyright (c) 2026 Aroha Labs
     SPDX-License-Identifier: Apache-2.0 -->

# Aroha Independent Implementer Onboarding Packet

**Owner:** Conformance Agent  
**Version:** 1.0 — 2026-05-28  
**For:** External teams building independent Aroha 1.0 implementations

This packet gives you everything needed to build and validate an independent Aroha 1.0 implementation. An independent implementation is one **not based on the reference codebase** in this repository.

---

## Why Independent Implementations Matter

W3C Working Group consideration requires two independent interoperable implementations. Your implementation — even partial — moves Aroha toward a recognised open standard.

---

## What You Need to Implement

The minimum viable Aroha 1.0 implementation covers Layers 0–3:

| Layer | What to build |
|-------|---------------|
| L0 | DID generation, resolution, key rotation |
| L1 | Signed envelope creation and verification |
| L2 | Capability manifest publication and registry query |
| L3 | Saga coordinator or participant (you can choose one role) |
| L4 | Optional — commerce/payment layer |

See [test-matrix.md](test-matrix.md) for the exact requirements at each layer.

---

## Specifications

| Document | Purpose |
|----------|---------|
| [Protocol spec (Aroha 1.0)](../spec/aroha-1.0.md) | Full protocol definition |
| [DID method spec](../spec/did-method.md) | `did:aroha:` DID method |
| [Message spec](../spec/messages.md) | Envelope schema and signing rules |
| [Conformance test matrix](test-matrix.md) | Pass/fail rubric |

---

## Validation Steps

### Step 1 — Implement

Use the specifications above. Do not copy reference implementation code.

### Step 2 — Self-test

Run the conformance checklist in [test-matrix.md](test-matrix.md) against your implementation. For each MUST row, document your test result.

### Step 3 — Interoperability test

Test against the reference implementation:

```bash
# Clone the reference implementation
git clone https://github.com/ArohaLabs/aroha-protocol.git
cd aroha-protocol
npm install && npm run build

# Terminal 1: the reference provider agent (agents/mock-provider-agent).
# It serves http://localhost:3001/aroha/v1 and its DID document at
# http://localhost:3001/.well-known/aroha-agent.json
NODE_ENV=development npm run dev:mock-provider

# Terminal 2: the reference registry (apps/registry-server), locally on port 8787.
# A local signing key goes in apps/registry-server/.dev.vars (gitignored).
cd apps/registry-server
echo "REGISTRY_SIGNING_KEY=$(openssl rand -hex 32)" > .dev.vars
npm run db:migrate
npx wrangler dev --port 8787

# Point your implementation at http://localhost:8787. It should:
#   1. Register a capability (L2)
#   2. Discover the reference agent (L2)
#   3. Exchange signed envelopes (L1)
#   4. Optional: execute a saga as coordinator or participant (saga extension, spec/extensions.md)
```

### Step 4 — Submit your results

Open an issue in this repository using the **Conformance Report** issue template. Include:

- Implementation name and language
- Which layers you tested (L0–L4)
- Your self-test results table (pass/fail per test ID)
- Interoperability test result (success / failure + log)
- Any deviations from SHOULD requirements and rationale

Use the **Conformance Report** issue template at [.github/ISSUE_TEMPLATE/conformance-report.yml](../../.github/ISSUE_TEMPLATE/conformance-report.yml).

---

## Support

- GitHub Issues with the `conformance` label, in `ArohaLabs/aroha-protocol`
- Email the maintainer (hello@aroha-labs.com, see MAINTAINERS.md)
- Maintainer response SLA: 5 business days (see [governance.md](../governance.md))

---

## Recognition

Independent implementers who achieve **Core conformance** or better will be:

- Listed on the Aroha ecosystem page as a verified implementation
- Credited in any future standards-body submission (none has been made yet)
- Eligible for the Ecosystem Verified tier badge

---

*Questions? Open a Discussion in this repository.*
