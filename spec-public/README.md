<!-- Copyright (c) 2026 Aroha Labs
     SPDX-License-Identifier: Apache-2.0 -->

# Aroha Protocol Specification

**Cryptographically bounded authority for AI agents.**

This repository contains the open specification for the Aroha Protocol — signed, verifiable,
delegable authority for agent systems. Mandates carry spending limits, task constraints, human
gates, and expiry; downstream agents can only narrow authority, never widen it; every action
traces back to a human issuer.

The spec is Apache-2.0-licensed and implementation-independent. Anyone may implement it, in any
language, without permission or coordination.

## Documents

| Document | What it covers |
|----------|----------------|
| [spec/aroha-1.0.md](spec/aroha-1.0.md) | Core protocol: five-layer architecture, envelopes, mandate chains, saga pattern, settlement, reputation |
| [spec/messages.md](spec/messages.md) | Wire format: ArohaRequest / ArohaResponse envelope schemas, signing, replay protection |
| [spec/did-method.md](spec/did-method.md) | The `did:aroha` method: identifier format, key binding, rotation |
| [spec/web-did.md](spec/web-did.md) | Web-based DID resolution for domain-bound agent identity |
| [spec/security.md](spec/security.md) | Threat model, security considerations, implementer checklist |
| [spec/csn.md](spec/csn.md) | Capability semantics and naming |
| [conformance/tiers.md](conformance/tiers.md) | Conformance tiers — what "Aroha-compatible" means, precisely |
| [conformance/test-matrix.md](conformance/test-matrix.md) | The behaviours a conformant implementation must exhibit |
| [conformance/guarantee-evidence.md](conformance/guarantee-evidence.md) | Every guarantee mapped to its enforcing function and the published test that proves it |
| [conformance/implementer-packet.md](conformance/implementer-packet.md) | Start here if you are writing a new implementation |
| [schemas/](schemas/) | JSON Schemas (2020-12) for the Conversation and Memory Profile: room, consent record, signed turn, action receipt v2, memory record, disclosure |
| [vectors/conversation-v1.json](vectors/conversation-v1.json) | Conformance vectors for the profile (RFC 8032 test keys): room, consent, turn, receipts v1/v2, disclosure-bearing envelope, task mandate v2 with `onBehalfOf` |

## How Aroha relates to the rest of the agent stack

Aroha is a complement, not a competitor, to the protocols agents already use:

- **MCP** connects agents to tools. Aroha bounds what those tools are allowed to do.
- **A2A** carries agent-to-agent messages. Aroha envelopes ride the same transports.
- **AP2** authorizes agent payments. Aroha task mandates cover the delegation that
  *isn't* a payment — research, scheduling, sending, deploying — plus the chain of
  authority above the payment itself.

## Implementations

| Implementation | Language | Source |
|----------------|----------|--------|
| `@aroha-sdk/*` (reference) | TypeScript | Published on [npm](https://www.npmjs.com/package/@aroha-sdk/core) with full source in the tarballs (`src/` included) |
| `aroha` | Python | Published on [PyPI](https://pypi.org/project/aroha/) |
| Go and Java SDKs | Go, Java | Coming soon — see the roadmap at [aroha-labs.com/sdks](https://www.aroha-labs.com/sdks) |

Independent implementations are welcome — the conformance suite defines compatibility,
not any particular codebase.

## Changes and governance

The spec follows semantic versioning; `aroha-1.0` is frozen except for errata.
Proposals for 1.x extensions are made by opening an issue in this repository with the
`rfc` label. Substantive changes require a published rationale and a compatibility
statement against the [conformance test matrix](conformance/test-matrix.md).

Trademark policy and long-term governance: [aroha-labs.com/docs/governance](https://www.aroha-labs.com/docs/governance).

## License

The specification is released under the [Apache License 2.0](LICENSE) (relicensed from MIT on
2026-10-19; see [NOTICE](NOTICE)). You may implement, copy, fork, and redistribute it freely.
