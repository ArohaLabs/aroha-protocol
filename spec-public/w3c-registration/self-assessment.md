# did:aroha — Registration Self-Assessment

Submitted with the registration PR per the did-extensions registration
process. This document explains how the `did:aroha` method specification
([docs/spec/did-method.md](https://github.com/ArohaLabs/aroha-protocol/blob/main/docs/spec/did-method.md))
conforms to the baseline requirements for DID method specifications in
[DID 1.0/1.1 §8](https://www.w3.org/TR/did-1.1/#methods), and how this PR
conforms to the registration policies of the DID Extensions registry.

## Conformance to DID Core §8.1 — Method Schemes

| Requirement | Where satisfied |
|---|---|
| Method name syntax (`method-name` ABNF, lowercase) | "aroha" — lowercase alphanumeric; Syntax section defines the scheme |
| Method-specific identifier ABNF | Syntax section: `<unique-id> ::= [a-z0-9][a-z0-9\-]{1,62}`, no leading/trailing hyphen |
| Identifiers unique within the method | Uniqueness enforced at Create (409 on duplicate); DIDs never re-assigned after Deactivate |

## Conformance to DID Core §8.2 — Method Operations

| Operation | Where satisfied |
|---|---|
| Create | "DID Method Operations → Create": keypair generation, manifest pinning, authenticated registration; server-side capability extraction from the content-addressed manifest |
| Read/Resolve | "DID Method Operations → Read (Resolve)" + Resolution algorithm: registry record → IPFS manifest (signature-verified) → DID Document, with `document.id === did` check |
| Update | "DID Method Operations → Update": manifest replacement and key rotation (self-signed by outgoing key, nonce-deduplicated, 5-minute freshness window, versioned with append-only superseded-key log) |
| Deactivate | "DID Method Operations → Deactivate": authenticated deactivation; record retained non-resolvable and non-reassignable for signature auditability |

## Conformance to DID Core §8.3 — Security Requirements

The specification contains a dedicated **Security Considerations**
section covering: cryptographic suite (Ed25519 over canonicalised JSON)
and post-quantum migration path; key-compromise handling and rotation
guarantees; the registry trust model (registry is trusted for liveness,
not content — capability lists are content-addressed, DID Documents are
verified against the DID); eavesdropping/MITM (HTTPS everywhere; the
`did:aroha-web` variant adds an independent DNS TXT factor);
denial-of-service mitigations (rate limits, authenticated registration,
48-hour discovery cooldown); and residual risks (typosquatting), with
required verifier behaviour.

It additionally specifies **caller identity** (`aroha-sig`): a request
signing scheme binding method, path, timestamp, nonce and a hash of the
body, for parties that must restrict who may invoke a resource rather
than merely who holds a shared secret. Two ordering constraints are
normative because they are themselves the security property — the
caller allow-list is evaluated *before* any key resolution, so an
endpoint cannot be used as an oracle for whether a DID exists; and the
replay nonce is consumed *last*, so a request bearing a bad signature
cannot burn a legitimate caller's nonce and deny them service through
the replay defence. Verification fails closed on every ambiguity.

## Conformance to DID Core §8.4 — Privacy Requirements

The specification contains a dedicated **Privacy Considerations**
section covering: prohibition of personal data in DID Documents,
registry records, and manifests (public + immutable media); pseudonymity
and correlation risks with guidance to use per-context DIDs;
resolution-metadata exposure and caching; and the
deactivation-vs-erasure distinction with its GDPR rationale.

A **Registry Discovery** subsection addresses disclosure through the
verifiable data registry itself. The existence of a record, its owning
organisation, and its capability list are themselves information, so
the specification defines visibility levels and access grants, and
constrains *how* a conformant registry filters: filtering must occur
inside the retrieval query, since post-filtering leaks existence
through result counts, pagination boundaries and timing. A viewer
without access must receive the same response as for a record that does
not exist — answering `403` would confirm existence and give an
attacker an enumeration oracle — and an unrecognised credential must
degrade to the anonymous view rather than producing an authentication
error, for the same reason. The specification also states plainly that
the `unlisted` level is obscurity rather than access control, and that
implementations must not present it to users as a privacy guarantee.

## Registration-policy conformance

- The specification is publicly available under the Apache License 2.0 at a
  stable URL and can be implemented royalty-free by anyone.
- The method is implemented (TypeScript and Python SDKs published on
  npm/PyPI; a public registry deployment is live) — the registration is
  not speculative name-squatting.
- Contact information for the registrant is provided in `aroha.json`.
- The method name does not conflict with any entry in the current
  methods registry (verified against `methods/` at submission time).
