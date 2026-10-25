# Register the `did:aroha` method

This PR registers the `did:aroha` DID method in the DID Extensions registry.

## Specification

https://github.com/ArohaLabs/aroha-spec/blob/main/spec/did-method.md

Published under the Apache License 2.0 at a stable URL, implementable
royalty-free by anyone. The specification defines all four DID Core §8.2
method operations (Create, Read, Update, Deactivate) against a
verifiable data registry, and includes the Security and Privacy
Considerations sections required by DID Core §8.3 and §8.4.

A ReSpec rendering is available at
https://github.com/ArohaLabs/aroha-spec/blob/main/spec/did-aroha-method-1.0.html

## Method name

`aroha` — verified as unclaimed against `methods/` immediately before
opening this PR.

## Implementation status

The method is implemented and deployed; this registration is not a
speculative name reservation.

- **TypeScript reference implementation** — `@aroha-sdk/core` and the wider
  `@aroha-sdk/*` packages, published on npm under Apache-2.0 with source
  included in the tarballs, implementing all three DID forms including
  rotatable inception DIDs (`did:aroha:E…`) and their Key Event Logs.
- **Python, Go and Java SDKs** — the Python SDK is published on PyPI as
  `aroha` (Apache-2.0); the Go and Java SDKs are not yet published. All three
  verify E-form DIDs and their Key Event Logs and are tested against shared
  vectors; their support for the web-anchored variant still follows an
  earlier schema. Each SDK's README states what it supports.
- **Registry** — a public deployment is live and serves DID resolution
  over HTTPS; DID Documents are verified against the DID and capability
  lists are content-addressed (IPFS), so the registry is trusted for
  liveness rather than for content.

## Self-assessment

The full self-assessment against DID Core §8 and the registration
policies follows.

---

<!--
  Paste the contents of self-assessment.md here when opening the PR.
  It is kept as a separate file so it can be reviewed and updated
  independently of this PR body; the editors require the assessment
  inline in the pull request rather than as a link.
-->

## Notes for editors

Two aspects of the Security and Privacy sections are worth flagging,
since they are the areas the registry editors most often ask about:

- **Ordering is normative where it is the security property.** The
  caller allow-list is evaluated before any key resolution, so an
  endpoint cannot be used as an oracle for whether a DID exists; and the
  replay nonce is consumed only after every other check passes, so a
  request bearing an invalid signature cannot burn a legitimate caller's
  nonce and deny them service through the replay defence itself.

- **Registry discovery is treated as a disclosure channel.** The
  existence of a record, its owning organisation, and its capability
  list are themselves information. The specification therefore
  constrains how a conformant registry filters — inside the retrieval
  query rather than by post-filtering, because post-filtering leaks
  existence through result counts, pagination boundaries, and timing —
  and requires that a viewer without access receive the same response as
  for a record that does not exist. It also states that the `unlisted`
  visibility level is obscurity rather than access control, and must not
  be presented to users as a privacy guarantee.

We are happy to revise the specification in response to editor feedback.
The registration links to the specification rather than inlining it, so
corrections can be made without reopening this PR.
