<!-- Copyright (c) 2026 Aroha Labs
     SPDX-License-Identifier: Apache-2.0 -->

# DID method registration — accepted 2026-11-14

This directory holds the material for registering `did:aroha` in the W3C DID Extensions
registry (`w3c/did-extensions`). It was submitted on 2026-10-27 as
[w3c/did-extensions#766](https://github.com/w3c/did-extensions/pull/766) and merged on 2026-11-14,
so `did:aroha` is listed in the registry as `methods/aroha.json`. A listing is not a W3C
standard or an endorsement.

`aroha.json` matches the entry in the pull request, including the 2026-10-28 revision of
`verifiableDataRegistry` (no registry for the E-form and z-form; the named form resolves
through an Aroha Registry instance). `pr-body.md` and `self-assessment.md` are the drafts the
pull request was written from.

| File | What it is |
|------|------------|
| `aroha.json` | The registry entry, in the registry's own JSON format |
| `pr-body.md` | Draft body for the registration pull request |
| `self-assessment.md` | Self-assessment against DID Core §8, to be pasted into the PR |

## About `"status": "registered"` in `aroha.json`

`"registered"` is the value the DID Extensions registry expects in the `status` field of a new
entry. It is the field's initial value for every method entry. The registry editors merged
the pull request on 2026-11-14.

## URLs in these files

The specification is public in `ArohaLabs/aroha-protocol` (`docs/spec/did-method.md`) and as
ReSpec HTML at https://www.aroha-labs.com/spec/did-aroha-method-1.0.html. `pr-body.md` and
`self-assessment.md` link there, and the `specification` field in `aroha.json` (and in the copy of
the entry in `did-aroha-method-1.0.html`) points to the same ReSpec URL.

Implementation status for the registration is stated in `pr-body.md`: the TypeScript packages
are the reference implementation; the Python, Go and Java SDKs verify E-form DIDs and Key Event
Logs, with web-anchored DID support still on an earlier schema.
