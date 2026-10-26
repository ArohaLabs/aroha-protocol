<!-- Copyright (c) 2026 Aroha Labs
     SPDX-License-Identifier: Apache-2.0 -->

# DID method registration — prepared, not submitted

This directory holds the material for registering `did:aroha` in the W3C DID Extensions
registry (`w3c/did-extensions`). **Nothing here has been submitted yet**: no pull request has
been opened against the registry, and `did:aroha` does not appear in it.

| File | What it is |
|------|------------|
| `aroha.json` | The registry entry, in the registry's own JSON format |
| `pr-body.md` | Draft body for the registration pull request |
| `self-assessment.md` | Self-assessment against DID Core §8, to be pasted into the PR |

## About `"status": "registered"` in `aroha.json`

`"registered"` is the value the DID Extensions registry expects in the `status` field of a new
entry — it is the field's initial value for *every* method entry, not a claim that registration
has happened. It becomes true only once the registry editors merge the pull request.

## URLs in these files

The specification is public in `ArohaLabs/aroha-protocol` (`docs/spec/did-method.md`) and as
ReSpec HTML at https://www.aroha-labs.com/spec/did-aroha-method-1.0.html. `pr-body.md` and
`self-assessment.md` link there, and the `specification` field in `aroha.json` (and in the copy of
the entry in `did-aroha-method-1.0.html`) points to the same ReSpec URL.

Implementation status for the registration is stated in `pr-body.md`: the TypeScript packages
are the reference implementation; the Python, Go and Java SDKs verify E-form DIDs and Key Event
Logs, with web-anchored DID support still on an earlier schema.
