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
| `SUBMIT.md` | Internal submission checklist (not part of the PR) |

## About `"status": "registered"` in `aroha.json`

`"registered"` is the value the DID Extensions registry expects in the `status` field of a new
entry — it is the field's initial value for *every* method entry, not a claim that registration
has happened. It becomes true only once the registry editors merge the pull request.

## URLs in these files

The specification is public in `ArohaLabs/aroha-protocol` (`docs/spec/did-method.md`) and as
ReSpec HTML at https://www.aroha-labs.com/spec/did-aroha-method-1.0.html. `pr-body.md`,
`self-assessment.md` and `SUBMIT.md` link there. `aroha.json` (and the copy of the entry in
`did-aroha-method-1.0.html`) still names `github.com/ArohaLabs/aroha-spec` as its
`specification`; that repository is private, so the URL does not resolve for the public or for
registry editors, and it must be changed before the pull request is opened.

Implementation status for the registration is stated in `pr-body.md`: the TypeScript packages
are the reference implementation; the Python, Go and Java SDKs verify E-form DIDs and Key Event
Logs, with web-anchored DID support still on an earlier schema.
