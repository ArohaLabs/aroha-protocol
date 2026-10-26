<!-- Internal — how to submit the did:aroha registration. Not part of the PR. -->

# Submitting the did:aroha registration to W3C

Target repo: https://github.com/w3c/did-extensions (the DID Extensions
registry, successor to did-spec-registries). Verify the method name is
still unclaimed immediately before submitting:
https://github.com/w3c/did-extensions/tree/main/methods

## Steps

**Precondition:** the `specification` URL in `aroha.json` must point to the public
specification (`ArohaLabs/aroha-protocol`, `docs/spec/did-method.md`) — it still names the private
`ArohaLabs/aroha-spec` repository, which the editors cannot review. Also confirm that the
`contactEmail` in `aroha.json` is a monitored mailbox.

```bash
gh repo fork w3c/did-extensions --clone
cd did-extensions
git checkout -b register-did-aroha
cp <this repo>/spec-public/w3c-registration/aroha.json methods/aroha.json
git add methods/aroha.json
git commit -m "Register the did:aroha method"
git push -u origin register-did-aroha
gh pr create --repo w3c/did-extensions \
  --title "Register the did:aroha method" \
  --body-file <this repo>/spec-public/w3c-registration/pr-body.md
```

## PR body (pr-body.md content)

Include, per the registry's PR template:
1. Link to the spec: https://github.com/ArohaLabs/aroha-protocol/blob/main/docs/spec/did-method.md
2. The full self-assessment (paste self-assessment.md — the editors
   require a written self-assessment against DID Core §8 and the
   registration policies)
3. Implementation status exactly as `pr-body.md` states it. Do not claim more.

## Expectations

- Review is by the registry editors; turnaround is typically weeks, and
  editors commonly request clarifications on the Security/Privacy
  sections — respond in-thread, update the did-method.md specification
  (`spec-public/spec/` is the source; run `sync.sh`) — the registration
  links to it, so fixes don't require a new PR.
- The submission is public and under the LLC's name via the contact
  fields; the GitHub account submitting should be one you're happy to
  have publicly associated with the method.
