<!-- Copyright (c) 2026 Aroha Labs
     SPDX-License-Identifier: Apache-2.0 -->

# Contributing to Aroha

Thank you for your interest in contributing. This guide covers everything from setting up your development environment to getting your PR merged.

---

## Before You Start

- Read the [protocol spec](docs/spec/aroha-1.0.md) to understand the primitives.
- Check [open issues](https://github.com/ArohaLabs/aroha-protocol/issues) — someone may already be working on it.
- For significant changes, open an issue first to discuss the approach before writing code.

---

## Development Setup

**Requirements:** Node.js ≥22, npm ≥10.

```bash
git clone https://github.com/ArohaLabs/aroha-protocol.git
cd aroha-protocol
npm install
npm run build
npm test
```

**Optional:** Set `ANTHROPIC_API_KEY` in your environment to run demos with live Claude reasoning.

### Workspace layout

```
packages/      Core protocol packages (@aroha-sdk/core, @aroha-sdk/cli, …)
agents/        Reference provider agent (mock-provider-agent)
apps/          Companion applications
docs/          Specification, governance, and documentation site
scripts/       Demo scripts
community/     Third-party ecosystem submissions
```

### Useful commands

```bash
npm run build          # Build all packages
npm test               # Run all tests (vitest)
npm run lint           # Lint all packages (eslint)
npx tsc --noEmit       # Type-check without emitting

# Run a specific workspace
npm run build --workspace=packages/aroha-core
npm run test --workspace=packages/aroha-core
```

---

## Making a Change

### 1. Create a branch

```bash
git checkout -b <type>/<short-description>
# Examples:
#   feat/key-rotation-did-aroha
#   fix/saga-cancel-idempotency
#   docs/conformance-test-matrix
```

Branch prefix conventions:

| Prefix | When to use |
|--------|-------------|
| `feat/` | New feature or behaviour |
| `fix/` | Bug fix |
| `docs/` | Documentation only |
| `refactor/` | No behaviour change |
| `test/` | Tests only |
| `chore/` | Build, deps, CI |

### 2. Make your changes

- Keep changes focused. One PR = one concern.
- Add or update tests for any changed behaviour.
- If you're implementing a new protocol layer feature, add tests that cover the relevant MUST rows in [docs/conformance/test-matrix.md](docs/conformance/test-matrix.md).

### 3. Commit message format

```
<type>(<scope>): <short description in imperative mood>

# Types: feat, fix, docs, refactor, test, chore
# Scopes: core, cli, credentials, registry, policy, conformance,
#          ecosystem, mcp-bridge, a2a-bridge, langchain-bridge, telemetry
```

Examples:
```
feat(core): add key rotation support to did:aroha identities
fix(credentials): refuse a child mandate that omits its parent's limit
docs(conformance): add L3 saga test matrix rows
```

### 4. Developer Certificate of Origin (DCO)

By submitting a PR you certify that you wrote the contribution or have the right to submit it under the Apache License 2.0. We use the standard [Developer Certificate of Origin 1.1](https://developercertificate.org/) rather than a CLA. Sign off **every** commit:

```bash
git commit -s -m "feat(core): your change"
```

This adds a `Signed-off-by: Your Name <you@example.com>` trailer. The name and email must match the commit author (`git config user.name` / `user.email`).

The **DCO** check ([.github/workflows/dco.yml](.github/workflows/dco.yml)) runs on every pull request to `main` and fails if a commit made **after the DCO cut-off** lacks a sign-off whose email matches the commit author.

**Cut-off.** No commit made before the DCO was introduced carries a sign-off, and history is not rewritten to add one. A commit is exempt when it is an ancestor of `7473e091839c8686c1f804f7d58de4504f391c38` (the tip of `fix/audit-remediation` in the private development repository when the check was introduced; that commit is not in this repository's public history) **or** its committer date is before **2026-11-01T00:00:00Z**. Both values live in `dco.yml` (`DCO_EXEMPT_BASE`, `DCO_CUTOFF_DATE`); change them only together and only by owner decision.

**Status:** the check is advisory. DCO is not one of the required status checks in the `main` ruleset, so merging a PR with a red DCO check is prevented only by the reviewer (manual process).

To fix a missing sign-off:

```bash
# Last commit only
git commit --amend -s --no-edit
# Every commit on your branch (rebasing onto main)
git rebase --signoff main
git push --force-with-lease
```

Tip: `git config --global format.signOff true` does not affect `git commit`; use an alias such as `git config --global alias.cs "commit -s"`.

---

## Pull Request Checklist

Before marking your PR ready for review:

- [ ] `npm run build` passes
- [ ] `npm test` passes
- [ ] `npm run lint` passes
- [ ] `npx tsc --noEmit` passes
- [ ] New behaviour is covered by tests
- [ ] Commits are signed off (DCO)
- [ ] PR description explains *why* the change is needed, not just what it does
- [ ] If changing protocol behaviour: 2-week spec comment period opened (see [governance.md](docs/governance.md))

---

## Review Process

- The maintainer will respond within **5 business days** (see [MAINTAINERS.md](MAINTAINERS.md); the project currently has one maintainer).
- Address all review comments. Don't resolve threads yourself — let the reviewer close them.
- Once approved and CI is green, a maintainer will merge.

See [docs/governance.md](docs/governance.md) for the full spec change process and maintainer list.

---

## Releasing

Packages in this repository version **independently**, so every release is named by a tag that
says exactly which product and version it is. Publishing happens only for a **published GitHub
Release** (or a tag push, where noted) whose tag matches one of these patterns; any other release
publishes nothing.

| Tag | Product | Workflow | Version must equal |
|-----|---------|----------|--------------------|
| `@aroha-sdk/<name>@<version>` (e.g. `@aroha-sdk/core@1.10.0`) | one npm package | `publish-npm.yml` (Release) | that package's `package.json` `version` |
| `create-aroha-agent@<version>` | the unscoped npm scaffolder | `publish-npm.yml` (Release) | `packages/create-aroha-agent/package.json` |
| `npm-v<label>` (e.g. `npm-v2026.10.08`) | batch: every npm workspace whose current version is not yet on npm | `publish-npm.yml` (Release) | — (already-published versions are skipped) |
| `python-v<version>` | PyPI `aroha` | `publish-pypi.yml` (Release) | `sdks/aroha-py/pyproject.toml` |
| `java-v<version>` | Maven `com.aroha-labs:aroha-sdk` | `publish-maven.yml` (Release) | `sdks/java/pom.xml` project version |
| `sdks/go/v<version>` | Go module `github.com/ArohaLabs/aroha-protocol/sdks/go` | `publish-go.yml` (tag push) | — (the Go toolchain reads the version from the tag) |

**Legacy tags.** Releases before this scheme used `v1.0.0` … `v1.3.0` (whole-repo versions) and
`python-sdk-v1.1.2`, `python-sdk-v1.1.3`, `python-sdk-v1.4.0`. Those tags, and the 2.0.0 tags, were
made in the private development repository; this public repository has no tags yet. The legacy forms
are not recognised by the gate or by any publish workflow. Do not create new tags in those forms.

### The Release Quality Gate

[`release-gate.yml`](.github/workflows/release-gate.yml) is a reusable workflow. **Every publish
workflow calls it as its first job, on the same commit, and the publish job `needs:` it** — a red or
skipped gate means nothing is published. (A same-run `needs:` was chosen over a `workflow_run`
trigger: it guarantees the gate and the publish see the same SHA and cannot be bypassed by a
different trigger.) It can also be run by hand (Actions → Release Quality Gate → Run workflow) to
pre-check a tag. It checks:

- if the tag already exists, it points at the commit being gated;
- the version in the tag equals the named product's version file;
- **`CHANGELOG.md` lists the exact tag string under a dated release heading** — a tag listed only
  under `## [Unreleased]` fails (script: [`.github/scripts/check-changelog-tag.mjs`](.github/scripts/check-changelog-tag.mjs));
- `npm run build`, `npm test`, and no `file:` dependencies.

CHANGELOG example:

```markdown
## [2.1.0] — 2026-10-20

- @aroha-sdk/core@1.10.0
- @aroha-sdk/credentials@1.4.0
- python-v1.6.0
```

### Release steps

1. Bump the version file(s), move the entries out of `## [Unreleased]` into a dated heading with the
   tag lines, open a PR, merge it.
2. Create the tag on the merge commit and push it:
   `git tag "@aroha-sdk/core@1.10.0" && git push origin "@aroha-sdk/core@1.10.0"`.
   The "release tags" ruleset restricts creating, updating and deleting tags in these forms;
   only organisation admins (who bypass it) can push them.
   For `sdks/go/v*` the tag push starts the workflow (gate first).
3. For npm, PyPI and Maven, publish a GitHub Release from that tag. The workflow runs the gate,
   then publishes. Manual re-runs take the tag as an input and must be started **from the tag ref**
   (the gate fails if the tag points elsewhere).

npm specifics: a 403/404 from the registry now **fails** the job. The `first-publish` input
(manual runs only) downgrades it to a warning, and exists solely for the first ever publish of a new
package name. PyPI specifics: re-uploading an existing version is an error (no `skip-existing`).

### The `release` environment

Every publish job runs in the GitHub environment **`release`**. Since 2026-10-25 it requires approval
from @projectmed99 or @rajganesan-aroha-labs before a publish job runs (verified 2026-10-26). Still to
do, in Settings → Environments → `release`:

1. add a required reviewer other than the person tagging, once there is a second maintainer;
2. restrict deployment to tags matching the patterns above;
3. put `NPM_TOKEN` (and the Maven/Cloudflare secrets, when provisioned) in `release` environment
   secrets rather than repository secrets.

### npm provenance and Trusted Publishing

`npm publish --provenance` is **not** used: npm only accepts provenance for packages built from a
public source repository, and every version published so far was built while this repository was
private. Published npm packages therefore carry no provenance statement. Target now that the
repository is public — npm Trusted Publishing (OIDC):

1. On npmjs.com, for each package (`@aroha-sdk/*`, `create-aroha-agent`): Settings → Trusted
   Publisher → GitHub Actions; organisation `ArohaLabs`, repository `aroha-protocol`, workflow
   `publish-npm.yml`, environment `release`.
2. Confirm npm CLI ≥ 11.5 on the runner (the workflow uses Node 24.x) — `id-token: write` is
   already granted to the publish job.
3. Run one release through it; then remove `NODE_AUTH_TOKEN` from the publish step, delete the
   `NPM_TOKEN` secret and revoke the token on npmjs.com.
4. Provenance is generated automatically with Trusted Publishing; update `docs/trust.md`.

Until then `NPM_TOKEN` stays in use.

### Secrets — what exists and what each workflow needs

| Secret | Exists? | Used by |
|---|---|---|
| `NPM_TOKEN` | **no** — not yet set on this repository (verified 2026-10-26) | `publish-npm.yml` |
| `VERCEL_TOKEN` | **no** — not yet set on this repository | no workflow references it (owner to document or delete) |
| — (OIDC, no secret) | n/a | `publish-pypi.yml` (PyPI trusted publishing) |
| `SONATYPE_USERNAME`, `SONATYPE_PASSWORD`, `GPG_PRIVATE_KEY`, `GPG_PASSPHRASE` | **no** | `publish-maven.yml` |
| `CLOUDFLARE_API_TOKEN`, `CLOUDFLARE_ACCOUNT_ID` | **no** | `registry-migrations-check.yml` |

**Maven Central publishing is not operational.** The `SONATYPE_*`/`GPG_*` secrets (and a Central
Portal namespace for `com.aroha-labs`) have not been provisioned; `publish-maven.yml` fails fast
with a clear message until the owner adds them. No build provenance attestation is produced —
GitHub artifact attestations are not used. See [docs/security/key-management.md](docs/security/key-management.md)
for custody and rotation of every secret.

---

## Submitting to the Ecosystem

If you're building a bridge, agent, or extension:

1. See [docs/ecosystem/quality-tiers.md](docs/ecosystem/quality-tiers.md) for tier requirements.
2. Use the submission template in that document.
3. Open a PR adding your package to [docs/ecosystem.md](docs/ecosystem.md).
4. For Verified tier: also open a conformance report issue — see [docs/conformance/implementer-packet.md](docs/conformance/implementer-packet.md).

---

## Reporting Security Issues

**Do not open a public issue for security vulnerabilities.**

Use [GitHub private vulnerability reporting](https://github.com/ArohaLabs/aroha-protocol/security/advisories/new) or email contact@aroha-labs.com with `SECURITY` in the subject line. See [SECURITY.md](SECURITY.md) for the full policy and response SLAs.

---

## Code of Conduct

Be respectful. See [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
