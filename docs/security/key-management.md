<!-- Copyright (c) 2026 Aroha Labs
     SPDX-License-Identifier: Apache-2.0 -->

# Project Key and Secret Management

**Owner:** Security Agent (human owner — to assign; one documented maintainer, see `MAINTAINERS.md`)  
**Date:** 2026-10-09  
**Status:** inventory published; rotation and custody procedures are **manual processes, not yet operating**. No rotation cadence below is enforced by automation.  
**Scope:** secrets and signing keys held by the Aroha project to build, publish and operate its own services. Keys that operators generate for their own agents are covered in [hardening.md](hardening.md#1-key-management).

This page never contains secret values. It records what each secret is for, where it lives, who holds it, and what to do if it leaks.

---

## Summary

| # | Secret / key | Where stored | State (2026-10-09) | Custodian |
|---|---|---|---|---|
| 1 | `NPM_TOKEN` | GitHub Actions secret | **Not yet set** on `ArohaLabs/aroha-protocol` (verified 2026-10-26) | owner — to assign |
| 2 | `VERCEL_TOKEN` | GitHub Actions secret | **Not yet set**; not referenced by any current workflow | owner — to assign |
| 3 | `ADMIN_SECRET` | Cloudflare Worker secret (`apps/registry-server`) | Deployed | owner — to assign |
| 4 | `PINATA_JWT` | Cloudflare Worker secrets (`apps/ipfs-gateway`, `apps/registry-server`) | Deployed (owner to confirm on both Workers) | owner — to assign |
| 5 | `CREDENTIAL_SECRET` | Cloudflare Worker secret (planned) | **Planned — not yet deployed** | owner — to assign |
| 6 | Runtime per-install audit key | End user's machine (OS keystore) | Generated per install | the end user |
| 7 | Maven GPG signing key (`GPG_PRIVATE_KEY`, `GPG_PASSPHRASE`) | GitHub Actions secret (planned) | **Planned — not provisioned** | owner — to assign |
| 8 | Apple Developer ID certificate (`APPLE_*`) | GitHub Actions secret (planned) | **Planned — not provisioned** | owner — to assign |
| 9 | Windows Authenticode certificate (`WINDOWS_CERTIFICATE`) | GitHub Actions secret (planned) | **Planned — not provisioned** | owner — to assign |
| 10 | `CLOUDFLARE_API_TOKEN` (+ `CLOUDFLARE_ACCOUNT_ID`) | GitHub Actions secret (planned) | **Planned — not provisioned** | owner — to assign |

Verified facts behind this table (2026-10-09): the GitHub repository `ArohaLabs/aroha-protocol` is private on a free plan, and its only repository secrets are `NPM_TOKEN` and `VERCEL_TOKEN`. No `SONATYPE_*`, `GPG_*`, `APPLE_*` or `CLOUDFLARE_API_TOKEN` secret exists. On a free plan for a private repository, branch protection and environment protection rules cannot be enforced, so a workflow's `environment:` setting is a label, not an approval gate. Since 2026-10-25 `ArohaLabs/aroha-protocol` is public and that plan limitation no longer applies. Re-checked 2026-10-26: the repository has no secrets yet, and the `release` environment requires approval from @projectmed99 or @rajganesan-aroha-labs.

## Standard compromise procedure

Every entry below refers to these steps. Adapt the specifics per entry.

1. **Revoke** the credential at its issuer (npm, Vercel, Cloudflare, Pinata, Apple, certificate authority, key server) so it stops working.
2. **Rotate** — generate a replacement and store it in the same place (`gh secret set`, `wrangler secret put`, etc.). Never paste it into chat, issues or logs.
3. **Re-sign / republish** where the key signed something users rely on (packages, binaries).
4. **Review** the issuer's audit log for use of the old credential between the suspected exposure and revocation.
5. **Notify users** per [SECURITY.md](../../SECURITY.md) and run the [incident response process](incident-response.md) if any user-facing artefact or service could have been affected.
6. **Record** the incident, the dates of revoke and rotate, and who performed them.

Recommended rotation cadences below are **targets**, labelled as such. None is operating yet.

---

## 1. `NPM_TOKEN`

- **Purpose:** authenticates `npm publish` for the `@aroha-sdk/*` packages and `create-aroha-agent` in `.github/workflows/publish-npm.yml`.
- **Where stored:** GitHub Actions repository secret.
- **Custodian:** owner — to assign.
- **Rotation (target):** every 90 days, and whenever someone with publish rights leaves. Not yet operating.
- **Compromise:** revoke the token at npmjs.com → create a new granular automation token scoped to the Aroha packages → `gh secret set NPM_TOKEN` → check every package's recent versions on npm for releases the project did not make; deprecate or unpublish any unauthorised version and republish a known-good one → notify users per SECURITY.md.
- **Verification:** the token's last-used date on npm matches known workflow runs; the next `publish-npm.yml` run succeeds with the new token.

## 2. `VERCEL_TOKEN`

- **Purpose:** Vercel API access. No workflow in `.github/workflows/` references it as of 2026-10-09; the owner should document its use or delete it.
- **Where stored:** GitHub Actions repository secret.
- **Custodian:** owner — to assign.
- **Rotation (target):** every 90 days, or delete if unused. Not yet operating.
- **Compromise:** revoke at vercel.com/account/tokens → replace (or remove) the GitHub secret → review recent Vercel deployments and project settings changes → notify users per SECURITY.md if a public site may have served altered content.
- **Verification:** the token list in Vercel shows only expected tokens; `gh secret list` matches this page.

## 3. Registry `ADMIN_SECRET`

- **Purpose:** bearer secret for the registry Worker's administrative routes (`apps/registry-server`), including org API key provisioning (`POST /v1/auth/keys`), key listing and revocation, analytics, signals and the detailed health check. It is also the root from which the registry derives its credential-JWT signing key (`src/routes/credential.ts`), so rotating it invalidates every outstanding registry credential.
- **Where stored:** Cloudflare Worker secret on the `aroha-registry` Worker (`wrangler secret put ADMIN_SECRET`). Any server that calls admin routes on users' behalf also holds a copy — owner to document which.
- **Custodian:** owner — to assign.
- **Rotation (target):** every 90 days. Not yet operating. Plan for the side effect: all issued registry credentials stop verifying.
- **Compromise:** `wrangler secret put ADMIN_SECRET` with a new random value (this both revokes and rotates) → update every caller that holds it → review org API keys issued since the suspected exposure and revoke unexpected ones → inform holders of registry credentials that they must re-request them → notify users per SECURITY.md.
- **Verification:** an admin request with the old value is refused; an admin request with the new value succeeds; the list of org keys matches expectations.
- **Planned change:** see `CREDENTIAL_SECRET` (§5).

## 4. `PINATA_JWT`

- **Purpose:** authenticates calls to Pinata (IPFS pinning service). `apps/ipfs-gateway` uses it for server-side pinning (required). `apps/registry-server` uses it, when set, to fetch manifests at registration time without public-gateway rate limits; its `wrangler.toml` notes it must be the same JWT as the gateway's.
- **Where stored:** Cloudflare Worker secrets on both Workers (`wrangler secret put PINATA_JWT`).
- **Custodian:** owner — to assign.
- **Rotation (target):** every 180 days. Not yet operating. Rotate on both Workers in the same change.
- **Compromise:** revoke the key in the Pinata dashboard → create a new key → `wrangler secret put PINATA_JWT` on both Workers → review the Pinata account for unexpected pins or deletions; re-pin any content the registry depends on → notify users per SECURITY.md if published manifests could have been affected.
- **Verification:** a test pin through the gateway succeeds; the old key shows as revoked in Pinata.

## 5. `CREDENTIAL_SECRET` (planned — not yet deployed)

- **Purpose (planned):** a dedicated secret for signing registry credentials, so credential signing no longer derives from `ADMIN_SECRET`. Owner to confirm scope before deployment.
- **Where stored (planned):** Cloudflare Worker secret on the registry Worker.
- **Custodian:** owner — to assign.
- **Rotation (target):** annually, with a documented overlap period for outstanding credentials. Not yet operating.
- **Compromise:** as for `ADMIN_SECRET`: replace the Worker secret → outstanding credentials stop verifying → holders re-request → notify per SECURITY.md.
- **Verification:** once deployed, a credential issued before rotation fails `POST /v1/credential/verify` and one issued after succeeds.

## 6. Runtime per-install audit key

- **Purpose:** Ed25519 key that each `aroha-runtime` install generates on first use to sign its own audit-log checkpoints (`apps/aroha-runtime/src/host/identity.ts`, `loadOrCreateInstallKey`; used by `src/host/audit-rotate.ts`). It is not an agent identity key and is not held by the project. The runtime source, including the `apps/aroha-runtime/` paths and the `runtime-release.yml` workflow cited on this page, is in the private development repository, not in this one.
- **Where stored:** on the end user's machine, keystore account `install.audit`, via the OS keystore chosen at runtime (`src/host/keystore.ts`):
  - macOS: Keychain, service `aroha-agent-key`;
  - Windows: DPAPI-protected blob at `<AROHA_HOME>/keys/install.audit.dpapi`;
  - Linux with `secret-tool`: Secret Service, service `aroha-agent-key`;
  - otherwise: file `<AROHA_HOME>/keys/install.audit.key` with mode `0600`.
  
  `AROHA_HOME` defaults to `~/.aroha`.
- **Custodian:** the end user who owns the install.
- **Rotation:** the runtime does not provide an install-key rotation command as of this branch. Checkpoints are verified against the install key's current public key, so replacing the key would make earlier checkpoints fail verification. Treat replacement as an incident, not routine maintenance.
- **Compromise (user guidance):** treat audit checkpoints signed after the suspected exposure as untrusted → preserve the existing audit log for review → remove the keystore entry so a new key is created → record the cut-over point → report to the project per SECURITY.md if a runtime defect caused the exposure.
- **Verification:** audit verification on the install reports checkpoints as signed by the current install key.

## 7. Maven GPG signing key (planned — not provisioned)

- **Purpose (planned):** sign Java SDK artefacts for Maven Central in `.github/workflows/publish-maven.yml` (with `SONATYPE_USERNAME` / `SONATYPE_PASSWORD`). That workflow is not operational because none of these secrets exist.
- **Where stored (planned):** GitHub Actions secrets `GPG_PRIVATE_KEY`, `GPG_PASSPHRASE`; public key on a public key server.
- **Custodian:** owner — to assign.
- **Rotation (target):** key expiry set to 2 years, renewed before expiry. Not yet operating.
- **Compromise:** publish a revocation certificate to key servers → generate and publish a new key → replace the GitHub secrets → re-sign and republish affected artefacts where the repository allows → notify users per SECURITY.md.
- **Verification:** published artefacts verify against the current public key; the revoked key shows as revoked on the key server.

## 8. Apple Developer ID certificate (planned — not provisioned)

- **Purpose (planned):** code-sign and notarise macOS runtime binaries in `.github/workflows/runtime-release.yml`. Without the `APPLE_*` secrets that workflow releases macOS binaries **unsigned** (it emits a warning). No runtime release has been published yet.
- **Where stored (planned):** GitHub Actions secrets `APPLE_CERTIFICATE` (base64 .p12), `APPLE_CERTIFICATE_PASSWORD`, `APPLE_SIGNING_IDENTITY`, `APPLE_TEAM_ID`, `APPLE_NOTARIZATION_APPLE_ID`, `APPLE_NOTARIZATION_PASSWORD`.
- **Custodian:** owner — to assign (Apple Developer account holder).
- **Rotation (target):** before certificate expiry; app-specific password annually. Not yet operating.
- **Compromise:** revoke the certificate in the Apple Developer portal → issue a new one → replace secrets → re-sign, re-notarise and republish affected binaries and `checksums.txt` → notify users per SECURITY.md.
- **Verification:** `codesign --verify` and `spctl --assess` pass on a freshly downloaded release binary.

## 9. Windows Authenticode certificate (planned — not provisioned)

- **Purpose (planned):** sign Windows runtime binaries. `runtime-release.yml` currently has no signing job for Windows; it fails if `WINDOWS_CERTIFICATE` is set, to avoid implying signing that does not happen.
- **Where stored (planned):** GitHub Actions secret `WINDOWS_CERTIFICATE` (or a cloud signing service — owner to decide).
- **Custodian:** owner — to assign.
- **Rotation (target):** before certificate expiry. Not yet operating.
- **Compromise:** ask the issuing CA to revoke → obtain a new certificate → re-sign and republish affected binaries and `checksums.txt` → notify users per SECURITY.md.
- **Verification:** `signtool verify /pa` passes on a freshly downloaded release binary.

## 10. `CLOUDFLARE_API_TOKEN` (planned — not provisioned)

- **Purpose (planned):** lets the manual D1 drift-check workflow `.github/workflows/registry-migrations-check.yml` read the remote registry database schema. Needs `CLOUDFLARE_ACCOUNT_ID` too. Without them the workflow fails fast. See [Database migrations](../../apps/registry-server/DEPLOY.md#database-migrations).
- **Where stored (planned):** GitHub Actions secret.
- **Custodian:** owner — to assign.
- **Rotation (target):** every 90 days. Scope the token to the minimum D1 permissions the check needs. Not yet operating.
- **Compromise:** revoke the token in the Cloudflare dashboard → create a new minimally scoped token → `gh secret set CLOUDFLARE_API_TOKEN` → review Cloudflare audit logs for D1 and Worker changes → notify users per SECURITY.md if registry data may have been altered.
- **Verification:** the drift-check workflow succeeds with the new token; the old token shows as revoked.

---

## Verification checklist

Run at each review (target: quarterly; not yet operating). Record date, reviewer and result.

- [ ] `gh secret list --repo ArohaLabs/aroha-protocol` matches the "Where stored: GitHub Actions" entries above, with no unlisted secrets.
- [ ] `wrangler secret list` for the `aroha-registry` and IPFS gateway Workers matches §3–§5.
- [ ] Every entry has a named custodian (currently all "owner — to assign").
- [ ] `VERCEL_TOKEN` is either documented as in use or deleted.
- [ ] Each secret's last rotation date is recorded and within its target cadence.
- [ ] No secret value appears in the repository: run a secret scan over the working tree and history.
- [ ] Planned entries (§5, §7–§10) are updated here when provisioned, with the date.
