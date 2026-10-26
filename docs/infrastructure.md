# Aroha Infrastructure Reference

> **Audience:** Engineers operating, deploying, or updating the Aroha platform.  
> **Last updated:** 2026-07-08  
> **Scope:** All systems in this monorepo (paths are relative to the repository root) — registry, IPFS gateway, CI/CD, packages, and agents. The website (with its auth setup) moved to a separate private repository on 2026-08-23; sections that still describe it are marked.

---

## Table of Contents

1. [Monorepo Structure](#1-monorepo-structure)
2. [Build System](#2-build-system)
3. [CI/CD Pipeline](#3-cicd-pipeline)
4. [Deployment — Vercel (Website)](#4-deployment--vercel-website)
5. [Cloudflare Workers](#5-cloudflare-workers)
6. [Database — Cloudflare D1](#6-database--cloudflare-d1)
7. [Authentication — NextAuth v5](#7-authentication--nextauth-v5)
8. [External Services](#8-external-services)
9. [Environment Variables — Complete Reference](#9-environment-variables--complete-reference)
10. [NPM Package Publishing](#10-npm-package-publishing)
11. [Multi-Language SDK Publishing](#11-multi-language-sdk-publishing)
12. [DNS & Domains](#12-dns--domains)
13. [Packages — Full List](#13-packages--full-list)
14. [Agents — Full List](#14-agents--full-list)
15. [Applications — Full List](#15-applications--full-list)
16. [Security & Compliance](#16-security--compliance)
17. [Monitoring & Observability](#17-monitoring--observability)
18. [How to Update Things](#18-how-to-update-things)

---

## 1. Monorepo Structure

```
aroha-protocol/                 ← root (npm workspace root, not published)
├── packages/                   ← @aroha-sdk/* npm packages
├── agents/                     ← reference agent implementations
├── apps/                       ← deployed applications
│   ├── registry-server/        ← Cloudflare Worker + D1
│   ├── ipfs-gateway/           ← Cloudflare Worker
│   └── status/                 ← Express health-check service
├── sdks/                       ← Go SDK, Java SDK (separate language targets)
├── scripts/                    ← build-ordered.mjs, smoke.mjs, etc.
├── .github/workflows/          ← all CI/CD definitions
├── tsconfig.base.json          ← shared TypeScript config
├── vitest.conformance.config.ts← conformance test runner
└── package.json                ← root workspace
```

**Package manager:** npm workspaces (`npm >= 10`, `node >= 22`)  
**Workspaces defined in `package.json`:**
```json
"workspaces": ["packages/*", "agents/*", "apps/*"]
```

**TypeScript base config (`tsconfig.base.json`):**

| Setting | Value |
|---------|-------|
| target | ES2022 |
| module | NodeNext |
| moduleResolution | NodeNext |
| lib | ES2022 |
| strict | true |
| declarationMaps | true |
| sourceMap | true |

Individual packages extend this and add `"DOM"` to `lib` if they use Web Crypto API (e.g. `@aroha-sdk/settlement`, now developed outside this repository and still published on npm).

---

## 2. Build System

**Build command:** `npm run build` → `node scripts/build-ordered.mjs`

The build script compiles packages in dependency order (core first, then dependents). Each package runs `tsc -p tsconfig.json`.

**Test runners:**

| Purpose | Runner | Config |
|---------|--------|--------|
| Unit tests | vitest (version in root `package.json`) | per-package |
| Conformance tests | vitest | `vitest.conformance.config.ts` |

Conformance tests live at `packages/*/src/**/*.conformance.test.ts` and run with a 15 second timeout (saga tests simulate timeouts).

**Useful root scripts:**

```bash
npm run build                    # build all packages in order
npm test                         # unit tests across all workspaces
npm run lint                     # ESLint 9.x across all workspaces
npm run smoke                    # smoke test (scripts/smoke.mjs)
npm run demo:fintech             # run fintech demo
npm run benchmark:crypto-throughput  # Ed25519 signing benchmark
npx vitest run --config vitest.conformance.config.ts  # conformance suite
```

---

## 3. CI/CD Pipeline

All workflows live in `.github/workflows/`. They are described below in full detail.

---

### `ci.yml` — Standard CI

**Triggers:** Push to `main`, `feat/*`, `fix/*`; pull requests to `main`  
**Matrix:** Node 22.x on `ubuntu-latest`

**Jobs:**

| Job | Steps |
|-----|-------|
| `build-and-test` | checkout → setup Node 22 (npm cache) → `npm ci` → `npm run build` → `npm test` |
| `lint` | checkout → `npm ci` → `npm run lint` |
| `typecheck` | checkout → `npm ci` → `npx tsc --noEmit -p tsconfig.json` |

`ci.yml` also runs durable-store (Postgres/Redis), README-example, Python, Go and Java SDK, deployment-example, npm audit, link and spec-parity jobs. Which of them are required on `main` is set by the repository ruleset — see [trust.md](trust.md).

**How to update:** Edit `.github/workflows/ci.yml`. To add a new check (e.g. a formatter), add a new job or step.

---

### `conformance.yml` — Protocol Conformance Suite

**Triggers:** Push to `main`, PRs to `main`, daily at `02:00 UTC`, manual (`workflow_dispatch`)  
**Runs on:** `ubuntu-latest`, Node 22.x

**What it does:**
1. Runs `npx vitest run --config vitest.conformance.config.ts --reporter=json --outputFile=conformance-results.json`
2. Generates `conformance-scorecard.json`:
   ```json
   {
     "date": "...",
     "implementation": "aroha-ts",
     "version": "...",
     "conformanceRate": 98.5,
     "passed": 130,
     "failed": 2,
     "total": 132,
     "status": "PASS"
   }
   ```
3. Uploads scorecard as a GitHub Actions artifact (90-day retention)
4. Publishes a summary to the GitHub job summary page

**How to update:** Add new `.conformance.test.ts` files alongside package source. The config auto-discovers them via glob.

---

### Vercel deploys — no workflow in this repository

There is no `.github/workflows/deploy.yml`; an earlier revision of this page described one that no longer exists. No workflow in `.github/workflows/` deploys to Vercel or references the `VERCEL_TOKEN` repository secret (verified 2026-10-09). How production deploys are triggered (Vercel Git integration or manual `vercel` CLI) is for the owner to document.

If a deploy workflow is reintroduced, take the Vercel identifiers from repository variables or secrets — `<VERCEL_ORG_ID>` and `<VERCEL_PROJECT_ID>` — rather than hard-coding them in the workflow or in this page. To add environment variables to the Vercel build, use the Vercel project dashboard (**Settings → Environment Variables**) or `vercel env add`.

---

### `publish-npm.yml` — NPM Package Publishing

**Triggers:** GitHub release published **whose tag is** `@aroha-sdk/<name>@<version>`, `create-aroha-agent@<version>` or `npm-v*` (any other release is ignored); manual (`workflow_dispatch`)  
**Runs on:** `ubuntu-latest`, Node 24.x  
**Registry:** `https://registry.npmjs.org`  
**Permissions:** `contents: read`, `id-token: write` (granted but unused: npm provenance is not used)

**Required GitHub secret:** `NPM_TOKEN`

**What it publishes:**
- A per-package tag publishes that one package, and fails if its `package.json` version differs from the tag
- An `npm-v*` tag (or a manual run with `package: all`) publishes every `packages/aroha-*/` and `packages/create-aroha-agent/` workspace whose version is not on npm yet

**Publish logic (per package):**
```bash
npm publish "$dir" --access public
```
- If the version is already published → skip (idempotent)
- If 403/404/permission error → warn and continue
- Other errors → fail the job

**How to release a new version:** see [CONTRIBUTING.md → Releasing](https://github.com/ArohaLabs/aroha-protocol/blob/main/CONTRIBUTING.md#releasing). In short: bump the package's version, list the tag (e.g. `@aroha-sdk/core@1.10.0`) in `CHANGELOG.md`, push the tag (the release gate runs), then publish a GitHub Release from it.

**How to manually re-publish a specific package:**
```bash
cd packages/aroha-core
npm publish --access public
```

---

### `release-gate.yml` — Pre-Release Validation

**Triggers:** called as the first job of every publish workflow (`workflow_call`) for its release tag (`@aroha-sdk/*@*`, `create-aroha-agent@*`, `python-v*`, `java-v*`, `sdks/go/v*`, `npm-v*`); manual with a tag input. It does not run on a bare tag push.  
**Permissions:** `contents: read`

**Validation checklist (all must pass):**
1. The version in the tag equals the version file of the product it names (only that product — packages version independently)
2. `CHANGELOG.md` mentions the exact tag
3. Full build + test suite
4. No `file:` dependencies in any `packages/*/package.json` or `agents/*/package.json`

**How to update:** Edit `.github/workflows/release-gate.yml`. This gate is intentionally strict — loosening it risks shipping with local-only dependencies.

---

## 4. Deployment — Vercel (Website)

The website was extracted to its own repository on 2026-08-23 and is no
longer built or deployed from here. Its Vercel project, environment
variables and deploy workflow moved with it.

It now lives in a separate, private repository (`ArohaLabs/aroha-website`).

## 5. Cloudflare Workers

Two workers in `apps/`. Both use Wrangler for deployment.

---

### `aroha-registry` (Registry API)

**Location:** `apps/registry-server/`  
**Name:** `aroha-registry`  
**Main:** `src/index.ts`  
**Compatibility date:** 2024-09-01  
**Compatibility flags:** `nodejs_compat`

**Bindings:**

| Binding | Type | Value |
|---------|------|-------|
| `DB` | D1 Database | `aroha-registry` (ID: `68e2d12b-88ff-4921-9a8b-65475ea52b03`) |
| `IPFS_GATEWAY` | Environment variable | `https://aroha-ipfs-gateway.aroha-labs.workers.dev/ipfs` |

**Secrets (stored in Wrangler / Cloudflare dashboard):**

| Secret | Purpose |
|--------|---------|
| `ADMIN_SECRET` | Authenticates `POST /v1/auth/keys` and mutation endpoints |
| `PINATA_JWT` | JWT for Pinata IPFS API (avoids public gateway limits) |

**Endpoints:**
- Production: `https://aroha-registry.aroha-labs.workers.dev`
- Custom domain alias: `https://registry.aroha-labs.com` (planned — not configured; does not resolve today)

**How to deploy:**
```bash
cd apps/registry-server
npx wrangler deploy
```

**How to update a secret:**
```bash
npx wrangler secret put ADMIN_SECRET
# paste the new value when prompted
```

**How to run schema migrations:**
```bash
npx wrangler d1 migrations apply aroha-registry --remote
```

---

### `aroha-ipfs-gateway` (IPFS Proxy)

**Location:** `apps/ipfs-gateway/`  
**Name:** `aroha-ipfs-gateway`  
**Main:** `src/index.ts`  
**Compatibility date:** 2024-09-01  
**Compatibility flags:** `nodejs_compat`

**Bindings:**

| Binding | Type | Value |
|---------|------|-------|
| `REGISTRY` | Service binding | `aroha-registry` worker (direct, no HTTP) |

**Secrets:**

| Secret | Purpose |
|--------|---------|
| `PINATA_JWT` | JWT for Pinata API — get from https://app.pinata.cloud/developers/api-keys |

**Endpoints:**
- Production: `https://aroha-ipfs-gateway.aroha-labs.workers.dev/ipfs/<CID>`
- Custom domain alias: `https://ipfs.aroha-labs.com` (planned — not configured; does not resolve today)

**How to deploy:**
```bash
cd apps/ipfs-gateway
npx wrangler deploy
```

**How to rotate the Pinata JWT:**
1. Go to https://app.pinata.cloud/developers/api-keys — revoke the old key, generate a new JWT
2. Update both workers:
```bash
cd apps/registry-server && npx wrangler secret put PINATA_JWT
cd apps/ipfs-gateway   && npx wrangler secret put PINATA_JWT
```

---

## 6. Database — Cloudflare D1

**Database name:** `aroha-registry`  
**Database ID:** `68e2d12b-88ff-4921-9a8b-65475ea52b03`  
**Engine:** SQLite (Cloudflare D1)  
**Schema file:** `apps/registry-server/schema.sql`

### Tables

**`agent_records`**

| Column | Type | Notes |
|--------|------|-------|
| `did_hash` | TEXT PRIMARY KEY | SHA-256 of DID |
| `did` | TEXT NOT NULL | Full DID string |
| `public_key` | TEXT NOT NULL | Base64url Ed25519 public key |
| `reputation_score` | REAL | Bayesian Beta score (0–1) |
| `key_version` | INTEGER | Increments on rotation |
| `key_rotated_at` | DATETIME | Timestamp of last rotation |

**`capability_index`** — extracted from IPFS manifests; enables capability-based search

**`mcp_records`** — registered Model Context Protocol servers

**`skill_records`** — registered agent skills

**`api_keys`** — organisation API keys (stored as SHA-256 hash, never plaintext)

### Common D1 Commands

```bash
# List databases
npx wrangler d1 list

# Run a query (remote)
npx wrangler d1 execute aroha-registry --remote --command "SELECT COUNT(*) FROM agent_records"

# Apply a migration
npx wrangler d1 migrations apply aroha-registry --remote

# Create a new migration file
npx wrangler d1 migrations create aroha-registry "add-column-x"
# Edit the generated SQL file, then apply

# Backup (export to local JSON)
npx wrangler d1 export aroha-registry --remote --output backup.sql
```

### Migrating to Postgres

The schema is ANSI SQL compatible. Differences to handle:
- Replace `INTEGER PRIMARY KEY AUTOINCREMENT` with `SERIAL PRIMARY KEY`
- Replace SQLite `BOOLEAN` with `BOOLEAN` or `SMALLINT`
- Replace `NUMERIC` columns used for wei/token amounts with `NUMERIC(78,0)` or `DECIMAL`
- Update `DATABASE_URL` env var and switch the worker from D1 binding to a Hyperdrive or direct Postgres connection

---

## 7. Authentication — NextAuth v5

> The website, and with it this auth setup, moved to a separate private repository on 2026-08-23. The `apps/website/` paths below are in that repository, not this one.

**Package:** `next-auth@5.0.0-beta.31`  
**Config file:** `apps/website/src/auth.ts`  
**Route:** `apps/website/src/app/api/auth/[...nextauth]/route.ts`

### Providers

| Provider | Env vars | OAuth App Location |
|----------|----------|--------------------|
| GitHub | `AUTH_GITHUB_ID`, `AUTH_GITHUB_SECRET` | https://github.com/settings/developers |
| Google | `AUTH_GOOGLE_ID`, `AUTH_GOOGLE_SECRET` | https://console.cloud.google.com/apis/credentials |

### Session Behaviour

- JWT strategy (no database session table needed)
- Token augmented with `provider` field (`github` or `google`)
- Session exposes `user.id` as `{provider}:{sub}` (e.g. `github:12345678`)
- Sign-in page: `/keys`

### Callback URLs to Register

When creating OAuth apps, register these callback URLs:

**Development:**
```
http://localhost:3000/api/auth/callback/github
http://localhost:3000/api/auth/callback/google
```

**Production (add these to the OAuth app):**
```
https://aroha-labs.com/api/auth/callback/github
https://aroha-labs.com/api/auth/callback/google
```

### How to Add a New OAuth Provider

1. Install the provider package (if not built into next-auth v5)
2. Add to `apps/website/src/auth.ts`:
   ```ts
   import NewProvider from "next-auth/providers/new-provider";
   // add to providers: [..., NewProvider({ clientId: ..., clientSecret: ... })]
   ```
3. Add env vars to Vercel dashboard
4. Register callback URL in the provider's developer console

### How to Rotate `AUTH_SECRET`

```bash
openssl rand -base64 32
```

Update in Vercel dashboard → Environment Variables. **Note:** rotating this invalidates all existing sessions — users will be signed out.

---

## 8. External Services

### Pinata (IPFS Pinning)

**Purpose:** Pin agent manifest JSON to IPFS; retrieve CIDs reliably without public gateway delays  
**Used by:** `aroha-registry` worker, `aroha-ipfs-gateway` worker  
**Console:** https://app.pinata.cloud/developers/api-keys  
**Secret name:** `PINATA_JWT` (Wrangler secret on both workers)

### Stripe

**Purpose:** Payment settlement backend via `StripeSettlement` in `@aroha-sdk/settlement` (optional extension; source not in this repository)  
**Env var:** `STRIPE_SECRET_KEY`  
**Pattern:** Authorize on `onReserve`, capture on `onCommit`, void on `onCancel`  
**Dashboard:** https://dashboard.stripe.com

### Anthropic / OpenAI / Google AI

**Purpose:** LLM providers used by demos and agent examples  
**Env vars:** `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `GOOGLE_API_KEY`  
**Used via:** Vercel AI SDK (`@ai-sdk/anthropic`, `@ai-sdk/openai`, `@ai-sdk/google`)

### Composio

**Purpose:** Exposes Aroha agents as Composio-compatible actions  
**Package:** `@aroha-sdk/composio-bridge`  
**Env var:** `COMPOSIO_API_KEY`


---

## 9. Environment Variables — Complete Reference

### Website (`apps/website/.env.local`, in the separate website repository)

```bash
# ── NextAuth ──────────────────────────────────────────────────
AUTH_SECRET=                        # required — openssl rand -base64 32
AUTH_GITHUB_ID=                     # GitHub OAuth App Client ID
AUTH_GITHUB_SECRET=                 # GitHub OAuth App Client Secret
AUTH_GOOGLE_ID=                     # Google OAuth Client ID
AUTH_GOOGLE_SECRET=                 # Google OAuth Client Secret

# ── Registry ─────────────────────────────────────────────────
NEXT_PUBLIC_REGISTRY_URL=https://aroha-registry.aroha-labs.workers.dev
```

### Registry Worker (`apps/registry-server/`)

```bash
# Wrangler secrets (set via: npx wrangler secret put <NAME>)
ADMIN_SECRET=                       # protects POST /v1/auth/keys
PINATA_JWT=                         # Pinata API JWT

# Wrangler env var (in wrangler.toml)
IPFS_GATEWAY=https://aroha-ipfs-gateway.aroha-labs.workers.dev/ipfs
```

### IPFS Gateway Worker (`apps/ipfs-gateway/`)

```bash
# Wrangler secrets
PINATA_JWT=                         # same JWT as registry worker
```

### Agent Identity (all agents)

```bash
AROHA_AGENT_DID=                    # did:aroha:agent:<id>
AROHA_PRIVATE_KEY=                  # base64url Ed25519 private key
AROHA_API_KEY=                      # registry API key
REGISTRY_URL=https://aroha-registry.aroha-labs.workers.dev
PORT=3000
```

### Settlement (when using payment backends)

```bash
STRIPE_SECRET_KEY=                  # sk_live_... or sk_test_...
DATABASE_URL=                       # Postgres connection string (EscrowSettlement)
ESCROW_SIGNER_KEY=                  # signing key for escrow mandates
AP2_PRIVATE_JWK=                    # JSON — ECDSA P-256 private key
AP2_PUBLIC_JWK=                     # JSON — ECDSA P-256 public key
AP2_PROCESSOR_URL=                  # AP2 payment processor endpoint (optional)
AP2_PROCESSOR_KEY=                  # AP2 processor auth key (optional)
```

### LLM Providers

```bash
ANTHROPIC_API_KEY=
OPENAI_API_KEY=
GOOGLE_API_KEY=
VLLM_URL=http://localhost:8000      # local vLLM server
VLLM_MODEL=Qwen/Qwen2.5-1.5B-Instruct
```

### Blockchain / EVM (optional, registry alternative)

```bash
RPC_URL=http://localhost:8545
REGISTRY_ADDRESS=0x0000000000000000000000000000000000000001
```

### Telemetry

```bash
AROHA_TELEMETRY=0                   # 0=off, 1=on (CLI usage telemetry)
```

---

## 10. NPM Package Publishing

**Registry:** https://registry.npmjs.org  
**Scope:** `@aroha-sdk`  
**Required GitHub secret:** `NPM_TOKEN`

### Release Process (step by step)

1. **Bump the version** of each package you are releasing (packages version independently)
2. **Update `CHANGELOG.md`** — list each release tag, e.g. `@aroha-sdk/core@1.10.0` (release-gate checks this)
3. **Ensure no `file:` deps** in any package.json (release-gate rejects these)
4. **Push to main**, ensure CI passes
5. **Push the tag(s)**
6. **Publish a GitHub Release** from each tag — `publish-npm.yml` runs `release-gate.yml` first, then publishes that package
7. Monitor the Actions run — failed packages are logged with reasons

### Manual publish (single package)

```bash
cd packages/aroha-core
npm publish --access public
```

### How to add a new package to the publish pipeline

The `publish-npm.yml` workflow auto-discovers all directories matching `packages/aroha-*/`. To add a new publishable package:
1. Create `packages/aroha-<name>/` with a `package.json` that has `"name": "@aroha-sdk/<name>"`
2. No workflow changes needed — it will be picked up automatically on next release

### How to deprecate a package

```bash
npm deprecate @aroha-sdk/old-package@"<= 1.0.0" "Use @aroha-sdk/new-package instead"
```

---

## 11. Multi-Language SDK Publishing

### PyPI (`sdks/aroha-py`)

**Trigger:** GitHub release published with a `python-v<version>` tag (must equal `pyproject.toml`'s version)  
**Build tool:** Hatch (`hatch build`)  
**Publish:** `pypa/gh-action-pypi-publish` with OIDC trusted publishing (no stored secret)  
**Skip existing:** true (idempotent)  
**Python version:** 3.11

To publish manually:
```bash
cd sdks/aroha-py
pip install hatch
hatch build
hatch publish
```

### Maven / Sonatype (`sdks/java`)

**Status:** not yet published to Maven Central.  
**Trigger:** GitHub release published with a `java-v<version>` tag (must equal the `pom.xml` version); tests run with `-DfailIfNoTests=true`  
**Java:** 21 (temurin)  
**Command:** `mvn --batch-mode deploy -P release`

**Required GitHub secrets:**
- `SONATYPE_USERNAME` → `MAVEN_USERNAME`
- `SONATYPE_PASSWORD` → `MAVEN_PASSWORD`
- `GPG_PASSPHRASE` → `MAVEN_GPG_PASSPHRASE`
- `GPG_PRIVATE_KEY`

### Go (`sdks/go`)

**Status:** unreleased (no `sdks/go/v*` tag yet; pkg.go.dev has no version).  
**Trigger:** push of a `sdks/go/v<version>` tag, or manual dispatch (which creates the tag)  
**Module:** `github.com/ArohaLabs/aroha-protocol/sdks/go`  
**Process:** after `go mod verify`, vet and tests, requests the version from `proxy.golang.org` so pkg.go.dev indexes it — there is no explicit publish step for Go modules.

---

## 12. DNS & Domains

| Domain / Subdomain | Purpose | Points to |
|-------------------|---------|-----------|
| `www.aroha-labs.com` | Main website (apex `aroha-labs.com` redirects here) | Vercel |
| `registry.aroha-labs.com` | Registry API (alias, planned — not configured) | `aroha-registry.aroha-labs.workers.dev` |
| `ipfs.aroha-labs.com` | IPFS Gateway (alias, planned — not configured) | `aroha-ipfs-gateway.aroha-labs.workers.dev` |
| `aroha-registry.aroha-labs.workers.dev` | Registry Worker (canonical) | Cloudflare |
| `aroha-ipfs-gateway.aroha-labs.workers.dev` | IPFS Worker (canonical) | Cloudflare |

**Hardcoded in source:**
- `https://aroha-labs.com/docs/errors#<ERROR_CODE>` — error reference URLs in SDK packages
- `https://aroha-labs.com/contexts/v1` — JSON-LD context for DID documents
- `https://aroha-labs.com/contexts/aroha-web/v1` — web DID context

**OAuth callback URLs (website repository; registered in provider dashboards):**
```
https://aroha-labs.com/api/auth/callback/github
https://aroha-labs.com/api/auth/callback/google
```

**How to add a custom domain to Vercel:**  
Vercel Dashboard → Project → Settings → Domains → Add Domain

**How to add a custom domain to a Cloudflare Worker:**  
Cloudflare Dashboard → Workers → `aroha-registry` → Settings → Triggers → Custom Domains → Add

---

## 13. Packages — Full List

Packages are under `packages/` and published as `@aroha-sdk/*` on npm, except the four marked as developed outside this repository. Versions are those of release 2.0.0 (2026-10-19); the full list of npm packages in that release, including ones not listed here (`bbs`, `delegation`, `gmail-mcp`, `mcp-guard`, `mcp-server`, `trust`), is in [CHANGELOG.md](https://github.com/ArohaLabs/aroha-protocol/blob/main/CHANGELOG.md). `@aroha-sdk/store-postgres` and `@aroha-sdk/store-redis` are not yet published.

| Package name | Version | Description |
|-------------|---------|-------------|
| `@aroha-sdk/core` | 2.0.0 | Identity (Ed25519 key pairs, DIDs), crypto primitives, message envelope, HTTP transport |
| `@aroha-sdk/cli` | 1.3.0 | CLI scaffolder (`create-aroha-agent`), protocol format converters |
| `@aroha-sdk/credentials` | 2.0.0 | Spending mandates (issue, attenuate, verify), RBAC, credential registry |
| `@aroha-sdk/registry` | 2.0.0 | Registry SDK — HTTP client, blockchain wrapper, IPFS manifest storage |
| `@aroha-sdk/settlement` | 2.0.0 | Pluggable payment backends: Null, Quota, Stripe, Escrow, ApiKey, Postgres, AP2 (developed outside this repository) |
| `@aroha-sdk/orchestrator` | 1.4.0 | SagaEngine, agent selection, capability negotiation, settlement hooks (developed outside this repository) |
| `@aroha-sdk/a2a-bridge` | 2.0.0 | A2A 1.0 (Agent2Agent) protocol adapter |
| `@aroha-sdk/audit` | 1.4.1 | Tamper-evident append-only audit log, SIEM export |
| `@aroha-sdk/cache` | 1.2.2 | Semantic caching with content-addressed keys |
| `@aroha-sdk/chaos` | 1.2.2 | Chaos engineering — fault injection, compensation testing |
| `@aroha-sdk/commerce` | 1.2.3 | Commerce patterns (B2B, B2C, C2B) (developed outside this repository) |
| `@aroha-sdk/composio-bridge` | 1.2.3 | Composio integration — exposes Aroha as Composio actions |
| `@aroha-sdk/evals` | 1.2.3 | Evaluation harness — golden-dataset tests, LLM-as-judge |
| `@aroha-sdk/hermes-bridge` | 1.2.5 | Hermes Agent / ZeroClaw MCP stdio bridge |
| `@aroha-sdk/langchain-bridge` | 2.0.0 | LangChain bridge and OpenAI function tools |
| `@aroha-sdk/mcp-bridge` | 3.0.0 | Model Context Protocol adapter |
| `@aroha-sdk/micro` | 2.0.0 | Minimal Express-like one-file API |
| `@aroha-sdk/openclaw-bridge` | 2.0.0 | OpenClaw bridge — skills ↔ capabilities |
| `@aroha-sdk/policy` | 1.3.1 | Policy-as-Code, JSON boundary enforcement |
| `@aroha-sdk/preferences` | 1.2.3 | User preference layer — filtering and scoring |
| `@aroha-sdk/reputation` | 1.4.1 | Bayesian Beta reputation engine, 11 signals, Thompson Sampling (developed outside this repository) |
| `@aroha-sdk/resilience` | 1.2.2 | Circuit breaker, bulkhead, retry, health checks |
| `@aroha-sdk/run` | 2.0.0 | `/v1/run` server and client — core agent request/response |
| `@aroha-sdk/telemetry` | 1.2.3 | W3C Trace Context propagation, OpenTelemetry Gen-AI semantics |
| `@aroha-sdk/trusted-mesh` | 2.0.0 | Skip Ed25519 verification inside VPC / mTLS environments |
| `create-aroha-agent` | 1.3.0 | Zero-config agent scaffolder (unscoped npm package) |

---

## 14. Agents — Full List

Only `agents/mock-provider-agent` remains under `agents/` (a private workspace, not published to npm). The other demo agents were removed (see [CHANGELOG.md](https://github.com/ArohaLabs/aroha-protocol/blob/main/CHANGELOG.md), Unreleased).

| Package name | Version | Description | Default port |
|-------------|---------|-------------|-------------|
| `@aroha-sdk/mock-provider-agent` | 1.0.1 | Reference provider (Expedia-style flight/hotel booking) | 3001 |

---

## 15. Applications — Full List

| App | Framework | Hosting | Description |
|-----|-----------|---------|-------------|
| `@aroha-sdk/website` | Next.js | Vercel | Main website — moved to a separate private repository on 2026-08-23; its hosted Hub, Studio, Playground and API-keys pages are offline |
| `@aroha/registry-server` | Cloudflare Workers + D1 | Cloudflare | Agent registry REST API with SQLite database |
| `@aroha/ipfs-gateway` | Cloudflare Workers | Cloudflare | IPFS proxy — authenticates Pinata requests, service-binds to registry |
| `@aroha-sdk/status` | Express | Self-hosted | Health check service — polls registry and IPFS gateway |

---

## 16. Security & Compliance

**Security contact:** contact@aroha-labs.com with the subject "SECURITY" — see [SECURITY.md](https://github.com/ArohaLabs/aroha-protocol/blob/main/SECURITY.md)  
**GitHub advisories:** https://github.com/ArohaLabs/aroha-protocol/security/advisories/new (private vulnerability reporting is enabled)  
**Advisory expiry:** 2027-01-01  
**License:** Apache-2.0 (Copyright 2026 Aroha Labs)

### Key Rotation

**Ed25519 agent keys:**
- Tracked in `agent_records` via `key_version` and `key_rotated_at` columns
- Mandate tokens issued before rotation are cryptographically rejected (public key mismatch)
- To rotate: generate a new key pair, call `PUT /v1/agents/{did}/key` with the new public key and a signature from the old key

**AP2 ECDSA P-256 keys (AP2Settlement):**
```typescript
// Generate new pair
const kp = await AP2Settlement.generateKeyPair();
const { privateJwk, publicJwk } = await AP2Settlement.exportKeyPair(kp);
// Store privateJwk in secrets manager, update AP2_PRIVATE_JWK + AP2_PUBLIC_JWK env vars
```

**AUTH_SECRET (NextAuth):**
```bash
openssl rand -base64 32
# Update in Vercel → Environment Variables
# Warning: all active sessions will be invalidated
```

**ADMIN_SECRET (registry worker):**
```bash
cd apps/registry-server
npx wrangler secret put ADMIN_SECRET
```

**PINATA_JWT:**
1. Revoke old key at https://app.pinata.cloud/developers/api-keys
2. Generate new JWT
3. Update both workers:
```bash
cd apps/registry-server && npx wrangler secret put PINATA_JWT
cd apps/ipfs-gateway   && npx wrangler secret put PINATA_JWT
```

**NPM_TOKEN:**
1. Generate at https://www.npmjs.com/settings/tokens (automation token, read/write)
2. Update in GitHub → Settings → Secrets → `NPM_TOKEN`

**VERCEL_TOKEN:**
1. Generate at https://vercel.com/account/tokens
2. Update in GitHub → Settings → Secrets → `VERCEL_TOKEN`

---

## 17. Monitoring & Observability

### Status App (`apps/status`)

**Default port:** 4000  
**Checks:**
- Registry API: `GET {REGISTRY_URL}/health`
- IPFS Gateway: `GET {IPFS_URL}/api/v0/version`

**Run:**
```bash
cd apps/status
STATUS_PORT=4000 npm start
```

### Conformance Score

- Generated daily by `conformance.yml` and on every push to `main`
- Available as a GitHub Actions artifact (90-day retention)
- Scorecard format: `{ conformanceRate, passed, failed, total, status }`

### Tracing

- W3C Trace Context headers propagated by `@aroha-sdk/telemetry`
- OpenTelemetry Gen-AI semantic conventions
- Trace IDs visible in agent call logs and `/v1/run` response `trace` field

### CLI Telemetry

- Endpoint: **none built in.** Nothing is sent and nobody is prompted unless an operator sets
  `AROHA_TELEMETRY_ENDPOINT` to an https URL they control. (The CLI used to post to
  `telemetry.aroha.dev`, a domain the project does not own; that default was removed.)
- Opt out: set `AROHA_TELEMETRY=0`
- Collects (only when an endpoint is set and the machine opted in with `aroha telemetry on`): command name, `--flag` names, Node version and a random session ID — no user data, no agent content. There is no startup prompt; `aroha telemetry status` shows the current state.

---

## 18. How to Update Things

Quick-reference for the most common operational tasks.

### Add a new doc page to the website

*In the separate website repository.*

1. Create `apps/website/src/app/docs/<slug>/page.tsx`
2. Add sidebar entry in `apps/website/src/components/docs-sidebar.tsx`
3. Add search entry in `apps/website/src/components/search.tsx` (the `INDEX` array)
4. Push to `main`

### Add a new blog post

*In the separate website repository.*

1. Add the post metadata to the `POSTS` array in `apps/website/src/app/blog/page.tsx`
2. Create `apps/website/src/app/blog/<slug>/page.tsx` with the full post
3. Add to search index in `apps/website/src/components/search.tsx`
4. Push to `main`

### Update the registry database schema

1. Create a new migration:
   ```bash
   cd apps/registry-server
   npx wrangler d1 migrations create aroha-registry "describe-the-change"
   ```
2. Edit the generated SQL file
3. Test locally:
   ```bash
   npx wrangler d1 migrations apply aroha-registry --local
   ```
4. Apply to production:
   ```bash
   npx wrangler d1 migrations apply aroha-registry --remote
   ```

### Release a new version of the SDK packages

See [CONTRIBUTING.md → Releasing](https://github.com/ArohaLabs/aroha-protocol/blob/main/CONTRIBUTING.md#releasing): one tag per product and version (`@aroha-sdk/<name>@<v>`, `python-v<v>`, `java-v<v>`, `sdks/go/v<v>`), each listed in `CHANGELOG.md`; each publish workflow acts only on its own tags.

### Add a new npm package

1. Create `packages/aroha-<name>/src/index.ts` and `package.json`
2. Add `"name": "@aroha-sdk/<name>"` in its package.json
3. Add it to the root `tsconfig.json` references
4. It will be auto-discovered by `publish-npm.yml` on next release

### Rotate all secrets (emergency)

Priority order:
1. `ADMIN_SECRET` (Wrangler) — controls registry mutations
2. `PINATA_JWT` (Wrangler × 2) — controls IPFS access
3. `AUTH_SECRET` (Vercel) — invalidates all sessions
4. `NPM_TOKEN` (GitHub Secrets) — controls package publishing
5. `VERCEL_TOKEN` (GitHub Secrets) — Vercel access token (no current workflow references it)
6. OAuth secrets — update GitHub + Google developer consoles, then Vercel env vars

### Change the default IPFS gateway URL

It is hardcoded in `apps/registry-server/wrangler.toml` as `IPFS_GATEWAY`. To change it:
```bash
cd apps/registry-server
# Edit wrangler.toml, then:
npx wrangler deploy
```

Also update `IPFS_GATEWAY_URL` / `IPFS_ENDPOINT` in any agent `.env` files referencing the old URL.

### Scale the registry under load

Current setup: Cloudflare Workers (globally distributed, auto-scaled) + D1 (SQLite, single write region).

If D1 write throughput becomes a bottleneck:
1. Migrate schema to Postgres (schema is ANSI-compatible — see [Database section](#6-database--cloudflare-d1))
2. Replace D1 binding in `wrangler.toml` with a Hyperdrive binding pointing to managed Postgres
3. Update the registry worker to use `env.DB` as a Postgres client instead of D1

### Add a new OAuth provider to the website

*In the separate website repository.*

1. Add provider to `apps/website/src/auth.ts`
2. Add env vars to Vercel dashboard
3. Register callback URL: `https://aroha-labs.com/api/auth/callback/<provider>`
4. Push to `main`

---

*This document is generated from direct inspection of the codebase and is authoritative over any other reference. Keep it updated when infrastructure changes are made.*
