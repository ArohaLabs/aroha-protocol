<!-- Copyright (c) 2026 Aroha Labs
     SPDX-License-Identifier: Apache-2.0 -->

# Deploying the Aroha Registry Server

One-time setup, then `npm run deploy` on every release.

## 1. Create the D1 database

```sh
cd apps/registry-server
npm run db:create
# Paste the database_id printed into wrangler.toml
```

## 2. Apply the schema

```sh
npm run db:migrate          # local dev
npm run db:migrate:remote   # production
```

## 3. Set secrets

```sh
wrangler secret put ADMIN_SECRET   # random string — protects key provisioning
```

## 4. Deploy

```sh
npm run deploy
# Cloudflare assigns: https://aroha-registry.<your-account>.workers.dev
```

## 5. (Optional) Add a custom domain

The managed registry is served from its workers.dev host,
`https://aroha-registry.aroha-labs.workers.dev` (`AROHA_MANAGED_REGISTRY_URL`
in `@aroha-sdk/core/endpoints`); no custom domain is attached today. To add
one: Cloudflare dashboard → Workers → aroha-registry → Settings → Domains, add
the hostname (Cloudflare auto-provisions TLS), then set `workers_dev = false`
in `wrangler.toml` (see the comment there) and update the SDK constant.

## 6. Provision your first org API key

```sh
curl -X POST https://aroha-registry.<your-account>.workers.dev/v1/auth/keys \
  -H "Authorization: Bearer <ADMIN_SECRET>" \
  -H "Content-Type: application/json" \
  -d '{"orgName": "my-org"}'
# → { "key": "...", "orgName": "my-org", "note": "Store this key securely" }
```

## Database migrations

**Owner:** @projectmed99 (the project's one maintainer — see `MAINTAINERS.md`).
**Status:** manual process. Nothing below is enforced by the repository
ruleset or a required check; it relies on the person deploying following it.

> **Status note:** this file does not record which migrations are applied to
> the Aroha-operated (production) D1 database. A deploy of code that reads
> columns from a migration that has not been applied will fail; run
> `npm run db:check:remote` and use the procedure below.

Scripts (from `package.json`; all wrap `scripts/migrate.mjs`, which targets
the D1 database `aroha-registry`):

| Command | What it does |
|---|---|
| `npm run db:check:remote` | `node scripts/migrate.mjs --check --remote` — lists pending migrations on production and exits 1 if any are pending. Changes nothing. |
| `npm run db:migrate:remote` | `node scripts/migrate.mjs --remote` — applies pending migrations to production, in filename order. |
| `npm run db:check` / `npm run db:migrate` | Same, against the local database. |
| `npm run deploy` | Runs `migrate.mjs --check --remote` and only then `wrangler deploy`; a pending migration stops the deploy. |
| `npm run deploy:force` | `wrangler deploy` with **no** migration check. |

### Procedure

Run from `apps/registry-server`.

1. **Check for drift.** Always run this before any deploy:

   ```sh
   npm run db:check:remote
   ```

   Exit 0 = up to date; skip to step 5. Exit 1 = pending migrations; continue.

2. **Record a Time Travel bookmark** (the rollback point) and write it in the
   deploy record before changing anything:

   ```sh
   npx wrangler d1 time-travel info aroha-registry
   ```

3. **Apply the migrations:**

   ```sh
   node scripts/migrate.mjs --remote     # same as: npm run db:migrate:remote
   ```

4. **Confirm** the database is now current — `npm run db:check:remote` must
   exit 0.

5. **Deploy** with `npm run deploy` (which repeats the check).

### Rollback

D1 Time Travel restores the whole database to an earlier point. Writes made
after that point are lost, so record what is being discarded.

```sh
npx wrangler d1 time-travel restore aroha-registry --bookmark=<bookmark>
# or
npx wrangler d1 time-travel restore aroha-registry --timestamp=<ts>
```

If the deployed Worker code depends on the restored-away schema, redeploy
the previous Worker version as well.

### Rules

- Never run `npm run deploy:force` without writing down, in the deploy
  record, the reason the migration check is being skipped.
- Never edit an already-applied migration file; add a new numbered one.

### Drift-check workflow (manual)

`.github/workflows/registry-migrations-check.yml` runs the same remote
drift check from GitHub Actions. It is `workflow_dispatch` only (it does not
run on push or on a schedule) and runs in the `release` environment. It
needs the `CLOUDFLARE_API_TOKEN` and `CLOUDFLARE_ACCOUNT_ID` secrets, which
**do not exist yet**; without them the workflow fails fast rather than
reporting a false "up to date". Until they are provisioned, run
`npm run db:check:remote` locally.

## Migrating to Postgres (zero downtime)

See `src/repository.ts` for the full checklist. Short version:

1. Implement `PostgresRepository` satisfying `RegistryRepository`
2. Export: `wrangler d1 export aroha-registry --output=dump.sql`
3. Import: `pgloader dump.sql postgres://...`
4. Serve the registry from a custom domain (the workers.dev host has no DNS to flip) and set its TTL to 60 s (24 h before migration)
5. In `src/index.ts` replace `new D1Repository(c.env.DB)` with `new PostgresRepository(...)`
6. Deploy new server → flip CNAME → done
