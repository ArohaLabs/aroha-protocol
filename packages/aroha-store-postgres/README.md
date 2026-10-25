# @aroha-sdk/store-postgres

Durable, shared Postgres stores for [`@aroha-sdk/credentials`](../aroha-credentials). Use them on any server that runs more than one process or restarts:

| Store | Implements | Protects |
|---|---|---|
| `PostgresNonceStore` | `HttpPresentationNonceStore` | replay of an `Aroha-Mandate` presentation |
| `PostgresEnrollmentStore` | `EnrollmentStore` | single-use enrollment challenges, account → DID bindings |
| `PostgresSpendingLedger` | `ISpendingLedger` | running totals against each mandate's limit |

The in-memory stores that ship with `@aroha-sdk/credentials` forget everything on restart and are not shared between processes, so a restart re-opens every nonce and resets every running total. These do not.

## Install

```bash
npm install @aroha-sdk/store-postgres pg
```

Requires Node 22+ and Postgres 12+ (tested on 16). `pg` 8 is a peer dependency.

## Schema

Run `migrate(pool)` once at start-up. It is idempotent and safe to run from several processes at once (it takes a transaction-scoped advisory lock). If you apply migrations with your own tool, use [`migrations/001_init.sql`](migrations/001_init.sql) (default prefix `aroha_`) or `schemaSql(prefix)`.

| Table | Columns |
|---|---|
| `aroha_http_nonces` | `key` TEXT PK, `expires_at_ms` BIGINT |
| `aroha_enrollment_challenges` | `challenge` TEXT PK, `account_id` TEXT, `expires_at_ms` BIGINT |
| `aroha_enrollment_bindings` | `account_id` TEXT PK, `did` TEXT, `updated_at` TIMESTAMPTZ |
| `aroha_spending_budgets` | `key` TEXT PK, `limit_micros` BIGINT, `allocated_micros` BIGINT, `expires_at_ms` BIGINT NULL |
| `aroha_spending_allocations` | `key` TEXT → budgets ON DELETE CASCADE, `allocation_id` TEXT, `amount_micros` BIGINT, PK (`key`, `allocation_id`) |

Money is integer micro-USD; times are Unix milliseconds from your application's clock. The layout is shared with the Python stores, so TypeScript and Python servers can use one database. Table names take a `tablePrefix` option (default `aroha_`, must match `^[a-z_][a-z0-9_]{0,40}$`); use the same prefix for `migrate()` and the stores. Every value is a bound parameter.

## Usage

### Replay protection and spending

```ts
import pg from "pg";
import { verifyHttpSpendRequest } from "@aroha-sdk/credentials";
import { migrate, PostgresNonceStore, PostgresSpendingLedger } from "@aroha-sdk/store-postgres";

const pool = new pg.Pool({ connectionString: process.env.DATABASE_URL });
await migrate(pool);
const nonces = new PostgresNonceStore(pool);
const ledger = new PostgresSpendingLedger(pool);

const result = await verifyHttpSpendRequest(req.headers["aroha-mandate"], {
  audience: "https://api.example.com", method: req.method, url: req.url, body: rawBody,
  nonces, ledger, expectedRoot: customerDid, isRevoked: null, amountUsd: invoice.amountUsd,
});
if (!result.ok) res.status(result.status).json({ code: result.code });
// …do the work; on failure: await result.charge.release();
```

### Enrollment

```ts
import pg from "pg";
import { completeEnrollment, enrolledDid, issueEnrollmentChallenge } from "@aroha-sdk/credentials";
import { migrate, PostgresEnrollmentStore } from "@aroha-sdk/store-postgres";

const pool = new pg.Pool({ connectionString: process.env.DATABASE_URL });
await migrate(pool);
const enrollment = new PostgresEnrollmentStore(pool, { maxChallenges: 100_000 });

// Signed-in customer asks for a challenge…
const challenge = await issueEnrollmentChallenge(enrollment, { authenticatedAccountId: session.accountId });
// …and later sends back { did, challenge, proof } from signEnrollment().
const done = await completeEnrollment(enrollment, {
  authenticatedAccountId: session.accountId, audience: "https://api.example.com", did, challenge: body.challenge, proof,
});
const root = await enrolledDid(enrollment, session.accountId); // pass as expectedRoot
```

### Housekeeping

Expired nonces and challenges are deleted opportunistically (every 256 claims / 64 issues by default; `pruneEvery: 0` turns it off). Each store also has `prune(nowMs?)` for a scheduled job. `PostgresSpendingLedger.prune()` deletes only budgets that were given an `expiresAt`.

## Guarantees

- **Nonce claim is atomic.** `INSERT … ON CONFLICT (key) DO UPDATE … WHERE expires_at_ms < now RETURNING 1`: of any number of concurrent claims of one key, exactly one returns `true`. An entry whose presentation has expired may be claimed again, as with the in-memory store.
- **Challenges are single-use.** `consumeChallenge` is `DELETE … RETURNING`.
- **Budgets cannot be overspent.** `allocate` is one statement: a conditional `UPDATE … SET allocated_micros = allocated_micros + $amount WHERE … allocated_micros + $amount <= limit_micros` plus the allocation insert in a CTE. `release` deletes the allocation and subtracts it in one statement, so repeating it is harmless.
- **Fail closed.** Every database error is thrown, never swallowed, so `verifyHttpPresentation` refuses with `NONCE_STORE_UNAVAILABLE`, `verifyHttpSpendRequest` with `LEDGER_UNAVAILABLE` (503) and `completeEnrollment` with `STORE_UNAVAILABLE` (503).

The enrollment bound (`maxChallenges`) is checked in the inserting statement; concurrent issuers can overshoot it by at most the number of inserts running at that instant.

## Testing

`npm test` runs the shared store contract against the in-memory reference stores and skips the Postgres suite unless `AROHA_TEST_POSTGRES_URL` is set:

```bash
AROHA_TEST_POSTGRES_URL=postgres://user:pass@127.0.0.1:5432/aroha_test npm test
```

Each run creates tables under a random prefix and drops them afterwards.

## License

Apache-2.0
