# @aroha-sdk/store-redis

Shared Redis stores for [`@aroha-sdk/credentials`](../aroha-credentials). Use them on any server that runs more than one process or restarts:

| Store | Implements | Protects |
|---|---|---|
| `RedisNonceStore` | `HttpPresentationNonceStore` | replay of an `Aroha-Mandate` presentation |
| `RedisEnrollmentStore` | `EnrollmentStore` | single-use enrollment challenges, account → DID bindings |
| `RedisSpendingLedger` | `ISpendingLedger` | running totals against each mandate's limit |

The in-memory stores that ship with `@aroha-sdk/credentials` forget everything on restart and are not shared between processes. These keep state in Redis.

## Install

```bash
npm install @aroha-sdk/store-redis ioredis
```

Requires Node 22+ and Redis 6+ (tested on 7). `ioredis` 5 is a peer dependency: it supports Redis Cluster and Sentinel with one client type, and the monorepo already uses it (`@aroha-sdk/cache`).

## Key layout

No schema to migrate. Every key starts with `keyPrefix` (default `aroha:`; 1-64 characters from `[A-Za-z0-9:_.{}-]`):

| Key | Type | Content |
|---|---|---|
| `aroha:nonce:<key>` | string | `"1"`, expires `expiresAtMs - nowMs + 1` ms after it is set |
| `aroha:enroll:challenge:<challenge>` | string | `{"accountId":…,"expiresAtMs":…}`, expires with the challenge |
| `aroha:enroll:challenges` | sorted set | outstanding challenges, scored by `expiresAtMs` |
| `aroha:enroll:binding:<accountId>` | string | the enrolled DID |
| `aroha:ledger:budget:<key>` | hash | `limit`, `allocated` (integer micro-USD as strings); `expires` (Unix ms) only when `init` was given one |
| `aroha:ledger:alloc:<key>` | hash | `allocationId` → micro-USD, one field per live allocation |

The layout is shared with the Python stores, so TypeScript and Python servers can use one Redis. Ledger keys are `grantor#mandateId` (`mandateRedemptionKey`). Budget keys have no Redis TTL; a budget given `expiresAt` stays in Redis but refuses every `allocate` after that time.

**Redis Cluster:** the enrollment and ledger scripts touch two keys each, so put a hash tag in the prefix (`keyPrefix: "{aroha}:"`). Without one, those calls fail with `CROSSSLOT`, and that failure refuses the request.

## Usage

### Replay protection and spending

```ts
import { Redis } from "ioredis";
import { verifyHttpSpendRequest } from "@aroha-sdk/credentials";
import { RedisNonceStore, RedisSpendingLedger } from "@aroha-sdk/store-redis";

// Fail fast while Redis is down instead of queueing commands.
const redis = new Redis(process.env.REDIS_URL!, { enableOfflineQueue: false, maxRetriesPerRequest: 1 });
const nonces = new RedisNonceStore(redis, { keyPrefix: "aroha:" });
const ledger = new RedisSpendingLedger(redis, { keyPrefix: "aroha:" });

const result = await verifyHttpSpendRequest(req.headers["aroha-mandate"], {
  audience: "https://api.example.com", method: req.method, url: req.url, body: rawBody,
  nonces, ledger, expectedRoot: customerDid, isRevoked: null, amountUsd: invoice.amountUsd,
});
if (!result.ok) res.status(result.status).json({ code: result.code });
// …do the work; on failure: await result.charge.release();
```

### Enrollment

```ts
import { Redis } from "ioredis";
import { completeEnrollment, enrolledDid, issueEnrollmentChallenge } from "@aroha-sdk/credentials";
import { RedisEnrollmentStore } from "@aroha-sdk/store-redis";

const redis = new Redis(process.env.REDIS_URL!, { enableOfflineQueue: false, maxRetriesPerRequest: 1 });
const enrollment = new RedisEnrollmentStore(redis, { maxChallenges: 100_000 });

// Signed-in customer asks for a challenge…
const challenge = await issueEnrollmentChallenge(enrollment, { authenticatedAccountId: session.accountId });
// …and later sends back { did, challenge, proof } from signEnrollment().
const done = await completeEnrollment(enrollment, {
  authenticatedAccountId: session.accountId, audience: "https://api.example.com", did, challenge: body.challenge, proof,
});
const root = await enrolledDid(enrollment, session.accountId); // pass as expectedRoot
```

## Guarantees

- **Nonce claim is atomic.** One command, `SET <key> 1 NX PX <ttl>`: of any number of concurrent claims, exactly one returns `true`. The TTL is relative, so it does not depend on the Redis clock agreeing with yours.
- **Challenges are single-use.** `consumeChallenge` is a Lua script (GET, DEL, ZREM); issuing prunes, checks `maxChallenges` and inserts in one script, so the bound is exact.
- **Budgets cannot be overspent.** `allocate` is a Lua script that checks `allocated + amount <= limit`, adds with `HINCRBY` and records the allocation in one step. `release` removes the allocation and subtracts it in one script, so repeating it is harmless.
- **Fail closed.** Every Redis error is thrown, never swallowed, so `verifyHttpPresentation` refuses with `NONCE_STORE_UNAVAILABLE`, `verifyHttpSpendRequest` with `LEDGER_UNAVAILABLE` (503) and `completeEnrollment` with `STORE_UNAVAILABLE` (503).

**Durability is Redis's.** For the ledger and the nonce store, run Redis with AOF persistence (`appendonly yes`; `appendfsync always` if losing the last second of spending is not acceptable). Without persistence a Redis restart forgets nonces and running totals. If you need the ledger to survive anything short of losing the disk, use [`@aroha-sdk/store-postgres`](../aroha-store-postgres).

## Testing

`npm test` skips the Redis suite unless `AROHA_TEST_REDIS_URL` is set:

```bash
AROHA_TEST_REDIS_URL=redis://127.0.0.1:6379 npm test
```

Each run writes under a random key prefix and deletes those keys afterwards. The contract suite is shared with `@aroha-sdk/store-postgres`.

## License

Apache-2.0
