<!-- Copyright (c) 2026 Aroha Labs
     SPDX-License-Identifier: Apache-2.0 -->

# `@aroha-sdk/settlement`

> **Developed in `ArohaLabs/aroha-extensions`.** `@aroha-sdk/settlement` stays published on npm; its
> source moved out of the protocol repository on 2026-10-25.


The `@aroha-sdk/settlement` package provides a pluggable financial and quota settlement interface (`IArohaSettlement`) for the `SagaEngine`. It enables you to seamlessly add API keys, token quotas, or atomic on-chain escrow to any Aroha saga, without changing your core agent logic.

```bash
npm install @aroha-sdk/settlement
```

---

## Why Pluggable Settlement?

The Aroha protocol kernel (`@aroha-sdk/core`) strictly handles messaging and identity. It has no opinion on whether an agent interaction is free, paid via API keys, metered by quota, or settled atomically via smart contracts.

By injecting a settlement strategy into the `SagaEngine`, you ensure that payment and quota deductions are perfectly synchronised with the `Reserve → Commit → Cancel` lifecycle of the agent saga. If a saga rolls back, funds are unconditionally refunded and quotas are released.

---

## The `IArohaSettlement` Interface

Every settlement strategy implements this interface. The `SagaEngine` automatically calls these hooks at the exact right moment during execution.

```typescript
export interface IArohaSettlement {
  /**
   * Called after a successful ArohaReserveAck.
   * Lock funds, decrement quota, or open an escrow.
   * Throwing rejects the step (triggers compensation).
   */
  onReserve(ctx: ReserveSettlementContext): Promise<void>;

  /**
   * Called after a successful ArohaCommitAck.
   * Approve a payment split or finalize a quota charge.
   * Throwing fails the commit (triggers LIFO compensation).
   */
  onCommit(ctx: CommitSettlementContext): Promise<void>;

  /**
   * Called when a step is cancelled during compensation.
   * Release held quota slots or unlock held funds.
   */
  onCancel(ctx: CancelSettlementContext): Promise<void>;

  /**
   * Called once at the end of the saga with the final outcome.
   * "SUCCESS" releases the escrow. "COMPENSATED" issues refunds.
   */
  onSagaComplete(sagaId: string, outcome: SettlementOutcome): Promise<void>;
}
```

---

## Built-in Settlement Strategies

`@aroha-sdk/settlement` ships six strategies at different maturity levels. `NullSettlement`, `ApiKeySettlement` and `QuotaSettlement` are stable. `PostgresSettlement` and `StripeSettlement` (Web2 backends, no blockchain) are **alpha**. `EscrowSettlement` is **pre-alpha**: it throws unless constructed with `acknowledgeAlpha: true`, and the `ArohaEscrow` contract it targets has no deployment, so it must not be used with real funds. None of them has had an independent security review.

### 1. `NullSettlement`

The default if no settlement is provided. A no-op implementation for free or internal agent networks.

```typescript
import { NullSettlement } from "@aroha-sdk/settlement";

const saga = new SagaEngine(client, orchestratorDID, privateKey, {
  settlement: new NullSettlement()
});
```

### 2. `ApiKeySettlement`

Validates that the orchestrator has configured a valid API key for the current provider.

```typescript
import { ApiKeySettlement } from "@aroha-sdk/settlement";

const settlement = new ApiKeySettlement({
  resolveKey: async (providerDID) => secureStorage.get(providerDID),
  onMissingKey: (provider) => { console.warn(`Missing key for ${provider}`); }
});
```

### 3. `QuotaSettlement`

Enforces invocation or compute quotas per orchestrator/provider pair. Temporarily holds a quota slot on `Reserve` and finalises the deduction on `Commit`. Drops the hold on `Cancel`.

```typescript
import { QuotaSettlement } from "@aroha-sdk/settlement";

const settlement = new QuotaSettlement({
  resolveQuota: async (orchestratorDID, providerDID) => quotaDB.get(),
  deductTokens: async (amount) => quotaDB.decrement(amount),
  releaseHold: async (amount) => quotaDB.increment(amount) // Rollback case
});
```

### 4. `EscrowSettlement`

> **Pre-alpha — not for real funds.** Requires `acknowledgeAlpha: true`; `ArohaEscrow.sol` is not deployed and has not been audited.

The Web3 settlement engine. Hooks into an EVM `IArohaEscrowClient` (such as `ethers.js` connected to `ArohaEscrow.sol`).

- **onReserve**: Opens the on-chain escrow with the orchestrator's funds.
- **onCommit**: Approves a payment split for the specific provider.
- **onSagaComplete (SUCCESS)**: Signals the oracle to release all approved splits to the providers.
- **onSagaComplete (COMPENSATED)**: Signals the oracle to refund the orchestrator in full.

```typescript
import { EscrowSettlement, IArohaEscrowClient } from "@aroha-sdk/settlement";
import { SagaEngine } from "@aroha-sdk/orchestrator";

// Ethers.js integration wrapper
const myEscrowClient: IArohaEscrowClient = new MyEthersEscrowClient();

const settlement = new EscrowSettlement({
  escrow: myEscrowClient,
  acknowledgeAlpha: true,      // required: throws without it
  totalBudgetWei: 1_000_000n,  // locked for the whole saga
  ttlSeconds: 3600,            // must exceed the longest expected saga
  resolveProviderAddress: async (did) => addressBook[did],
  resolveSplitWei: (ctx) => splitFor(ctx),
});

const saga = new SagaEngine(client, orchestratorDID, privateKey, {
  settlement
});

// Design intent: if the saga rolls back, the escrow refunds the orchestrator.
// Pre-alpha — the contract is undeployed and unaudited; test networks only.
```

### 5. `PostgresSettlement`

Enterprise Web2 settlement backend — tracks saga reservations and outcomes in a Postgres database. No blockchain, no IPFS. Ideal for internal enterprise deployments where you want the Aroha saga guarantees (atomic commit/rollback) without touching a smart contract.

```bash
npm install pg          # peer dependency
```

```typescript
import { PostgresSettlement } from "@aroha-sdk/settlement";

const settlement = new PostgresSettlement({
  connectionString: process.env.DATABASE_URL,
  // Optional: hook into your internal billing system
  onCharge: async (ctx) => {
    const approved = await internalBilling.authorize(ctx.sagaId, ctx.capability);
    return approved; // return false to reject and trigger compensation
  },
});

const saga = new SagaEngine(client, orchestratorDID, privateKey, { settlement });
```

`PostgresSettlement` creates two tables on first use (`aroha_settlement_reservations`, `aroha_settlement_sagas`). Pass `autoMigrate: false` to manage schema yourself.

You can also pass an existing `pg` Client or Pool via the `client` option to reuse your application's existing connection.

### 6. `StripeSettlement`

SaaS billing settlement using Stripe's manual-capture payment intents. The saga lifecycle maps cleanly onto Stripe's authorize/capture model — funds are never actually charged until all saga participants commit.

```bash
npm install stripe       # peer dependency
```

```typescript
import { StripeSettlement } from "@aroha-sdk/settlement";

const settlement = new StripeSettlement({
  secretKey: process.env.STRIPE_SECRET_KEY,
  resolveCharge: async (ctx) => {
    if (ctx.capability === "book-flight") {
      return { amountCents: 45000, currency: "usd", customerId: "cus_abc123" };
    }
    return null; // free capability — skip payment
  },
});
```

| Saga phase | Stripe action |
|------------|--------------|
| `ArohaReserve` | `PaymentIntent` created (`capture_method: "manual"`) — authorization only |
| `ArohaCommit`  | `PaymentIntent` captured — money moves |
| `ArohaCancel`  | `PaymentIntent` cancelled — hold released, no charge |

---

## On-Chain Reputation

Even if you aren't using `EscrowSettlement`, your sagas can still build on-chain reputation by passing an `IReputationRecorder` to the SagaEngine:

```typescript
export interface IReputationRecorder {
  record(
    sagaId: string,
    agentDID: string,
    outcome: SettlementOutcome
  ): Promise<void>;
}
```

This decouples the concept of "did a multi-agent transaction succeed?" from financial settlement, allowing free tiers to still accrue network reputation.