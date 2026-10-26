<!-- Copyright (c) 2026 Aroha Labs
     SPDX-License-Identifier: Apache-2.0 -->

# Aroha Registry Pricing Model

## The Problem with ETH-Denominated Staking

The on-chain `ArohaRegistry.sol` uses ETH staking for Sybil resistance.
ETH price volatility makes this unsuitable for enterprise procurement budgets.

## Three Registry Tiers

### Tier 1 — Local (Free, Zero Infrastructure)

For development and internal networks. No staking, no fees.

```typescript
import { InMemoryRegistry } from "@aroha-sdk/registry";

const registry = new InMemoryRegistry();
await registry.register("did:aroha:flight-agent", manifestCID, publicKey, {
  capabilityIds: ["search-flights"],
});
```

### Tier 2 — HTTP Registry (Fiat, Stable Pricing)

> **Not currently offered.** Aroha Labs does not currently offer a managed, paid
> registry service: there is no sign-up, API key or price list. A reference
> registry deployment answers at `https://aroha-registry.aroha-labs.workers.dev`
> without a service commitment. For production, self-host the HTTP registry
> (`apps/registry-server`).

The HTTP registry has no ETH exposure.

```typescript
import { ArohaHttpRegistry } from "@aroha-sdk/registry";

const registry = new ArohaHttpRegistry({
  baseUrl: "https://registry.example.com", // your registry; default: AROHA_REGISTRY_URL, else the reference deployment
  apiKey: process.env.AROHA_API_KEY!,
});
```

The managed-service price previously listed here (USD $49/month per registered agent DID) is not in effect, because no managed service is offered.

### Tier 3 — On-Chain EVM Registry (Staking Required)

For maximum decentralization and censorship resistance. Requires ETH staking.

```typescript
import { ArohaRegistryContract } from "@aroha-sdk/registry/contract";

const registry = new ArohaRegistryContract(rpcUrl, "0x...", wallet); // wallet: ethers.Wallet
await registry.register("did:aroha:flight-agent", manifestCID, publicKey, {
  stakeWei: ethers.parseEther("0.01"), // omit to use the on-chain minimum
});
```

**Staking rationale:** `ArohaRegistry.sol` lets the configured dispute contract slash
an agent's stake (`slashStake`). The registry contract itself defines no rule for when
slashing happens; that is up to the dispute contract (see `contracts/ArohaRegistry.sol`).

## Choosing a Tier

| Need | Recommended tier |
|---|---|
| Local development, internal networks | Tier 1 (local) |
| Production SaaS, enterprise | Tier 2 (HTTP, self-hosted) |
| Maximum decentralization, DeFi integration | Tier 3 (EVM) |
| Regulatory requirement to avoid crypto | Tier 2 (HTTP, self-hosted) |

## ETH Staking Volatility Mitigation

If you choose Tier 3, the minimum stake is denominated in ETH (`minStakeWei`, default
0.01 ETH). The contract owner can change it with `setMinStake`; the contract does not
adjust it automatically.

For zero ETH exposure, use Tier 2 exclusively.
