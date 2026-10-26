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
import { HttpRegistryClient } from "@aroha-sdk/registry";

const registry = new HttpRegistryClient({
  mode: "local",
  agents: new Map([
    ["did:aroha:flight-agent", { endpoint: "http://localhost:3040", manifest }],
  ]),
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
const registry = new HttpRegistryClient({
  apiKey: process.env.AROHA_REGISTRY_API_KEY,
  endpoint: "https://aroha-registry.aroha-labs.workers.dev",
});
```

The managed-service price previously listed here (USD $49/month per registered agent DID) is not in effect, because no managed service is offered.

### Tier 3 — On-Chain EVM Registry (Staking Required)

For maximum decentralization and censorship resistance. Requires ETH staking.

```typescript
import { EvmRegistryClient } from "@aroha-sdk/registry";

const registry = new EvmRegistryClient({
  contractAddress: "0x...",
  signer: wallet,
  stakeAmount: ethers.parseEther("0.1"),
});
```

**Staking rationale:** Stake is slashed when an agent repeatedly fails to honour Commits
or deliver valid Cancel acknowledgements. Slashing is governed by the `ArohaRegistry.sol`
slashing rules (see `contracts/ArohaRegistry.sol`).

## Choosing a Tier

| Need | Recommended tier |
|---|---|
| Local development, internal networks | Tier 1 (local) |
| Production SaaS, enterprise | Tier 2 (HTTP, self-hosted) |
| Maximum decentralization, DeFi integration | Tier 3 (EVM) |
| Regulatory requirement to avoid crypto | Tier 2 (HTTP, self-hosted) |

## ETH Staking Volatility Mitigation

If you choose Tier 3, the minimum stake is denominated in ETH but sized to approximate
a USD floor. The governance process updates the minimum stake quarterly to maintain a
roughly USD-equivalent cost, reducing the procurement budget risk.

For zero ETH exposure, use Tier 2 exclusively.
