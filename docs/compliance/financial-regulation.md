<!-- Copyright (c) 2026 Aroha Labs
     SPDX-License-Identifier: Apache-2.0 -->

# Financial Regulation Guide for Aroha Settlement

> **Disclaimer:** This document is informational only and is not legal advice.
> Consult qualified financial regulation counsel for your jurisdiction before
> deploying any payment-handling system.

## The Risk

`EscrowSettlement` temporarily holds funds while a saga executes. In several jurisdictions,
holding customer funds — even briefly — may constitute **money transmission** and require
a license (US: FinCEN MTL; EU: PSD2 Payment Institution; UK: FCA E-Money).

## How to Stay Below the Threshold

### Option A: Agent-to-Agent Payments Only (Recommended)

The lowest-risk configuration: only Aroha agents pay other Aroha agents.
Customer funds never touch Aroha — your existing payment processor handles that.

```
Customer → Your App (Stripe/etc) → Your Agent → ArohaEscrow → Provider Agent
                ^                      ^
           your processor         only agent-to-agent
           handles this           Aroha handles this
```

### Option B: Postgres Settlement (No On-Chain Escrow)

`PostgresSettlement` records obligations in your database — no on-chain fund holding.
Settlement happens as a bookkeeping entry, real money moves via your existing processor.
This keeps all payment regulation squarely within your existing compliance framework.

### Option C: NullSettlement for Internal Agents

For internal enterprise agent networks, use `NullSettlement`. Agents are all
within the same legal entity, eliminating payment regulation concerns entirely.

## Red Lines — What to Avoid

- ❌ Holding end-customer funds in `EscrowSettlement` without a money transmitter license
- ❌ Cross-border escrow without reviewing both jurisdictions' requirements
- ❌ Using `EscrowSettlement` for consumer-facing sagas where the consumer's money is held

## Jurisdiction Notes

| Jurisdiction | Threshold | Regulator |
|---|---|---|
| United States | Any transmission | FinCEN + state MTLs |
| European Union | >€1M/year | PSD2 (national regulator) |
| United Kingdom | >£1M/year | FCA |
| Singapore | Any | MAS |

## Further Reading

- [FinCEN Money Services Business guide](https://www.fincen.gov/money-services-business-msb-information-center)
- [EBA PSD2 Guidelines](https://www.eba.europa.eu/regulation-and-policy/payment-services-and-electronic-money)
- Open an issue at github.com/ArohaLabs/aroha-protocol for compliance questions
