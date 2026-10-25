<!-- Copyright (c) 2026 Aroha Labs
     SPDX-License-Identifier: Apache-2.0 -->

# Aroha mandates and UCP `$requestConstraints`

**Status:** draft mapping, documentation only. No code in this repository emits or consumes UCP objects.
**Owner:** @projectmed99 (sole named maintainer, per `MAINTAINERS.md`). **Date:** 2026-10-15.
**Verification criterion:** a UCP constraint derived from a mandate with this table validates in the UCP sample server, and a request outside the mandate is refused by both sides. Not yet run.

## Why the two fit

Universal Commerce Protocol release v2026-08-25 lets a server return `$requestConstraints`: schema limits that later requests in the same session must satisfy. That is server-side attenuation. An Aroha mandate chain is the client-side version: every hop can only narrow what its parent allowed (spec §6.5, §6.6). A merchant that receives an Aroha mandate can turn the verified leaf into `$requestConstraints`, so its own request validation enforces the same bounds as the mandate verifier.

**ASSUMPTION:** this page assumes that `$requestConstraints` takes JSON Schema keywords (`maximum`, `enum`, `const`, `format`) on named request fields. The field paths in the right-hand column (`/checkout/total/amount` and similar) are placeholders. Confirm both against the published UCP schema before you implement anything. Owner: @projectmed99. Due: 2026-11-30.

## Mapping table (spending mandates)

Always derive the constraints from the **verified leaf** of a chain that `verifyMandateChain` accepted, never from an unverified token.

| Aroha mandate field (verified leaf) | UCP `$requestConstraints` (proposed) | Notes |
|---|---|---|
| `constraints.spendLimitUsd` | `maximum` on the order total, in the order currency | Convert currency first. Both sides compare in minor units to avoid float drift. |
| `constraints.sessionLimitUsd` | `maximum` on the cumulative session total | UCP enforces it per request. The cumulative check stays with Aroha redemption tracking (§6.5). |
| `constraints.currency` | `const` on the order currency | The mandate default is USD. |
| `constraints.allowedMerchants` (DIDs) | `enum` of the merchant identifiers the merchant answers to | Needs a DID-to-merchant-id binding that the merchant publishes. With no binding, refuse. |
| `constraints.merchantCategory` | `const` on the MCC field | Only when the merchant exposes an MCC. |
| `constraints.requireHumanApprovalAboveUsd` | none (an approval is not a schema limit) | Map to the UCP buyer-consent step. The approval itself stays an Aroha `UserApproval` with `presentedHash`. |
| `constraints.validFrom` / `validUntil`, `expiresAt` | Session expiry no later than the earliest of these | UCP sessions that outlive the mandate must be refused. |
| `actingFor` (`payer` \| `payee`) | none (record as metadata) | Declares which side of the payment the chain acts for (PSD3/PSR). A merchant-side agent receiving a `payer` chain must not also act for the payee. |
| `mandateId`, root grantor | Request metadata for audit | Lets the merchant join its records to the Aroha action receipt (`mandateId`, `principalDid`). |

## Mapping table (task mandates)

| Aroha task-mandate field | UCP equivalent | Notes |
|---|---|---|
| `allowed` / `blocked` | The set of UCP operations offered to this session | Each Aroha capability id maps to one UCP operation. Unmapped capabilities are refused. |
| `taskConstraints.actionLimits` | Per-operation request count | UCP has no count keyword (ASSUMPTION). Enforce on the Aroha side with `enforceTaskConstraints`. |
| `taskConstraints.onBehalfOf`, `roomId` | none | A guest grant in a shared conversation (spec §12). It stays on the Aroha side, where the request's room and member come from the runtime's records. |

## What this does not do

- It does not make a UCP server verify Aroha signatures. The merchant still runs `verifyMandateChain` (governed profile recommended, §6.8) before it derives any constraint.
- It does not replace Web Bot Auth, network agent identifiers or risk scores, the other inputs merchant verification is converging on.
