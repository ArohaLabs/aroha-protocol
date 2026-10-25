<!-- Copyright (c) 2026 Aroha Labs
     SPDX-License-Identifier: Apache-2.0 -->

# `@aroha-sdk/commerce`

> **Developed in `ArohaLabs/aroha-extensions`.** `@aroha-sdk/commerce` stays published on npm; its
> source moved out of the protocol repository on 2026-10-25.


The `@aroha-sdk/commerce` package implements all three principal commercial interaction patterns between Aroha agents: **B2B**, **B2C**, and **C2B**. It is an optional extension — the Aroha protocol kernel never requires it.

```bash
npm install @aroha-sdk/commerce
```

---

## Why B2B, B2C, and C2B?

The agent economy mirrors the broader economy. Every commercial transaction involves at least two parties, a relationship type, and a set of terms. Aroha's commerce layer formalises these:

| Pattern | Relationship | Example |
|---------|-------------|---------|
| **B2B** | Organisation ↔ Organisation | A logistics company's planning agent consumes a freight-pricing agent under a quarterly contract with SLA |
| **B2C** | Organisation → Consumer | A travel-booking provider's agent serves a personal travel agent under a monthly subscription with GDPR consent |
| **C2B** | Consumer → Organisation | A user's personal agent submits quality feedback on a completed booking, which the provider records on-chain |

All three patterns use the same identity primitives (`OrgIdentity`, `PersonalIdentity`), the same audit log (`CommerceAuditLog`), and plug into the same settlement interface (`IArohaSettlement` from `@aroha-sdk/settlement`).

---

## Identity

### `generateOrgIdentity(name)`

Creates an organisational identity with an Ed25519 keypair and a `did:aroha:org:<name>` DID.

```typescript
import { generateOrgIdentity } from "@aroha-sdk/commerce";

const expedia = await generateOrgIdentity("expedia");
// { orgDID: "did:aroha:org:expedia", name: "expedia", agentDIDs: [], publicKey, privateKey }
```

### `issueAgentDelegation(org, agentDID, capabilities)`

Issues a signed `AgentDelegationCredential` that authorises a specific agent DID to act on the org's behalf.

```typescript
import { issueAgentDelegation } from "@aroha-sdk/commerce";

const credential = await issueAgentDelegation(
  expedia,
  "did:aroha:expedia-booking-agent",
  ["search-flights", "book-flight"],
  7 * 24 * 3_600_000  // valid for 7 days
);
```

### `generatePersonalIdentity(displayName?)`

Creates a consumer identity with a `did:aroha:personal:<uuid>` DID.

```typescript
import { generatePersonalIdentity } from "@aroha-sdk/commerce";

const alice = await generatePersonalIdentity("Alice");
```

---

## B2B — Organisation-to-Organisation

### Agreement lifecycle

```typescript
import {
  createAgreement,
  signAgreementAsProvider,
  signAgreementAsConsumer,
  verifyAgreement,
  openB2BSession,
} from "@aroha-sdk/commerce";

// 1. Provider creates the agreement
const draft = createAgreement({
  providerOrgDID: expedia.orgDID,
  consumerOrgDID: corporateTravelCo.orgDID,
  capabilities: [
    { capability: "book-flight", callQuota: 10_000, maxResponseMs: 3_000 },
    { capability: "book-hotel",  callQuota: 8_000,  maxResponseMs: 3_000 },
  ],
  billingTerms: {
    model: "per-call",
    currency: "USD",
    pricePerCall: 0.05,
    billingPeriod: "monthly",
    paymentTermsDays: 30,
  },
  slaTerms: { uptimePercent: 99.9, maxResponseMs: 3_000, supportTier: "enterprise" },
  validFrom: Date.now(),
  validUntil: Date.now() + 365 * 86_400_000,
});

// 2. Provider signs
const signedByProvider = await signAgreementAsProvider(draft, expedia.privateKey);

// 3. Consumer countersigns → agreement is active
const countersigned = await signAgreementAsConsumer(signedByProvider, corporateTravelCo.privateKey);

// 4. Verify (either party)
const result = await verifyAgreement(countersigned, expedia.publicKey, corporateTravelCo.publicKey);
// { valid: true }

// 5. Open a session for this agreement
const session = openB2BSession(countersigned);
```

### Billing settlement

Mount `B2BBillingSettlement` as the `settlement` option of `SagaEngine` to automatically charge per call:

```typescript
import { B2BBillingSettlement } from "@aroha-sdk/commerce";
import { SagaEngine } from "@aroha-sdk/orchestrator";

const billingRecords: B2BBillingRecord[] = [];

const saga = new SagaEngine(client, orchestratorDID, privateKey, {
  settlement: new B2BBillingSettlement({
    agreement: countersigned,
    onCharge: async (record) => { billingRecords.push(record); },
    onSlaViolation: (cap, latencyMs, limitMs) => {
      console.warn(`SLA breach: ${cap} took ${latencyMs}ms (limit ${limitMs}ms)`);
    },
  }),
});
```

### Invoice generation

```typescript
import { generateInvoice } from "@aroha-sdk/commerce";

const invoice = generateInvoice(countersigned, billingRecords);
// { invoiceId, totalAmount, currency, lineItems, dueAt, status: "pending" }
```

### SLA monitoring

```typescript
import { SlaMonitor } from "@aroha-sdk/commerce";

const sla = new SlaMonitor(countersigned.slaTerms);
sla.recordLatency("book-flight", 287);
sla.recordLatency("book-flight", 4210);  // violation

const stats = sla.stats("book-flight");
// { p50Ms: 287, p99Ms: 4210, violations: [{ observedMs: 4210, limitMs: 3000 }] }
```

---

## B2C — Business-to-Consumer

### Service terms and subscriptions

```typescript
import { createServiceTerms, createSubscription, grantConsent } from "@aroha-sdk/commerce";

const terms = createServiceTerms({
  providerOrgDID: expedia.orgDID,
  version: "2026-04",
  subscriptionTier: "pro",
  callQuotaPerPeriod: 500,
  billingPeriod: "monthly",
  pricePerPeriod: 19.99,
  currency: "USD",
  capabilities: ["search-flights", "book-flight", "search-hotels"],
  dataTerms: {
    allowedUsePurposes: ["service-delivery", "personalisation"],
    retentionDays: 365,
    crossBorderTransferAllowed: false,
    gdprApplicable: true,
  },
});
```

### Consumer consent (GDPR-aligned)

Every consent record is signed by the consumer's Ed25519 key. The provider must verify the signature before using the data.

```typescript
// Consumer side: grant consent
const consent = await grantConsent(
  alice.personalDID,
  expedia.orgDID,
  "book-flight",
  ["service-delivery", "personalisation"],
  alice.privateKey,
  null  // no expiry
);

// Provider side: verify consent
import { verifyConsent } from "@aroha-sdk/commerce";
const check = await verifyConsent(consent, alice.publicKey);
// { valid: true }

// Consumer side: withdraw consent
import { withdrawConsent } from "@aroha-sdk/commerce";
const withdrawn = await withdrawConsent(consent, alice.privateKey);
```

### Consent middleware

```typescript
import { createConsentMiddleware } from "@aroha-sdk/commerce";

const server = new ArohaServer({
  // ...
  middleware: [
    createConsentMiddleware({
      resolveConsent: async (personalDID, capability) =>
        consentStore.get(personalDID, capability),
      resolveConsumerPublicKey: async (did) => keyStore.get(did),
      requiredPurposes: ["service-delivery"],
    }),
  ],
});
```

---

## C2B — Consumer-to-Business

### Quality feedback

Consumers rate completed interactions with 1–5 stars. The signature proves the consumer actually made this rating — providers cannot fabricate positive reviews.

```typescript
import { submitFeedback, aggregateFeedback, signalToOnChainStars } from "@aroha-sdk/commerce";

// Consumer submits feedback
const feedback = await submitFeedback(
  alice.personalDID,
  expedia.orgDID,
  sagaId,
  "book-flight",
  5,              // qualityStars
  alice.privateKey,
  "Smooth booking, great price"
);

// Provider aggregates verified feedback
const signal = aggregateFeedback(expedia.orgDID, "book-flight", [feedback]);
// { averageStars: 5.0, feedbackCount: 1 }

// Convert to on-chain uint8 for ArohaReputation.sol
const stars = signalToOnChainStars(signal);  // 5
```

### Data submission

```typescript
import { createDataSubmission, verifyDataSubmission } from "@aroha-sdk/commerce";

// Consumer submits preferences
const submission = await createDataSubmission(
  alice.personalDID,
  expedia.orgDID,
  "search-flights",
  { preferredSeat: "aisle", mealType: "vegetarian" },
  ["service-delivery", "personalisation"],
  alice.privateKey
);

// Provider verifies
const ok = await verifyDataSubmission(submission, alice.publicKey);
// { valid: true }
```

---

## Middleware

Three composable `ArohaMiddleware` factories for mounting on `ArohaServer`:

### `createDelegationMiddleware` (B2B)

Verifies that the sender agent holds a valid, signed `AgentDelegationCredential` from its org.

```typescript
import { createDelegationMiddleware } from "@aroha-sdk/commerce";

middleware: [
  createDelegationMiddleware({
    resolveCredential: async (agentDID) => credentialStore.get(agentDID),
    resolveOrgPublicKey: async (orgDID) => orgKeyStore.get(orgDID),
  }),
]
```

### `createAgreementMiddleware` (B2B)

Verifies an active, countersigned `B2BAgreement` exists and covers the requested capability.

```typescript
import { createAgreementMiddleware } from "@aroha-sdk/commerce";

middleware: [
  createAgreementMiddleware({
    providerOrgDID: expedia.orgDID,
    resolveAgentOrg: async (agentDID) => agentOrgMap.get(agentDID),
    resolveAgreement: async (consumerOrg, providerOrg) =>
      agreementStore.findActive(consumerOrg, providerOrg),
  }),
]
```

### `createConsentMiddleware` (B2C / C2B)

Verifies the consumer has granted valid, non-withdrawn consent for the requested capability and purpose.

---

## Audit log

Every interaction — B2B, B2C, or C2B — can be appended to a `CommerceAuditLog`. Each record is linked to the previous via SHA-256 hash and signed by the recording party.

```typescript
import { CommerceAuditLog } from "@aroha-sdk/commerce";

const log = new CommerceAuditLog();

await log.append({
  pattern: "B2B",
  sagaId: "saga-001",
  agreementId: countersigned.agreementId,
  senderDID: corporateTravelCo.orgDID,
  receiverDID: expedia.orgDID,
  capability: "book-flight",
  outcome: "SUCCESS",
  latencyMs: 287,
  chargeAmount: 0.05,
  signerPrivateKey: expedia.privateKey,
});

// Verify chain integrity
const result = await log.verify(async (did) => keyStore.getPublicKey(did));
// { valid: true }
```

The audit log can provide evidence for the following (self-assessed; not auditor-reviewed — no compliance assessor has evaluated it):

- **GDPR** — data access and consent records with provenance
- **SOC 2** — a tamper-evident system activity log (sufficiency is your auditor's call)
- **SLA disputes** — latency and outcome records per capability
- **Financial compliance** — charge records per call or period
