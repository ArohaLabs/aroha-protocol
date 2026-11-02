<!-- Copyright (c) 2026 Aroha Labs
     SPDX-License-Identifier: Apache-2.0 -->

# Mandates in sixty seconds

Two scripts, no server, no keys to configure. They install the published
`@aroha-sdk` packages, as a user would, and run offline.

```bash
cd examples/mandates
npm install
node inbox.mjs
node flight.mjs
```

## `inbox.mjs`: an assistant that cannot delete, even when told to

A person signs a task mandate for an inbox assistant: *read mail* and *propose
what to archive*, for one hour, with *delete* explicitly blocked. The mail tool
checks every call against the mandate before touching the mailbox. Then the
assistant hands summarising to a sub-agent with read-only access, and tries,
and fails, to hand it delete as well.

```
read-email      → allowed
propose-archive → allowed
delete-email    → refused (CAPABILITY_NOT_PERMITTED): Capability "delete-email" is not in the mandate's allowed list
sub-agent chain → valid, may: read-email
widening        → Cannot attenuate task mandate: child allowed includes "delete-email" which is not in parent's allowed list
```

The assistant does not need to be trustworthy, and it does not need to
remember the instruction. The tool checks the signed mandate, not the
assistant's intentions, and a sub-agent two hops away verifies the whole
chain back to the person without calling anyone.

Functions used: `issueTaskMandate`, `enforceTaskConstraints`,
`attenuateTaskMandate` (`@aroha-sdk/credentials`) and
`verifyTaskMandateChain` (`@aroha-sdk/delegation`).

## `flight.mjs`: the $500 flight

The example from the [root README](../../README.md): $500 for airline
purchases becomes $300 for the flight agent, which verifies the chain before
acting. Widening to $600 is refused.

```
valid: true chainVerified: true limit: 300
widening to $600 → Cannot attenuate intent → payment: child spendLimitUsd (600) exceeds parent (500)
```

`verifyMandateChain` also prints a warning when it runs without a revocation
hook. In production, pass `isRevoked` (for example `httpRevocationCheck`) or
use `governedVerification()` to require one.

## Make it yours

The capability names (`read-email`, `delete-email`) are strings you choose;
the mandate and the tool have to agree on them. Replace them with the actions
your own agent takes, put the `enforceTaskConstraints` call inside the tool
that performs each action, and the mandate does the rest. For a full agent
with an HTTP endpoint, start from `npx create-aroha-agent` ([quickstart](../../docs/quickstart.md)).
