# Aroha Go SDK

Module `github.com/ArohaLabs/aroha-protocol/sdks/go` · Go 1.22+ · one dependency (`github.com/google/uuid`).

**Not released yet** (no `sdks/go/v*` tag): build from a checkout of this repository; see
[Installation](../../docs/sdks/go.md#installation).

Full reference: [`docs/sdks/go.md`](../../docs/sdks/go.md). This page lists the
packages and how their wire formats are checked against the TypeScript
reference.

| Package | What it does | Checked against |
|---|---|---|
| `aroha/messages` | Envelope build / validate, nonce registry, ArohaDisclosure | `spec-public/vectors/conversation-v1.json` (disclosure envelope) |
| `aroha/mandate` | Spending mandates v2 (issue, attenuate, chain verification); **task mandates** (`IssueTaskMandate`, `AttenuateTaskMandate`, `VerifyTaskMandate`, `CheckTaskNarrowing`, `CheckTaskConstraints`, `EnforceTaskConstraints`) | `packages/aroha-credentials/test-vectors/mandate-v2.json`, `task-mandate-v2.json`; live interop with `-tags integration` |
| `aroha/conversation` | Conversation profile verification: rooms, consent records (per-event signatures, hash chain), turns; speaker kind from a verified KEL | `spec-public/vectors/conversation-v1.json` |
| `aroha/receipts` | Action receipts v1/v2 verification, `presentedHash` | `spec-public/vectors/conversation-v1.json` |
| `aroha/registry` | Registry client: `Register` (challenge proof of key possession), `Resolve`, `Discover`, `List`, `UpdateManifest`, `Deactivate`; `HTTPKelSource` | in-process server with `apps/registry-server` response shapes |
| `aroha/identity` | `did:aroha` (z-form, E-form KEL), `did:aroha-web` | shared vectors |
| `aroha/jcs` | RFC 8785 canonicalisation | RFC 8785 examples |
| `aroha/orchestrator`, `aroha/transport`, `aroha/crypto` | Saga engine, HTTP transport, signing / encryption | unit tests |

## Task mandates

```go
root, err := mandate.IssueTaskMandate(humanDID, agentDID,
    []string{"search", "send-email"},
    mandate.TaskConstraints{
        ActionLimits: map[string]float64{"send-email": 3},
        HumanGates:   []string{"send-email"},
        RoomID:       "room-1", OnBehalfOf: guestDID,
    },
    humanKey, time.Hour, mandate.TaskIssueOptions{})

// At the capability gate:
m, err := mandate.EnforceTaskConstraints(token, humanPub, mandate.EnforceTaskOptions{
    ExpectedGrantee: myDID,
    TaskActionRequest: mandate.TaskActionRequest{
        RequestedCapability: "send-email", HumanApproved: true,
        RoomID: "room-1", OnBehalfOf: guestDID,
        CurrentActionCounts: map[string]float64{"send-email": used},
    },
})
// err is a *mandate.TaskConstraintViolation with a Code such as ACTION_LIMIT_EXCEEDED.
```

A task token carries one link. `CheckTaskNarrowing` is the per-link rule a
chain verifier applies; a multi-link task-chain verifier
(`@aroha-sdk/delegation` `verifyTaskMandateChain`) is not ported.

## Conversation profile

```go
resolve := conversation.WithContentAddressedAgents(conversation.KelResolver(kelSource))
room, err := conversation.VerifyRoom(roomJSON, resolve)
consent, err := conversation.VerifyConsent(consentJSON, resolve, &room.Value)
turn, err := conversation.VerifyTurn(turnJSON, resolve, &room.Value) // turn.Signer.Kind is the speaker kind
```

Verification only; signing rooms, consent events and turns belongs to the runtime.

## Registry

```go
c, err := registry.New(registry.Options{APIKey: os.Getenv("AROHA_API_KEY")}) // AROHA_REGISTRY_URL or the managed registry
didHash, err := c.Register(ctx, did, manifestCID, pub, registry.RegisterOptions{PrivateKey: priv})
rec, err := c.Resolve(ctx, did)              // nil, nil when not found
agents, err := c.Discover(ctx, []string{"book-flight"})
kels, err := registry.HTTPKelSource("", registry.KelSourceOptions{}) // an identity.KelSource
```

## Tests

```bash
go vet ./... && go test ./...
# live interop with the TypeScript reference (needs node and a built packages/aroha-credentials):
AROHA_CREDENTIALS_DIR=../../packages/aroha-credentials go test -tags integration ./aroha/mandate/
```
