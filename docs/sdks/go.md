<!-- Copyright (c) 2026 Aroha Labs
     SPDX-License-Identifier: Apache-2.0 -->

# Go SDK

**Module:** `github.com/ArohaLabs/aroha-protocol/sdks/go` · **Requires:** Go 1.22+

## Installation

> **Not released yet.** No version of this module has been tagged (`sdks/go/vX.Y.Z`),
> so there is no release to `go get`. Build from a checkout with a `replace` directive:
>
> ```bash
> git clone https://github.com/ArohaLabs/aroha-protocol
> go mod edit -replace github.com/ArohaLabs/aroha-protocol/sdks/go=../aroha-protocol/sdks/go
> go get github.com/ArohaLabs/aroha-protocol/sdks/go
> ```
>
> Once a `sdks/go/vX.Y.Z` tag exists, plain
> `go get github.com/ArohaLabs/aroha-protocol/sdks/go@vX.Y.Z` will work.

**Dependencies:** one module, `github.com/google/uuid`; Ed25519 and ECDH come from the
standard library (`crypto/ed25519`, `crypto/ecdh`). No web framework.

**Parity:** v2 mandate tokens (with chain verification), the hardened envelope rules and E-DID /
Key Event Log verification are implemented and tested against the shared vectors, and
`did:aroha-web` follows the current TypeScript schema. See the [feature matrix](feature-matrix.md).

## Quick Start

```go
package main

import (
    "context"
    "crypto/ed25519"
    "fmt"
    "log"

    "github.com/ArohaLabs/aroha-protocol/sdks/go/aroha/identity"
    "github.com/ArohaLabs/aroha-protocol/sdks/go/aroha/messages"
    "github.com/ArohaLabs/aroha-protocol/sdks/go/aroha/transport"
)

func main() {
    // 1. Generate identity
    id, err := identity.Generate("my-agent", "http://localhost:3001")
    if err != nil {
        log.Fatal(err)
    }

    nonces := messages.NewNonceRegistry()

    // 2. Start a server (binds 127.0.0.1 unless Host is set)
    srv, err := transport.NewArohaServer(transport.ServerConfig{
        Port:        3001,
        DIDDocument: id.DIDDocument,
        MyDID:       id.DID,
        ResolvePublicKey: func(did string) ed25519.PublicKey {
            return nil // add real key resolution
        },
        NonceRegistry: nonces,
        OnMessage: func(envelope map[string]any, respond, stream func(map[string]any)) {
            fmt.Println("received:", envelope["type"])
        },
        DevMode: true, // refused unless AROHA_DEV_MODE=1; never in production
    })
    if err != nil {
        log.Fatal(err)
    }

    log.Fatal(srv.Start(context.Background()))
}
```

---

## `aroha/identity`

### `Generate(agentID, endpoint string) (*AgentIdentity, error)`

Generates a `did:aroha:` DID, an Ed25519 keypair, and a conformant DID Document.

```go
id, err := identity.Generate("pricing-agent", "https://agents.example.com/pricing")

id.DID          // "did:aroha:pricing-agent"
id.KeyID        // "did:aroha:pricing-agent#key-1"
id.DIDDocument  // map[string]any — the full DID Document
id.PrivateKey   // ed25519.PrivateKey
id.PublicKey    // ed25519.PublicKey
```

### `AgentIdentity`

```go
type AgentIdentity struct {
    DID         string
    KeyID       string
    DIDDocument map[string]any
    PrivateKey  ed25519.PrivateKey
    PublicKey   ed25519.PublicKey
}
```

### Helpers

```go
pub, err  := identity.ExtractPublicKey(didDocument)  // → ed25519.PublicKey
endpoint, err := identity.ExtractEndpoint(didDocument) // → string

encoded := identity.ToMultibase(rawBytes)    // → "z<base58btc>"
decoded, err := identity.FromMultibase(encoded) // → []byte
```

---

## `aroha/crypto`

### Signing

```go
import "github.com/ArohaLabs/aroha-protocol/sdks/go/aroha/crypto"

// Sign — mutates the envelope map, adding a "proof" field
err := crypto.SignMessage(envelope, privateKey, "did:aroha:my-agent#key-1")

// Verify
ok, err := crypto.VerifyMessageSignature(envelope, publicKey)

// Canonical JSON (lexicographically sorted keys, deep)
canonical, err := crypto.Canonicalize(envelope)
```

### Encryption (ECDH-ES + AES-256-GCM)

```go
import "github.com/ArohaLabs/aroha-protocol/sdks/go/aroha/crypto"

encrypted, err := crypto.EncryptBody(plaintextMap, recipientECDHPub)
// → map with "alg", "epk", "iv", "ciphertext", "tag"

plaintext, err := crypto.DecryptBody(encrypted, recipientECDHPriv)
```

---

## `aroha/messages`

### `Build(...) (map[string]any, error)`

Builds and signs an outbound envelope.

```go
import "github.com/ArohaLabs/aroha-protocol/sdks/go/aroha/messages"

envelope, err := messages.Build(
    messages.TypeRequest,        // message type constant
    "did:aroha:sender",           // from DID
    "did:aroha:receiver",         // to DID
    map[string]any{              // body
        "capability": "convert",
        "amount":     100,
    },
    messages.NewCorrelationID(), // correlation ID
    identity.PrivateKey,         // Ed25519 private key
    identity.KeyID,              // "did:aroha:sender#key-1"
    5*time.Minute,               // TTL
    // optional extra fields (traceparent, routingHint, etc.)
    map[string]any{"traceparent": "00-abc-def-01"},
)
```

Use `messages.BuildDefault` for a 5-minute TTL without extra fields:

```go
envelope, err := messages.BuildDefault(
    messages.TypeRequest, from, to, body, corrID, privateKey, keyID,
)
```

### `Validate(...) error`

Validates an inbound envelope through the full pipeline.

```go
nonces := messages.NewNonceRegistry()

err := messages.Validate(
    envelope,
    senderPubKey,
    "did:aroha:my-agent",
    nonces,
    // optional:
    messages.ValidateOptions{SkipSignature: false},
)
// SkipSignature: true is for a mesh where a transport-level check (mTLS, a
// private link) authenticates the peer. Validate refuses it unless you also
// set AcknowledgeUnauthenticated: true or the environment sets
// AROHA_DEV_MODE=1. Nonces longer than 128 characters are rejected.

if err != nil {
    var ve *messages.ValidationError
    if errors.As(err, &ve) {
        fmt.Println("rejected:", ve.Reason)
    }
}
```

### Message Type Constants

```go
messages.TypeRequest      // "ArohaRequest"
messages.TypeResponse     // "ArohaResponse"
messages.TypeStream       // "ArohaStream"
messages.TypeNegotiate    // "ArohaNegotiate"
messages.TypeCounterOffer // "ArohaCounterOffer"
messages.TypeAccept       // "ArohaAccept"
messages.TypeReserve      // "ArohaReserve"
messages.TypeReserveAck   // "ArohaReserveAck"
messages.TypeCommit       // "ArohaCommit"
messages.TypeCommitAck    // "ArohaCommitAck"
messages.TypeCancel       // "ArohaCancel"
messages.TypeCancelAck    // "ArohaCancelAck"
messages.TypeDelegate     // "ArohaDelegate"
messages.TypeError        // "ArohaError"
messages.TypeSatisfaction // "ArohaSatisfactionSignal"
messages.TypeSpendingMandate   // "ArohaSpendingMandate"
messages.TypeTaskMandate       // "ArohaTaskMandate"
messages.TypeDispute           // "ArohaDispute"
messages.TypeDisputeResolution // "ArohaDisputeResolution"
```

### Error Code Constants

```go
// Auth
messages.ErrUnauthorized            // "Aroha_UNAUTHORIZED"
messages.ErrForbidden               // "Aroha_FORBIDDEN"
// Protocol
messages.ErrInvalidSignature        // "Aroha_INVALID_SIGNATURE"
messages.ErrExpiredMessage          // "Aroha_EXPIRED_MESSAGE"
messages.ErrReplayDetected          // "Aroha_REPLAY_DETECTED"
messages.ErrUnknownCapability       // "Aroha_UNKNOWN_CAPABILITY"
messages.ErrTrustLevelInsufficient  // "Aroha_TRUST_LEVEL_INSUFFICIENT"
// Saga
messages.ErrReservationFailed       // "Aroha_RESERVATION_FAILED"
messages.ErrReservationExpired      // "Aroha_RESERVATION_EXPIRED"
messages.ErrCommitFailed            // "Aroha_COMMIT_FAILED"
messages.ErrCancelFailed            // "Aroha_CANCEL_FAILED"
messages.ErrInvalidToken            // "Aroha_INVALID_TOKEN"
// Availability
messages.ErrNoInventory             // "Aroha_NO_INVENTORY"
messages.ErrCapacityExceeded        // "Aroha_CAPACITY_EXCEEDED"
messages.ErrServiceUnavailable      // "Aroha_SERVICE_UNAVAILABLE"
// Generic
messages.ErrInternalError           // "Aroha_INTERNAL_ERROR"
messages.ErrInvalidParams           // "Aroha_INVALID_PARAMS"
// … and 18 more (CSN, task-mandate enforcement, settlement, mandate-chain admission); messages.ErrorCodes lists all 35
```

### `NonceRegistry`

Thread-safe replay prevention using `sync.RWMutex`.

```go
nonces := messages.NewNonceRegistry()
fresh  := nonces.Check("abc123", "2026-04-29T12:00:00Z") // true first time
fresh   = nonces.Check("abc123", "2026-04-29T12:00:00Z") // false (replay)
size   := nonces.Size()
```

---

## `aroha/transport`

### `ArohaServer`

Standard library `net/http` server — no framework dependency.

```go
import "github.com/ArohaLabs/aroha-protocol/sdks/go/aroha/transport"

srv, err := transport.NewArohaServer(transport.ServerConfig{
    Host:        "127.0.0.1", // default; "0.0.0.0" to accept remote connections
    Port:        3001,
    DIDDocument: id.DIDDocument,
    MyDID:       id.DID,
    ResolvePublicKey: func(did string) ed25519.PublicKey {
        // return the sender's public key, or nil if unknown
        return keyStore[did]
    },
    NonceRegistry: messages.NewNonceRegistry(),
    OnMessage: func(
        envelope  map[string]any,
        respond   func(map[string]any),  // call to reply synchronously (200)
        stream    func(map[string]any),  // call for SSE stream events
    ) {
        switch envelope["type"] {
        case messages.TypeRequest:
            respond(map[string]any{
                "type": messages.TypeResponse,
                "body": map[string]any{"result": "ok"},
            })
        }
    },
    DevMode: false, // true is refused unless AROHA_DEV_MODE=1
    // MaxBodyBytes: 0 → 1 MiB; larger request bodies get 413
})
if err != nil {
    log.Fatal(err)
}

ctx := context.Background()
if err := srv.Start(ctx); err != nil {
    log.Fatal(err)
}
```

### `ArohaClient`

```go
import "github.com/ArohaLabs/aroha-protocol/sdks/go/aroha/transport"

client := transport.NewArohaClient() // 30s default timeout

// Endpoints must be https, except loopback hosts (127.0.0.0/8, ::1,
// localhost). For plain http on a network you control:
// transport.NewArohaClientWithOptions(transport.ClientOptions{AllowInsecureHTTP: true})

// Send — returns nil on 202 Accepted
reply, err := client.Send("http://localhost:3001/aroha/v1", envelope)

// Custom timeout
reply, err = client.SendWithTimeout(endpoint, envelope, 10*time.Second)

// Fetch DID Document
doc, err := client.FetchDIDDocument("http://localhost:3001")
```

---

## `aroha/orchestrator`

### `SagaEngine`

Coordinates atomic 3-phase transactions.

```go
import "github.com/ArohaLabs/aroha-protocol/sdks/go/aroha/orchestrator"

engine := orchestrator.NewSagaEngine(
    client,
    id.DID,
    id.KeyID,
    id.PrivateKey,
)

result, err := engine.Execute([]*orchestrator.SagaStep{
    {
        AgentDID:      "did:aroha:flight-agent",
        AgentEndpoint: "https://flights.example.com/aroha/v1",
        Capability:    "book-flight",
        Params:        map[string]any{"origin": "JFK", "dest": "NRT"},
        HoldDurationMs: 30_000,
    },
    {
        AgentDID:      "did:aroha:hotel-agent",
        AgentEndpoint: "https://hotels.example.com/aroha/v1",
        Capability:    "book-hotel",
        Params:        map[string]any{"city": "Tokyo", "nights": 5},
        HoldDurationMs: 30_000,
    },
})

if result.Success {
    fmt.Println(result.Results) // map[int]map[string]any
} else {
    fmt.Println(result.Failures)
}
```

**Saga phases:**
1. **Reserve** — all steps run in parallel goroutines; any error cancels
2. **Commit** — steps run in order; failure triggers LIFO cancel
3. **Compensate** — `ArohaCancel` sent in reverse commit order

### `AgentSelector`

```go
selector := orchestrator.NewAgentSelector(client, id.DID, id.KeyID, id.PrivateKey)

result, err := selector.Select(
    "sentiment-analysis",
    map[string]any{"ticker": "BTC"},
    []map[string]any{
        {"did": "did:aroha:feed-a", "endpoint": "https://feed-a.example.com/aroha/v1"},
        {"did": "did:aroha:feed-b", "endpoint": "https://feed-b.example.com/aroha/v1"},
    },
    &orchestrator.SelectOptions{
        Weights: map[string]float64{
            "price":      0.5,
            "reputation": 0.3,
            "latency":    0.2,
        },
        FanOutTimeout: 5 * time.Second,
    },
)

fmt.Println(result.Winner.AgentDID, result.Winner.Score)
```

**Default weights:** price 0.35 · reputation 0.30 · latency 0.15 · preference 0.15 · availability 0.05

---

## `aroha/identity` — `did:aroha-web:`

Two-factor DNS-anchored identity. See [did:aroha-web: spec →](../spec/web-did.md)

A port of the TypeScript resolver: same document shape (`verificationMethod[]`
with base58 `publicKeyMultibase`, `arohaWeb.keyHistory` newest first, v2
DID-bound rotation records) and the same resolution rules, checked against a
TypeScript-generated vector.

```go
import "github.com/ArohaLabs/aroha-protocol/sdks/go/aroha/identity"

agent, err := identity.GenerateWebAgent("stripe.com", "payments-agent", "")
// agent.DID == "did:aroha-web:stripe.com:payments-agent"
// Serve agent.Document (JSON) at agent.WellKnownURL; publish agent.DNSTXTRecord at _aroha.stripe.com.

rotated, err := identity.RotateKey(agent, 24*time.Hour, time.Time{}) // v2 record signed by the old key

result, err := identity.ResolveWebDID("did:aroha-web:stripe.com:payments-agent", identity.ResolveWebDIDOptions{})
key, err := identity.SelectWebDIDKey(result, "") // error when no key is accepted (fail closed)
```

`ResolveWebDID` refuses domains that are not hostnames (IPv4 needs
`AllowIPLiteral`) and paths outside `^[a-z0-9-]+(/[a-z0-9-]+)*$`; fetches over
https without following redirects, with a 10 s timeout and a 64 KiB cap; hashes
the served key itself and requires the rotation chain to link it to a key
`_aroha.{domain}` commits to (system resolver by default). `DNSVerified` is
false whenever DNS was not checked.

---

## `aroha/orchestrator` — CSN

Capability Schema Negotiation — structural matching before LLM fallback.
See [CSN guide →](../spec/csn.md)

```go
import "github.com/ArohaLabs/aroha-protocol/sdks/go/aroha/orchestrator"

// ── Provider ──────────────────────────────────────────────────────────────────
registry := orchestrator.NewCapabilityRegistry()
registry.Register(&orchestrator.CapabilityEntry{
    Name:        "fx-convert",
    Description: "Convert between two currencies",
    InputSchema: map[string]any{
        "type": "object",
        "properties": map[string]any{
            "amount": map[string]any{"type": "number"},
            "from":   map[string]any{"type": "string"},
            "to":     map[string]any{"type": "string"},
        },
        "required": []any{"amount", "from", "to"},
    },
    SupportsSaga: true,
})

handler := orchestrator.NewCSNHandler(
    registry, agentDID, privateKey, buildEnvelopeFn,
    nil, // optional ICapabilityMatcher — only called for score 0.5–0.85
)

// In your message handler:
if msgType == "ArohaNegotiate" {
    if csn := body["csn"]; csn != nil {
        reply, err := handler.Handle(ctx, envelope, senderDID)
        respond(reply)
    }
}

// ── Requestor ─────────────────────────────────────────────────────────────────
negotiator := orchestrator.NewCapabilityNegotiator(
    sendFn, buildEnvelopeFn, orchestratorDID, privateKey, nil,
)
result, err := negotiator.Discover(ctx,
    "https://fx.example.com/aroha/v1",
    "did:aroha-web:fx.example.com:agent",
    &orchestrator.DiscoveryRequest{
        CapabilityIntent: "convert currency from USD to JPY",
        DesiredSchema: map[string]any{"input": map[string]any{
            "type": "object",
            "properties": map[string]any{
                "amount": map[string]any{"type": "number"},
                "from":   map[string]any{"type": "string"},
                "to":     map[string]any{"type": "string"},
            },
            "required": []any{"amount", "from", "to"},
        }},
    },
)
// result.ResolvedCapability == "fx-convert"
// result.MatchMethod == "schema"   (deterministic, no LLM)
// result.Rounds == 0               (DiscoveryCache hit on repeat)
```

---

## `aroha/reputation`

Bayesian Beta reputation engine with 12 signals and Thompson Sampling.
See [Reputation Model →](../reputation-model.md)

```go
import "github.com/ArohaLabs/aroha-protocol/sdks/go/aroha/reputation"

engine := reputation.New(nil) // nil = default weights

ok := true
latency := 120.0
sla := 5000.0
engine.RecordEvent(reputation.ReputationEvent{
    Type:          reputation.EventSagaComplete,
    SagaID:        "saga-123",
    AgentDID:      "did:aroha:fx-agent",
    Domain:        "fx",
    Success:       &ok,
    LatencyMs:     &latency,
    SLADurationMs: &sla,
})

score  := engine.CompositeScore("did:aroha:fx-agent", "fx")
ranked := engine.ThompsonSelect([]map[string]any{
    {"agentDID": "did:aroha:fx-a"},
    {"agentDID": "did:aroha:fx-b"},
}, "fx", true) // true = risk-gated (Wilson lower-bound floor)
```

---

## `aroha/mandate`

Spending mandate delegation chain. See [@aroha-sdk/credentials →](../packages/credentials.md)

```go
import "github.com/ArohaLabs/aroha-protocol/sdks/go/aroha/mandate"

intent, err := mandate.IssueIntent(
    "did:aroha:personal-agent-alice",
    "did:aroha:personal-agent",
    mandate.SpendingConstraints{SpendLimitUSD: 500, Currency: "USD"},
    userPrivKey,
    time.Hour,
)

cart, err := mandate.AttenuateToCart(
    intent,
    "did:aroha:shopping-orchestrator",
    mandate.SpendingConstraints{SpendLimitUSD: 79.99},
    personalAgentKey,
    nil, // nil = the parent's expiry
)

// The caller's key verifies the leaf (signed by the personal agent). Ancestor
// keys come from ResolveKey; without it only content-addressed DIDs resolve.
resolveKey := func(did string) (ed25519.PublicKey, error) {
    if did == "did:aroha:personal-agent-alice" {
        return userPubKey, nil
    }
    return nil, fmt.Errorf("unknown DID %s", did)
}
r := mandate.VerifyMandate(cart.Token, personalAgentPublicKey, "did:aroha:shopping-orchestrator",
    mandate.VerifyOptions{ResolveKey: resolveKey})
if r.Valid {
    fmt.Println(r.Mandate.Constraints.SpendLimitUSD) // 79.99
}
// VerifyMandate checks one leaf key; before moving money use mandate.VerifyMandateChain.
```

