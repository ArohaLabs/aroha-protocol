<!-- Copyright (c) 2026 Aroha Labs
     SPDX-License-Identifier: Apache-2.0 -->

# Java SDK

**Artifact:** `com.aroha-labs:aroha-sdk:1.0.0` · **Requires:** Java 21+ · **Build:** Maven 3

## Installation

> **Not on Maven Central.** `com.aroha-labs:aroha-sdk` has not been published, so the coordinates
> below resolve only after you install the SDK into your local Maven repository from a checkout:
>
> ```bash
> cd sdks/java && mvn -B install
> ```
>
> Java packages are `com.arohalabs.*` (the groupId is `com.aroha-labs`). v2 mandate tokens (with
> chain verification), the hardened envelope rules and E-DID / Key Event Log verification are
> implemented and tested against the shared vectors, and `did:aroha-web` follows the current
> TypeScript schema — see the [feature matrix](feature-matrix.md).

=== "Maven"

    ```xml
    <dependency>
        <groupId>com.aroha-labs</groupId>
        <artifactId>aroha-sdk</artifactId>
        <version>1.0.0</version>
    </dependency>
    ```

=== "Gradle"

    ```groovy
    implementation 'com.aroha-labs:aroha-sdk:1.0.0'
    ```

**Key dependencies:** `org.bouncycastle:bcprov-jdk18on:1.78.1` (Ed25519), `com.fasterxml.jackson.core:jackson-databind:2.17.1` (JSON).

## Quick Start

```java
import com.arohalabs.identity.DID;
import com.arohalabs.messages.ArohaEnvelope;
import com.arohalabs.messages.NonceRegistry;
import com.arohalabs.transport.ArohaServer;

// 1. Generate identity
var identity = DID.generate("my-agent", "http://localhost:3001");

// 2. Start a server (virtual threads via JDK 21)
var server = new ArohaServer(
    3001,
    identity.didDocument(),
    identity.did(),
    did -> null,               // publicKeyResolver — add real lookup
    new NonceRegistry(),
    (envelope, respond, stream) -> {
        System.out.println("Received: " + envelope.get("type"));
        // respond.accept(replyEnvelope) for synchronous reply
        // return nothing for 202 Accepted
    },
    true                       // devMode — refused unless AROHA_DEV_MODE=1; never in production
);

server.start();
```

---

## `com.arohalabs.identity.DID`

### `generate(agentId, endpoint) → AgentIdentity`

Generates a `did:aroha:` DID, an Ed25519 keypair, and a conformant DID Document.

```java
import com.arohalabs.identity.DID;

var identity = DID.generate("pricing-agent", "https://agents.example.com/pricing");

identity.did()         // "did:aroha:pricing-agent"
identity.keyId()       // "did:aroha:pricing-agent#key-1"
identity.didDocument() // Map<String, Object> — full DID Document
identity.privateKey()  // Ed25519PrivateKeyParameters (Bouncy Castle)
identity.publicKey()   // Ed25519PublicKeyParameters
```

### `AgentIdentity` (record)

```java
record AgentIdentity(
    String did,
    String keyId,
    Map<String, Object> didDocument,
    Ed25519PrivateKeyParameters privateKey,
    Ed25519PublicKeyParameters  publicKey
) {}
```

### `Ed25519KeyPair` (record)

```java
// Generate a raw keypair without a full DID:
var pair = DID.generateKeyPair();
pair.privateKey();  // Ed25519PrivateKeyParameters
pair.publicKey();   // Ed25519PublicKeyParameters
```

### Helpers

```java
byte[]  pubBytes = DID.extractPublicKey(didDocumentMap);
String  endpoint = DID.extractEndpoint(didDocumentMap);
String  encoded  = DID.toMultibase(rawBytes);    // → "z<base58btc>"
byte[]  decoded  = DID.fromMultibase(encoded);
```

---

## `com.arohalabs.crypto.Signing`

```java
import com.arohalabs.crypto.Signing;

// Sign — adds "proof" field to the envelope map
Signing.signMessage(envelopeMap, privateKey, "did:aroha:my-agent#key-1");

// Verify
boolean valid = Signing.verifyMessageSignature(envelopeMap, publicKey);

// Canonical JSON (lexicographically sorted keys, for signing)
byte[] canonical = Signing.canonicalize(envelopeMap);
```

## `com.arohalabs.crypto.Encryption`

ECDH-ES + AES-256-GCM body encryption.

```java
import com.arohalabs.crypto.Encryption;

// Byte-compatible with aroha-core encryptBody/decryptBody: takes the
// recipient's Ed25519 keys (Ed25519PublicKeyParameters / Ed25519PrivateKeyParameters).
// Encrypt — returns a map with "alg", "epk" (raw X25519), "iv", "ciphertext", "tag"
Map<String, Object> encrypted = Encryption.encryptBody(plaintextMap, recipientPublicKey);

// Decrypt
Map<String, Object> plaintext = Encryption.decryptBody(encrypted, recipientPrivateKey);
```

---

## `com.arohalabs.messages`

### `ArohaEnvelope.build(...)`

Builds and signs an outbound Aroha envelope.

```java
import com.arohalabs.messages.ArohaEnvelope;
import com.arohalabs.messages.MessageTypes;

// Standard build (300s TTL)
Map<String, Object> envelope = ArohaEnvelope.build(
    MessageTypes.Aroha_REQUEST,           // type
    "did:aroha:sender",                   // from
    "did:aroha:receiver",                 // to
    Map.of("capability", "convert",      // body
           "amount", 100),
    ArohaEnvelope.newCorrelationId(),     // correlationId
    identity.privateKey(),               // Ed25519PrivateKeyParameters
    identity.keyId()                     // "did:aroha:sender#key-1"
);

// With custom TTL
Map<String, Object> envelope = ArohaEnvelope.build(
    type, from, to, body, corrId, privateKey, keyId,
    60   // ttlSeconds
);

// With extra fields (traceparent, routingHint, etc.)
var extras = new LinkedHashMap<String, Object>();
extras.put("traceparent", "00-4bf92f3577b34da6a3ce929d0e0e4736-01");
extras.put("routingHint", Map.of("complexity", "standard"));

Map<String, Object> envelope = ArohaEnvelope.build(
    type, from, to, body, corrId, privateKey, keyId, 300, extras
);
```

### `ArohaEnvelope.validate(...)`

Validates an inbound envelope: recipient → expiry → nonce → signature.

```java
import com.arohalabs.messages.ArohaEnvelope;
import com.arohalabs.messages.NonceRegistry;

var nonces = new NonceRegistry();

ArohaEnvelope.ValidationResult result = ArohaEnvelope.validate(
    envelopeMap,
    senderPublicKey,          // Ed25519PublicKeyParameters
    "did:aroha:my-agent",      // myDid
    nonces
);

if (!result.ok()) {
    System.err.println("Rejected: " + result.reason());
}

// For mTLS / VPC trusted-mesh environments, where a transport-level check
// authenticates the peer. skipSignature alone is refused (DevMode.NotPermittedException)
// unless acknowledgeUnauthenticated(true) is set or AROHA_DEV_MODE=1.
ArohaEnvelope.validate(envelope, senderKey, myDid, nonces,
    new ArohaEnvelope.ValidateOptions().skipSignature(true).acknowledgeUnauthenticated(true));
// Nonces longer than 128 characters are rejected.
```

### `ValidationResult` (record)

```java
record ValidationResult(boolean ok, String reason) {
    static ValidationResult ok()           { ... }
    static ValidationResult fail(String r) { ... }
}
```

### `MessageTypes`

```java
import com.arohalabs.messages.MessageTypes;

MessageTypes.Aroha_REQUEST       // "ArohaRequest"
MessageTypes.Aroha_RESPONSE      // "ArohaResponse"
MessageTypes.Aroha_STREAM        // "ArohaStream"
MessageTypes.Aroha_NEGOTIATE     // "ArohaNegotiate"
MessageTypes.Aroha_COUNTER_OFFER // "ArohaCounterOffer"
MessageTypes.Aroha_ACCEPT        // "ArohaAccept"
MessageTypes.Aroha_RESERVE       // "ArohaReserve"
MessageTypes.Aroha_RESERVE_ACK   // "ArohaReserveAck"
MessageTypes.Aroha_COMMIT        // "ArohaCommit"
MessageTypes.Aroha_COMMIT_ACK    // "ArohaCommitAck"
MessageTypes.Aroha_CANCEL        // "ArohaCancel"
MessageTypes.Aroha_CANCEL_ACK    // "ArohaCancelAck"
MessageTypes.Aroha_DELEGATE      // "ArohaDelegate"
MessageTypes.Aroha_ERROR         // "ArohaError"
MessageTypes.Aroha_SATISFACTION  // "ArohaSatisfactionSignal"

MessageTypes.ALL  // Set<String> of all 15 types
```

### `MessageTypes.ErrorCode`

```java
import com.arohalabs.messages.MessageTypes.ErrorCode;

// Auth
ErrorCode.UNAUTHORIZED              // "Aroha_UNAUTHORIZED"
ErrorCode.FORBIDDEN                 // "Aroha_FORBIDDEN"
// Protocol
ErrorCode.INVALID_SIGNATURE         // "Aroha_INVALID_SIGNATURE"
ErrorCode.EXPIRED_MESSAGE           // "Aroha_EXPIRED_MESSAGE"
ErrorCode.REPLAY_DETECTED           // "Aroha_REPLAY_DETECTED"
ErrorCode.UNKNOWN_CAPABILITY        // "Aroha_UNKNOWN_CAPABILITY"
ErrorCode.TRUST_LEVEL_INSUFFICIENT  // "Aroha_TRUST_LEVEL_INSUFFICIENT"
// Saga
ErrorCode.RESERVATION_FAILED        // "Aroha_RESERVATION_FAILED"
ErrorCode.RESERVATION_EXPIRED       // "Aroha_RESERVATION_EXPIRED"
ErrorCode.COMMIT_FAILED             // "Aroha_COMMIT_FAILED"
ErrorCode.CANCEL_FAILED             // "Aroha_CANCEL_FAILED"
ErrorCode.INVALID_TOKEN             // "Aroha_INVALID_TOKEN"
// Availability
ErrorCode.NO_INVENTORY              // "Aroha_NO_INVENTORY"
ErrorCode.CAPACITY_EXCEEDED         // "Aroha_CAPACITY_EXCEEDED"
ErrorCode.SERVICE_UNAVAILABLE       // "Aroha_SERVICE_UNAVAILABLE"
// Generic
ErrorCode.INTERNAL_ERROR            // "Aroha_INTERNAL_ERROR"
ErrorCode.INVALID_PARAMS            // "Aroha_INVALID_PARAMS"
```

!!! warning "Wire format"
    Always use these constants when setting the `code` field of a `ArohaError` body. Never rely on `enum.name()` — Java's default serialisation produces `UNKNOWN_CAPABILITY`, not the required `Aroha_UNKNOWN_CAPABILITY`.

### `NonceRegistry`

Thread-safe replay prevention backed by `ConcurrentHashMap`.

```java
import com.arohalabs.messages.NonceRegistry;

var nonces = new NonceRegistry();
boolean fresh   = nonces.check("abc123", "2026-04-29T12:00:00Z"); // true
boolean replay  = nonces.check("abc123", "2026-04-29T12:00:00Z"); // false
```

---

## `com.arohalabs.transport`

### `ArohaServer`

Uses the JDK built-in `com.sun.net.httpserver` with virtual threads (`Executors.newVirtualThreadPerTaskExecutor()`). For production TLS, terminate with nginx, Caddy, or a cloud load balancer.

```java
import com.arohalabs.transport.ArohaServer;

var server = new ArohaServer(
    3001,                     // port
    identity.didDocument(),   // DID Document (served at /.well-known)
    identity.did(),           // this agent's DID
    did -> keyStore.get(did), // Function<String, Ed25519PublicKeyParameters>
    new NonceRegistry(),
    (envelope, respond, stream) -> {
        String type = (String) envelope.get("type");

        if (MessageTypes.Aroha_REQUEST.equals(type)) {
            var reply = ArohaEnvelope.build(
                MessageTypes.Aroha_RESPONSE,
                identity.did(),
                (String) envelope.get("from"),
                Map.of("result", "ok"),
                (String) envelope.get("correlationId"),
                identity.privateKey(),
                identity.keyId()
            );
            respond.accept(reply);   // synchronous 200 reply
        }
        // not calling respond → 202 Accepted (async)
    }
    // devMode defaults to false — true skips crypto and is refused unless AROHA_DEV_MODE=1
);
// Binds 127.0.0.1 and answers 413 for bodies over 1 MiB. To accept remote
// connections: new ArohaServer("0.0.0.0", port, doc, did, resolver, nonces, handler, false, 0)

server.start(); // blocks
// server.stop() to shut down
```

### `MessageHandler` (functional interface)

```java
@FunctionalInterface
public interface MessageHandler {
    void handle(
        Map<String, Object> envelope,
        Consumer<Map<String, Object>> respond,     // call for synchronous reply (200)
        Consumer<Map<String, Object>> streamEvent  // call for SSE stream events
    ) throws Exception;
}
```

### `ArohaClient`

Uses `java.net.http.HttpClient` (Java 11+) with a 30-second default timeout.

```java
import com.arohalabs.transport.ArohaClient;

var client = new ArohaClient();
// Endpoints must be https except loopback hosts (127.0.0.0/8, ::1, localhost).
// new ArohaClient(true) permits plain http on a network you control.

// Synchronous — returns null on 202 Accepted
Map<String, Object> reply = client.send(
    "http://localhost:3001/aroha/v1",
    signedEnvelope
);

// Custom timeout
Map<String, Object> reply = client.send(endpoint, envelope, Duration.ofSeconds(10));

// Non-blocking
CompletableFuture<Map<String, Object>> future = client.sendAsync(endpoint, envelope);

// Fetch DID Document
Map<String, Object> doc = client.fetchDIDDocument("http://localhost:3001");
```

---

## `com.arohalabs.orchestrator.SagaEngine`

Coordinates atomic 3-phase transactions. Virtual threads handle parallel reserve operations.

```java
import com.arohalabs.orchestrator.SagaEngine;
import com.arohalabs.orchestrator.SagaEngine.SagaStep;

var engine = new SagaEngine(client, identity.did(), identity.keyId(), identity.privateKey());

var steps = List.of(
    new SagaStep(
        "did:aroha:flight-agent",
        "https://flights.example.com/aroha/v1",
        "book-flight",
        Map.of("origin", "JFK", "dest", "NRT"),
        30_000  // holdDurationMs
    ),
    new SagaStep(
        "did:aroha:hotel-agent",
        "https://hotels.example.com/aroha/v1",
        "book-hotel",
        Map.of("city", "Tokyo", "nights", 5),
        30_000
    )
);

SagaEngine.SagaResult result = engine.execute(steps);

if (result.success()) {
    System.out.println(result.results());  // Map<Integer, Map<String,Object>>
} else {
    System.out.println(result.failures()); // List<Map<String,Object>>
}
```

**Saga phases:**
1. **Reserve** — all steps in parallel virtual threads; any failure cancels all
2. **Commit** — steps in order; failure triggers LIFO `ArohaCancel` to committed steps
3. **Compensate** — cancellations sent in reverse commit order

### `SagaStep` fields

| Field | Type | Description |
|---|---|---|
| `agentDid` | `String` | Target agent's DID |
| `agentEndpoint` | `String` | Target agent's `/aroha/v1` URL |
| `capability` | `String` | Capability name |
| `params` | `Map<String,Object>` | Request parameters |
| `holdDurationMs` | `long` | Reservation hold window (ms) |
| `stepId` | `String` | Auto-generated UUID |
| `state` | `SagaStep.State` | `PENDING` → `RESERVED` → `COMMITTED` / `CANCELLED` |
| `reservationToken` | `String` | Token returned by `ArohaReserveAck` |

---

## Framework Bridges

### Spring AI

```java
import com.arohalabs.bridges.SpringAiBridge;

// Wrap a Aroha capability as a Spring AI tool
var tool = SpringAiBridge.arohaCapabilityAsTool(
    "did:aroha:fx-agent",
    "https://fx.example.com/aroha/v1",
    "convert",
    client,
    identity
);
```

!!! note
    The Spring AI bridge is currently a stub. Full implementation is on the roadmap. Community contributions welcome — see the [GitHub repo](https://github.com/ArohaLabs/aroha-protocol).

---

## `com.arohalabs.identity.WebDID`

Two-factor DNS-anchored identity. See [did:aroha-web: spec →](../spec/web-did.md)

A port of the TypeScript resolver: same document shape (`verificationMethod[]`
with base58 `publicKeyMultibase`, `arohaWeb.keyHistory` newest first, v2
DID-bound rotation records) and the same resolution rules, checked against a
TypeScript-generated vector.

```java
import com.arohalabs.identity.WebDID;

var agent = WebDID.generateWebAgent("stripe.com", "payments-agent", null);
// agent.did() == "did:aroha-web:stripe.com:payments-agent"
// Serve agent.document() (JSON) at agent.wellKnownUrl(); publish agent.dnsTxtRecord() at _aroha.stripe.com.

var rotated = WebDID.rotateKey(agent, Duration.ofHours(24), Instant.now()); // v2 record signed by the old key

var result = WebDID.resolveWebDID("did:aroha-web:stripe.com:payments-agent");
byte[] key = WebDID.selectWebDIDKey(result, null); // throws when no key is accepted (fail closed)
```

`resolveWebDID` refuses domains that are not hostnames (IPv4 needs
`allowIpLiteral(true)`) and paths outside `^[a-z0-9-]+(/[a-z0-9-]+)*$`; fetches
over https without following redirects, with a 10 s timeout and a 64 KiB cap;
hashes the served key itself and requires the rotation chain to link it to a key
`_aroha.{domain}` commits to (JDK JNDI DNS by default). `dnsVerified()` is false
whenever DNS was not checked.

---

## `com.arohalabs.orchestrator.CSNHandler`

Capability Schema Negotiation — structural matching before LLM fallback.
See [CSN guide →](../spec/csn.md)

```java
import com.arohalabs.orchestrator.CSNHandler;

// ── Provider ──────────────────────────────────────────────────────────────────
var registry = new CSNHandler.CapabilityRegistry();
registry.register(new CSNHandler.CapabilityEntry(
    "fx-convert", "Convert between two currencies",
    Map.of("type", "object",
        "properties", Map.of(
            "amount", Map.of("type", "number"),
            "from",   Map.of("type", "string"),
            "to",     Map.of("type", "string")
        ),
        "required", List.of("amount", "from", "to"))
));

var handler = new CSNHandler(registry, agentDID, privateKey, this::buildEnvelope, null);

// In your onMessage handler:
if ("ArohaNegotiate".equals(type) && body.containsKey("csn")) {
    var reply = handler.handle(envelope, senderDID);
    respond(reply);
}

// ── Requestor ─────────────────────────────────────────────────────────────────
var negotiator = new CSNHandler.CapabilityNegotiator(
    sendFn, this::buildEnvelope, orchestratorDID, privateKey,
    new CSNHandler.DiscoveryCache()
);
var result = negotiator.discover(
    "https://fx.example.com/aroha/v1",
    "did:aroha-web:fx.example.com:agent",
    new CSNHandler.DiscoveryRequest(
        "convert currency from USD to JPY",
        Map.of("input", Map.of("type", "object",
            "properties", Map.of(
                "amount", Map.of("type", "number"),
                "from",   Map.of("type", "string"),
                "to",     Map.of("type", "string")
            ), "required", List.of("amount", "from", "to"))),
        Map.of(), false
    )
);
// result.resolvedCapability() == "fx-convert"
// result.matchMethod() == "schema"   (deterministic, no LLM)
// result.rounds() == 0               (DiscoveryCache hit on repeat)
```

### Compatibility score thresholds

| Score | Meaning | Action |
|-------|---------|--------|
| ≥ 0.85 | Confident structural match | Accept — no LLM |
| 0.5–0.85 | Ambiguous | LLM fallback (if `ICapabilityMatcher` configured) |
| < 0.5 | Incompatible | Reject |

---

## `com.arohalabs.reputation.ReputationEngine`

Bayesian Beta reputation engine with 11 signals and Thompson Sampling.
See [Reputation Model →](../reputation-model.md)

```java
import com.arohalabs.reputation.ReputationEngine;

var engine = new ReputationEngine(ReputationEngine.CompositeWeights.defaults());

engine.recordEvent(new ReputationEngine.ReputationEvent.Builder()
    .agentDid("did:aroha:fx-agent")
    .domain("fx")
    .signal("saga_complete")
    .success(true)
    .responseMs(120)
    .build());

double score = engine.compositeScore("did:aroha:fx-agent", "fx");

var ranked = engine.thompsonSelect(
    List.of("did:aroha:fx-a", "did:aroha:fx-b"),
    "fx",
    true   // risk-gated (Wilson lower-bound)
);
```

---

## `com.arohalabs.mandate.ArohaMandateCredential`

Spending mandate delegation chain — Intent → Cart → Payment.
See [@aroha-sdk/credentials →](../packages/credentials.md)

```java
import com.arohalabs.mandate.ArohaMandateCredential;
import com.arohalabs.mandate.ArohaMandateCredential.*;

var constraints = SpendingConstraints.builder()
    .spendLimitUsd(500.0)
    .currency("USD")
    .build();

var intent = ArohaMandateCredential.issueIntent(
    "did:aroha:personal-agent-alice",
    "did:aroha:personal-agent",
    constraints,
    userPrivKey,
    3_600_000L
);

var cartConstraints = SpendingConstraints.builder()
    .spendLimitUsd(79.99)
    .allowedMerchants(List.of("did:aroha:bookshop"))
    .build();

var cart = ArohaMandateCredential.attenuateToCart(
    intent, "did:aroha:shopping-orchestrator", cartConstraints, personalAgentKey, 0L
);

var result = ArohaMandateCredential.verify(
    cart.token(), grantorPublicKey, "did:aroha:shopping-orchestrator"
);
if (result.valid()) {
    System.out.println(result.mandate().constraints().spendLimitUsd()); // 79.99
}
```
