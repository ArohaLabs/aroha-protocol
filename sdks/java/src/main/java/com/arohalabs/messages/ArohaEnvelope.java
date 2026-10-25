// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

package com.arohalabs.messages;

import com.arohalabs.crypto.Signing;
import com.arohalabs.identity.DID;
import com.arohalabs.util.IsoTime;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;

import java.security.SecureRandom;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.*;

/**
 * Aroha Layer 3 — Envelope Builder and Validator
 *
 * Builds signed Aroha message envelopes and validates incoming ones.
 *
 * Envelope format (JSON-LD):
 * <pre>{@code
 * {
 *   "@context": [...],
 *   "id":            "urn:uuid:<uuid>",
 *   "type":          "<MessageType>",
 *   "from":          "did:aroha:<sender>",
 *   "to":            "did:aroha:<recipient>",
 *   "created":       "<ISO8601>",
 *   "expires":       "<ISO8601>",
 *   "nonce":         "<64 hex chars: 32 random bytes>",
 *   "correlationId": "<id>",
 *   "body":          { ... },
 *   "proof":         { "type": "Ed25519Signature2020", ... },
 *   "traceparent":   "<W3C-traceparent>"  // optional — set by telemetry layer
 *   "routingHint":   { ... }              // optional — set by orchestrator
 * }
 * }</pre>
 */
public final class ArohaEnvelope {

    private ArohaEnvelope() {}

    private static final List<String> CONTEXT = List.of(
        "https://aroha-labs.com/contexts/v1",
        "https://w3id.org/security/suites/ed25519-2020/v1"
    );

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    // ── Build ─────────────────────────────────────────────────────────────────

    /**
     * Builds and signs a Aroha envelope.
     *
     * @param type           message type (e.g. "ArohaRequest")
     * @param fromDid        sender DID
     * @param toDid          recipient DID
     * @param body           message body (will be included as-is)
     * @param correlationId  saga or session ID
     * @param privateKey     sender's Ed25519 private key
     * @param keyId          e.g. "did:aroha:alice#key-1"
     * @param ttlSeconds     time-to-live for the message (default 300). Receivers
     *                       reject envelopes whose {@code expires - created}
     *                       exceeds their maximum TTL (default also 5 minutes),
     *                       so a longer TTL only works against receivers
     *                       configured to accept it.
     * @return signed envelope as a mutable LinkedHashMap
     */
    public static Map<String, Object> build(
            String type,
            String fromDid,
            String toDid,
            Map<String, Object> body,
            String correlationId,
            Ed25519PrivateKeyParameters privateKey,
            String keyId,
            int ttlSeconds) throws Exception {

        return build(type, fromDid, toDid, body, correlationId, privateKey, keyId, ttlSeconds, null);
    }

    /** Convenience overload with default TTL of 300 seconds. */
    public static Map<String, Object> build(
            String type,
            String fromDid,
            String toDid,
            Map<String, Object> body,
            String correlationId,
            Ed25519PrivateKeyParameters privateKey,
            String keyId) throws Exception {
        return build(type, fromDid, toDid, body, correlationId, privateKey, keyId, 300, null);
    }

    /**
     * Builds and signs a Aroha envelope with optional extra fields.
     *
     * Extra fields are merged into the envelope before signing. Use this to
     * inject W3C traceparent or routingHint set by the telemetry / orchestrator
     * layers:
     *
     * <pre>{@code
     * Map<String, Object> extras = new LinkedHashMap<>();
     * extras.put("traceparent", "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01");
     * extras.put("routingHint", Map.of("complexity", "standard"));
     * ArohaEnvelope.build("ArohaRequest", from, to, body, corrId, key, keyId, 300, extras);
     * }</pre>
     *
     * @param extraFields optional map of additional envelope fields; may be null
     */
    public static Map<String, Object> build(
            String type,
            String fromDid,
            String toDid,
            Map<String, Object> body,
            String correlationId,
            Ed25519PrivateKeyParameters privateKey,
            String keyId,
            int ttlSeconds,
            Map<String, Object> extraFields) throws Exception {

        Instant now = Instant.now().truncatedTo(ChronoUnit.MILLIS);
        Map<String, Object> envelope = new LinkedHashMap<>();
        envelope.put("@context",      CONTEXT);
        envelope.put("id",            "urn:uuid:" + UUID.randomUUID());
        envelope.put("type",          type);
        envelope.put("from",          fromDid);
        envelope.put("to",            toDid);
        envelope.put("created",       IsoTime.format(now));
        envelope.put("expires",       IsoTime.format(now.plus(ttlSeconds, ChronoUnit.SECONDS)));
        envelope.put("nonce",         randomNonce());
        envelope.put("correlationId", correlationId);
        envelope.put("body",          body != null ? body : Map.of());

        // Merge optional extra fields (traceparent, routingHint, etc.)
        if (extraFields != null) {
            envelope.putAll(extraFields);
        }

        Signing.signMessage(envelope, privateKey, keyId);
        return envelope;
    }

    // ── Validate ──────────────────────────────────────────────────────────────

    /**
     * Default ceiling on an envelope's declared lifetime ({@code expires - created}):
     * 5 minutes, equal to the default build TTL. The TTL is the replay window a
     * nonce store must cover; an in-memory store forgets nonces on restart, so
     * an uncapped TTL let a captured envelope be replayed after any restart.
     */
    public static final long DEFAULT_MAX_ENVELOPE_TTL_MS = 300_000L;

    /**
     * Default allowance for a sender's clock running ahead of ours when
     * checking {@code created}.
     */
    public static final long DEFAULT_MAX_FUTURE_SKEW_MS = 30_000L;

    /**
     * Longest nonce {@code validate} accepts. Envelopes built by any Aroha SDK
     * carry 64 hex characters; the cap bounds what a sender can make the
     * replay store hold per message.
     */
    public static final int MAX_NONCE_LENGTH = 128;

    /** Options for {@link #validate(Map, Ed25519PublicKeyParameters, String, NonceRegistry, ValidateOptions)}. */
    public static final class ValidateOptions {
        private boolean skipSignature;
        private boolean acknowledgeUnauthenticated;
        private long clockToleranceMs;
        private long maxTtlMs = DEFAULT_MAX_ENVELOPE_TTL_MS;
        private Long maxFutureSkewMs;
        private Long nowMs;

        /**
         * Skip the Ed25519 check — only inside a trusted mesh. The nonce is
         * still recorded under the CLAIMED sender, which nothing authenticates
         * in this mode. It MUST be paired with a transport-level check that
         * authenticates the peer: validation throws
         * {@link DevMode.NotPermittedException} unless
         * {@link #acknowledgeUnauthenticated(boolean)} is also set or the
         * environment sets {@code AROHA_DEV_MODE=1}.
         */
        public ValidateOptions skipSignature(boolean v) { skipSignature = v; return this; }
        /**
         * States that a transport-level check (mTLS, a private link, a
         * signed-request layer) authenticates the peer, which is what makes
         * {@link #skipSignature(boolean)} acceptable outside dev mode.
         */
        public ValidateOptions acknowledgeUnauthenticated(boolean v) { acknowledgeUnauthenticated = v; return this; }
        /** Accept envelopes that expired up to this many ms ago. Default 0. */
        public ValidateOptions clockToleranceMs(long v) { clockToleranceMs = v; return this; }
        /** Maximum accepted {@code expires - created}. Default {@link #DEFAULT_MAX_ENVELOPE_TTL_MS}. */
        public ValidateOptions maxTtlMs(long v) { maxTtlMs = v; return this; }
        /** How far {@code created} may be in the future. Default max(clockTolerance, 30 s). */
        public ValidateOptions maxFutureSkewMs(long v) { maxFutureSkewMs = v; return this; }
        /** Override "now" (epoch ms) — tests and replayed audits. */
        public ValidateOptions nowMs(long v) { nowMs = v; return this; }
    }

    /**
     * Validates an incoming envelope with full cryptographic verification and
     * default options.
     */
    public static ValidationResult validate(
            Map<String, Object> envelope,
            Ed25519PublicKeyParameters senderPubKey,
            String myDid,
            NonceRegistry nonceRegistry) {
        return validate(envelope, senderPubKey, myDid, nonceRegistry, new ValidateOptions());
    }

    /** Validates an incoming envelope; {@code skipSignature} as in {@link ValidateOptions#skipSignature}. */
    public static ValidationResult validate(
            Map<String, Object> envelope,
            Ed25519PublicKeyParameters senderPubKey,
            String myDid,
            NonceRegistry nonceRegistry,
            boolean skipSignature) {
        return validate(envelope, senderPubKey, myDid, nonceRegistry,
            new ValidateOptions().skipSignature(skipSignature));
    }

    /**
     * Validates an incoming envelope against the sender's public key.
     *
     * <p>Order of checks (matches {@code validateEnvelope} in @aroha-sdk/core):
     * <ol>
     *   <li>Recipient: {@code to} must equal {@code myDid}.</li>
     *   <li>Timestamps — pure functions of the envelope, no state touched:
     *       {@code created}/{@code expires} parse; not expired (allowing
     *       {@code clockToleranceMs}); {@code created} not beyond the allowed
     *       future skew; declared lifetime within {@code maxTtlMs}; nonce present.</li>
     *   <li>Signature (unless skipped): a {@code proof.verificationMethod} that
     *       names a DID must name {@code from}; then Ed25519 over the JCS form.</li>
     *   <li>Nonce — recorded only now, under the per-sender key
     *       {@code <from>:<nonce>}, retained until {@code expires + tolerance}.</li>
     * </ol>
     *
     * <p>Signature before nonce: recording the nonce first let any
     * unauthenticated client fill the store or "pre-burn" a legitimate
     * sender's nonce. Per-sender keys stop one sender's envelope from
     * consuming another sender's nonce.
     */
    public static ValidationResult validate(
            Map<String, Object> envelope,
            Ed25519PublicKeyParameters senderPubKey,
            String myDid,
            NonceRegistry nonceRegistry,
            ValidateOptions options) {
        return validateInternal(envelope, senderPubKey, null, myDid, nonceRegistry, options);
    }

    /**
     * Validates against the sender's DID Document: its {@code id} must equal
     * {@code from}, and the key is the verification method that
     * {@code proof.verificationMethod} names (multi-device keys).
     */
    public static ValidationResult validate(
            Map<String, Object> envelope,
            Map<String, Object> senderDidDocument,
            String myDid,
            NonceRegistry nonceRegistry,
            ValidateOptions options) {
        return validateInternal(envelope, null, senderDidDocument, myDid, nonceRegistry, options);
    }

    private static ValidationResult validateInternal(
            Map<String, Object> envelope,
            Ed25519PublicKeyParameters senderPubKey,
            Map<String, Object> senderDoc,
            String myDid,
            NonceRegistry nonceRegistry,
            ValidateOptions options) {
        ValidateOptions opts = options != null ? options : new ValidateOptions();
        if (opts.skipSignature && !opts.acknowledgeUnauthenticated) {
            DevMode.require("ArohaEnvelope.ValidateOptions.skipSignature");
        }

        // 1. Recipient check — must be addressed to us
        Object to = envelope.get("to");
        if (myDid == null || !myDid.equals(to)) {
            return ValidationResult.fail("Message addressed to " + to + ", not " + myDid);
        }

        // 2. Timestamp checks — pure functions of the envelope, no state touched.
        long tolerance = opts.clockToleranceMs;
        if (tolerance < 0) {
            return ValidationResult.fail("Invalid clockToleranceMs: must be non-negative");
        }
        Long createdMs = IsoTime.parseMillis(envelope.get("created"));
        Long expiresMs = IsoTime.parseMillis(envelope.get("expires"));
        if (createdMs == null || expiresMs == null) {
            return ValidationResult.fail("Malformed created/expires timestamp");
        }
        long now = opts.nowMs != null ? opts.nowMs : System.currentTimeMillis();
        if (expiresMs + tolerance < now) {
            return ValidationResult.fail(
                "Message expired at " + envelope.get("expires") + " (outside tolerance window)");
        }
        long futureSkew = opts.maxFutureSkewMs != null
            ? opts.maxFutureSkewMs : Math.max(tolerance, DEFAULT_MAX_FUTURE_SKEW_MS);
        if (createdMs > now + futureSkew) {
            return ValidationResult.fail("Message created at " + envelope.get("created")
                + " is in the future (beyond allowed clock skew)");
        }
        if (expiresMs - createdMs > opts.maxTtlMs) {
            return ValidationResult.fail("Message lifetime " + (expiresMs - createdMs)
                + "ms exceeds maximum " + opts.maxTtlMs + "ms");
        }
        if (!(envelope.get("nonce") instanceof String nonce) || nonce.isEmpty()) {
            return ValidationResult.fail("Missing nonce");
        }
        if (nonce.codePointCount(0, nonce.length()) > MAX_NONCE_LENGTH) {
            return ValidationResult.fail("Nonce too long (max " + MAX_NONCE_LENGTH + " characters)");
        }
        Object from = envelope.get("from");

        // 3. Signature verification — BEFORE the nonce is recorded.
        if (!opts.skipSignature) {
            String vmId = null;
            if (envelope.get("proof") instanceof Map<?, ?> proof && proof.get("verificationMethod") instanceof String v) {
                vmId = v;
            }
            if (vmId != null) {
                String vmDid = didOfVerificationMethod(vmId);
                if (vmDid != null && !vmDid.equals(from)) {
                    return ValidationResult.fail(
                        "Signature verification failed: proof key belongs to a different DID than `from`");
                }
            }

            Ed25519PublicKeyParameters key = senderPubKey;
            if (senderDoc != null) {
                if (!Objects.equals(senderDoc.get("id"), from)) {
                    return ValidationResult.fail(
                        "Signature verification failed: sender DID document does not match `from`");
                }
                try {
                    key = new Ed25519PublicKeyParameters(DID.extractPublicKey(senderDoc, vmId, now), 0);
                } catch (Exception e) {
                    return ValidationResult.fail("Signature verification failed: " + e.getMessage());
                }
            }
            boolean ok;
            try {
                ok = key != null && Signing.verifyMessageSignature(envelope, key);
            } catch (Exception e) {
                ok = false;
            }
            if (!ok) return ValidationResult.fail("Signature verification failed");
        }

        // 4. Nonce (replay) — only authenticated envelopes reach here. Kept
        // until expires + tolerance: the expiry check accepts the envelope for
        // that long, so evicting earlier would reopen a replay window.
        boolean fresh = nonceRegistry.check(from + ":" + nonce, IsoTime.formatMillis(expiresMs + tolerance));
        if (!fresh) return ValidationResult.fail("Nonce replay detected");

        return ValidationResult.ok();
    }

    /** DID part of an absolute verification method id; null for a relative ("#frag") one. */
    private static String didOfVerificationMethod(String vmId) {
        if (vmId.startsWith("#")) return null;
        int hash = vmId.indexOf('#');
        return hash >= 0 ? vmId.substring(0, hash) : vmId;
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    /** New correlation id for a saga or session ({@code saga-<uuid>}, as in TS). */
    public static String newCorrelationId() {
        return "saga-" + UUID.randomUUID();
    }

    /** 32 random bytes, hex — the TypeScript SDK's nonce size. */
    private static String randomNonce() {
        byte[] bytes = new byte[32];
        SECURE_RANDOM.nextBytes(bytes);  // SecureRandom — never java.util.Random
        return HexFormat.of().formatHex(bytes);
    }

    // ── Result Type ───────────────────────────────────────────────────────────

    /** Validation verdict; {@code reason} is set when {@code valid} is false. */
    public record ValidationResult(boolean valid, String reason) {
        public static ValidationResult ok()           { return new ValidationResult(true,  null); }
        public static ValidationResult fail(String r) { return new ValidationResult(false, r); }
        /** Same as {@link #valid()}; kept for callers of the earlier {@code ok()} accessor. */
        public boolean isOk() { return valid; }
    }
}
