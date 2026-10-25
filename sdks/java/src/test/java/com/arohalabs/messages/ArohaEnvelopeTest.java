// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

package com.arohalabs.messages;

import com.arohalabs.TestSupport;
import com.arohalabs.crypto.Signing;
import com.arohalabs.identity.DID;
import com.arohalabs.messages.ArohaEnvelope.ValidateOptions;
import com.arohalabs.messages.ArohaEnvelope.ValidationResult;
import com.arohalabs.util.IsoTime;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.*;

import static org.junit.jupiter.api.Assertions.*;

class ArohaEnvelopeTest {

    static final Ed25519PrivateKeyParameters ALICE = TestSupport.seed(31);
    static final Ed25519PrivateKeyParameters BOB = TestSupport.seed(32);
    static final Ed25519PublicKeyParameters ALICE_PUB = ALICE.generatePublicKey();
    static final Ed25519PublicKeyParameters BOB_PUB = BOB.generatePublicKey();
    static final String ALICE_DID = "did:aroha:alice";
    static final String BOB_DID = "did:aroha:bob";
    static final String ME = "did:aroha:provider";

    static Map<String, Object> build(Ed25519PrivateKeyParameters key, String from) throws Exception {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("capability", "fx-convert");
        body.put("amount", 100.0);
        return ArohaEnvelope.build("ArohaRequest", from, ME, body, ArohaEnvelope.newCorrelationId(), key, from + "#key-1");
    }

    /** Edit fields, then re-sign as {@code key} so only the edited rule can fail. */
    static Map<String, Object> resign(Map<String, Object> env, Ed25519PrivateKeyParameters key) throws Exception {
        return Signing.signMessage(env, key, env.get("from") + "#key-1");
    }

    @Test
    void builtEnvelopeHasTsShape() throws Exception {
        Map<String, Object> env = build(ALICE, ALICE_DID);
        assertTrue(((String) env.get("nonce")).matches("[0-9a-f]{64}"), "32-byte hex nonce");
        assertTrue(((String) env.get("created")).matches(".*\\.\\d{3}Z"));
        assertTrue(((String) env.get("correlationId")).startsWith("saga-"));
        long ttl = IsoTime.parseMillis(env.get("expires")) - IsoTime.parseMillis(env.get("created"));
        assertEquals(300_000, ttl);
        // Canonical form is JCS: the double amount is written as 100, not 100.0.
        String canonical = new String(Signing.canonicalize(env), StandardCharsets.UTF_8);
        assertTrue(canonical.contains("\"amount\":100,"), canonical);
        assertFalse(canonical.contains("proof"));
    }

    @Test
    void validEnvelopePasses() throws Exception {
        ValidationResult r = ArohaEnvelope.validate(build(ALICE, ALICE_DID), ALICE_PUB, ME, new NonceRegistry());
        assertTrue(r.valid(), r.reason());
        assertTrue(r.isOk());
    }

    @Test
    void wrongRecipientFails() throws Exception {
        ValidationResult r = ArohaEnvelope.validate(build(ALICE, ALICE_DID), ALICE_PUB, "did:aroha:someone-else", new NonceRegistry());
        assertFalse(r.valid());
        assertTrue(r.reason().startsWith("Message addressed to"));
    }

    @Test
    void wrongKeyFails() throws Exception {
        ValidationResult r = ArohaEnvelope.validate(build(ALICE, ALICE_DID), BOB_PUB, ME, new NonceRegistry());
        assertEquals("Signature verification failed", r.reason());
    }

    @Test
    void tamperedBodyFails() throws Exception {
        Map<String, Object> env = build(ALICE, ALICE_DID);
        @SuppressWarnings("unchecked") Map<String, Object> body = (Map<String, Object>) env.get("body");
        body.put("amount", 1);
        assertFalse(ArohaEnvelope.validate(env, ALICE_PUB, ME, new NonceRegistry()).valid());
    }

    @Test
    void expiredAndToleranceWindow() throws Exception {
        Map<String, Object> env = build(ALICE, ALICE_DID);
        long expires = IsoTime.parseMillis(env.get("expires"));
        ValidationResult r = ArohaEnvelope.validate(env, ALICE_PUB, ME, new NonceRegistry(),
            new ValidateOptions().nowMs(expires + 1));
        assertTrue(r.reason().startsWith("Message expired"), r.reason());
        assertTrue(ArohaEnvelope.validate(env, ALICE_PUB, ME, new NonceRegistry(),
            new ValidateOptions().nowMs(expires + 1).clockToleranceMs(5_000)).valid());
        assertTrue(ArohaEnvelope.validate(env, ALICE_PUB, ME, new NonceRegistry(),
            new ValidateOptions().clockToleranceMs(-1)).reason().contains("non-negative"));
    }

    @Test
    void lifetimeAboveFiveMinutesIsRejectedByDefault() throws Exception {
        Map<String, Object> env = ArohaEnvelope.build("ArohaRequest", ALICE_DID, ME, Map.of(), "c", ALICE,
            ALICE_DID + "#key-1", 3600);
        ValidationResult r = ArohaEnvelope.validate(env, ALICE_PUB, ME, new NonceRegistry());
        assertFalse(r.valid());
        assertTrue(r.reason().contains("exceeds maximum 300000ms"), r.reason());
        assertTrue(ArohaEnvelope.validate(env, ALICE_PUB, ME, new NonceRegistry(),
            new ValidateOptions().maxTtlMs(3_600_000)).valid());
    }

    @Test
    void createdTooFarInTheFutureIsRejected() throws Exception {
        Map<String, Object> env = build(ALICE, ALICE_DID);
        Instant future = Instant.now().plusSeconds(120);
        env.put("created", IsoTime.format(future));
        env.put("expires", IsoTime.format(future.plusSeconds(60)));
        ValidationResult r = ArohaEnvelope.validate(resign(env, ALICE), ALICE_PUB, ME, new NonceRegistry());
        assertTrue(r.reason().contains("is in the future"), r.reason());
    }

    @Test
    void malformedTimestampsAndMissingNonceAreRejected() throws Exception {
        Map<String, Object> env = build(ALICE, ALICE_DID);
        env.put("expires", "tomorrow");
        assertEquals("Malformed created/expires timestamp",
            ArohaEnvelope.validate(resign(env, ALICE), ALICE_PUB, ME, new NonceRegistry()).reason());
        Map<String, Object> noNonce = build(ALICE, ALICE_DID);
        noNonce.remove("nonce");
        assertEquals("Missing nonce",
            ArohaEnvelope.validate(resign(noNonce, ALICE), ALICE_PUB, ME, new NonceRegistry()).reason());
    }

    @Test
    void replayIsRejected() throws Exception {
        NonceRegistry nonces = new NonceRegistry();
        Map<String, Object> env = build(ALICE, ALICE_DID);
        assertTrue(ArohaEnvelope.validate(env, ALICE_PUB, ME, nonces).valid());
        assertEquals("Nonce replay detected", ArohaEnvelope.validate(env, ALICE_PUB, ME, nonces).reason());
    }

    @Test
    void noncesAreScopedPerSender() throws Exception {
        NonceRegistry nonces = new NonceRegistry();
        Map<String, Object> a = build(ALICE, ALICE_DID);
        Map<String, Object> b = build(BOB, BOB_DID);
        b.put("nonce", a.get("nonce"));
        resign(b, BOB);
        assertTrue(ArohaEnvelope.validate(a, ALICE_PUB, ME, nonces).valid());
        assertTrue(ArohaEnvelope.validate(b, BOB_PUB, ME, nonces).valid(), "same nonce, different sender");
    }

    @Test
    void forgedEnvelopeCannotPreBurnANonce() throws Exception {
        NonceRegistry nonces = new NonceRegistry();
        Map<String, Object> genuine = build(ALICE, ALICE_DID);
        Map<String, Object> forged = new LinkedHashMap<>(genuine);
        resign(forged, BOB); // claims to be Alice, signed by Bob
        assertFalse(ArohaEnvelope.validate(forged, ALICE_PUB, ME, nonces).valid());
        assertTrue(ArohaEnvelope.validate(genuine, ALICE_PUB, ME, nonces).valid(),
            "the nonce is recorded only after the signature verifies");
    }

    @Test
    void proofKeyMustBelongToFrom() throws Exception {
        Map<String, Object> env = build(ALICE, ALICE_DID);
        Signing.signMessage(env, ALICE, BOB_DID + "#key-1");
        ValidationResult r = ArohaEnvelope.validate(env, ALICE_PUB, ME, new NonceRegistry());
        assertTrue(r.reason().contains("proof key belongs to a different DID"), r.reason());
    }

    @Test
    void skipSignatureStillRecordsTheNonce() throws Exception {
        NonceRegistry nonces = new NonceRegistry();
        Map<String, Object> env = build(ALICE, ALICE_DID);
        ValidateOptions ack = new ValidateOptions().skipSignature(true).acknowledgeUnauthenticated(true);
        assertTrue(ArohaEnvelope.validate(env, (Ed25519PublicKeyParameters) null, ME, nonces, ack).valid());
        assertFalse(ArohaEnvelope.validate(env, (Ed25519PublicKeyParameters) null, ME, nonces, ack).valid());
    }

    @Test
    void skipSignatureNeedsAcknowledgementOrDevEnv() throws Exception {
        Map<String, Object> env = build(ALICE, ALICE_DID);
        try {
            DevMode.setEnvLookupForTesting(k -> null);
            DevMode.NotPermittedException e = assertThrows(DevMode.NotPermittedException.class,
                () -> ArohaEnvelope.validate(env, null, ME, new NonceRegistry(), true));
            assertTrue(e.getMessage().contains("AROHA_DEV_MODE=1"), e.getMessage());
            DevMode.setEnvLookupForTesting(k -> "true");
            assertThrows(DevMode.NotPermittedException.class,
                () -> ArohaEnvelope.validate(env, null, ME, new NonceRegistry(), true));
            DevMode.setEnvLookupForTesting(k -> DevMode.ENV.equals(k) ? "1" : null);
            assertTrue(ArohaEnvelope.validate(env, null, ME, new NonceRegistry(), true).valid());
        } finally {
            DevMode.setEnvLookupForTesting(null);
        }
    }

    @Test
    void nonceLongerThan128CharactersIsRejected() throws Exception {
        for (int n : new int[]{128, 129}) {
            Map<String, Object> env = build(ALICE, ALICE_DID);
            env.put("nonce", "a".repeat(n));
            env = resign(env, ALICE);
            ValidationResult r = ArohaEnvelope.validate(env, ALICE_PUB, ME, new NonceRegistry());
            if (n == 128) assertTrue(r.valid(), r.reason());
            else assertEquals("Nonce too long (max 128 characters)", r.reason());
        }
    }

    @Test
    void didDocumentSelectsTheNamedVerificationMethod() throws Exception {
        var id = DID.generate("alice-multi", "https://alice.example/aroha/v1");
        Map<String, Object> doc = new LinkedHashMap<>(id.didDocument());
        Ed25519PrivateKeyParameters device2 = TestSupport.seed(33);
        List<Object> vms = new ArrayList<>((List<?>) doc.get("verificationMethod"));
        vms.add(Map.of("id", "#key-2", "type", "Ed25519VerificationKey2020", "controller", id.did(),
            "publicKeyMultibase", DID.toMultibase(TestSupport.pub(device2))));
        doc.put("verificationMethod", vms);

        Map<String, Object> env = ArohaEnvelope.build("ArohaRequest", id.did(), ME, Map.of(), "c", device2, id.did() + "#key-2");
        assertTrue(ArohaEnvelope.validate(env, doc, ME, new NonceRegistry(), new ValidateOptions()).valid());

        Map<String, Object> wrongDoc = new LinkedHashMap<>(doc);
        wrongDoc.put("id", "did:aroha:mallory");
        assertTrue(ArohaEnvelope.validate(env, wrongDoc, ME, new NonceRegistry(), new ValidateOptions())
            .reason().contains("does not match `from`"));
    }

    @Test
    void nonceRegistryDropsExpiredEntries() {
        NonceRegistry r = new NonceRegistry();
        assertTrue(r.check("k", IsoTime.format(Instant.now().plusSeconds(60))));
        assertFalse(r.check("k", IsoTime.format(Instant.now().plusSeconds(60))));
        assertFalse(r.check("old", IsoTime.format(Instant.now().minusSeconds(1))), "already expired");
        assertFalse(r.check("bad", "not-a-date"));
        assertEquals(1, r.size());
    }
}
