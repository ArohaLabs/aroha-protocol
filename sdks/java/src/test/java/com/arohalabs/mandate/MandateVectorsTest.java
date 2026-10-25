// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

package com.arohalabs.mandate;

import com.arohalabs.TestSupport;
import com.arohalabs.crypto.Jcs;
import com.arohalabs.crypto.Signing;
import com.arohalabs.identity.DID;
import com.arohalabs.mandate.ArohaMandateCredential.VerificationResult;
import com.arohalabs.mandate.ArohaMandateCredential.VerifyOptions;
import com.fasterxml.jackson.core.type.TypeReference;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;

import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.time.Instant;
import java.util.*;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * Cross-SDK conformance: packages/aroha-credentials/test-vectors/mandate-v2.json,
 * produced by the TypeScript reference. Skipped (not failed) when the SDK is
 * built outside the monorepo.
 */
class MandateVectorsTest {

    static final Path VECTORS = TestSupport.repoFile("packages/aroha-credentials/test-vectors/mandate-v2.json");
    static Map<String, Object> vectors;

    @BeforeAll
    static void load() throws Exception {
        assumeTrue(TestSupport.exists(VECTORS), "mandate-v2.json not found at " + VECTORS);
        vectors = TestSupport.readJson(VECTORS);
    }

    @SuppressWarnings("unchecked")
    static Map<String, Object> key(String name) {
        return (Map<String, Object>) ((Map<String, Object>) vectors.get("keys")).get(name);
    }

    @SuppressWarnings("unchecked")
    static List<Map<String, Object>> list(String name) {
        return (List<Map<String, Object>>) vectors.get(name);
    }

    @Test
    void keysDeriveTheirContentAddressedDids() {
        for (String name : List.of("human", "agent", "provider")) {
            Map<String, Object> k = key(name);
            Ed25519PrivateKeyParameters priv = TestSupport.keyFromHex((String) k.get("privateKeyHex"));
            byte[] pub = TestSupport.pub(priv);
            assertEquals(k.get("publicKeyHex"), HexFormat.of().formatHex(pub), name);
            assertEquals(k.get("did"), DID.generateDid(pub), name);
            assertArrayEquals(pub, ArohaMandateCredential.resolveContentAddressedKey((String) k.get("did")), name);
        }
    }

    @TestFactory
    @SuppressWarnings("unchecked")
    Stream<DynamicTest> signingPayloadsAndSignatures() {
        return list("mandates").stream().map(v -> DynamicTest.dynamicTest((String) v.get("name"), () -> {
            Map<String, Object> mandate = (Map<String, Object>) v.get("mandate");
            String payload = ArohaMandateCredential.mandateSigningPayloadV2(mandate);
            assertEquals(v.get("expectedSigningPayload"), payload);

            // The typed record round-trips to the same signed bytes.
            assertEquals(payload, ArohaMandateCredential.mandateSigningPayloadV2(ArohaMandateCredential.toTyped(mandate)));

            Ed25519PrivateKeyParameters signer = TestSupport.keyFromHex((String) key((String) v.get("signer")).get("privateKeyHex"));
            byte[] sig = Signing.signBytes(payload.getBytes(StandardCharsets.UTF_8), signer);
            assertEquals(v.get("expectedSignature"), Base64.getUrlEncoder().withoutPadding().encodeToString(sig));
        }));
    }

    @TestFactory
    @SuppressWarnings("unchecked")
    Stream<DynamicTest> tokenVerdicts() {
        return list("tokens").stream().map(t -> DynamicTest.dynamicTest((String) t.get("name"), () -> {
            Map<String, Object> expected = (Map<String, Object>) t.get("expected");
            VerifyOptions opts = new VerifyOptions().now(Instant.parse((String) t.get("verifyAt")));
            VerificationResult r = ArohaMandateCredential.verifyMandateChain((String) t.get("token"), null, opts);

            assertEquals(expected.get("valid"), r.valid(), r.reason());
            if (r.valid()) {
                assertTrue(r.chainVerified());
                assertEquals(expected.get("rootGrantor"), r.rootGrantor());
                assertEquals(expected.get("leafMandateId"), r.mandate().mandateId());
            } else {
                String cls = (String) expected.get("reasonClass");
                switch (cls) {
                    case "narrowing" -> assertTrue(r.reason().contains("Cannot attenuate"), r.reason());
                    case "time" -> assertTrue(r.reason().contains("expired") || r.reason().contains("validUntil")
                        || r.reason().contains("not yet valid"), r.reason());
                    default -> fail("unknown reasonClass " + cls);
                }
            }
        }));
    }

    @Test
    void validTokenAlsoVerifiesThroughTheLeafKeyEntryPoint() {
        Map<String, Object> t = list("tokens").get(0);
        byte[] agentPub = HexFormat.of().parseHex((String) key("agent").get("publicKeyHex"));
        VerificationResult r = ArohaMandateCredential.verify((String) t.get("token"),
            new Ed25519PublicKeyParameters(agentPub, 0), (String) key("provider").get("did"),
            new VerifyOptions().now(Instant.parse((String) t.get("verifyAt"))).expectedRoot((String) key("human").get("did")));
        assertTrue(r.valid(), r.reason());
        assertTrue(r.chainVerified());
        assertEquals(2, r.chain().size());
    }

    /**
     * Token bytes are not signed, but Java should still produce the same JSON
     * text as JSON.stringify for the same objects: rebuild the valid token from
     * its parts and compare the decoded JSON byte for byte.
     */
    @Test
    @SuppressWarnings("unchecked")
    void tokenJsonMatchesJsonStringify() throws Exception {
        String token = (String) list("tokens").get(0).get("token");
        String json = new String(Base64.getUrlDecoder().decode(token), StandardCharsets.UTF_8);
        Map<String, Object> parsed = TestSupport.JSON.readValue(json, new TypeReference<LinkedHashMap<String, Object>>() {});
        assertEquals(json, Jcs.stringify(parsed));
        // And the leaf carries the camelCase issuedAt the shape check requires.
        assertTrue(((Map<String, Object>) parsed.get("mandate")).containsKey("issuedAt"));
    }

    @Test
    void decodedVectorTokenCanBeAttenuatedFurther() {
        Map<String, Object> t = list("tokens").get(0);
        var parent = ArohaMandateCredential.decodeMandateToken((String) t.get("token"));
        assertEquals(2, parent.v());
        assertEquals(1, parent.chain().size());

        Ed25519PrivateKeyParameters provider = TestSupport.keyFromHex((String) key("provider").get("privateKeyHex"));
        var payee = DID.generateDid(TestSupport.pub(TestSupport.seed(9)));
        var payment = ArohaMandateCredential.attenuateToPayment(parent, payee,
            ArohaMandateCredential.SpendingConstraints.builder(10).merchants(List.of("did:aroha:merchant-a")).build(),
            provider, null);
        assertEquals(2, payment.chain().size());

        VerificationResult r = ArohaMandateCredential.verifyMandateChain(payment.token(), null,
            new VerifyOptions().expectedGrantee(payee).expectedRoot((String) key("human").get("did")));
        assertTrue(r.valid(), r.reason());
        assertEquals(3, r.chain().size());
        // Inherited from the cart: session limit, approval threshold, validUntil.
        assertEquals(42.07, r.mandate().constraints().sessionLimitUsd());
        assertEquals(100.0, r.mandate().constraints().requireHumanApprovalAboveUsd());
        assertEquals("2099-01-01T00:00:00.000Z", r.mandate().constraints().validUntil());
    }
}
