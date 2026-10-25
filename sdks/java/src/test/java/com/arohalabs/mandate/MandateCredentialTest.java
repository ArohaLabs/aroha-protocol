// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

package com.arohalabs.mandate;

import com.arohalabs.TestSupport;
import com.arohalabs.crypto.Jcs;
import com.arohalabs.crypto.Signing;
import com.arohalabs.identity.DID;
import com.arohalabs.mandate.ArohaMandateCredential.SignedMandate;
import com.arohalabs.mandate.ArohaMandateCredential.SpendingConstraints;
import com.arohalabs.mandate.ArohaMandateCredential.VerificationResult;
import com.arohalabs.mandate.ArohaMandateCredential.VerifyOptions;
import com.fasterxml.jackson.core.type.TypeReference;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.*;

import static org.junit.jupiter.api.Assertions.*;

class MandateCredentialTest {

    static final Ed25519PrivateKeyParameters HUMAN = TestSupport.seed(21);
    static final Ed25519PrivateKeyParameters AGENT = TestSupport.seed(22);
    static final Ed25519PrivateKeyParameters SHOP = TestSupport.seed(23);
    static final Ed25519PrivateKeyParameters MALLORY = TestSupport.seed(24);
    static final String HUMAN_DID = DID.generateDid(TestSupport.pub(HUMAN));
    static final String AGENT_DID = DID.generateDid(TestSupport.pub(AGENT));
    static final String SHOP_DID = DID.generateDid(TestSupport.pub(SHOP));
    static final String MALLORY_DID = DID.generateDid(TestSupport.pub(MALLORY));

    static SpendingConstraints rootConstraints() {
        return SpendingConstraints.builder(500)
            .sessionLimit(200.5)
            .approvalAbove(100)
            .merchants(List.of("did:aroha:merchant-a", "did:aroha:merchant-b"))
            .validUntil("2099-01-01T00:00:00.000Z")
            .build();
    }

    static SignedMandate intent() {
        return ArohaMandateCredential.issueIntent(HUMAN_DID, AGENT_DID, rootConstraints(), HUMAN, Duration.ofHours(1));
    }

    static SignedMandate cart(SignedMandate intent) {
        return ArohaMandateCredential.attenuateToCart(intent, SHOP_DID,
            SpendingConstraints.builder(42.07).merchants(List.of("did:aroha:merchant-a")).build(), AGENT, null);
    }

    @SuppressWarnings("unchecked")
    static Map<String, Object> decode(String token) throws Exception {
        return TestSupport.JSON.readValue(Base64.getUrlDecoder().decode(token),
            new TypeReference<LinkedHashMap<String, Object>>() {});
    }

    static String encode(Map<String, Object> tokenJson) {
        return Base64.getUrlEncoder().withoutPadding()
            .encodeToString(Jcs.stringify(tokenJson).getBytes(StandardCharsets.UTF_8));
    }

    static String sign(Map<String, Object> mandate, Ed25519PrivateKeyParameters key) {
        byte[] payload = ArohaMandateCredential.mandateSigningPayloadV2(mandate).getBytes(StandardCharsets.UTF_8);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(Signing.signBytes(payload, key));
    }

    // ── Issuance and wire shape ──────────────────────────────────────────────

    @Nested
    class WireShape {
        @Test
        @SuppressWarnings("unchecked")
        void issuedTokenIsV2WithCamelCaseIssuedAtAndNoNulls() throws Exception {
            SignedMandate m = intent();
            assertEquals(2, m.v());
            assertTrue(m.chain().isEmpty());
            Map<String, Object> t = decode(m.token());
            assertEquals(List.of("v", "mandate", "signature", "chain"), new ArrayList<>(t.keySet()));
            Map<String, Object> body = (Map<String, Object>) t.get("mandate");
            assertEquals(List.of("mandateTier", "constraints", "grantee", "grantor", "issuedAt", "expiresAt",
                "parentMandateId", "mandateId"), new ArrayList<>(body.keySet()));
            assertNull(body.get("parentMandateId"));
            assertTrue(body.containsKey("parentMandateId"), "root keeps parentMandateId: null");
            assertTrue(((String) body.get("issuedAt")).matches("\\d{4}-\\d\\d-\\d\\dT\\d\\d:\\d\\d:\\d\\d\\.\\d{3}Z"));
            Map<String, Object> c = (Map<String, Object>) body.get("constraints");
            assertFalse(c.containsKey("currency"), "absent currency is omitted, not defaulted");
            assertFalse(c.containsKey("validFrom"));
            assertFalse(c.containsValue(null));
            // Amount formatting: 500 not 500.0
            assertTrue(new String(Base64.getUrlDecoder().decode(m.token()), StandardCharsets.UTF_8)
                .contains("\"spendLimitUsd\":500,"));
        }

        @Test
        void unknownFieldsAreIgnoredOnReadButStillSigned() throws Exception {
            Map<String, Object> t = decode(intent().token());
            @SuppressWarnings("unchecked") Map<String, Object> body = (Map<String, Object>) t.get("mandate");
            body.put("futureField", Map.of("x", 1));
            t.put("signature", sign(body, HUMAN));
            VerificationResult r = ArohaMandateCredential.verifyMandateChain(encode(t), null, new VerifyOptions());
            assertTrue(r.valid(), r.reason());
            assertEquals(HUMAN_DID, r.rootGrantor());
        }

        @Test
        void rejectsInvalidConstraintsAtIssuance() {
            assertThrows(IllegalArgumentException.class, () -> ArohaMandateCredential.issueIntent(
                HUMAN_DID, AGENT_DID, SpendingConstraints.builder(Double.NaN).build(), HUMAN, null));
            assertThrows(IllegalArgumentException.class, () -> ArohaMandateCredential.issueIntent(
                HUMAN_DID, AGENT_DID, SpendingConstraints.builder(-1).build(), HUMAN, null));
            assertThrows(IllegalArgumentException.class, () -> ArohaMandateCredential.issueIntent(
                HUMAN_DID, AGENT_DID, SpendingConstraints.builder(1).validUntil("not a date").build(), HUMAN, null));
        }
    }

    // ── Chain verification ───────────────────────────────────────────────────

    @Nested
    class Chain {
        @Test
        void intentCartPaymentVerifiesToTheRoot() {
            SignedMandate pay = ArohaMandateCredential.attenuateToPayment(cart(intent()), MALLORY_DID,
                SpendingConstraints.builder(10).merchants(List.of("did:aroha:merchant-a")).build(), SHOP, Duration.ofMinutes(5));
            assertEquals(2, pay.chain().size());
            VerificationResult r = ArohaMandateCredential.verifyMandateChain(pay.token(), null,
                new VerifyOptions().expectedRoot(HUMAN_DID).expectedGrantee(MALLORY_DID));
            assertTrue(r.valid(), r.reason());
            assertEquals(List.of("intent", "cart", "payment"), r.chain().stream().map(m -> m.mandateTier()).toList());
            assertEquals(HUMAN_DID, r.rootGrantor());
            assertNotNull(r.mandate().issuedAt());
        }

        @Test
        void childNeverOutlivesParent() {
            SignedMandate parent = intent();
            SignedMandate child = ArohaMandateCredential.attenuateToCart(parent, SHOP_DID,
                SpendingConstraints.builder(1).merchants(List.of("did:aroha:merchant-a")).build(), AGENT, Duration.ofDays(30));
            assertEquals(parent.mandate().expiresAt(), child.mandate().expiresAt());
        }

        @Test
        void expectedRootAndGranteeMismatchesFail() {
            String token = cart(intent()).token();
            assertFalse(ArohaMandateCredential.verifyMandateChain(token, null,
                new VerifyOptions().expectedRoot(MALLORY_DID)).valid());
            VerificationResult r = ArohaMandateCredential.verifyMandateChain(token, null,
                new VerifyOptions().expectedGrantee(MALLORY_DID));
            assertFalse(r.valid());
            assertTrue(r.reason().contains("grantee mismatch"));
        }

        @Test
        void revokingTheIntentKillsEverythingBeneathIt() {
            SignedMandate root = intent();
            String token = cart(root).token();
            String rootId = root.mandate().mandateId();
            VerificationResult r = ArohaMandateCredential.verifyMandateChain(token, null,
                new VerifyOptions().isRevoked((id, grantor) -> id.equals(rootId) && grantor.equals(HUMAN_DID)));
            assertFalse(r.valid());
            assertTrue(r.reason().contains("has been revoked"), r.reason());

            VerificationResult failing = ArohaMandateCredential.verifyMandateChain(token, null,
                new VerifyOptions().isRevoked((id, grantor) -> { throw new IllegalStateException("down"); }));
            assertFalse(failing.valid(), "a failing revocation hook fails closed");
        }

        @Test
        void lookAlikeReusingAnIdUnderAnotherGrantorIsNotRevoked() throws Exception {
            SignedMandate original = intent();
            Set<String> revoked = Set.of(HUMAN_DID + "#" + original.mandate().mandateId());
            VerifyOptions opts = new VerifyOptions().isRevoked((id, grantor) -> revoked.contains(grantor + "#" + id));
            assertFalse(ArohaMandateCredential.verifyMandateChain(original.token(), null, opts).valid());

            Map<String, Object> tok = decode(original.token());
            @SuppressWarnings("unchecked")
            Map<String, Object> wire = new LinkedHashMap<>((Map<String, Object>) tok.get("mandate"));
            wire.put("grantor", MALLORY_DID);
            Map<String, Object> look = new LinkedHashMap<>();
            look.put("v", 2);
            look.put("mandate", wire);
            look.put("signature", sign(wire, MALLORY));
            look.put("chain", List.of());
            VerificationResult r = ArohaMandateCredential.verifyMandateChain(encode(look), null, opts);
            assertTrue(r.valid(), r.reason());
            assertEquals(original.mandate().mandateId(), r.mandate().mandateId());
        }

        @Test
        void customResolverIsUsedForNamedDids() {
            String named = "did:aroha:alice-personal";
            SignedMandate root = ArohaMandateCredential.issueIntent(named, AGENT_DID, rootConstraints(), HUMAN, null);
            assertFalse(ArohaMandateCredential.verifyMandateChain(root.token(), null, new VerifyOptions()).valid(),
                "named DIDs do not resolve by default");
            byte[] humanPub = TestSupport.pub(HUMAN);
            VerificationResult r = ArohaMandateCredential.verifyMandateChain(root.token(),
                did -> did.equals(named) ? humanPub : null, new VerifyOptions());
            assertTrue(r.valid(), r.reason());
        }

        @Test
        void contentAddressedResolverRejectsLookalikes() {
            assertNull(ArohaMandateCredential.resolveContentAddressedKey("did:aroha:zoo"));
            assertNull(ArohaMandateCredential.resolveContentAddressedKey("did:aroha:alice"));
            assertNull(ArohaMandateCredential.resolveContentAddressedKey("did:aroha:z0OIl"));
        }

        @Test
        void timeWindowsAreEnforced() {
            String token = cart(intent()).token();
            assertFalse(ArohaMandateCredential.verifyMandateChain(token, null,
                new VerifyOptions().now(Instant.now().plus(Duration.ofHours(2)))).valid(), "expired");
            VerificationResult early = ArohaMandateCredential.verifyMandateChain(token, null,
                new VerifyOptions().now(Instant.now().minus(Duration.ofMinutes(5))));
            assertFalse(early.valid());
            assertTrue(early.reason().contains("in the future"), early.reason());
        }

        @Test
        void maxDepthIsEnforced() {
            assertFalse(ArohaMandateCredential.verifyMandateChain(cart(intent()).token(), null,
                new VerifyOptions().maxDepth(1)).valid());
        }

        @Test
        void tamperedSignatureFails() throws Exception {
            Map<String, Object> t = decode(cart(intent()).token());
            @SuppressWarnings("unchecked") Map<String, Object> body = (Map<String, Object>) t.get("mandate");
            @SuppressWarnings("unchecked") Map<String, Object> c = (Map<String, Object>) body.get("constraints");
            c.put("spendLimitUsd", 42.08);
            VerificationResult r = ArohaMandateCredential.verifyMandateChain(encode(t), null, new VerifyOptions());
            assertFalse(r.valid());
            assertTrue(r.reason().contains("Invalid signature"), r.reason());
        }

        @Test
        void malformedTokensAreRejectedNotThrown() {
            assertEquals("Malformed token", ArohaMandateCredential.verifyMandateChain("!!!", null, null).reason());
            String v3 = Base64.getUrlEncoder().withoutPadding().encodeToString("{\"v\":3}".getBytes(StandardCharsets.UTF_8));
            assertTrue(ArohaMandateCredential.verifyMandateChain(v3, null, null).reason().contains("Unsupported"));
        }
    }

    // ── Verifier-side narrowing: a dishonest delegate skips its own check ────

    @Nested
    class VerifierSideNarrowing {

        /** A cart that the agent signs itself, bypassing attenuateToCart's checks. */
        @SuppressWarnings("unchecked")
        String forgedCart(java.util.function.Consumer<Map<String, Object>> editConstraints) throws Exception {
            SignedMandate root = intent();
            Map<String, Object> rootToken = decode(root.token());
            Map<String, Object> rootBody = (Map<String, Object>) rootToken.get("mandate");

            Map<String, Object> constraints = new LinkedHashMap<>((Map<String, Object>) rootBody.get("constraints"));
            constraints.put("spendLimitUsd", 50);
            constraints.put("allowedMerchants", List.of("did:aroha:merchant-a"));
            editConstraints.accept(constraints);

            Map<String, Object> body = new LinkedHashMap<>();
            body.put("mandateTier", "cart");
            body.put("constraints", constraints);
            body.put("grantee", SHOP_DID);
            body.put("grantor", AGENT_DID);
            body.put("issuedAt", rootBody.get("issuedAt"));
            body.put("expiresAt", rootBody.get("expiresAt"));
            body.put("parentMandateId", rootBody.get("mandateId"));
            body.put("mandateId", UUID.randomUUID().toString());

            Map<String, Object> link = new LinkedHashMap<>();
            link.put("v", 2);
            link.put("mandate", rootBody);
            link.put("signature", rootToken.get("signature"));

            Map<String, Object> token = new LinkedHashMap<>();
            token.put("v", 2);
            token.put("mandate", body);
            token.put("signature", sign(body, AGENT));
            token.put("chain", List.of(link));
            return encode(token);
        }

        VerificationResult verify(String token) {
            return ArohaMandateCredential.verifyMandateChain(token, null, new VerifyOptions());
        }

        @Test
        void honestForgeryBaselineVerifies() throws Exception {
            assertTrue(verify(forgedCart(c -> {})).valid());
        }

        @Test
        void wideningSpendLimitIsRejected() throws Exception {
            VerificationResult r = verify(forgedCart(c -> c.put("spendLimitUsd", 501)));
            assertFalse(r.valid());
            assertTrue(r.reason().contains("child spendLimitUsd (501) exceeds parent (500)"), r.reason());
        }

        @Test
        void omittingTheApprovalThresholdIsWidening() throws Exception {
            VerificationResult r = verify(forgedCart(c -> c.remove("requireHumanApprovalAboveUsd")));
            assertFalse(r.valid());
            assertTrue(r.reason().contains("but child omits it"), r.reason());
        }

        @Test
        void omittingSessionLimitOrValidUntilIsWidening() throws Exception {
            assertFalse(verify(forgedCart(c -> c.remove("sessionLimitUsd"))).valid());
            assertFalse(verify(forgedCart(c -> c.remove("validUntil"))).valid());
            assertFalse(verify(forgedCart(c -> c.put("validUntil", "2100-01-01T00:00:00.000Z"))).valid());
        }

        @Test
        void merchantsMustStayInsideTheParentList() throws Exception {
            assertFalse(verify(forgedCart(c -> c.put("allowedMerchants", List.of("did:aroha:merchant-z")))).valid());
            assertFalse(verify(forgedCart(c -> c.remove("allowedMerchants"))).valid());
            assertFalse(verify(forgedCart(c -> c.put("allowedMerchants", null))).valid());
            assertFalse(verify(forgedCart(c -> c.put("allowedMerchants", List.of()))).valid());
        }

        @Test
        void currencyCannotChange() throws Exception {
            VerificationResult r = verify(forgedCart(c -> c.put("currency", "EUR")));
            assertFalse(r.valid());
            assertTrue(r.reason().contains("differs from parent \"USD\""), r.reason());
            assertTrue(verify(forgedCart(c -> c.put("currency", "USD"))).valid(), "explicit USD equals absent");
        }

        @Test
        void mistypedAmountsFailTheShapeCheck() throws Exception {
            VerificationResult r = verify(forgedCart(c -> c.put("spendLimitUsd", "50")));
            assertFalse(r.valid());
            assertTrue(r.reason().startsWith("Malformed token"), r.reason());
        }
    }

    // ── Attenuation-side narrowing (shared rules) ────────────────────────────

    @Nested
    class AttenuationSide {
        @Test
        void omittedLimitsAreInheritedNotDropped() {
            SignedMandate c = cart(intent());
            assertEquals(200.5, c.mandate().constraints().sessionLimitUsd());
            assertEquals(100.0, c.mandate().constraints().requireHumanApprovalAboveUsd());
            assertEquals("2099-01-01T00:00:00.000Z", c.mandate().constraints().validUntil());
        }

        @Test
        void wideningThrows() {
            SignedMandate root = intent();
            assertThrows(IllegalArgumentException.class, () -> ArohaMandateCredential.attenuateToCart(root, SHOP_DID,
                SpendingConstraints.builder(501).merchants(List.of("did:aroha:merchant-a")).build(), AGENT, null));
            assertThrows(IllegalArgumentException.class, () -> ArohaMandateCredential.attenuateToCart(root, SHOP_DID,
                SpendingConstraints.builder(5).build(), AGENT, null), "merchant restriction must be restated");
            assertThrows(IllegalArgumentException.class, () -> ArohaMandateCredential.attenuateToCart(root, SHOP_DID,
                SpendingConstraints.builder(5).merchants(List.of("did:aroha:merchant-a")).approvalAbove(101).build(), AGENT, null));
        }

        @Test
        void tierCannotBroaden() {
            SignedMandate payment = ArohaMandateCredential.attenuateToPayment(intent(), SHOP_DID,
                SpendingConstraints.builder(5).merchants(List.of("did:aroha:merchant-a")).build(), AGENT, null);
            assertThrows(IllegalArgumentException.class, () -> ArohaMandateCredential.attenuateToCart(payment, MALLORY_DID,
                SpendingConstraints.builder(1).merchants(List.of("did:aroha:merchant-a")).build(), SHOP, null));
        }

        @Test
        void emptyParentMerchantListMeansNoMerchant() {
            var p = SpendingConstraints.builder(10).merchants(List.of()).build();
            assertNull(ArohaMandateCredential.checkNarrowing(p,
                SpendingConstraints.builder(5).merchants(List.of()).build(), "intent", "cart"));
            assertNotNull(ArohaMandateCredential.checkNarrowing(p,
                SpendingConstraints.builder(5).merchants(List.of("did:aroha:m")).build(), "intent", "cart"));
        }

        @Test
        void merchantCategoryMustMatch() {
            var p = SpendingConstraints.builder(10).category("5812").build();
            assertNotNull(ArohaMandateCredential.checkNarrowing(p, SpendingConstraints.builder(5).build(), "intent", "cart"));
            assertNotNull(ArohaMandateCredential.checkNarrowing(p,
                SpendingConstraints.builder(5).category("5999").build(), "intent", "cart"));
            assertNull(ArohaMandateCredential.checkNarrowing(p,
                SpendingConstraints.builder(5).category("5812").build(), "intent", "cart"));
        }

        @Test
        void validFromCannotMoveEarlier() {
            var p = SpendingConstraints.builder(10).validFrom("2026-01-01T00:00:00.000Z").build();
            assertNotNull(ArohaMandateCredential.checkNarrowing(p,
                SpendingConstraints.builder(5).validFrom("2025-12-31T00:00:00.000Z").build(), "intent", "cart"));
            assertNull(ArohaMandateCredential.checkNarrowing(p,
                SpendingConstraints.builder(5).validFrom(Instant.parse("2026-02-01T00:00:00Z")).build(), "intent", "cart"));
        }
    }

    // ── Legacy v1 (read-only) ────────────────────────────────────────────────

    @Nested
    class LegacyV1 {
        String v1Token(Map<String, Object> body, Ed25519PrivateKeyParameters key) {
            byte[] payload = Jcs.canonicalize(body).getBytes(StandardCharsets.UTF_8);
            Map<String, Object> t = new LinkedHashMap<>();
            t.put("mandate", body);
            t.put("signature", Base64.getUrlEncoder().withoutPadding().encodeToString(Signing.signBytes(payload, key)));
            return encode(t);
        }

        @SuppressWarnings("unchecked")
        Map<String, Object> body(String tier, String parent) throws Exception {
            Map<String, Object> b = (Map<String, Object>) decode(intent().token()).get("mandate");
            b.put("mandateTier", tier);
            b.put("parentMandateId", parent);
            return b;
        }

        @Test
        void v1RootVerifiesEverywhere() throws Exception {
            String token = v1Token(body("intent", null), HUMAN);
            VerificationResult r = ArohaMandateCredential.verify(token,
                new org.bouncycastle.crypto.params.Ed25519PublicKeyParameters(TestSupport.pub(HUMAN), 0), AGENT_DID);
            assertTrue(r.valid(), r.reason());
            assertTrue(r.chainVerified());
            assertTrue(ArohaMandateCredential.verifyMandateChain(token, null, null).valid());
        }

        @Test
        void v1ChildIsValidButNotChainVerified() throws Exception {
            String token = v1Token(body("cart", "some-parent"), HUMAN);
            VerificationResult r = ArohaMandateCredential.verify(token,
                new org.bouncycastle.crypto.params.Ed25519PublicKeyParameters(TestSupport.pub(HUMAN), 0), null);
            assertTrue(r.valid(), r.reason());
            assertFalse(r.chainVerified());
            assertFalse(ArohaMandateCredential.verifyMandateChain(token, null, null).valid());
        }

        @Test
        void v1SignatureIsNotAcceptedAsV2() throws Exception {
            Map<String, Object> b = body("intent", null);
            Map<String, Object> t = decode(v1Token(b, HUMAN));
            t.put("v", 2);
            t.put("chain", List.of());
            assertFalse(ArohaMandateCredential.verifyMandateChain(encode(t), null, null).valid());
        }

        @Test
        void v1WithChainIsMalformed() throws Exception {
            Map<String, Object> t = decode(v1Token(body("intent", null), HUMAN));
            t.put("chain", List.of());
            assertTrue(ArohaMandateCredential.verifyMandateChain(encode(t), null, null).reason()
                .contains("chain present without v: 2"));
        }
    }

    // ── Enforcement ──────────────────────────────────────────────────────────

    @Test
    void enforceSpendingConstraints() throws Exception {
        SignedMandate c = cart(intent());
        var agentKey = new org.bouncycastle.crypto.params.Ed25519PublicKeyParameters(TestSupport.pub(AGENT), 0);
        assertEquals(c.mandate().mandateId(), ArohaMandateCredential.enforceSpendingConstraints(c.token(), agentKey,
            SHOP_DID, "did:aroha:merchant-a", 40, true, null).mandateId());
        var over = assertThrows(ArohaMandateCredential.SpendingConstraintViolation.class, () ->
            ArohaMandateCredential.enforceSpendingConstraints(c.token(), agentKey, SHOP_DID, "did:aroha:merchant-a", 42.08, true, null));
        assertEquals("LIMIT_EXCEEDED", over.code());
        assertEquals("MERCHANT_NOT_ALLOWED", assertThrows(ArohaMandateCredential.SpendingConstraintViolation.class, () ->
            ArohaMandateCredential.enforceSpendingConstraints(c.token(), agentKey, SHOP_DID, null, 1, true, null)).code());
        assertEquals("INVALID_AMOUNT", assertThrows(ArohaMandateCredential.SpendingConstraintViolation.class, () ->
            ArohaMandateCredential.enforceSpendingConstraints(c.token(), agentKey, SHOP_DID, "did:aroha:merchant-a", Double.NaN, true, null)).code());
    }

    // ── The caller's key verifies the leaf link only ────────────────────────

    @Test
    void callerKeyNeverVerifiesAnAncestorNamingTheSameGrantor() {
        // A named DID whose real key is what the resolver returns. MALLORY
        // forges a root and a child both naming it, signs both, and passes her
        // own key as the leaf key. The root must be checked against the REAL
        // key (SHOP's) and fail. Matching the caller key by DID used to let it.
        String named = "did:aroha:shop";
        String expires = Instant.now().plus(Duration.ofHours(1)).toString();
        Map<String, Object> root = new LinkedHashMap<>();
        root.put("mandateTier", "intent");
        root.put("constraints", new LinkedHashMap<>(Map.of("spendLimitUsd", 1000000)));
        root.put("grantee", named);
        root.put("grantor", named);
        root.put("issuedAt", Instant.now().toString());
        root.put("expiresAt", expires);
        root.put("parentMandateId", null);
        root.put("mandateId", "forged-root");
        Map<String, Object> child = new LinkedHashMap<>(root);
        child.put("mandateTier", "cart");
        child.put("grantee", "did:aroha:payee");
        child.put("parentMandateId", "forged-root");
        child.put("mandateId", "forged-leaf");

        Map<String, Object> rootLink = new LinkedHashMap<>();
        rootLink.put("v", 2);
        rootLink.put("mandate", root);
        rootLink.put("signature", sign(root, MALLORY));
        Map<String, Object> token = new LinkedHashMap<>();
        token.put("v", 2);
        token.put("mandate", child);
        token.put("signature", sign(child, MALLORY));
        token.put("chain", List.of(rootLink));

        VerifyOptions opts = new VerifyOptions();
        opts.resolveKey = did -> named.equals(did) ? TestSupport.pub(SHOP) : null;
        opts.expectedRoot = named;
        VerificationResult r = ArohaMandateCredential.verify(
            encode(token), MALLORY.generatePublicKey(), null, opts);
        assertFalse(r.valid(), "a forged root must not verify against the caller's leaf key");
    }

    @Test
    void callerKeyMustMatchASelfCertifyingLeafGrantor() throws Exception {
        SignedMandate root = intent();
        // intent() is signed by HUMAN (a z-DID); MALLORY's key does not belong to it.
        assertFalse(ArohaMandateCredential.verify(root.token(), MALLORY.generatePublicKey(), null).valid());
    }

    /** A task mandate must never pass as a spending mandate, whatever else it carries. */
    @org.junit.jupiter.api.Test
    void shapeCheckRefusesTaskMandates() {
        java.util.Map<String, Object> body = new java.util.LinkedHashMap<>();
        body.put("mandateTier", "intent");
        body.put("constraints", java.util.Map.of("spendLimitUsd", 100));
        body.put("grantor", "did:aroha:zA");
        body.put("grantee", "did:aroha:zB");
        body.put("mandateId", "m1");
        body.put("issuedAt", "2026-01-01T00:00:00.000Z");
        body.put("expiresAt", "2027-01-01T00:00:00.000Z");
        String want = "mandateType present: this is a task mandate, not a spending mandate";
        org.junit.jupiter.api.Assertions.assertNotEquals(want, ArohaMandateCredential.checkMandateShape(body));
        for (String type : java.util.List.of("task", "hybrid")) {
            java.util.Map<String, Object> withType = new java.util.LinkedHashMap<>(body);
            withType.put("mandateType", type);
            org.junit.jupiter.api.Assertions.assertEquals(want, ArohaMandateCredential.checkMandateShape(withType));
        }
    }
}
