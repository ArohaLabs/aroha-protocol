// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

package com.arohalabs.mandate;

import com.arohalabs.TestSupport;
import com.arohalabs.crypto.Signing;
import com.arohalabs.mandate.TaskMandate.SignedTaskMandate;
import com.arohalabs.mandate.TaskMandate.TaskActionRequest;
import com.arohalabs.mandate.TaskMandate.TaskConstraintViolation;
import com.arohalabs.mandate.TaskMandate.VerificationResult;
import com.fasterxml.jackson.core.type.TypeReference;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.*;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Task mandates issued, attenuated and judged by the TypeScript reference
 * (src/test/resources/task-mandate-ts-vectors.json, written by
 * scripts/task-mandate-interop.mjs gen) must get the SAME verdicts — and the
 * same reason strings and violation codes — from the Java SDK.
 */
class TaskMandateTsInteropTest {

    static Map<String, Object> V;

    @BeforeAll
    static void load() throws Exception {
        try (InputStream in = TaskMandateTsInteropTest.class.getResourceAsStream("/task-mandate-ts-vectors.json")) {
            V = TestSupport.JSON.readValue(in, new TypeReference<>() {});
        }
    }

    @SuppressWarnings("unchecked")
    static Map<String, Object> map(Object o) { return (Map<String, Object>) o; }

    @SuppressWarnings("unchecked")
    static List<Map<String, Object>> list(Object o) { return (List<Map<String, Object>>) o; }

    static Ed25519PublicKeyParameters pubFromSeed(Object seedHex) {
        return TestSupport.keyFromHex((String) seedHex).generatePublicKey();
    }

    static long at(Map<String, Object> t) { return ((Number) t.get("verifyAt")).longValue(); }

    static Map<String, Object> mandateOf(String token) {
        return TaskMandate.decode(token).mandate();
    }

    @Test
    void typescriptTokensVerifyAndSigningBytesMatch() {
        for (var e : map(V.get("tokens")).entrySet()) {
            Map<String, Object> t = map(e.getValue());
            String token = (String) t.get("token");
            VerificationResult r = TaskMandate.verify(token, pubFromSeed(t.get("grantorSeed")), (String) t.get("grantee"),
                new TaskMandate.VerifyOptions().now(at(t)));
            assertTrue(r.valid(), e.getKey() + ": " + r.reason());
            assertEquals(t.get("signingPayload"), TaskMandate.signingPayloadV2(r.mandate()), e.getKey());

            // Ed25519 is deterministic: signing the same JCS bytes with the
            // same seed reproduces TypeScript's signature exactly.
            Ed25519PrivateKeyParameters k = TestSupport.keyFromHex((String) t.get("grantorSeed"));
            byte[] sig = Signing.signBytes(((String) t.get("signingPayload")).getBytes(StandardCharsets.UTF_8), k);
            assertEquals(t.get("signature"), Base64.getUrlEncoder().withoutPadding().encodeToString(sig), e.getKey());
        }
    }

    @Test
    void typedViewReadsEveryTypeScriptField() {
        var root = TaskMandate.decode((String) map(map(V.get("tokens")).get("root")).get("token")).body();
        assertEquals("task", root.mandateType());
        assertEquals(3.0, root.taskConstraints().actionLimits().get("send-email"));
        assertEquals(1.5, root.taskConstraints().computeLimit().cpuSeconds());
        assertEquals("write", root.taskConstraints().dataAccess().get("drafts"));
        assertEquals(2, root.taskConstraints().maxDelegationDepth());
        assertEquals("room-01J9ZK3Q7V", root.taskConstraints().roomId());
        assertEquals("did:aroha:guest-ben", root.taskConstraints().onBehalfOf());
        assertNull(root.parentMandateId());

        var hybrid = TaskMandate.decode((String) map(map(V.get("tokens")).get("hybrid")).get("token")).body();
        assertEquals("hybrid", hybrid.mandateType());
        assertEquals(500.0, hybrid.spendingConstraints().spendLimitUsd());
        assertEquals("JFK", hybrid.invariants().parameters().get("destination"));
        assertEquals(450.0, hybrid.invariants().maxAmount().amount());
    }

    @Test
    void rejectedTokensGetTheSameReason() {
        for (Map<String, Object> t : list(V.get("rejected"))) {
            VerificationResult r = TaskMandate.verify((String) t.get("token"), pubFromSeed(t.get("grantorSeed")),
                (String) t.get("grantee"), new TaskMandate.VerifyOptions().now(at(t)));
            Map<String, Object> expected = map(t.get("expected"));
            assertFalse(r.valid(), (String) t.get("name"));
            assertEquals(expected.get("reason"), r.reason(), (String) t.get("name"));
        }
    }

    @Test
    void widenedChildrenGetTheSameNarrowingReason() {
        Map<String, Object> tokens = map(V.get("tokens"));
        int checked = 0;
        for (Map<String, Object> w : list(V.get("widened"))) {
            String parentName = w.containsKey("parent") ? (String) w.get("parent") : "root";
            Map<String, Object> parent = mandateOf((String) map(tokens.get(parentName)).get("token"));
            Map<String, Object> child = mandateOf((String) w.get("token"));
            assertEquals(w.get("reason"), TaskMandate.checkTaskNarrowing(parent, child), (String) w.get("name"));
            checked++;
        }
        assertTrue(checked >= 20, "expected the full widened set");
    }

    @Test
    void requestsGetTheSameVerdictCodeAndMessage() {
        Map<String, Object> tokens = map(V.get("tokens"));
        for (Map<String, Object> q : list(V.get("requests"))) {
            Map<String, Object> mandate = mandateOf((String) map(tokens.get(q.get("on"))).get("token"));
            TaskConstraintViolation v = TaskMandate.checkTaskConstraints(mandate, toRequest(map(q.get("request"))));
            Map<String, Object> expected = map(q.get("expected"));
            String name = (String) q.get("name");
            if (expected == null) {
                assertNull(v, name + ": " + (v == null ? "" : v.getMessage()));
            } else {
                assertNotNull(v, name);
                assertEquals(expected.get("code"), v.code(), name);
                assertEquals(expected.get("message"), v.getMessage(), name);
            }
        }
    }

    @Test
    void javaAttenuatesATypeScriptParent() {
        Map<String, Object> root = map(map(V.get("tokens")).get("root"));
        SignedTaskMandate parent = TaskMandate.decode((String) root.get("token"));
        Ed25519PrivateKeyParameters agentA = TestSupport.seed(2);
        SignedTaskMandate child = TaskMandate.attenuate(parent, "did:aroha:agent-c", List.of("search"),
            TaskMandate.TaskConstraints.builder()
                .computeLimit(new TaskMandate.ComputeLimit(100.0, 1.0, 1000.0, 0.5))
                .dataAccess(Map.of())
                .outputHandling("internal-only")
                .checkpointIntervalMs(1000)
                .build(),
            agentA, null, null);
        // room and on-behalf-of bindings and the blocked list are inherited
        assertEquals("room-01J9ZK3Q7V", child.body().taskConstraints().roomId());
        assertEquals("did:aroha:guest-ben", child.body().taskConstraints().onBehalfOf());
        assertEquals(List.of("delete-email"), child.body().blocked());
        assertEquals("cart", child.body().mandateTier());
        assertEquals(parent.mandate().get("expiresAt"), child.mandate().get("expiresAt"));
        assertNull(TaskMandate.checkTaskNarrowing(parent.mandate(), child.mandate()));
        // The vector's parent has long expired, so the child (which inherits
        // that expiry) is checked by signature, not by time window.
        assertTrue(TaskMandate.verifySignature(child.mandate(), child.signature(), 2, TestSupport.pub(agentA)));
        // The token carries exactly the body that was signed (compared as JCS: in
        // memory the issued body holds 100.0 where the decoded one holds 100).
        assertEquals(TaskMandate.signingPayloadV2(child.mandate()),
            TaskMandate.signingPayloadV2(TaskMandate.decode(child.token()).mandate()));
    }

    @SuppressWarnings("unchecked")
    static TaskActionRequest toRequest(Map<String, Object> q) {
        TaskActionRequest r = new TaskActionRequest((String) q.get("requestedCapability"));
        if (q.get("currentActionCounts") != null) r.currentActionCounts((Map<String, Number>) q.get("currentActionCounts"));
        if (q.get("currentCompute") instanceof Map<?, ?> c) {
            r.currentCompute((Number) c.get("llmTokens"), (Number) c.get("webRequests"), (Number) c.get("wallClockMs"));
        }
        if (q.get("capabilityReversibility") != null) r.capabilityReversibility((String) q.get("capabilityReversibility"));
        if (q.get("dataAccess") != null) r.dataAccess((Map<String, String>) q.get("dataAccess"));
        if (Boolean.TRUE.equals(q.get("humanApproved"))) r.humanApproved(true);
        if (q.get("roomId") != null) r.roomId((String) q.get("roomId"));
        if (q.get("onBehalfOf") != null) r.onBehalfOf((String) q.get("onBehalfOf"));
        return r;
    }
}
