// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

package com.arohalabs.mandate;

import com.arohalabs.TestSupport;
import com.arohalabs.mandate.ArohaMandateCredential.SpendingConstraints;
import com.arohalabs.mandate.TaskMandate.*;
import com.arohalabs.util.IsoTime;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.time.Duration;
import java.util.*;

import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

class TaskMandateTest {

    static final Ed25519PrivateKeyParameters USER = TestSupport.seed(1);
    static final Ed25519PrivateKeyParameters AGENT_A = TestSupport.seed(2);
    static final String U = "did:aroha:user", A = "did:aroha:agent-a", B = "did:aroha:agent-b";

    static TaskConstraints rootConstraints() {
        return TaskConstraints.builder()
            .actionLimit("send-email", 3)
            .computeLimit(new ComputeLimit(1000.0, 10.0, 60_000.0, null))
            .dataAccess("calendar", "read")
            .dataAccess("drafts", "write")
            .humanGates(List.of("send-email"))
            .reversibleOnly(true)
            .maxDelegationDepth(1)
            .roomId("room-1")
            .onBehalfOf("did:aroha:guest")
            .build();
    }

    static SignedTaskMandate root() {
        return TaskMandate.issue(U, A, List.of("search", "send-email", "draft"), rootConstraints(), USER,
            Duration.ofHours(1), new IssueOptions().blocked(List.of("delete")));
    }

    static Map<String, Object> decodeJson(String token) throws Exception {
        @SuppressWarnings("unchecked")
        Map<String, Object> m = (Map<String, Object>) TestSupport.parse(new String(Base64.getUrlDecoder().decode(token), StandardCharsets.UTF_8));
        return m;
    }

    static String encodeJson(Object o) throws Exception {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(TestSupport.JSON.writeValueAsBytes(o));
    }

    @Nested
    class IssueAndVerify {
        @Test
        void roundTrip() {
            SignedTaskMandate m = root();
            assertEquals(2, m.v());
            assertEquals("task", m.body().mandateType());
            assertEquals("intent", m.body().mandateTier());
            assertTrue(m.mandate().containsKey("parentMandateId"));
            VerificationResult r = TaskMandate.verify(m.token(), USER.generatePublicKey(), A);
            assertTrue(r.valid(), r.reason());
            assertEquals(1, r.body().taskConstraints().maxDelegationDepth());
        }

        @Test
        void tokenWireShape() throws Exception {
            Map<String, Object> t = decodeJson(root().token());
            assertEquals(List.of("v", "mandate", "signature"), new ArrayList<>(t.keySet()));
            assertEquals(2, t.get("v"));
            @SuppressWarnings("unchecked") Map<String, Object> m = (Map<String, Object>) t.get("mandate");
            assertEquals(List.of("mandateType", "mandateTier", "allowed", "blocked", "taskConstraints", "grantee", "grantor",
                "issuedAt", "expiresAt", "parentMandateId", "mandateId"), new ArrayList<>(m.keySet()));
            // whole numbers on the wire are written as JS writes them
            assertTrue(new String(Base64.getUrlDecoder().decode(root().token()), StandardCharsets.UTF_8)
                .contains("\"actionLimits\":{\"send-email\":3}"));
        }

        @Test
        void hybridWhenSpendingGiven() {
            SignedTaskMandate m = TaskMandate.issue(U, A, List.of("book"), TaskConstraints.none(), USER, null,
                new IssueOptions().spendingConstraints(SpendingConstraints.builder(100).build()));
            assertEquals("hybrid", m.body().mandateType());
            assertTrue(TaskMandate.verify(m.token(), USER.generatePublicKey(), null).valid());
        }

        @Test
        void wrongKeyGranteeAndTamperAreRefused() throws Exception {
            SignedTaskMandate m = root();
            assertEquals("Invalid signature", TaskMandate.verify(m.token(), AGENT_A.generatePublicKey(), A).reason());
            assertEquals("Grantee mismatch: expected " + B, TaskMandate.verify(m.token(), USER.generatePublicKey(), B).reason());

            Map<String, Object> t = decodeJson(m.token());
            @SuppressWarnings("unchecked") Map<String, Object> body = (Map<String, Object>) t.get("mandate");
            @SuppressWarnings("unchecked") Map<String, Object> tc = (Map<String, Object>) body.get("taskConstraints");
            tc.put("actionLimits", Map.of("send-email", 1000));
            assertEquals("Invalid signature", TaskMandate.verify(encodeJson(t), USER.generatePublicKey(), A).reason());
        }

        @Test
        void expiredAndFutureAreRefused() {
            SignedTaskMandate m = root();
            long exp = IsoTime.parseMillis(m.mandate().get("expiresAt"));
            long iat = IsoTime.parseMillis(m.mandate().get("issuedAt"));
            assertEquals("Task mandate expired",
                TaskMandate.verify(m.token(), USER.generatePublicKey(), A, new VerifyOptions().now(exp + 1)).reason());
            assertTrue(TaskMandate.verify(m.token(), USER.generatePublicKey(), A, new VerifyOptions().now(iat - 31_000))
                .reason().contains("is in the future"));
            assertTrue(TaskMandate.verify(m.token(), USER.generatePublicKey(), A, new VerifyOptions().now(iat - 29_000)).valid());
        }

        @Test
        void malformedTokensNeverThrow() throws Exception {
            var key = USER.generatePublicKey();
            assertEquals("Malformed token", TaskMandate.verify("", key, null).reason());
            assertEquals("Malformed token", TaskMandate.verify("!!!", key, null).reason());
            assertEquals("Malformed token", TaskMandate.verify(encodeJson(List.of(1)), key, null).reason());
            assertEquals("Malformed token: signature missing", TaskMandate.verify(encodeJson(Map.of("v", 2)), key, null).reason());

            Map<String, Object> t = decodeJson(root().token());
            @SuppressWarnings("unchecked") Map<String, Object> body = (Map<String, Object>) t.get("mandate");
            @SuppressWarnings("unchecked") Map<String, Object> tc = (Map<String, Object>) body.get("taskConstraints");
            tc.put("roomId", 42);
            assertEquals("Malformed token: taskConstraints.roomId must be a non-empty string",
                TaskMandate.verify(encodeJson(t), key, null).reason());
            tc.put("roomId", "room-1");
            tc.put("actionLimits", Map.of("x", -1));
            assertTrue(TaskMandate.verify(encodeJson(t), key, null).reason().contains("actionLimits[\"x\"]"));
            tc.remove("actionLimits");
            body.put("expiresAt", "garbage");
            assertEquals("Malformed token: expiresAt is not a date", TaskMandate.verify(encodeJson(t), key, null).reason());
        }

        @Test
        void revocationIsKeyedByGrantorAndFailsClosed() {
            SignedTaskMandate m = root();
            String id = (String) m.mandate().get("mandateId");
            assertFalse(TaskMandate.verify(m.token(), USER.generatePublicKey(), A,
                new VerifyOptions().isRevoked((mid, g) -> mid.equals(id) && g.equals(U))).valid());
            assertTrue(TaskMandate.verify(m.token(), USER.generatePublicKey(), A,
                new VerifyOptions().isRevoked((mid, g) -> mid.equals(id) && g.equals("did:someone-else"))).valid());
            assertEquals("Revocation check failed for task mandate " + id, TaskMandate.verify(m.token(), USER.generatePublicKey(), A,
                new VerifyOptions().isRevoked((mid, g) -> { throw new RuntimeException("down"); })).reason());
        }
    }

    @Nested
    class Attenuation {
        @Test
        void inheritsBindingsBlockedAndClampsExpiry() {
            SignedTaskMandate parent = root();
            SignedTaskMandate child = TaskMandate.attenuate(parent, B, List.of("search"),
                TaskConstraints.builder()
                    .computeLimit(new ComputeLimit(10.0, 1.0, 1000.0, null))
                    .dataAccess(Map.of())
                    .reversibleOnly(true)
                    .build(),
                AGENT_A, Duration.ofDays(30), null);
            TaskMandateBody b = child.body();
            assertEquals(A, b.grantor());
            assertEquals("cart", b.mandateTier());
            assertEquals(parent.mandate().get("mandateId"), b.parentMandateId());
            assertEquals(List.of("delete"), b.blocked());
            assertEquals("room-1", b.taskConstraints().roomId());
            assertEquals("did:aroha:guest", b.taskConstraints().onBehalfOf());
            assertEquals(parent.mandate().get("expiresAt"), b.expiresAt());
            assertTrue(TaskMandate.verify(child.token(), AGENT_A.generatePublicKey(), B).valid());

            // grandchild: cart → execution
            SignedTaskMandate gc = TaskMandate.attenuate(child, "did:aroha:c", List.of("search"),
                TaskConstraints.builder().computeLimit(new ComputeLimit(1.0, 1.0, 1.0, null)).dataAccess(Map.of())
                    .reversibleOnly(true).build(), TestSupport.seed(3), Duration.ofMinutes(5), null);
            assertEquals("execution", gc.body().mandateTier());
        }

        @Test
        void refusesEveryWidening() {
            SignedTaskMandate parent = root();
            TaskConstraints ok = TaskConstraints.builder()
                .actionLimit("send-email", 2).computeLimit(new ComputeLimit(10.0, 1.0, 1000.0, null))
                .dataAccess(Map.of()).humanGates(List.of("send-email")).reversibleOnly(true).build();
            assertDoesNotThrow(() -> TaskMandate.attenuate(parent, B, List.of("send-email"), ok, AGENT_A, null, null));

            Map<String, TaskConstraints> bad = new LinkedHashMap<>();
            bad.put("limit raised", TaskConstraints.builder().actionLimit("send-email", 4)
                .computeLimit(new ComputeLimit(10.0, 1.0, 1000.0, null)).dataAccess(Map.of())
                .humanGates(List.of("send-email")).reversibleOnly(true).build());
            bad.put("reversibleOnly dropped", TaskConstraints.builder().actionLimit("send-email", 2)
                .computeLimit(new ComputeLimit(10.0, 1.0, 1000.0, null)).dataAccess(Map.of())
                .humanGates(List.of("send-email")).build());
            bad.put("gate dropped", TaskConstraints.builder().actionLimit("send-email", 2)
                .computeLimit(new ComputeLimit(10.0, 1.0, 1000.0, null)).dataAccess(Map.of()).reversibleOnly(true).build());
            bad.put("write-only widened to read-write", TaskConstraints.builder().actionLimit("send-email", 2)
                .computeLimit(new ComputeLimit(10.0, 1.0, 1000.0, null)).dataAccess("drafts", "read-write")
                .humanGates(List.of("send-email")).reversibleOnly(true).build());
            bad.put("room changed", TaskConstraints.builder().actionLimit("send-email", 2)
                .computeLimit(new ComputeLimit(10.0, 1.0, 1000.0, null)).dataAccess(Map.of())
                .humanGates(List.of("send-email")).reversibleOnly(true).roomId("room-2").build());
            for (var e : bad.entrySet()) {
                IllegalArgumentException ex = assertThrows(IllegalArgumentException.class,
                    () -> TaskMandate.attenuate(parent, B, List.of("send-email"), e.getValue(), AGENT_A, null, null), e.getKey());
                assertTrue(ex.getMessage().startsWith("Cannot attenuate task mandate: "), ex.getMessage());
            }
            assertThrows(IllegalArgumentException.class,
                () -> TaskMandate.attenuate(parent, B, List.of("send-email", "pay"), ok, AGENT_A, null, null));
        }

        @Test
        void invariantsMustBeRestated() {
            MandateInvariants inv = new MandateInvariants(List.of("did:payee"), Map.of("dest", "JFK"), new Amount(10, "USD"), null);
            SignedTaskMandate p = TaskMandate.issue(U, A, List.of("pay"), TaskConstraints.none(), USER, null,
                new IssueOptions().invariants(inv));
            assertThrows(IllegalArgumentException.class,
                () -> TaskMandate.attenuate(p, B, List.of("pay"), TaskConstraints.none(), AGENT_A, null, null));
            assertDoesNotThrow(() -> TaskMandate.attenuate(p, B, List.of("pay"), TaskConstraints.none(), AGENT_A, null,
                new AttenuateOptions().invariants(inv)));
            MandateInvariants changed = new MandateInvariants(List.of("did:payee"), Map.of("dest", "LAX"), new Amount(10, "USD"), null);
            IllegalArgumentException ex = assertThrows(IllegalArgumentException.class,
                () -> TaskMandate.attenuate(p, B, List.of("pay"), TaskConstraints.none(), AGENT_A, null,
                    new AttenuateOptions().invariants(changed)));
            assertEquals("Cannot attenuate task mandate: child parameter \"dest\" does not match parent's fixed value", ex.getMessage());
        }
    }

    @Nested
    class Enforcement {
        TaskActionRequest inRoomSearch() {
            return new TaskActionRequest("search").roomId("room-1").onBehalfOf("did:aroha:guest").capabilityReversibility("full");
        }

        @Test
        void enforceVerifiesThenChecks() throws Exception {
            SignedTaskMandate m = root();
            assertEquals(m.mandate().get("mandateId"),
                TaskMandate.enforce(m.token(), USER.generatePublicKey(), A, null, inRoomSearch()).get("mandateId"));

            TaskConstraintViolation v = assertThrows(TaskConstraintViolation.class,
                () -> TaskMandate.enforce(m.token(), AGENT_A.generatePublicKey(), A, null, inRoomSearch()));
            assertEquals("MANDATE_INVALID", v.code());

            v = assertThrows(TaskConstraintViolation.class, () -> TaskMandate.enforce(m.token(), USER.generatePublicKey(), A, null,
                new TaskActionRequest("send-email").roomId("room-1").onBehalfOf("did:aroha:guest").capabilityReversibility("semi")
                    .humanApproved(true).currentActionCounts(Map.of("send-email", 3))));
            assertEquals("ACTION_LIMIT_EXCEEDED", v.code());
        }

        @Test
        void codesForEachRule() {
            Map<String, Object> m = root().mandate();
            assertNull(TaskMandate.checkTaskConstraints(m, inRoomSearch()));
            assertEquals("CONTEXT_MISMATCH", TaskMandate.checkTaskConstraints(m, new TaskActionRequest("search")).code());
            assertEquals("REVERSIBILITY_VIOLATION", TaskMandate.checkTaskConstraints(m,
                new TaskActionRequest("search").roomId("room-1").onBehalfOf("did:aroha:guest")).code());
            assertEquals("CAPABILITY_NOT_PERMITTED", TaskMandate.checkTaskConstraints(m,
                new TaskActionRequest("delete").roomId("room-1").onBehalfOf("did:aroha:guest")).code());
            assertEquals("HUMAN_GATE_REQUIRED", TaskMandate.checkTaskConstraints(m,
                new TaskActionRequest("send-email").roomId("room-1").onBehalfOf("did:aroha:guest").capabilityReversibility("semi")).code());
            assertEquals("COMPUTE_LIMIT_EXCEEDED", TaskMandate.checkTaskConstraints(m,
                inRoomSearch().currentCompute(1000, null, null)).code());
            assertNull(TaskMandate.checkTaskConstraints(m, inRoomSearch().currentCompute(999, 9, 59_999)));
            assertEquals("DATA_ACCESS_VIOLATION", TaskMandate.checkTaskConstraints(m,
                inRoomSearch().dataAccess(Map.of("drafts", "read"))).code());
            assertNull(TaskMandate.checkTaskConstraints(m, inRoomSearch().dataAccess(Map.of("drafts", "write"))));
            assertEquals("DATA_ACCESS_VIOLATION", TaskMandate.checkTaskConstraints(m,
                inRoomSearch().dataAccess(Map.of("calendar", "admin"))).code());
        }
    }

    /** spec-public/vectors/conversation-v1.json → taskMandateV2: a guest grant bound to a room and a member. */
    @Nested
    class ConversationVector {
        @Test
        void signingPayloadSignatureAndBindings() throws Exception {
            Path p = TestSupport.repoFile("spec-public/vectors/conversation-v1.json");
            assumeTrue(TestSupport.exists(p), "conversation-v1.json not found (outside the monorepo)");
            Map<String, Object> V = TestSupport.readJson(p);
            @SuppressWarnings("unchecked") Map<String, Object> tm = (Map<String, Object>) V.get("taskMandateV2");
            @SuppressWarnings("unchecked") Map<String, Object> keys = (Map<String, Object>) V.get("keys");
            @SuppressWarnings("unchecked") Map<String, Object> host = (Map<String, Object>) keys.get("host");
            @SuppressWarnings("unchecked") Map<String, Object> mandate = (Map<String, Object>) tm.get("mandate");

            assertEquals(tm.get("expectedSigningPayload"), TaskMandate.signingPayloadV2(mandate));
            var hostKey = TestSupport.keyFromHex((String) host.get("privateKeyHex"));
            assertTrue(TaskMandate.verifySignature(mandate, (String) tm.get("signature"), 2, TestSupport.pub(hostKey)));

            long within = IsoTime.parseMillis(mandate.get("issuedAt")) + 1000;
            VerificationResult r = TaskMandate.verify((String) tm.get("token"), hostKey.generatePublicKey(),
                (String) mandate.get("grantee"), new VerifyOptions().now(within));
            assertTrue(r.valid(), r.reason());
            assertEquals(mandate, r.mandate());

            @SuppressWarnings("unchecked") List<Map<String, Object>> reqs = (List<Map<String, Object>>) tm.get("requests");
            for (Map<String, Object> q : reqs) {
                @SuppressWarnings("unchecked") Map<String, Object> rq = (Map<String, Object>) q.get("request");
                TaskConstraintViolation v = TaskMandate.checkTaskConstraints(r.mandate(), TaskMandateTsInteropTest.toRequest(rq));
                if (Boolean.TRUE.equals(q.get("allowed"))) assertNull(v, String.valueOf(rq));
                else assertEquals(q.get("code"), v == null ? null : v.code(), String.valueOf(rq));
            }
        }
    }
}
