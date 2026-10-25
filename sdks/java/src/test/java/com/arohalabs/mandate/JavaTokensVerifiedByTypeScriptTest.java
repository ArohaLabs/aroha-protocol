// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

package com.arohalabs.mandate;

import com.arohalabs.TestSupport;
import com.arohalabs.mandate.ArohaMandateCredential.SpendingConstraints;
import com.arohalabs.mandate.TaskMandate.*;
import com.arohalabs.util.IsoTime;
import com.fasterxml.jackson.core.type.TypeReference;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * The other direction of {@link TaskMandateTsInteropTest}: tokens the JAVA
 * SDK issues and attenuates are verified by the TypeScript reference
 * (scripts/task-mandate-interop.mjs verify), which must reach the same
 * verdicts with the same reason strings and codes.
 *
 * <p>Needs node on PATH and a built {@code @aroha-sdk/credentials} (dist/),
 * found at {@code $AROHA_CREDENTIALS_DIR} or {@code packages/aroha-credentials}
 * in this monorepo. Skipped when either is missing (the Java CI job has no
 * TypeScript build).
 */
class JavaTokensVerifiedByTypeScriptTest {

    static final Ed25519PrivateKeyParameters USER = TestSupport.seed(11);
    static final Ed25519PrivateKeyParameters AGENT_A = TestSupport.seed(12);
    static final String U = "did:aroha:user-java", A = "did:aroha:agent-a-java", B = "did:aroha:agent-b-java";
    static final String GUEST = "did:aroha:guest-java", ROOM = "room-java-1";

    static String hex(byte[] b) { return HexFormat.of().formatHex(b); }

    static Path credentialsDir() {
        String env = System.getenv("AROHA_CREDENTIALS_DIR");
        return env != null && !env.isEmpty() ? Path.of(env) : TestSupport.repoFile("packages/aroha-credentials");
    }

    static boolean nodeAvailable() {
        try {
            Process p = new ProcessBuilder("node", "--version").redirectErrorStream(true).start();
            return p.waitFor(20, TimeUnit.SECONDS) && p.exitValue() == 0;
        } catch (Exception e) {
            return false;
        }
    }

    static Map<String, Object> tokenEntry(SignedTaskMandate m, Ed25519PrivateKeyParameters grantor, String grantee) {
        Map<String, Object> e = new LinkedHashMap<>();
        e.put("token", m.token());
        e.put("grantorPublicKey", hex(TestSupport.pub(grantor)));
        e.put("grantee", grantee);
        e.put("verifyAt", IsoTime.parseMillis(m.mandate().get("issuedAt")) + 1000);
        return e;
    }

    static Map<String, Object> verdict(TaskConstraintViolation v) {
        if (v == null) return null;
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("code", v.code());
        m.put("message", v.getMessage());
        return m;
    }

    @Test
    void typescriptAgreesWithJavaOnJavaIssuedTokens() throws Exception {
        Path cred = credentialsDir();
        Path script = Path.of(System.getProperty("basedir", System.getProperty("user.dir")), "scripts", "task-mandate-interop.mjs");
        assumeTrue(Files.isRegularFile(cred.resolve("dist/index.js")), "@aroha-sdk/credentials is not built at " + cred);
        assumeTrue(Files.isRegularFile(script), "interop script not found");
        assumeTrue(nodeAvailable(), "node not on PATH");

        TaskConstraints rc = TaskConstraints.builder()
            .actionLimit("send-email", 2).actionLimit("draft", 5)
            .computeLimit(new ComputeLimit(2000.0, 20.0, 120_000.0, 0.25))
            .dataAccess("inbox", "read").dataAccess("outbox", "write").dataAccess("notes", "read-write")
            .outputHandling("user-only").humanGates(List.of("send-email")).checkpointIntervalMs(10_000)
            .maxDelegationDepth(3).onBehalfOf(GUEST).roomId(ROOM)
            .build();
        SignedTaskMandate root = TaskMandate.issue(U, A, List.of("search", "draft", "send-email", "café-lookup"), rc, USER,
            Duration.ofHours(2), new IssueOptions().blocked(List.of("wipe")));
        SignedTaskMandate child = TaskMandate.attenuate(root, B, List.of("search", "send-email"),
            TaskConstraints.builder().actionLimit("send-email", 1).computeLimit(new ComputeLimit(100.0, 2.0, 1000.0, 0.1))
                .dataAccess("inbox", "read").outputHandling("internal-only").humanGates(List.of("send-email"))
                .checkpointIntervalMs(5000).build(),
            AGENT_A, Duration.ofMinutes(30), null);
        SignedTaskMandate hybrid = TaskMandate.issue(U, A, List.of("pay"), TaskConstraints.builder().reversibleOnly(true).build(),
            USER, null, new IssueOptions()
                .spendingConstraints(SpendingConstraints.builder(250.5).sessionLimit(100).category("food").build())
                .invariants(new MandateInvariants(List.of("did:aroha:shop"), new LinkedHashMap<>(Map.of("order", "A-1", "qty", 3)),
                    new Amount(99.99, "USD"), null)));

        Map<String, Object> tokens = new LinkedHashMap<>();
        tokens.put("root", tokenEntry(root, USER, A));
        tokens.put("child", tokenEntry(child, AGENT_A, B));
        tokens.put("hybrid", tokenEntry(hybrid, USER, A));

        // ── rejected
        Map<String, Object> raw = TestSupport.JSON.readValue(Base64.getUrlDecoder().decode(root.token()), new TypeReference<>() {});
        @SuppressWarnings("unchecked") Map<String, Object> body = new LinkedHashMap<>((Map<String, Object>) raw.get("mandate"));
        body.put("allowed", List.of("search", "draft", "send-email", "café-lookup", "wipe"));
        Map<String, Object> tamperedRaw = new LinkedHashMap<>(raw);
        tamperedRaw.put("mandate", body);
        String tampered = Base64.getUrlEncoder().withoutPadding().encodeToString(TestSupport.JSON.writeValueAsBytes(tamperedRaw));
        Map<String, Object> v9 = new LinkedHashMap<>(raw);
        v9.put("v", 9);
        String badVersion = Base64.getUrlEncoder().withoutPadding().encodeToString(TestSupport.JSON.writeValueAsBytes(v9));
        long t0 = IsoTime.parseMillis(root.mandate().get("issuedAt")) + 1000;
        long exp = IsoTime.parseMillis(root.mandate().get("expiresAt"));

        List<Map<String, Object>> rejected = new ArrayList<>();
        List<String> javaRejectReasons = new ArrayList<>();
        Object[][] rej = {
            {"tampered-allowed", tampered, USER, A, t0},
            {"unsupported-version", badVersion, USER, A, t0},
            {"wrong-grantor-key", root.token(), AGENT_A, A, t0},
            {"wrong-grantee", root.token(), USER, B, t0},
            {"expired", root.token(), USER, A, exp + 1},
        };
        for (Object[] r : rej) {
            Map<String, Object> e = new LinkedHashMap<>();
            e.put("name", r[0]);
            e.put("token", r[1]);
            e.put("grantorPublicKey", hex(TestSupport.pub((Ed25519PrivateKeyParameters) r[2])));
            e.put("grantee", r[3]);
            e.put("verifyAt", r[4]);
            rejected.add(e);
            VerificationResult jr = TaskMandate.verify((String) r[1], ((Ed25519PrivateKeyParameters) r[2]).generatePublicKey(),
                (String) r[3], new VerifyOptions().now((Long) r[4]));
            assertFalse(jr.valid(), (String) r[0]);
            javaRejectReasons.add(jr.reason());
        }

        // ── widened children, issued directly (what a dishonest delegator would sign)
        Map<String, TaskConstraints> widen = new LinkedHashMap<>();
        java.util.function.Supplier<TaskConstraints.Builder> base = () -> TaskConstraints.builder().actionLimit("send-email", 1)
            .computeLimit(new ComputeLimit(100.0, 2.0, 1000.0, 0.1)).dataAccess("inbox", "read").outputHandling("internal-only")
            .humanGates(List.of("send-email")).checkpointIntervalMs(5000).onBehalfOf(GUEST).roomId(ROOM);
        widen.put("action-limit-raised", base.get().actionLimit("send-email", 9).build());
        widen.put("cpu-raised", base.get().computeLimit(new ComputeLimit(100.0, 2.0, 1000.0, 0.5)).build());
        widen.put("outbox-write-only-to-read", base.get().dataAccess(Map.of("outbox", "read")).build());
        widen.put("room-changed", base.get().roomId("room-other").build());
        widen.put("output-widened", base.get().outputHandling("shareable").build());
        widen.put("honest", base.get().build());
        List<Map<String, Object>> widened = new ArrayList<>();
        List<String> javaWidenReasons = new ArrayList<>();
        for (var e : widen.entrySet()) {
            SignedTaskMandate c = TaskMandate.issue(A, B, List.of("search", "send-email"), e.getValue(), AGENT_A, Duration.ofMinutes(10),
                new IssueOptions().blocked(List.of("wipe")).parentMandateId((String) root.mandate().get("mandateId")).tier("cart"));
            widened.add(new LinkedHashMap<>(Map.of("name", e.getKey(), "token", c.token(), "parentToken", root.token())));
            javaWidenReasons.add(TaskMandate.checkTaskNarrowing(root.mandate(), c.mandate()));
        }
        assertNull(javaWidenReasons.get(javaWidenReasons.size() - 1));

        // ── requests
        Object[][] reqs = {
            {"root", "ok", Map.of("requestedCapability", "search", "roomId", ROOM, "onBehalfOf", GUEST)},
            {"root", "unicode", Map.of("requestedCapability", "café-lookup", "roomId", ROOM, "onBehalfOf", GUEST)},
            {"root", "no-member", Map.of("requestedCapability", "search", "roomId", ROOM)},
            {"root", "blocked-not-allowed", Map.of("requestedCapability", "wipe", "roomId", ROOM, "onBehalfOf", GUEST)},
            {"root", "gate", Map.of("requestedCapability", "send-email", "roomId", ROOM, "onBehalfOf", GUEST)},
            {"root", "limit", Map.of("requestedCapability", "send-email", "humanApproved", true, "roomId", ROOM, "onBehalfOf", GUEST,
                "currentActionCounts", Map.of("send-email", 2))},
            {"root", "cpu-not-checked-but-llm", Map.of("requestedCapability", "search", "roomId", ROOM, "onBehalfOf", GUEST,
                "currentCompute", Map.of("llmTokens", 2000))},
            {"root", "write-only", Map.of("requestedCapability", "draft", "roomId", ROOM, "onBehalfOf", GUEST,
                "dataAccess", Map.of("outbox", "read-write"))},
            {"hybrid", "irreversible", Map.of("requestedCapability", "pay")},
            {"hybrid", "full", Map.of("requestedCapability", "pay", "capabilityReversibility", "full")},
            {"child", "child-gone", Map.of("requestedCapability", "draft", "roomId", ROOM, "onBehalfOf", GUEST)},
        };
        Map<String, SignedTaskMandate> byName = Map.of("root", root, "child", child, "hybrid", hybrid);
        List<Map<String, Object>> requests = new ArrayList<>();
        List<Map<String, Object>> javaVerdicts = new ArrayList<>();
        for (Object[] q : reqs) {
            @SuppressWarnings("unchecked") Map<String, Object> rq = (Map<String, Object>) q[2];
            requests.add(new LinkedHashMap<>(Map.of("on", q[0], "name", q[1], "request", rq)));
            javaVerdicts.add(verdict(TaskMandate.checkTaskConstraints(byName.get((String) q[0]).mandate(),
                TaskMandateTsInteropTest.toRequest(rq))));
        }

        // ── TypeScript attenuates a Java parent
        List<Map<String, Object>> attenuation = new ArrayList<>();
        Map<String, Object> honestTc = new LinkedHashMap<>();
        honestTc.put("computeLimit", Map.of("llmTokens", 10, "webRequests", 1, "executionTimeMs", 10, "cpuSeconds", 0.01));
        honestTc.put("dataAccess", Map.of());
        honestTc.put("outputHandling", "internal-only");
        honestTc.put("checkpointIntervalMs", 1000);
        Map<String, Object> wideTc = new LinkedHashMap<>(honestTc);
        wideTc.put("dataAccess", Map.of("notes", "read-write", "inbox", "write"));
        for (Object[] a : new Object[][]{{"ts-honest", honestTc}, {"ts-widening", wideTc}}) {
            Map<String, Object> e = new LinkedHashMap<>();
            e.put("name", a[0]);
            e.put("parent", "root");
            e.put("grantee", B);
            e.put("allowed", List.of("search"));
            e.put("taskConstraints", a[1]);
            e.put("grantorSeed", hex(AGENT_A.getEncoded()));
            e.put("grantorPublicKey", hex(TestSupport.pub(AGENT_A)));
            attenuation.add(e);
        }

        Map<String, Object> file = new LinkedHashMap<>();
        file.put("tokens", tokens);
        file.put("rejected", rejected);
        file.put("widened", widened);
        file.put("requests", requests);
        file.put("attenuation", attenuation);
        Path out = Path.of(System.getProperty("basedir", System.getProperty("user.dir")), "target", "interop", "java-task-mandates.json");
        Files.createDirectories(out.getParent());
        Files.write(out, TestSupport.JSON.writerWithDefaultPrettyPrinter().writeValueAsBytes(file));

        Map<String, Object> ts = runNode(script, cred, out);

        // tokens: TS verifies Java-issued tokens and computes the same signing payload
        @SuppressWarnings("unchecked") Map<String, Map<String, Object>> tsTokens = (Map<String, Map<String, Object>>) ts.get("tokens");
        for (var e : byName.entrySet()) {
            Map<String, Object> r = tsTokens.get(e.getKey());
            assertEquals(true, r.get("valid"), e.getKey() + ": " + r.get("reason"));
            assertEquals(TaskMandate.signingPayloadV2(e.getValue().mandate()), r.get("signingPayload"), e.getKey());
        }
        @SuppressWarnings("unchecked") List<Map<String, Object>> tsRejected = (List<Map<String, Object>>) ts.get("rejected");
        assertEquals(javaRejectReasons.size(), tsRejected.size());
        for (int i = 0; i < tsRejected.size(); i++) {
            assertEquals(false, tsRejected.get(i).get("valid"), (String) tsRejected.get(i).get("name"));
            assertEquals(javaRejectReasons.get(i), tsRejected.get(i).get("reason"), (String) tsRejected.get(i).get("name"));
        }
        @SuppressWarnings("unchecked") List<Map<String, Object>> tsWidened = (List<Map<String, Object>>) ts.get("widened");
        assertEquals(javaWidenReasons.size(), tsWidened.size());
        for (int i = 0; i < tsWidened.size(); i++) {
            assertEquals(javaWidenReasons.get(i), tsWidened.get(i).get("reason"), (String) tsWidened.get(i).get("name"));
        }
        @SuppressWarnings("unchecked") List<Map<String, Object>> tsReqs = (List<Map<String, Object>>) ts.get("requests");
        assertEquals(javaVerdicts.size(), tsReqs.size());
        for (int i = 0; i < tsReqs.size(); i++) {
            assertEquals(javaVerdicts.get(i), tsReqs.get(i).get("verdict"), (String) tsReqs.get(i).get("name"));
        }
        @SuppressWarnings("unchecked") List<Map<String, Object>> tsAtt = (List<Map<String, Object>>) ts.get("attenuation");
        Map<String, Object> honest = tsAtt.get(0);
        assertEquals(true, honest.get("ok"), String.valueOf(honest.get("error")));
        assertEquals(true, honest.get("valid"), String.valueOf(honest.get("reason")));
        // …and Java accepts the TypeScript child of its own parent
        SignedTaskMandate tsChild = TaskMandate.decode((String) honest.get("token"));
        assertTrue(TaskMandate.verify(tsChild.token(), AGENT_A.generatePublicKey(), B).valid());
        assertNull(TaskMandate.checkTaskNarrowing(root.mandate(), tsChild.mandate()));
        assertEquals(ROOM, tsChild.body().taskConstraints().roomId());
        Map<String, Object> widening = tsAtt.get(1);
        assertEquals(false, widening.get("ok"));
        assertTrue(((String) widening.get("error")).startsWith("Cannot attenuate task mandate: child dataAccess[\"inbox\"] (write) exceeds parent (read)"),
            String.valueOf(widening.get("error")));
    }

    static Map<String, Object> runNode(Path script, Path cred, Path input) throws Exception {
        ProcessBuilder pb = new ProcessBuilder("node", script.toString(), "verify", input.toString());
        pb.environment().put("AROHA_CREDENTIALS_DIR", cred.toAbsolutePath().toString());
        pb.redirectError(ProcessBuilder.Redirect.INHERIT);
        Process p = pb.start();
        byte[] stdout = p.getInputStream().readAllBytes();
        assertTrue(p.waitFor(120, TimeUnit.SECONDS), "node timed out");
        assertEquals(0, p.exitValue(), "node failed: " + new String(stdout, StandardCharsets.UTF_8));
        return TestSupport.JSON.readValue(stdout, new TypeReference<>() {});
    }
}
