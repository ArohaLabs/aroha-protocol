// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

package com.arohalabs.orchestrator;

import com.arohalabs.messages.ArohaEnvelope;
import com.arohalabs.transport.ArohaClient;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;

import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * Aroha Layer 4 — Saga Engine
 *
 * Implements the Aroha atomic transaction pattern:
 *
 *   Phase 1 — RESERVE: fan out ArohaReserve to all participants in parallel
 *   Phase 2 — COMMIT:  send ArohaCommit to each, sequentially
 *   Phase 3 — COMPENSATE: on any failure, send ArohaCancel in LIFO order
 *
 * This mirrors the Python and TypeScript SDK saga implementations exactly.
 */
public final class SagaEngine {

    private final ArohaClient client;
    private final String orchestratorDid;
    private final String orchestratorKeyId;
    private final Ed25519PrivateKeyParameters privateKey;
    private final ExecutorService executor = Executors.newVirtualThreadPerTaskExecutor();

    public SagaEngine(
            ArohaClient client,
            String orchestratorDid,
            String orchestratorKeyId,
            Ed25519PrivateKeyParameters privateKey) {
        this.client = client;
        this.orchestratorDid = orchestratorDid;
        this.orchestratorKeyId = orchestratorKeyId;
        this.privateKey = privateKey;
    }

    // ── Public API ────────────────────────────────────────────────────────────

    /**
     * Executes a saga across the given participants.
     *
     * @param participants list of saga steps to execute
     * @return SagaResult with success flag, results, and any failures
     */
    public SagaResult execute(List<SagaStep> participants) throws Exception {
        String sagaId = "saga-" + UUID.randomUUID();
        String correlationId = ArohaEnvelope.newCorrelationId();

        for (int i = 0; i < participants.size(); i++) {
            participants.get(i).stepId = i;
        }

        // ── Phase 1: RESERVE (parallel) ───────────────────────────────────────
        List<CompletableFuture<Void>> reserveTasks = new ArrayList<>();
        for (SagaStep step : participants) {
            reserveTasks.add(CompletableFuture.runAsync(
                () -> reserve(step, correlationId), executor));
        }
        CompletableFuture.allOf(reserveTasks.toArray(new CompletableFuture[0])).join();

        boolean allReserved = participants.stream()
            .allMatch(s -> s.state == SagaStep.State.RESERVED);

        if (!allReserved) {
            compensate(participants, correlationId);
            List<Map<String, Object>> failures = new ArrayList<>();
            for (SagaStep s : participants) {
                if (s.state == SagaStep.State.FAILED) {
                    Map<String, Object> f = new LinkedHashMap<>();
                    f.put("stepId", s.stepId);
                    f.put("reason", s.error != null ? s.error : "Reserve failed");
                    failures.add(f);
                }
            }
            return new SagaResult(false, sagaId, Map.of(), failures);
        }

        // ── Phase 2: COMMIT (sequential) ──────────────────────────────────────
        for (SagaStep step : participants) {
            try {
                Map<String, Object> ack = commit(step, correlationId);
                step.state = SagaStep.State.COMMITTED;
                @SuppressWarnings("unchecked")
                Map<String, Object> result = (Map<String, Object>) ack.getOrDefault("result", Map.of());
                step.commitResult = result;
            } catch (Exception exc) {
                step.state = SagaStep.State.FAILED;
                step.error = exc.getMessage();
                compensate(participants, correlationId);
                return new SagaResult(false, sagaId, Map.of(),
                    List.of(Map.of("stepId", step.stepId, "reason", step.error)));
            }
        }

        // Build results map
        Map<Integer, Map<String, Object>> results = new LinkedHashMap<>();
        for (SagaStep s : participants) {
            results.put(s.stepId, s.commitResult != null ? s.commitResult : Map.of());
        }
        return new SagaResult(true, sagaId, results, List.of());
    }

    // ── Phase Implementations ─────────────────────────────────────────────────

    @SuppressWarnings("unchecked")
    private void reserve(SagaStep step, String correlationId) {
        try {
            Map<String, Object> body = new LinkedHashMap<>();
            body.put("capability",    step.capability);
            body.put("params",        step.params);
            body.put("holdDurationMs", step.holdDurationMs);

            Map<String, Object> envelope = ArohaEnvelope.build(
                "ArohaReserve", orchestratorDid, step.agentDid,
                body, correlationId, privateKey, orchestratorKeyId);

            Map<String, Object> response = client.send(step.agentEndpoint, envelope);
            if (response == null) throw new RuntimeException("No response from " + step.agentDid);
            if ("ArohaError".equals(response.get("type"))) {
                Map<String, Object> b = (Map<String, Object>) response.get("body");
                throw new RuntimeException((String) b.getOrDefault("message", "Reserve failed"));
            }

            Map<String, Object> respBody = (Map<String, Object>) response.get("body");
            step.reservationToken    = (String) respBody.get("reservationToken");
            step.reservationExpiresAt = (String) respBody.get("expiresAt");
            step.state = SagaStep.State.RESERVED;
        } catch (Exception e) {
            step.state = SagaStep.State.FAILED;
            step.error = e.getMessage();
        }
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> commit(SagaStep step, String correlationId) throws Exception {
        Map<String, Object> body = Map.of("reservationToken", step.reservationToken);
        Map<String, Object> envelope = ArohaEnvelope.build(
            "ArohaCommit", orchestratorDid, step.agentDid,
            body, correlationId, privateKey, orchestratorKeyId);

        Map<String, Object> response = client.send(step.agentEndpoint, envelope);
        if (response == null) throw new RuntimeException("No response from " + step.agentDid);
        if ("ArohaError".equals(response.get("type"))) {
            Map<String, Object> b = (Map<String, Object>) response.get("body");
            throw new RuntimeException((String) b.getOrDefault("message", "Commit failed"));
        }
        return (Map<String, Object>) response.get("body");
    }

    private void compensate(List<SagaStep> steps, String correlationId) {
        // LIFO order
        List<SagaStep> toCancel = new ArrayList<>();
        for (int i = steps.size() - 1; i >= 0; i--) {
            SagaStep s = steps.get(i);
            if (s.state == SagaStep.State.RESERVED || s.state == SagaStep.State.COMMITTED) {
                toCancel.add(s);
            }
        }
        for (SagaStep step : toCancel) {
            try {
                Map<String, Object> body = new LinkedHashMap<>();
                body.put("reservationToken", step.reservationToken);
                body.put("reason", "Saga compensation — rolling back");
                Map<String, Object> envelope = ArohaEnvelope.build(
                    "ArohaCancel", orchestratorDid, step.agentDid,
                    body, correlationId, privateKey, orchestratorKeyId);
                client.send(step.agentEndpoint, envelope);
                step.state = SagaStep.State.CANCELLED;
            } catch (Exception e) {
                System.err.println("[Aroha Saga] Cancel failed for step " + step.stepId + ": " + e.getMessage());
            }
        }
    }

    // ── Data Types ────────────────────────────────────────────────────────────

    public static final class SagaStep {
        public enum State { PENDING, RESERVED, COMMITTED, CANCELLED, FAILED }

        public String agentDid;
        public String agentEndpoint;
        public String capability;
        public Map<String, Object> params;
        public int holdDurationMs = 300_000;

        // set by engine
        public int stepId;
        public State state = State.PENDING;
        public String reservationToken;
        public String reservationExpiresAt;
        public Map<String, Object> commitResult;
        public String error;

        public SagaStep(String agentDid, String agentEndpoint,
                        String capability, Map<String, Object> params) {
            this.agentDid       = agentDid;
            this.agentEndpoint  = agentEndpoint;
            this.capability     = capability;
            this.params         = params;
        }
    }

    public record SagaResult(
        boolean success,
        String sagaId,
        Map<Integer, Map<String, Object>> results,
        List<Map<String, Object>> failures
    ) {}
}
