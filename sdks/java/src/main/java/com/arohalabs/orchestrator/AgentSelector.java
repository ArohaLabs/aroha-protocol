// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

package com.arohalabs.orchestrator;

import com.arohalabs.messages.ArohaEnvelope;
import com.arohalabs.transport.ArohaClient;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;

import java.time.Duration;
import java.util.*;
import java.util.concurrent.*;
import java.util.stream.Collectors;

/**
 * Aroha Layer 4 — Agent Selector
 *
 * Fans out a ArohaRequest to all eligible candidates in parallel, collects responses,
 * scores them on 5 dimensions, and returns a ranked list.
 *
 * Scoring weights (configurable):
 *   price        0.35
 *   reputation   0.30
 *   latency      0.15
 *   preference   0.15
 *   availability 0.05
 */
public final class AgentSelector {

    public static final Map<String, Double> DEFAULT_WEIGHTS = Map.of(
        "price",        0.35,
        "reputation",   0.30,
        "latency",      0.15,
        "preference",   0.15,
        "availability", 0.05
    );

    private final ArohaClient client;
    private final String orchestratorDid;
    private final String orchestratorKeyId;
    private final Ed25519PrivateKeyParameters privateKey;
    private final ExecutorService executor = Executors.newVirtualThreadPerTaskExecutor();

    public AgentSelector(
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
     * Selects the best agent for a capability from a list of candidates.
     *
     * @param capability        capability ID to request
     * @param params            request parameters
     * @param candidates        list of candidate agents (must have "did", "endpoint", optionally "reputation")
     * @param weights           scoring weights (or null to use defaults)
     * @param preferenceScores  per-DID preference boost scores 0–1 (or null)
     * @param blockedAgents     DIDs to exclude (or null)
     * @param fanOutTimeoutMs   timeout for each individual request in milliseconds
     * @return SelectionResult with winner and ranked list
     */
    public SelectionResult select(
            String capability,
            Map<String, Object> params,
            List<Map<String, Object>> candidates,
            Map<String, Double> weights,
            Map<String, Double> preferenceScores,
            List<String> blockedAgents,
            long fanOutTimeoutMs) throws Exception {

        Map<String, Double> w    = weights           != null ? weights           : DEFAULT_WEIGHTS;
        Map<String, Double> pref = preferenceScores  != null ? preferenceScores  : Map.of();
        Set<String> blocked      = blockedAgents     != null ? new HashSet<>(blockedAgents) : Set.of();
        String correlationId     = ArohaEnvelope.newCorrelationId();

        List<Map<String, Object>> eligible = candidates.stream()
            .filter(c -> !blocked.contains(c.get("did")))
            .collect(Collectors.toList());

        if (eligible.isEmpty()) {
            throw new IllegalArgumentException("No eligible agents for capability: " + capability);
        }

        // Fan-out requests
        List<Future<AgentOffer>> futures = new ArrayList<>();
        for (Map<String, Object> candidate : eligible) {
            futures.add(executor.submit(() ->
                sendRequest(candidate, capability, params, correlationId, fanOutTimeoutMs)));
        }

        List<AgentOffer> offers = new ArrayList<>();
        for (Future<AgentOffer> f : futures) {
            try {
                AgentOffer offer = f.get(fanOutTimeoutMs + 1000, TimeUnit.MILLISECONDS);
                if (offer != null) offers.add(offer);
            } catch (Exception ignored) {}
        }

        if (offers.isEmpty()) {
            throw new IllegalStateException("No agents responded for capability: " + capability);
        }

        List<AgentOffer> scored = scoreOffers(offers, eligible, w, pref);
        scored.sort(Comparator.comparingDouble((AgentOffer o) -> o.score).reversed());
        return new SelectionResult(scored.get(0), scored);
    }

    /** Convenience overload with default timeout (5 seconds). */
    public SelectionResult select(
            String capability,
            Map<String, Object> params,
            List<Map<String, Object>> candidates) throws Exception {
        return select(capability, params, candidates, null, null, null, 5000);
    }

    // ── Internal ──────────────────────────────────────────────────────────────

    @SuppressWarnings("unchecked")
    private AgentOffer sendRequest(
            Map<String, Object> agent,
            String capability,
            Map<String, Object> params,
            String correlationId,
            long timeoutMs) {
        try {
            Map<String, Object> body = new LinkedHashMap<>();
            body.put("capability", capability);
            body.put("params",     params);

            Map<String, Object> envelope = ArohaEnvelope.build(
                "ArohaRequest", orchestratorDid, (String) agent.get("did"),
                body, correlationId, privateKey, orchestratorKeyId);

            long start = System.currentTimeMillis();
            Map<String, Object> response = client.send(
                (String) agent.get("endpoint"), envelope,
                Duration.ofMillis(timeoutMs));

            if (response == null || "ArohaError".equals(response.get("type"))) return null;

            long latencyMs = System.currentTimeMillis() - start;
            Map<String, Object> result =
                (Map<String, Object>) ((Map<String, Object>) response.get("body"))
                    .getOrDefault("result", Map.of());

            Object priceRaw = result.getOrDefault("price", result.get("totalPrice"));
            Double price = priceRaw != null ? ((Number) priceRaw).doubleValue() : null;

            return new AgentOffer(
                (String) agent.get("did"),
                (String) agent.get("endpoint"),
                response,
                price,
                latencyMs);
        } catch (Exception e) {
            return null;
        }
    }

    private List<AgentOffer> scoreOffers(
            List<AgentOffer> offers,
            List<Map<String, Object>> candidates,
            Map<String, Double> w,
            Map<String, Double> pref) {

        List<Double> prices = offers.stream()
            .filter(o -> o.price != null).map(o -> o.price).collect(Collectors.toList());
        double minPrice = prices.stream().mapToDouble(Double::doubleValue).min().orElse(0);
        double maxPrice = prices.stream().mapToDouble(Double::doubleValue).max().orElse(0);

        List<Double> latencies = offers.stream().map(o -> (double) o.latencyMs).collect(Collectors.toList());
        double minLat = latencies.stream().mapToDouble(Double::doubleValue).min().orElse(0);
        double maxLat = latencies.stream().mapToDouble(Double::doubleValue).max().orElse(0);

        Map<String, Integer> repByDid = new HashMap<>();
        for (Map<String, Object> c : candidates) {
            Object rep = c.get("reputation");
            repByDid.put((String) c.get("did"), rep != null ? ((Number) rep).intValue() : 5000);
        }

        for (AgentOffer offer : offers) {
            double priceScore = offer.price == null ? 1.0
                : norm(maxPrice - offer.price, 0, maxPrice - minPrice);
            double rep        = repByDid.getOrDefault(offer.agentDid, 5000) / 10_000.0;
            double latScore   = norm(maxLat - offer.latencyMs, 0, maxLat - minLat);
            double prefScore  = pref.getOrDefault(offer.agentDid, 0.5);

            offer.score =
                priceScore * w.getOrDefault("price",        0.35) +
                rep        * w.getOrDefault("reputation",   0.30) +
                latScore   * w.getOrDefault("latency",      0.15) +
                prefScore  * w.getOrDefault("preference",   0.15) +
                1.0        * w.getOrDefault("availability", 0.05);
        }
        return offers;
    }

    private static double norm(double v, double lo, double hi) {
        return hi == lo ? 1.0 : (v - lo) / (hi - lo);
    }

    // ── Data Types ────────────────────────────────────────────────────────────

    public static final class AgentOffer {
        public final String agentDid;
        public final String agentEndpoint;
        public final Map<String, Object> response;
        public final Double price;
        public final long latencyMs;
        public double score;

        public AgentOffer(String agentDid, String agentEndpoint,
                          Map<String, Object> response, Double price, long latencyMs) {
            this.agentDid      = agentDid;
            this.agentEndpoint = agentEndpoint;
            this.response      = response;
            this.price         = price;
            this.latencyMs     = latencyMs;
        }
    }

    public record SelectionResult(AgentOffer winner, List<AgentOffer> ranked) {}
}
