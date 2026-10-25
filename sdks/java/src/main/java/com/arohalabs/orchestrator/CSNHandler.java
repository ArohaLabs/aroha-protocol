// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

package com.arohalabs.orchestrator;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.*;
import java.util.function.BiFunction;

import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * Aroha Capability Schema Negotiation (CSN)
 *
 * <p>Aroha's superior alternative to ANP's meta-protocol:
 * <ul>
 *   <li>ANP: LLM generates NEW protocol → both sides code-generate → fragile</li>
 *   <li>Aroha CSN: structural JSON Schema matching first (deterministic, no LLM);
 *       LLM only when ambiguous (0.5–0.85); maps to EXISTING typed capability;
 *       transaction terms negotiated in same round; SHA-256 cached.</li>
 * </ul>
 *
 * <h2>Provider usage</h2>
 * <pre>{@code
 * var registry = new CapabilityRegistry();
 * registry.register(new CapabilityEntry("fx-convert", "Convert currency", inputSchema, ...));
 * var handler = new CSNHandler(registry, agentDID, privateKey, buildEnvelopeFn, null);
 *
 * // In your server's onMessage:
 * if ("ArohaNegotiate".equals(type) && body.containsKey("csn")) {
 *     var reply = handler.handle(envelope, senderDID);
 *     respond(reply);
 * }
 * }</pre>
 */
public final class CSNHandler {

    private static final double CONFIDENT_THRESHOLD = 0.85;
    private static final ObjectMapper MAPPER = new ObjectMapper();

    // ── Capability registry ───────────────────────────────────────────────────

    public record CapabilityEntry(
        String name,
        String description,
        Map<String, Object> inputSchema,
        Map<String, Object> outputSchema,
        boolean supportsSaga,
        Map<String, Object> defaultPricing,
        Map<String, Object> defaultSla
    ) {
        public CapabilityEntry(String name, String description, Map<String, Object> inputSchema) {
            this(name, description, inputSchema, null, true, null, null);
        }
    }

    public record CapabilityMatch(CapabilityEntry entry, double score, boolean confident) {}

    public static final class CapabilityRegistry {
        private final Map<String, CapabilityEntry> caps = new LinkedHashMap<>();

        public void register(CapabilityEntry entry) {
            caps.put(entry.name(), entry);
        }

        public Optional<CapabilityEntry> get(String name) {
            return Optional.ofNullable(caps.get(name));
        }

        public List<CapabilityEntry> list() {
            return List.copyOf(caps.values());
        }

        public Optional<CapabilityMatch> findByInputSchema(Map<String, Object> desired) {
            CapabilityMatch best = null;
            for (var e : caps.values()) {
                double score = schemaCompatibilityScore(desired, e.inputSchema());
                if (best == null || score > best.score()) {
                    best = new CapabilityMatch(e, score, score >= CONFIDENT_THRESHOLD);
                }
            }
            return Optional.ofNullable(best);
        }

        public List<CapabilityMatch> findCandidates(Map<String, Object> desired, double minScore) {
            var results = new ArrayList<CapabilityMatch>();
            for (var e : caps.values()) {
                double score = schemaCompatibilityScore(desired, e.inputSchema());
                if (score >= minScore) {
                    results.add(new CapabilityMatch(e, score, score >= CONFIDENT_THRESHOLD));
                }
            }
            results.sort(Comparator.comparingDouble(CapabilityMatch::score).reversed());
            return results;
        }
    }

    // ── Schema matching ───────────────────────────────────────────────────────

    @SuppressWarnings("unchecked")
    public static double schemaCompatibilityScore(
        Map<String, Object> desired,
        Map<String, Object> available
    ) {
        var desiredProps   = (Map<String, Object>) desired.getOrDefault("properties", Map.of());
        var availableProps = (Map<String, Object>) available.getOrDefault("properties", Map.of());
        var required       = new HashSet<>((List<String>) desired.getOrDefault("required", List.of()));

        if (desiredProps.isEmpty()) return 1.0;

        double matchScore = 0, totalWeight = 0;

        for (var entry : desiredProps.entrySet()) {
            var key    = entry.getKey();
            double w   = required.contains(key) ? 1.0 : 0.4;
            totalWeight += w;

            if (!availableProps.containsKey(key)) continue;

            var dType = fieldType(entry.getValue());
            var aType = fieldType(availableProps.get(key));

            if (dType == null || aType == null || dType.equals(aType)) {
                matchScore += w;
            } else if (typesCompatible(dType, aType)) {
                matchScore += w * 0.7;
            }
        }
        return totalWeight == 0 ? 1.0 : matchScore / totalWeight;
    }

    @SuppressWarnings("unchecked")
    private static String fieldType(Object field) {
        if (field instanceof Map<?, ?> m) {
            return (String) ((Map<String, Object>) m).get("type");
        }
        return null;
    }

    private static boolean typesCompatible(String a, String b) {
        var numeric = Set.of("number", "integer");
        return numeric.contains(a) && numeric.contains(b);
    }

    /** SHA-256 hex of the canonical schema — used as discovery cache key. */
    public static String schemaHash(Map<String, Object> schema) {
        try {
            var canonical = MAPPER.writeValueAsString(sortedMap(schema));
            var digest    = MessageDigest.getInstance("SHA-256");
            var bytes     = digest.digest(canonical.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(bytes);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @SuppressWarnings("unchecked")
    private static Object sortedMap(Object v) {
        if (v instanceof Map<?, ?> m) {
            var sorted = new TreeMap<String, Object>();
            ((Map<String, Object>) m).forEach((k, val) -> sorted.put(k, sortedMap(val)));
            return sorted;
        }
        if (v instanceof List<?> list) {
            return list.stream().map(CSNHandler::sortedMap).toList();
        }
        return v;
    }

    // ── Discovery cache ───────────────────────────────────────────────────────

    public record CacheEntry(
        String capabilityName,
        Map<String, Object> agreedSchema,
        String matchMethod,
        double compatibilityScore,
        Instant cachedAt,
        int hitCount
    ) {}

    public static final class DiscoveryCache {
        private final Map<String, CacheEntry> store = new LinkedHashMap<>();

        private String key(String agentDID, String hash) { return agentDID + ":" + hash; }

        public Optional<CacheEntry> get(String agentDID, String hash) {
            var e = store.get(key(agentDID, hash));
            if (e != null) {
                store.put(key(agentDID, hash), new CacheEntry(
                    e.capabilityName(), e.agreedSchema(), e.matchMethod(),
                    e.compatibilityScore(), e.cachedAt(), e.hitCount() + 1
                ));
            }
            return Optional.ofNullable(store.get(key(agentDID, hash)));
        }

        public void put(String agentDID, String hash, String capability,
                        Map<String, Object> schema, String method, double score) {
            store.put(key(agentDID, hash),
                new CacheEntry(capability, schema, method, score, Instant.now(), 0));
        }

        public void invalidate(String agentDID, String capabilityName) {
            var prefix = agentDID + ":";
            store.keySet().removeIf(k -> k.startsWith(prefix)
                && (capabilityName == null || capabilityName.equals(store.get(k).capabilityName())));
        }
    }

    // ── LLM matcher interface ─────────────────────────────────────────────────

    public record LLMCandidate(String name, String description, Map<String, Object> inputSchema) {}

    @FunctionalInterface
    public interface ICapabilityMatcher {
        /** Returns the best-matching capability name, or null if uncertain. */
        String match(String intent, List<LLMCandidate> candidates);
    }

    // ── Request / result types ────────────────────────────────────────────────

    public record DiscoveryRequest(
        String capabilityIntent,
        Map<String, Object> desiredSchema,
        Map<String, Object> proposedTerms,
        boolean requestCapabilityManifest
    ) {}

    public record DiscoveryResult(
        String resolvedCapability,
        Map<String, Object> agreedSchema,
        Map<String, Object> agreedTerms,
        String matchMethod,
        double compatibilityScore,
        Map<String, Object> capabilityManifest,
        int rounds
    ) {}

    // ── Build envelope interface ──────────────────────────────────────────────

    @FunctionalInterface
    public interface BuildEnvelopeFn {
        Map<String, Object> build(String type, String from, String to,
                                  Map<String, Object> body, String correlationId,
                                  byte[] privateKey) throws Exception;
    }

    // ── Provider: CSNHandler ──────────────────────────────────────────────────

    private final CapabilityRegistry registry;
    private final String agentDID;
    private final byte[] privateKey;
    private final BuildEnvelopeFn buildEnvelope;
    private final ICapabilityMatcher llmMatcher;
    private final boolean serveManifest;

    public CSNHandler(
        CapabilityRegistry registry,
        String agentDID,
        byte[] privateKey,
        BuildEnvelopeFn buildEnvelope,
        ICapabilityMatcher llmMatcher
    ) {
        this.registry      = registry;
        this.agentDID      = agentDID;
        this.privateKey    = privateKey;
        this.buildEnvelope = buildEnvelope;
        this.llmMatcher    = llmMatcher;
        this.serveManifest = true;
    }

    /**
     * Handle an inbound ArohaNegotiate envelope with a CSN extension.
     * Returns ArohaAccept or ArohaError.
     */
    @SuppressWarnings("unchecked")
    public Map<String, Object> handle(Map<String, Object> inbound, String senderDID) throws Exception {
        var body   = (Map<String, Object>) inbound.get("body");
        var csn    = (Map<String, Object>) body.getOrDefault("csn", Map.of());
        var corrId = (String) inbound.getOrDefault("correlationId", "");

        String matchMethod = "schema";
        String matchedName = null;
        double matchedScore = 0;

        // ── 1. Structural schema matching ─────────────────────────────────────
        var desiredSchema = (Map<String, Object>) csn.get("desiredSchema");
        Map<String, Object> desiredInput = null;
        if (desiredSchema != null) {
            desiredInput = (Map<String, Object>) desiredSchema.get("input");
        }
        if (desiredInput != null) {
            var result = registry.findByInputSchema(desiredInput);
            if (result.isPresent() && result.get().score() >= 0.5) {
                matchedName  = result.get().entry().name();
                matchedScore = result.get().score();
                matchMethod  = "schema";
            }
        }

        // ── 2. LLM fallback (ambiguous range) ─────────────────────────────────
        var intent = (String) csn.get("capabilityIntent");
        if ((matchedName == null || matchedScore < 0.85) && intent != null && llmMatcher != null) {
            var baseSchema = desiredInput != null ? desiredInput : Map.<String, Object>of();
            var candidates = registry.findCandidates(baseSchema, 0.0).stream()
                .map(m -> new LLMCandidate(m.entry().name(), m.entry().description(), m.entry().inputSchema()))
                .toList();
            if (!candidates.isEmpty()) {
                var llmResult = llmMatcher.match(intent, candidates);
                if (llmResult != null && registry.get(llmResult).isPresent()) {
                    matchedName  = llmResult;
                    matchedScore = 0.75;
                    matchMethod  = "intent";
                }
            }
        }

        // ── 3. Direct name lookup ─────────────────────────────────────────────
        var capName = (String) body.get("capability");
        if (matchedName == null && capName != null && !capName.equals("unknown")) {
            var entry = registry.get(capName);
            if (entry.isPresent()) {
                matchedName  = entry.get().name();
                matchedScore = 1.0;
                matchMethod  = "schema";
            }
        }

        // ── No match → ArohaError ──────────────────────────────────────────────
        if (matchedName == null) {
            return buildEnvelope.build("ArohaError", agentDID, senderDID, Map.of(
                "code",      "Aroha_UNKNOWN_CAPABILITY",
                "message",   "No capability matched the provided intent or schema",
                "retryable", false
            ), corrId, privateKey);
        }

        var entry = registry.get(matchedName).get();

        // ── 4. Agreed schema ──────────────────────────────────────────────────
        var agreedSchema = new LinkedHashMap<String, Object>();
        agreedSchema.put("input", entry.inputSchema());
        if (entry.outputSchema() != null) agreedSchema.put("output", entry.outputSchema());

        // ── 5. Manifest if requested ──────────────────────────────────────────
        Map<String, Object> manifest = null;
        if (Boolean.TRUE.equals(csn.get("requestCapabilityManifest")) && serveManifest) {
            manifest = buildManifest();
        }

        // ── 6. Terms ──────────────────────────────────────────────────────────
        // The provider's own terms are not negotiable here. This used to put
        // the provider's price and SLA in first and then putAll() the caller's
        // proposal over them, so a request proposing price 0 came back as an
        // ArohaAccept the provider had signed for a price it never offered.
        // A proposal may add terms the provider left open; one that CHANGES a
        // term the provider set is answered with a counter-offer naming the
        // provider's terms, which the caller can accept or walk away from.
        var providerTerms = new LinkedHashMap<String, Object>();
        if (entry.defaultPricing() != null) providerTerms.put("price", entry.defaultPricing());
        if (entry.defaultSla()     != null) providerTerms.put("sla",   entry.defaultSla());
        var proposed = (Map<String, Object>) body.get("proposedTerms");

        var acceptedTerms = new LinkedHashMap<String, Object>(providerTerms);
        boolean conflicts = false;
        if (proposed != null) {
            for (var e : proposed.entrySet()) {
                if (providerTerms.containsKey(e.getKey())) {
                    if (!Objects.equals(providerTerms.get(e.getKey()), e.getValue())) conflicts = true;
                } else {
                    acceptedTerms.put(e.getKey(), e.getValue());
                }
            }
        }

        var csnReply = new LinkedHashMap<String, Object>();
        csnReply.put("resolvedCapability", matchedName);
        csnReply.put("agreedSchema",       agreedSchema);
        csnReply.put("schemaHash",         csn.get("schemaHash"));
        csnReply.put("matchMethod",        matchMethod);
        csnReply.put("compatibilityScore", matchedScore);
        csnReply.put("capabilityManifest", manifest);

        if (conflicts) {
            return buildEnvelope.build("ArohaCounterOffer", agentDID, senderDID, Map.of(
                "capability",   matchedName,
                "revisedTerms", acceptedTerms,
                "csn",          csnReply
            ), corrId, privateKey);
        }

        return buildEnvelope.build("ArohaAccept", agentDID, senderDID, Map.of(
            "capability",    matchedName,
            "acceptedTerms", acceptedTerms,
            "csn",           csnReply
        ), corrId, privateKey);
    }

    private Map<String, Object> buildManifest() {
        var caps = registry.list().stream().map(e -> {
            var m = new LinkedHashMap<String, Object>();
            m.put("name",         e.name());
            m.put("description",  e.description());
            m.put("inputSchema",  e.inputSchema());
            m.put("outputSchema", e.outputSchema());
            m.put("supportsSaga", e.supportsSaga());
            return (Map<String, Object>) m;
        }).toList();
        return Map.of(
            "agentDID",     agentDID,
            "capabilities", caps,
            "generatedAt",  com.arohalabs.util.IsoTime.now()
        );
    }

    // ── Requestor: CapabilityNegotiator ──────────────────────────────────────

    /**
     * Requestor-side CSN negotiator.
     *
     * <pre>{@code
     * var negotiator = new CSNHandler.CapabilityNegotiator(
     *     sendFn, buildEnvFn, orchestratorDID, privateKey, new DiscoveryCache());
     * var result = negotiator.discover(
     *     "https://fx.example.com/aroha/v1", "did:aroha:fx-agent",
     *     new DiscoveryRequest("convert USD to JPY", desiredSchema, Map.of(), false));
     * }</pre>
     */
    public static final class CapabilityNegotiator {

        @FunctionalInterface
        public interface SendFn {
            Map<String, Object> send(String endpoint, Map<String, Object> envelope) throws Exception;
        }

        private final SendFn send;
        private final BuildEnvelopeFn buildEnvelope;
        private final String orchestratorDID;
        private final byte[] privateKey;
        private final DiscoveryCache cache;

        public CapabilityNegotiator(
            SendFn send,
            BuildEnvelopeFn buildEnvelope,
            String orchestratorDID,
            byte[] privateKey,
            DiscoveryCache cache
        ) {
            this.send            = send;
            this.buildEnvelope   = buildEnvelope;
            this.orchestratorDID = orchestratorDID;
            this.privateKey      = privateKey;
            this.cache           = cache != null ? cache : new DiscoveryCache();
        }

        @SuppressWarnings("unchecked")
        public DiscoveryResult discover(
            String agentEndpoint,
            String agentDID,
            DiscoveryRequest req
        ) throws Exception {
            String h = req.desiredSchema() != null ? schemaHash(req.desiredSchema()) : null;

            // ── 1. Cache lookup ───────────────────────────────────────────────
            if (h != null) {
                var cached = cache.get(agentDID, h);
                if (cached.isPresent()) {
                    var c = cached.get();
                    return new DiscoveryResult(c.capabilityName(), c.agreedSchema(),
                        Map.of(), "cache", c.compatibilityScore(), null, 0);
                }
            }

            // ── 2. ArohaNegotiate ──────────────────────────────────────────────
            var correlationId = "csn-" + System.nanoTime();
            var body = new LinkedHashMap<String, Object>();
            body.put("capability",    req.capabilityIntent() != null ? req.capabilityIntent() : "unknown");
            body.put("proposedTerms", req.proposedTerms() != null ? req.proposedTerms() : Map.of());
            var csnExt = new LinkedHashMap<String, Object>();
            csnExt.put("capabilityIntent",          req.capabilityIntent());
            csnExt.put("desiredSchema",              req.desiredSchema());
            csnExt.put("schemaHash",                 h);
            csnExt.put("requestCapabilityManifest",  req.requestCapabilityManifest());
            body.put("csn", csnExt);

            var envelope  = buildEnvelope.build("ArohaNegotiate", orchestratorDID, agentDID,
                body, correlationId, privateKey);
            var response  = send.send(agentEndpoint, envelope);

            if (response == null) throw new RuntimeException("No response from " + agentDID);

            var type     = (String) response.get("type");
            var respBody = (Map<String, Object>) response.get("body");

            if ("ArohaError".equals(type)) {
                throw new RuntimeException("CSN failed: " + respBody.get("message"));
            }

            // ── 3. ArohaAccept ─────────────────────────────────────────────────
            if ("ArohaAccept".equals(type)) {
                var csn       = (Map<String, Object>) respBody.getOrDefault("csn", Map.of());
                var resolved  = strVal(csn, "resolvedCapability", strVal(respBody, "capability", ""));
                var method    = strVal(csn, "matchMethod", "schema");
                var compat    = csn.getOrDefault("compatibilityScore", 0.0);
                var agreed    = (Map<String, Object>) csn.getOrDefault("agreedSchema", req.desiredSchema());
                if (h != null && agreed != null) {
                    cache.put(agentDID, h, resolved, agreed, method, ((Number) compat).doubleValue());
                }
                return new DiscoveryResult(
                    resolved, agreed,
                    (Map<String, Object>) respBody.getOrDefault("acceptedTerms", Map.of()),
                    method, ((Number) compat).doubleValue(),
                    (Map<String, Object>) csn.get("capabilityManifest"), 1
                );
            }

            // ── 4. Counter-offer ──────────────────────────────────────────────
            if ("ArohaCounterOffer".equals(type)) {
                var csn      = (Map<String, Object>) respBody.getOrDefault("csn", Map.of());
                var resolved = strVal(csn, "resolvedCapability", strVal(respBody, "capability", ""));
                if (!resolved.isEmpty()) {
                    var revised = (Map<String, Object>) respBody.getOrDefault("revisedTerms", Map.of());
                    var accBody = Map.of("capability", resolved, "acceptedTerms", revised);
                    var accEnv  = buildEnvelope.build("ArohaAccept", orchestratorDID, agentDID,
                        (Map<String, Object>) accBody, correlationId, privateKey);
                    send.send(agentEndpoint, accEnv);
                    var agreed = (Map<String, Object>) csn.getOrDefault("agreedSchema", req.desiredSchema());
                    if (h != null && agreed != null) cache.put(agentDID, h, resolved, agreed, "schema", 0);
                    return new DiscoveryResult(
                        resolved, agreed, revised, "schema", 0,
                        (Map<String, Object>) csn.get("capabilityManifest"), 2
                    );
                }
            }

            throw new RuntimeException("CSN negotiation with " + agentDID + " did not produce an agreement");
        }

        private static String strVal(Map<String, Object> m, String key, String fallback) {
            if (m == null) return fallback;
            var v = m.get(key);
            return (v instanceof String s && !s.isEmpty()) ? s : fallback;
        }
    }
}
