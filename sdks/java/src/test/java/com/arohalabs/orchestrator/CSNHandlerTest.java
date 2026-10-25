// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

package com.arohalabs.orchestrator;

import com.arohalabs.orchestrator.CSNHandler.CapabilityEntry;
import com.arohalabs.orchestrator.CSNHandler.CapabilityRegistry;
import org.junit.jupiter.api.Test;

import java.util.*;

import static org.junit.jupiter.api.Assertions.*;

/**
 * The CSN fix: a requester's proposedTerms used to be written over the
 * provider's price and SLA and returned as a signed ArohaAccept. A proposal
 * that changes a provider term now gets an ArohaCounterOffer with the
 * provider's own terms.
 */
class CSNHandlerTest {

    static final String PROVIDER = "did:aroha:fx-agent";
    static final String REQUESTER = "did:aroha:orchestrator";

    /** Records every envelope "built", without signing. */
    static final class Recorder implements CSNHandler.BuildEnvelopeFn {
        final List<Map<String, Object>> built = new ArrayList<>();
        @Override
        public Map<String, Object> build(String type, String from, String to, Map<String, Object> body,
                                         String correlationId, byte[] privateKey) {
            Map<String, Object> env = new LinkedHashMap<>();
            env.put("type", type);
            env.put("from", from);
            env.put("to", to);
            env.put("body", body);
            env.put("correlationId", correlationId);
            built.add(env);
            return env;
        }
    }

    static CSNHandler provider(Recorder rec) {
        CapabilityRegistry reg = new CapabilityRegistry();
        Map<String, Object> input = Map.of(
            "type", "object",
            "properties", Map.of("from", Map.of("type", "string"), "to", Map.of("type", "string"),
                "amount", Map.of("type", "number")),
            "required", List.of("from", "to", "amount"));
        reg.register(new CapabilityEntry("fx-convert", "Convert currency", input, null, true,
            Map.of("amount", 0.5, "currency", "USD"), Map.of("p95LatencyMs", 800)));
        return new CSNHandler(reg, PROVIDER, new byte[32], rec, null);
    }

    static Map<String, Object> negotiate(Map<String, Object> proposedTerms) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("capability", "fx-convert");
        body.put("proposedTerms", proposedTerms);
        body.put("csn", Map.of("capabilityIntent", "convert USD to JPY"));
        return Map.of("type", "ArohaNegotiate", "body", body, "correlationId", "corr-1");
    }

    @SuppressWarnings("unchecked")
    static Map<String, Object> body(Map<String, Object> env) {
        return (Map<String, Object>) env.get("body");
    }

    @Test
    void proposalThatChangesTheProviderPriceGetsACounterOffer() throws Exception {
        Map<String, Object> reply = provider(new Recorder())
            .handle(negotiate(Map.of("price", Map.of("amount", 0, "currency", "USD"))), REQUESTER);
        assertEquals("ArohaCounterOffer", reply.get("type"));
        @SuppressWarnings("unchecked") Map<String, Object> revised = (Map<String, Object>) body(reply).get("revisedTerms");
        assertEquals(Map.of("amount", 0.5, "currency", "USD"), revised.get("price"), "the provider's price, not the proposal");
        assertEquals(Map.of("p95LatencyMs", 800), revised.get("sla"));
        assertFalse(body(reply).containsKey("acceptedTerms"));
    }

    @Test
    void proposalMatchingProviderTermsIsAccepted() throws Exception {
        Map<String, Object> reply = provider(new Recorder())
            .handle(negotiate(Map.of("price", Map.of("amount", 0.5, "currency", "USD"))), REQUESTER);
        assertEquals("ArohaAccept", reply.get("type"));
    }

    @Test
    void proposalMayAddTermsTheProviderLeftOpen() throws Exception {
        Map<String, Object> reply = provider(new Recorder())
            .handle(negotiate(Map.of("deliveryWindow", "24h")), REQUESTER);
        assertEquals("ArohaAccept", reply.get("type"));
        @SuppressWarnings("unchecked") Map<String, Object> accepted = (Map<String, Object>) body(reply).get("acceptedTerms");
        assertEquals("24h", accepted.get("deliveryWindow"));
        assertEquals(Map.of("amount", 0.5, "currency", "USD"), accepted.get("price"));
    }

    @Test
    void unknownCapabilityIsAnError() throws Exception {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("capability", "teleport");
        body.put("csn", Map.of());
        Map<String, Object> reply = provider(new Recorder()).handle(Map.of("body", body), REQUESTER);
        assertEquals("ArohaError", reply.get("type"));
        assertEquals("Aroha_UNKNOWN_CAPABILITY", body(reply).get("code"));
    }

    @Test
    void negotiatorAcceptsACounterOfferOnTheProvidersTerms() throws Exception {
        Recorder providerRec = new Recorder();
        CSNHandler handler = provider(providerRec);
        Recorder requesterRec = new Recorder();
        List<Map<String, Object>> sent = new ArrayList<>();
        CSNHandler.CapabilityNegotiator negotiator = new CSNHandler.CapabilityNegotiator(
            (endpoint, env) -> {
                sent.add(env);
                return "ArohaNegotiate".equals(env.get("type")) ? handler.handle(env, REQUESTER) : null;
            },
            requesterRec, REQUESTER, new byte[32], null);

        Map<String, Object> desired = Map.of("input", Map.of("type", "object",
            "properties", Map.of("from", Map.of("type", "string"), "to", Map.of("type", "string"),
                "amount", Map.of("type", "integer")),
            "required", List.of("from", "to", "amount")));
        var result = negotiator.discover("https://fx.example/aroha/v1", PROVIDER,
            new CSNHandler.DiscoveryRequest("fx-convert", desired, Map.of("price", Map.of("amount", 0.01)), false));

        assertEquals("fx-convert", result.resolvedCapability());
        assertEquals(2, result.rounds());
        assertEquals(Map.of("amount", 0.5, "currency", "USD"), result.agreedTerms().get("price"));
        assertEquals("ArohaAccept", sent.get(sent.size() - 1).get("type"));
    }

    @Test
    void schemaScoringAndCaching() {
        Map<String, Object> want = Map.of("properties", Map.of("a", Map.of("type", "integer")), "required", List.of("a"));
        Map<String, Object> have = Map.of("properties", Map.of("a", Map.of("type", "number")));
        assertEquals(0.7, CSNHandler.schemaCompatibilityScore(want, have), 1e-9);
        assertEquals(CSNHandler.schemaHash(Map.of("b", 1, "a", 2)), CSNHandler.schemaHash(new TreeMap<>(Map.of("a", 2, "b", 1))));
    }
}
