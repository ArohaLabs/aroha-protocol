// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

package com.arohalabs.transport;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Map;
import java.util.concurrent.CompletableFuture;

/**
 * Aroha Layer 0 — HTTP Client
 *
 * Sends Aroha envelopes to remote agents and fetches DID documents
 * from well-known endpoints.
 *
 * Uses Java 11+ built-in java.net.http.HttpClient (no external dependency).
 *
 * <p>Endpoints must be https, except loopback hosts (127.0.0.0/8, ::1,
 * localhost); see {@link Endpoints#requireSecure}. Construct with
 * {@code new ArohaClient(true)} to permit plain http to other hosts on a
 * network you control. Redirects are never followed.
 */
public final class ArohaClient {

    private final HttpClient http;
    private final boolean allowInsecureHttp;
    private final ObjectMapper mapper = new ObjectMapper();

    private static final Duration DEFAULT_TIMEOUT = Duration.ofSeconds(30);
    private static final TypeReference<Map<String, Object>> MAP_TYPE =
        new TypeReference<>() {};

    public ArohaClient() {
        this(false);
    }

    /** @param allowInsecureHttp permit plain http to non-loopback hosts */
    public ArohaClient(boolean allowInsecureHttp) {
        this.allowInsecureHttp = allowInsecureHttp;
        this.http = HttpClient.newBuilder()
            .connectTimeout(DEFAULT_TIMEOUT)
            .followRedirects(HttpClient.Redirect.NEVER)
            .build();
    }

    // ── Send ──────────────────────────────────────────────────────────────────

    /**
     * Sends a Aroha envelope to the given endpoint via HTTPS POST.
     *
     * @param endpoint  the agent's Aroha endpoint URL
     * @param envelope  the signed envelope map
     * @return the response envelope, or null if the server responded 202 (async accepted)
     * @throws Exception on HTTP error (4xx/5xx) or network failure
     */
    public Map<String, Object> send(String endpoint, Map<String, Object> envelope) throws Exception {
        return send(endpoint, envelope, DEFAULT_TIMEOUT);
    }

    public Map<String, Object> send(
            String endpoint,
            Map<String, Object> envelope,
            Duration timeout) throws Exception {

        byte[] body = mapper.writeValueAsBytes(envelope);

        HttpRequest req = HttpRequest.newBuilder()
            .uri(Endpoints.requireSecure(endpoint, allowInsecureHttp))
            .timeout(timeout)
            .header("Content-Type", "application/json")
            .POST(HttpRequest.BodyPublishers.ofByteArray(body))
            .build();

        HttpResponse<byte[]> resp = http.send(req, HttpResponse.BodyHandlers.ofByteArray());

        if (resp.statusCode() == 202) {
            return null;  // async — provider accepted, will stream result
        }
        if (resp.statusCode() >= 400) {
            throw new RuntimeException("Aroha endpoint returned HTTP " + resp.statusCode());
        }
        return mapper.readValue(resp.body(), MAP_TYPE);
    }

    /**
     * Async variant — returns a CompletableFuture.
     */
    public CompletableFuture<Map<String, Object>> sendAsync(
            String endpoint,
            Map<String, Object> envelope) throws Exception {

        byte[] body = mapper.writeValueAsBytes(envelope);

        HttpRequest req = HttpRequest.newBuilder()
            .uri(Endpoints.requireSecure(endpoint, allowInsecureHttp))
            .timeout(DEFAULT_TIMEOUT)
            .header("Content-Type", "application/json")
            .POST(HttpRequest.BodyPublishers.ofByteArray(body))
            .build();

        return http.sendAsync(req, HttpResponse.BodyHandlers.ofByteArray())
            .thenApply(resp -> {
                if (resp.statusCode() == 202) return null;
                if (resp.statusCode() >= 400) {
                    throw new RuntimeException("Aroha endpoint returned HTTP " + resp.statusCode());
                }
                try {
                    return mapper.readValue(resp.body(), MAP_TYPE);
                } catch (Exception e) {
                    throw new RuntimeException("Failed to parse response", e);
                }
            });
    }

    // ── DID Document Fetch ────────────────────────────────────────────────────

    /**
     * Fetches the DID Document from a well-known endpoint.
     *
     * @param baseUrl  agent's base URL, e.g. "https://agents.expedia.com"
     * @return the DID Document as a map
     */
    public Map<String, Object> fetchDIDDocument(String baseUrl) throws Exception {
        String url = baseUrl.replaceAll("/+$", "") + "/.well-known/aroha-agent.json";
        HttpRequest req = HttpRequest.newBuilder()
            .uri(Endpoints.requireSecure(url, allowInsecureHttp))
            .timeout(DEFAULT_TIMEOUT)
            .GET()
            .build();
        HttpResponse<byte[]> resp = http.send(req, HttpResponse.BodyHandlers.ofByteArray());
        if (resp.statusCode() != 200) {
            throw new RuntimeException("Could not fetch DID Document: HTTP " + resp.statusCode());
        }
        return mapper.readValue(resp.body(), MAP_TYPE);
    }
}
