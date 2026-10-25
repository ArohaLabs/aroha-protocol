// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

package com.arohalabs.transport;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import com.arohalabs.messages.ArohaEnvelope;
import com.arohalabs.messages.DevMode;
import com.arohalabs.messages.NonceRegistry;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.concurrent.Executors;
import java.util.function.Consumer;
import java.util.function.Function;

/**
 * Aroha Layer 0 — HTTP Server
 *
 * Exposes two endpoints:
 *   GET  /.well-known/aroha-agent.json  → returns the DID Document
 *   POST /aroha/v1                       → validates + dispatches incoming envelopes
 *
 * Uses the JDK built-in com.sun.net.httpserver (no extra dependency).
 * For production TLS termination, put this behind nginx / Caddy / a cloud LB.
 *
 * <p>Binds {@value #DEFAULT_HOST} (loopback) unless a host is given; request
 * bodies over {@link #DEFAULT_MAX_BODY_BYTES} (1 MiB) are answered 413.
 */
public final class ArohaServer {

    /** Default bind address: loopback only. */
    public static final String DEFAULT_HOST = "127.0.0.1";
    /** Default request body cap (1 MiB). */
    public static final int DEFAULT_MAX_BODY_BYTES = 1 << 20;

    private final String host;
    private final int maxBodyBytes;
    private final int port;
    private final Map<String, Object> didDocument;
    private final String myDid;
    private final Function<String, Ed25519PublicKeyParameters> publicKeyResolver;
    private final NonceRegistry nonceRegistry;
    private final MessageHandler handler;
    private final boolean devMode;
    private final ObjectMapper mapper = new ObjectMapper();

    private HttpServer server;

    /**
     * @param port               TCP port to listen on
     * @param didDocument        this agent's DID Document (served at well-known)
     * @param myDid              this agent's DID (for recipient validation)
     * @param publicKeyResolver  resolves a "from" DID to its Ed25519 public key
     * @param nonceRegistry      shared nonce registry for replay prevention
     * @param handler            application callback for valid envelopes
     */
    public ArohaServer(
            int port,
            Map<String, Object> didDocument,
            String myDid,
            Function<String, Ed25519PublicKeyParameters> publicKeyResolver,
            NonceRegistry nonceRegistry,
            MessageHandler handler) {
        this(port, didDocument, myDid, publicKeyResolver, nonceRegistry, handler, false);
    }

    /**
     * @param devMode  when true, skip ALL cryptographic validation (signature,
     *                 nonce replay, expiry). Intended for local development and
     *                 hackathons — never pass true in production. Refused
     *                 ({@link DevMode.NotPermittedException}) unless the
     *                 environment sets {@code AROHA_DEV_MODE=1}; a warning is
     *                 printed to stderr once when on. Flip to false and the
     *                 full zero-trust pipeline re-engages with no handler code
     *                 changes required.
     */
    public ArohaServer(
            int port,
            Map<String, Object> didDocument,
            String myDid,
            Function<String, Ed25519PublicKeyParameters> publicKeyResolver,
            NonceRegistry nonceRegistry,
            MessageHandler handler,
            boolean devMode) {
        this(DEFAULT_HOST, port, didDocument, myDid, publicKeyResolver, nonceRegistry, handler, devMode,
            DEFAULT_MAX_BODY_BYTES);
    }

    /**
     * @param host          interface to bind; {@code null} = {@value #DEFAULT_HOST}.
     *                      Use {@code "0.0.0.0"} to accept remote connections.
     * @param maxBodyBytes  request body cap; larger bodies get 413. {@code <= 0} = 1 MiB.
     */
    public ArohaServer(
            String host,
            int port,
            Map<String, Object> didDocument,
            String myDid,
            Function<String, Ed25519PublicKeyParameters> publicKeyResolver,
            NonceRegistry nonceRegistry,
            MessageHandler handler,
            boolean devMode,
            int maxBodyBytes) {
        if (devMode) DevMode.require("ArohaServer devMode");
        this.host = host == null || host.isEmpty() ? DEFAULT_HOST : host;
        this.maxBodyBytes = maxBodyBytes <= 0 ? DEFAULT_MAX_BODY_BYTES : maxBodyBytes;
        this.port = port;
        this.didDocument = didDocument;
        this.myDid = myDid;
        this.publicKeyResolver = publicKeyResolver;
        this.nonceRegistry = nonceRegistry;
        this.handler = handler;
        this.devMode = devMode;
    }

    // ── Lifecycle ─────────────────────────────────────────────────────────────

    public void start() throws IOException {
        server = HttpServer.create(new InetSocketAddress(host, port), 0);
        server.createContext("/.well-known/aroha-agent.json", this::handleWellKnown);
        server.createContext("/aroha/v1", this::handleAroha);
        server.setExecutor(Executors.newVirtualThreadPerTaskExecutor());
        server.start();
    }

    public void stop() {
        if (server != null) server.stop(0);
    }

    /** The bound address once started (useful with port 0), else the configured one. */
    public InetSocketAddress address() {
        return server != null ? server.getAddress() : new InetSocketAddress(host, port);
    }

    // ── Handlers ──────────────────────────────────────────────────────────────

    private void handleWellKnown(HttpExchange ex) throws IOException {
        if (!"GET".equals(ex.getRequestMethod())) {
            ex.sendResponseHeaders(405, -1);
            return;
        }
        byte[] body = mapper.writeValueAsBytes(didDocument);
        ex.getResponseHeaders().add("Content-Type", "application/json");
        ex.sendResponseHeaders(200, body.length);
        try (OutputStream os = ex.getResponseBody()) {
            os.write(body);
        }
    }

    private void handleAroha(HttpExchange ex) throws IOException {
        if (!"POST".equals(ex.getRequestMethod())) {
            ex.sendResponseHeaders(405, -1);
            return;
        }

        String declared = ex.getRequestHeaders().getFirst("Content-Length");
        if (declared != null) {
            try {
                if (Long.parseLong(declared.trim()) > maxBodyBytes) {
                    sendError(ex, 413, "Payload too large");
                    return;
                }
            } catch (NumberFormatException ignored) {
                // fall through to the bounded read
            }
        }
        byte[] requestBody;
        try (InputStream in = ex.getRequestBody()) {
            requestBody = in.readNBytes(maxBodyBytes + 1);
        }
        if (requestBody.length > maxBodyBytes) {
            sendError(ex, 413, "Payload too large");
            return;
        }

        Map<String, Object> envelope;
        try {
            envelope = mapper.readValue(requestBody, new TypeReference<>() {});
        } catch (Exception e) {
            sendError(ex, 400, "Invalid JSON");
            return;
        }

        // ── Dev mode: skip all crypto — localhost / hackathon mode ────────────
        if (devMode) {
            dispatch(ex, envelope);
            return;
        }

        // Resolve sender public key
        String fromDid = (String) envelope.get("from");
        Ed25519PublicKeyParameters senderKey = publicKeyResolver.apply(fromDid);
        if (senderKey == null) {
            sendError(ex, 403, "Unknown sender: " + fromDid);
            return;
        }

        // Validate envelope
        ArohaEnvelope.ValidationResult result;
        try {
            result = ArohaEnvelope.validate(envelope, senderKey, myDid, nonceRegistry);
        } catch (Exception e) {
            sendError(ex, 400, "Validation error: " + e.getMessage());
            return;
        }

        if (!result.valid()) {
            sendError(ex, 400, result.reason());
            return;
        }

        dispatch(ex, envelope);
    }

    @SuppressWarnings("unchecked")
    private void dispatch(HttpExchange ex, Map<String, Object> envelope) throws IOException {
        try {
            Map<String, Object>[] responseHolder = new Map[]{null};

            handler.handle(
                envelope,
                response -> responseHolder[0] = response,
                streamEvent -> { /* WebSocket streaming not supported in this minimal impl */ }
            );

            if (responseHolder[0] != null) {
                byte[] body = mapper.writeValueAsBytes(responseHolder[0]);
                ex.getResponseHeaders().add("Content-Type", "application/json");
                ex.sendResponseHeaders(200, body.length);
                try (OutputStream os = ex.getResponseBody()) {
                    os.write(body);
                }
            } else {
                ex.sendResponseHeaders(202, -1);  // async accepted
            }
        } catch (Exception e) {
            sendError(ex, 500, "Handler error: " + e.getMessage());
        }
    }

    private void sendError(HttpExchange ex, int status, String message) throws IOException {
        byte[] body = ("{\"error\":\"" + message.replace("\"", "'") + "\"}").getBytes(StandardCharsets.UTF_8);
        ex.getResponseHeaders().add("Content-Type", "application/json");
        ex.sendResponseHeaders(status, body.length);
        try (OutputStream os = ex.getResponseBody()) {
            os.write(body);
        }
    }

    // ── Handler Interface ─────────────────────────────────────────────────────

    /**
     * Application callback interface for handling valid Aroha messages.
     * {@code handle(envelope, respond, streamEvent)} receives the validated,
     * signed envelope; call {@code respond} with a response envelope to reply
     * synchronously, and {@code streamEvent} with stream events (ArohaStream).
     */
    @FunctionalInterface
    public interface MessageHandler {
        void handle(
            Map<String, Object> envelope,
            Consumer<Map<String, Object>> respond,
            Consumer<Map<String, Object>> streamEvent
        ) throws Exception;
    }
}
