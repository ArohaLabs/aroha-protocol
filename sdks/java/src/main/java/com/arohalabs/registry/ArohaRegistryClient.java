// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

package com.arohalabs.registry;

import com.arohalabs.crypto.Signing;
import com.arohalabs.identity.DID;
import com.arohalabs.identity.Kel;
import com.arohalabs.transport.Endpoints;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.bouncycastle.crypto.digests.KeccakDigest;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;

import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.*;

/**
 * Aroha Registry HTTP client — register / discover / resolve against the
 * registry REST API ({@code apps/registry-server}). Port of
 * {@code ArohaHttpRegistry} and {@code httpKelSource} in
 * {@code @aroha-sdk/registry} (http-registry.ts), with the request shapes of
 * Python's {@code aroha.hub}.
 *
 * <pre>
 *   POST   /v1/agents/challenge          one-time nonce for proof of key possession
 *   POST   /v1/agents                    register      → {"didHash": "0x…"} (201)
 *   GET    /v1/agents?capabilities=a,b   discover      → [AgentRecord…]
 *   GET    /v1/agents?limit=&amp;offset=     list          → [AgentRecord…]
 *   GET    /v1/agents/:didOrHash         resolve       → AgentRecord, 404 = unknown or not visible
 *   PUT    /v1/agents/:didHash/manifest  update manifest CID
 *   DELETE /v1/agents/:didHash           deactivate (owning API key only)
 *   GET    /v1/kel/:did                  Key Event Log ({@link #kelSource})
 * </pre>
 *
 * <p>Registration proves key possession: for every DID except a rotatable
 * {@code did:aroha:E…}, the client fetches a nonce and signs
 * {@code {"action":"prove-ownership","did":…,"nonce":…}} (exactly that key
 * order, as {@code JSON.stringify} writes it). An E-DID's key comes from its
 * Key Event Log instead, sent as {@code kel} or posted to /v1/kel first.
 *
 * <p>Transport: https only, except loopback, unless {@code allowInsecureHttp}
 * (the API key rides every request, and a resolved record decides which key
 * an agent is trusted under). Redirects are never followed. Fallback URLs are
 * tried in order on network errors and 5xx; a 4xx is the caller's mistake and
 * is thrown at once.
 */
public final class ArohaRegistryClient {

    /** The managed registry (same host as {@code AROHA_MANAGED_REGISTRY_URL} in TS and Python). */
    public static final String AROHA_MANAGED_REGISTRY_URL = "https://aroha-registry.aroha-labs.workers.dev";

    private static final Duration DEFAULT_TIMEOUT = Duration.ofSeconds(30);

    static final ObjectMapper MAPPER = new ObjectMapper()
        .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);

    private final List<String> urls;
    private final String apiKey;
    private final HttpClient http;
    private final Duration timeout;

    /** Constructor options. Every field optional except where noted. */
    public static final class Options {
        String baseUrl;
        List<String> fallbackUrls = List.of();
        String apiKey;
        boolean allowInsecureHttp;
        Duration timeout = DEFAULT_TIMEOUT;
        HttpClient httpClient;

        /** Default: {@code AROHA_REGISTRY_URL}, then {@link #AROHA_MANAGED_REGISTRY_URL}. */
        public Options baseUrl(String v) { baseUrl = v; return this; }
        /** Mirrors tried in order on a network error or 5xx. */
        public Options fallbackUrls(List<String> v) { fallbackUrls = v == null ? List.of() : List.copyOf(v); return this; }
        /** Bearer API key. Required for register / updateManifest / deactivate; optional for reads. */
        public Options apiKey(String v) { apiKey = v; return this; }
        /** DEVELOPMENT ONLY: permit http:// to non-loopback hosts. */
        public Options allowInsecureHttp(boolean v) { allowInsecureHttp = v; return this; }
        /** Per-request timeout. Default 30 s. */
        public Options timeout(Duration v) { timeout = v; return this; }
        /** Custom client (tests, proxies). Should not follow redirects. */
        public Options httpClient(HttpClient v) { httpClient = v; return this; }
    }

    /** Registration options (TS {@code RegisterOptions}). */
    public static final class RegisterOptions {
        String endpointUrl;
        Ed25519PrivateKeyParameters privateKey;
        ChallengeSigner signer;
        List<Map<String, Object>> kel;
        List<Map<String, Object>> controllerKel;
        String visibility;

        /** Where the agent receives Aroha messages. */
        public RegisterOptions endpointUrl(String v) { endpointUrl = v; return this; }
        /** The agent's key; signs the registration challenge. Must match the registered public key. */
        public RegisterOptions privateKey(Ed25519PrivateKeyParameters v) { privateKey = v; return this; }
        /** Alternative to privateKey: an external signer (HSM, KMS) returning a 64-byte Ed25519 signature. */
        public RegisterOptions signer(ChallengeSigner v) { signer = v; return this; }
        /** E-DIDs only: the agent's Key Event Log (omit if already posted to /v1/kel). */
        public RegisterOptions kel(List<Map<String, Object>> v) { kel = v; return this; }
        /** E-DIDs only: the controlling person's log. */
        public RegisterOptions controllerKel(List<Map<String, Object>> v) { controllerKel = v; return this; }
        /** "public" (default), "unlisted" or "private". */
        public RegisterOptions visibility(String v) { visibility = v; return this; }
    }

    /** Signs the registration challenge bytes; must return a 64-byte Ed25519 signature. */
    @FunctionalInterface
    public interface ChallengeSigner {
        byte[] sign(byte[] message) throws Exception;
    }

    /** An agent as the registry returns it ({@code toApiRecord} in routes/agents.ts). Unknown fields are ignored. */
    @JsonIgnoreProperties(ignoreUnknown = true)
    public record AgentRecord(
        String did,
        String didHash,
        String publishedBy,
        String ownerAddress,
        String manifestCID,
        String publicKeyB64,
        String stakedWei,
        Integer reputationScore,
        Boolean active,
        Long registeredAt,
        Long lastUpdatedAt,
        List<String> capabilityIds,
        String endpointUrl,
        Integer keyVersion,
        Long keyRotatedAt,
        Boolean verified,
        String verificationTier,
        String domain,
        Boolean orgSigned,
        String visibility
    ) {
        /**
         * The 32-byte key the registry holds for this agent (base64url or
         * base64), or null. This is the registry's word: for a content-addressed
         * DID prefer the key the DID encodes, for an E-DID its verified KEL.
         */
        public byte[] publicKey() {
            if (publicKeyB64 == null) return null;
            try {
                String s = publicKeyB64.replace('+', '-').replace('/', '_').replaceAll("=+$", "");
                byte[] k = Base64.getUrlDecoder().decode(s);
                return k.length == 32 ? k : null;
            } catch (IllegalArgumentException e) {
                return null;
            }
        }
    }

    /** A non-2xx answer from the registry. */
    public static final class RegistryHttpException extends IOException {
        private final int statusCode;
        private final String body;
        public RegistryHttpException(int statusCode, String body) {
            super("Aroha Registry HTTP " + statusCode + ": " + body);
            this.statusCode = statusCode;
            this.body = body;
        }
        public int statusCode() { return statusCode; }
        public String body() { return body; }
    }

    public ArohaRegistryClient(Options options) {
        Options o = options != null ? options : new Options();
        List<String> all = new ArrayList<>();
        all.add(resolveRegistryUrl(o.baseUrl));
        for (String f : o.fallbackUrls) all.add(stripTrailingSlash(f));
        for (String u : all) Endpoints.requireSecure(u, o.allowInsecureHttp);
        this.urls = List.copyOf(all);
        this.apiKey = o.apiKey;
        this.timeout = o.timeout != null ? o.timeout : DEFAULT_TIMEOUT;
        this.http = o.httpClient != null ? o.httpClient : HttpClient.newBuilder()
            .connectTimeout(this.timeout)
            .followRedirects(HttpClient.Redirect.NEVER)
            .build();
    }

    /** {@code override} → {@code AROHA_REGISTRY_URL} → {@link #AROHA_MANAGED_REGISTRY_URL}; no trailing slash. */
    public static String resolveRegistryUrl(String override) {
        String env = System.getenv("AROHA_REGISTRY_URL");
        String u = override != null && !override.isEmpty() ? override
            : env != null && !env.isEmpty() ? env : AROHA_MANAGED_REGISTRY_URL;
        return stripTrailingSlash(u);
    }

    private static String stripTrailingSlash(String u) {
        return u.replaceAll("/+$", "");
    }

    // ── Register ─────────────────────────────────────────────────────────────

    /** The bytes a registrant signs: {@code {"action":"prove-ownership","did":…,"nonce":…}}. */
    public static byte[] registrationChallengeMessage(String did, String nonce) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("action", "prove-ownership");
        m.put("did", did);
        m.put("nonce", nonce);
        return com.arohalabs.crypto.Jcs.stringify(m).getBytes(StandardCharsets.UTF_8);
    }

    /** True unless {@code did} is a rotatable {@code did:aroha:E…} (whose KEL binds the key instead). */
    public static boolean registrationNeedsProof(String did) {
        return !Kel.isInceptionDid(did);
    }

    /**
     * Register an agent. {@code publicKey} is its 32-byte Ed25519 key; a
     * content-addressed {@code did:aroha:z…} DID must encode exactly it. For
     * any DID but an E-DID, {@code options.privateKey} (or {@code signer}) is
     * required to answer the registration challenge. Returns the registry's
     * didHash.
     */
    public String register(String did, String manifestCID, byte[] publicKey, RegisterOptions options) throws IOException {
        RegisterOptions o = options != null ? options : new RegisterOptions();
        Objects.requireNonNull(did, "did");
        Objects.requireNonNull(manifestCID, "manifestCID");
        boolean needsProof = registrationNeedsProof(did);
        if (needsProof && o.privateKey == null && o.signer == null) {
            throw new IllegalArgumentException("ArohaRegistryClient.register(" + did + "): a privateKey or signer is required — "
                + "the registry only registers a DID whose key the caller proves it holds (POST /v1/agents/challenge)");
        }
        assertRegistrationKey(did, publicKey, o.privateKey);

        // The challenge is redeemable only at the server that issued it, so
        // each fallback attempt runs the whole exchange.
        return withFallback(base -> {
            Map<String, Object> body = new LinkedHashMap<>();
            body.put("did", did);
            body.put("manifestCID", manifestCID);
            if (publicKey != null) body.put("publicKeyB64", b64url(publicKey));
            if (o.endpointUrl != null) body.put("endpointUrl", o.endpointUrl);
            if (o.visibility != null) body.put("visibility", o.visibility);
            if (o.kel != null) body.put("kel", o.kel);
            if (o.controllerKel != null) body.put("controllerKel", o.controllerKel);
            if (needsProof) {
                Map<String, Object> ch = sendJson(base, "POST", "/v1/agents/challenge", Map.of("did", did), true);
                if (!(ch != null && ch.get("nonce") instanceof String nonce) || nonce.isEmpty()) {
                    throw new RegistryHttpException(502, "registry returned no challenge nonce");
                }
                byte[] sig = signChallenge(o, did, nonce);
                body.put("challengeNonce", nonce);
                body.put("challengeSignature", b64url(sig));
            }
            Map<String, Object> res = sendJson(base, "POST", "/v1/agents", body, true);
            Object h = res == null ? null : res.get("didHash");
            return h instanceof String s ? s : hashDID(did);
        });
    }

    private static byte[] signChallenge(RegisterOptions o, String did, String nonce) throws IOException {
        byte[] msg = registrationChallengeMessage(did, nonce);
        byte[] sig;
        try {
            sig = o.privateKey != null ? Signing.signBytes(msg, o.privateKey) : o.signer.sign(msg);
        } catch (Exception e) {
            throw new IOException("registration signer failed: " + e.getMessage(), e);
        }
        if (sig == null || sig.length != 64) {
            throw new IllegalArgumentException("Registration signer must return a 64-byte Ed25519 signature");
        }
        return sig;
    }

    private static void assertRegistrationKey(String did, byte[] publicKey, Ed25519PrivateKeyParameters privateKey) {
        if (publicKey == null) {
            if (registrationNeedsProof(did)) throw new IllegalArgumentException("publicKey is required");
            return; // an E-DID's key comes from its KEL
        }
        if (publicKey.length != 32) throw new IllegalArgumentException("publicKey must be a 32-byte Ed25519 public key");
        if (did.startsWith("did:aroha:z")) {
            byte[] encoded;
            try {
                encoded = DID.fromMultibase(did.substring("did:aroha:".length()));
            } catch (Exception e) {
                encoded = null;
            }
            if (encoded == null || !Arrays.equals(encoded, publicKey)) {
                throw new IllegalArgumentException(did + " is content-addressed and can only be registered with the key it encodes");
            }
        }
        if (privateKey != null && !Arrays.equals(privateKey.generatePublicKey().getEncoded(), publicKey)) {
            throw new IllegalArgumentException("Registration signer's private key does not match the publicKey being registered");
        }
    }

    // ── Update / deactivate ──────────────────────────────────────────────────

    /** Point an owned agent at a new manifest CID. */
    public void updateManifest(String did, String newManifestCID) throws IOException {
        String path = "/v1/agents/" + hashDID(did) + "/manifest";
        withFallback(base -> sendJson(base, "PUT", path, Map.of("manifestCID", newManifestCID), true));
    }

    /** Deactivate an owned agent. */
    public void deactivate(String did) throws IOException {
        String path = "/v1/agents/" + hashDID(did);
        withFallback(base -> sendJson(base, "DELETE", path, null, true));
    }

    // ── Resolve / discover ───────────────────────────────────────────────────

    /** Resolve by DID (sent as its keccak-256 didHash). Null on 404 — unknown, or private and not visible to you. */
    public AgentRecord resolveByDID(String did) throws IOException {
        return resolveByHash(hashDID(did));
    }

    /** Resolve by didHash ({@code 0x…}). Null on 404. */
    public AgentRecord resolveByHash(String didHash) throws IOException {
        String path = "/v1/agents/" + URLEncoder.encode(didHash, StandardCharsets.UTF_8);
        return withFallback(base -> {
            HttpResponse<String> res = send(base, "GET", path, null);
            if (res.statusCode() == 404) return null;
            if (res.statusCode() < 200 || res.statusCode() >= 300) throw new RegistryHttpException(res.statusCode(), res.body());
            return MAPPER.readValue(res.body(), AgentRecord.class);
        });
    }

    /**
     * Discover agents serving ALL of {@code capabilityIds} (TS
     * {@code queryByCapability}). Agents still in their post-registration
     * cooldown, unlisted agents and private agents you cannot see are not
     * returned by the registry.
     */
    public List<AgentRecord> queryByCapability(List<String> capabilityIds) throws IOException {
        StringJoiner j = new StringJoiner(",");
        for (String c : capabilityIds) j.add(encodeComponent(c));
        return listFrom("/v1/agents?capabilities=" + j);
    }

    /** Alias of {@link #queryByCapability}. */
    public List<AgentRecord> discover(List<String> capabilityIds) throws IOException {
        return queryByCapability(capabilityIds);
    }

    /** Browse agents. The registry clamps limit to [1, 100] (default 50) and offset to ≥ 0. */
    public List<AgentRecord> listAgents(int limit, int offset) throws IOException {
        return listFrom("/v1/agents?limit=" + limit + "&offset=" + offset);
    }

    private List<AgentRecord> listFrom(String path) throws IOException {
        return withFallback(base -> {
            HttpResponse<String> res = send(base, "GET", path, null);
            if (res.statusCode() < 200 || res.statusCode() >= 300) throw new RegistryHttpException(res.statusCode(), res.body());
            return MAPPER.readValue(res.body(), new TypeReference<List<AgentRecord>>() {});
        });
    }

    // ── KEL source ───────────────────────────────────────────────────────────

    /**
     * A {@link Kel.KelSource} backed by GET /v1/kel/:did (TS {@code httpKelSource}).
     * 200 → the events (the CALLER re-verifies them: a registry can withhold
     * a log, never forge one); 404 → null; 409 (recorded duplicity, or a log
     * the registry knows is stale) → throws, so a verifier fails closed;
     * other 4xx → throws; network error / 5xx → next fallback, then throws.
     */
    public Kel.KelSource kelSource() {
        return did -> withFallback(base -> {
            HttpResponse<String> res = send(base, "GET", "/v1/kel/" + encodeComponent(did), null);
            if (res.statusCode() == 404) return null;
            if (res.statusCode() < 200 || res.statusCode() >= 300) throw new RegistryHttpException(res.statusCode(), res.body());
            Map<String, Object> body = MAPPER.readValue(res.body(), new TypeReference<Map<String, Object>>() {});
            if (body.containsKey("did") && !did.equals(body.get("did"))) {
                throw new IOException("registry answered GET /v1/kel for " + body.get("did") + ", not " + did);
            }
            if (!(body.get("events") instanceof List<?> events)) throw new IOException("registry returned no events array for " + did);
            List<Map<String, Object>> out = new ArrayList<>();
            for (Object e : events) {
                if (!(e instanceof Map<?, ?>)) throw new IOException("registry returned a malformed event for " + did);
                @SuppressWarnings("unchecked") Map<String, Object> m = (Map<String, Object>) e;
                out.add(m);
            }
            return out;
        });
    }

    // ── didHash ──────────────────────────────────────────────────────────────

    /** keccak-256 of the DID's UTF-8 bytes, {@code 0x}-prefixed lowercase hex — the registry's didHash. */
    public static String hashDID(String did) {
        byte[] in = did.getBytes(StandardCharsets.UTF_8);
        KeccakDigest k = new KeccakDigest(256);
        k.update(in, 0, in.length);
        byte[] out = new byte[32];
        k.doFinal(out, 0);
        return "0x" + HexFormat.of().formatHex(out);
    }

    // ── HTTP ─────────────────────────────────────────────────────────────────

    @FunctionalInterface
    private interface Attempt<T> {
        T run(String baseUrl) throws IOException, InterruptedException;
    }

    private <T> T withFallback(Attempt<T> fn) throws IOException {
        IOException last = null;
        for (String base : urls) {
            try {
                return fn.run(base);
            } catch (RegistryHttpException e) {
                if (e.statusCode() >= 400 && e.statusCode() < 500) throw e;
                last = e;
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new IOException("interrupted", e);
            } catch (IOException e) {
                last = e;
            }
        }
        throw last != null ? last : new IOException("no registry URL");
    }

    /** Send and require 2xx; returns the parsed JSON object body, or null when the body is empty. */
    private Map<String, Object> sendJson(String base, String method, String path, Object body, boolean auth)
            throws IOException, InterruptedException {
        if (auth && (apiKey == null || apiKey.isEmpty())) {
            throw new IllegalStateException("an API key is required for " + method + " " + path);
        }
        HttpResponse<String> res = send(base, method, path, body);
        if (res.statusCode() < 200 || res.statusCode() >= 300) throw new RegistryHttpException(res.statusCode(), res.body());
        String b = res.body();
        if (b == null || b.isBlank()) return null;
        Object parsed = MAPPER.readValue(b, Object.class);
        @SuppressWarnings("unchecked") Map<String, Object> m = parsed instanceof Map<?, ?> ? (Map<String, Object>) parsed : null;
        return m;
    }

    private HttpResponse<String> send(String base, String method, String path, Object body)
            throws IOException, InterruptedException {
        HttpRequest.Builder b = HttpRequest.newBuilder()
            .uri(URI.create(base + path))
            .timeout(timeout)
            .header("Accept", "application/json");
        if (apiKey != null && !apiKey.isEmpty()) b.header("Authorization", "Bearer " + apiKey);
        if (body != null) {
            b.header("Content-Type", "application/json");
            b.method(method, HttpRequest.BodyPublishers.ofByteArray(MAPPER.writeValueAsBytes(body)));
        } else {
            b.method(method, HttpRequest.BodyPublishers.noBody());
        }
        HttpResponse<String> res = http.send(b.build(), HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
        if (res.statusCode() >= 500) throw new RegistryHttpException(res.statusCode(), res.body());
        return res;
    }

    /** encodeURIComponent. */
    private static String encodeComponent(String s) {
        return URLEncoder.encode(s, StandardCharsets.UTF_8)
            .replace("+", "%20").replace("%21", "!").replace("%27", "'")
            .replace("%28", "(").replace("%29", ")").replace("%7E", "~");
    }

    private static String b64url(byte[] b) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(b);
    }
}
