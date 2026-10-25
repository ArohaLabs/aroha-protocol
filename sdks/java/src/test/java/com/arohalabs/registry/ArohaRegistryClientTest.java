// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

package com.arohalabs.registry;

import com.arohalabs.TestSupport;
import com.arohalabs.crypto.Jcs;
import com.arohalabs.crypto.Signing;
import com.arohalabs.identity.DID;
import com.arohalabs.identity.Kel;
import com.arohalabs.registry.ArohaRegistryClient.AgentRecord;
import com.arohalabs.registry.ArohaRegistryClient.Options;
import com.arohalabs.registry.ArohaRegistryClient.RegisterOptions;
import com.arohalabs.registry.ArohaRegistryClient.RegistryHttpException;
import com.arohalabs.transport.Endpoints;
import com.fasterxml.jackson.core.type.TypeReference;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.*;

/**
 * The client against an in-process registry that reproduces the request
 * checks and response shapes of apps/registry-server/src/routes/agents.ts
 * and kel.ts: Bearer auth on writes, one-time challenge nonces bound to the
 * API key, the prove-ownership signature, the z-DID key rule, 201
 * {@code {didHash}}, a bare JSON array for list/discover, 404
 * {@code {"error":"Not found"}}, {@code {did, events, sequence}} for KELs and
 * 409 for a recorded duplicity.
 */
class ArohaRegistryClientTest {

    static final String API_KEY = "ak_test_123";

    FakeRegistry registry;
    HttpServer server;
    String baseUrl;

    @BeforeEach
    void start() throws IOException {
        registry = new FakeRegistry();
        server = registry.start(0);
        baseUrl = "http://127.0.0.1:" + server.getAddress().getPort();
    }

    @AfterEach
    void stop() {
        server.stop(0);
    }

    ArohaRegistryClient client() {
        return new ArohaRegistryClient(new Options().baseUrl(baseUrl).apiKey(API_KEY));
    }

    @Test
    void hashDidMatchesTheRegistry() {
        // Reference values from @noble/hashes keccak_256 (what the registry server uses).
        assertEquals("0xdda3c6d62b88602cd572ce0afb443a240b65de6acac7c8dec80e6bf8d587086b", ArohaRegistryClient.hashDID("did:aroha:test"));
        assertEquals("0x5e62bd31691efcfc1cf70e5bed68b23f68db2e10457748be79aa872f94998eb5", ArohaRegistryClient.hashDID("did:aroha:café"));
    }

    @Test
    void challengeMessageIsJsonStringifyInKeyOrder() {
        assertEquals("{\"action\":\"prove-ownership\",\"did\":\"did:aroha:x\",\"nonce\":\"n-1\"}",
            new String(ArohaRegistryClient.registrationChallengeMessage("did:aroha:x", "n-1"), StandardCharsets.UTF_8));
    }

    @Test
    void registerResolveDiscoverUpdateDeactivate() throws Exception {
        Ed25519PrivateKeyParameters key = TestSupport.seed(7);
        byte[] pub = TestSupport.pub(key);
        String did = DID.generateDid(pub);
        ArohaRegistryClient c = client();

        String didHash = c.register(did, "bafy-manifest-1", pub,
            new RegisterOptions().privateKey(key).endpointUrl("https://agent.example/aroha"));
        assertEquals(ArohaRegistryClient.hashDID(did), didHash);
        assertEquals(1, registry.challengesIssued.get());

        AgentRecord r = c.resolveByDID(did);
        assertNotNull(r);
        assertEquals(did, r.did());
        assertEquals(didHash, r.didHash());
        assertEquals("bafy-manifest-1", r.manifestCID());
        assertEquals("https://agent.example/aroha", r.endpointUrl());
        assertArrayEquals(pub, r.publicKey());
        assertEquals(5000, r.reputationScore());
        assertEquals("0", r.stakedWei());
        assertEquals("community", r.verificationTier());
        assertEquals(List.of("search", "book-flight"), r.capabilityIds());
        assertEquals(didHash, c.resolveByHash(didHash).didHash());
        assertNull(c.resolveByDID("did:aroha:zNobody"));

        // discover: the registry's AND-match on capabilities
        assertEquals(1, c.queryByCapability(List.of("search")).size());
        assertEquals(1, c.discover(List.of("search", "book-flight")).size());
        assertEquals(0, c.queryByCapability(List.of("search", "pay")).size());
        assertEquals(1, c.listAgents(10, 0).size());
        assertEquals(0, c.listAgents(10, 1).size());

        // a second registration of the same DID is a 409 (thrown, not retried)
        RegistryHttpException dup = assertThrows(RegistryHttpException.class,
            () -> c.register(did, "bafy-2", pub, new RegisterOptions().privateKey(key)));
        assertEquals(409, dup.statusCode());

        c.updateManifest(did, "bafy-manifest-2");
        assertEquals("bafy-manifest-2", c.resolveByDID(did).manifestCID());

        c.deactivate(did);
        assertFalse(c.resolveByDID(did).active());
        RegistryHttpException gone = assertThrows(RegistryHttpException.class, () -> c.deactivate("did:aroha:zNobody"));
        assertEquals(404, gone.statusCode());
    }

    @Test
    void externalSignerAndBadSignerAreHandled() throws Exception {
        Ed25519PrivateKeyParameters key = TestSupport.seed(8);
        byte[] pub = TestSupport.pub(key);
        String did = DID.generateDid(pub);
        ArohaRegistryClient c = client();

        // A signer holding the wrong key: the server's signature check refuses it.
        Ed25519PrivateKeyParameters other = TestSupport.seed(9);
        RegistryHttpException ex = assertThrows(RegistryHttpException.class, () -> c.register(did, "bafy", pub,
            new RegisterOptions().signer(msg -> Signing.signBytes(msg, other))));
        assertEquals(403, ex.statusCode());

        assertNotNull(c.register(did, "bafy", pub, new RegisterOptions().signer(msg -> Signing.signBytes(msg, key))));
    }

    @Test
    void clientSideKeyChecks() {
        Ed25519PrivateKeyParameters key = TestSupport.seed(7);
        byte[] pub = TestSupport.pub(key);
        String did = DID.generateDid(pub);
        ArohaRegistryClient c = client();
        // no proof material
        assertThrows(IllegalArgumentException.class, () -> c.register(did, "bafy", pub, null));
        // z-DID encodes a different key
        assertThrows(IllegalArgumentException.class, () -> c.register(did, "bafy", TestSupport.pub(TestSupport.seed(3)),
            new RegisterOptions().privateKey(TestSupport.seed(3))));
        // private key does not match publicKey
        assertThrows(IllegalArgumentException.class, () -> c.register("did:aroha:named", "bafy", pub,
            new RegisterOptions().privateKey(TestSupport.seed(3))));
        assertEquals(0, registry.challengesIssued.get());
    }

    @Test
    void writesNeedAnApiKeyReadsDoNot() throws Exception {
        ArohaRegistryClient anon = new ArohaRegistryClient(new Options().baseUrl(baseUrl));
        Ed25519PrivateKeyParameters key = TestSupport.seed(7);
        byte[] pub = TestSupport.pub(key);
        assertThrows(IllegalStateException.class,
            () -> anon.register(DID.generateDid(pub), "bafy", pub, new RegisterOptions().privateKey(key)));
        assertEquals(List.of(), anon.listAgents(50, 0));

        // A wrong key is the server's 401.
        ArohaRegistryClient wrong = new ArohaRegistryClient(new Options().baseUrl(baseUrl).apiKey("nope"));
        assertEquals(401, assertThrows(RegistryHttpException.class,
            () -> wrong.register(DID.generateDid(pub), "bafy", pub, new RegisterOptions().privateKey(key))).statusCode());
    }

    @Test
    void rotatableEDidRegistersWithItsKelAndNoChallenge() throws Exception {
        Ed25519PrivateKeyParameters key = TestSupport.seed(20), next = TestSupport.seed(21);
        Map<String, Object> inception = new LinkedHashMap<>();
        inception.put("v", 1);
        inception.put("type", "inception");
        inception.put("kind", "agent");
        inception.put("keys", List.of(DID.toMultibase(TestSupport.pub(key))));
        inception.put("nextKeyDigest", Kel.keyDigest(TestSupport.pub(next)));
        inception.put("createdAt", "2026-10-01T00:00:00.000Z");
        inception.put("sig", Base64.getUrlEncoder().withoutPadding().encodeToString(
            Signing.signBytes(Jcs.canonicalizeToBytes(inception), key)));
        String did = Kel.didFromInception(inception);
        assertFalse(ArohaRegistryClient.registrationNeedsProof(did));

        ArohaRegistryClient c = client();
        c.register(did, "bafy-e", null, new RegisterOptions().kel(List.of(inception)));
        assertEquals(0, registry.challengesIssued.get());
        assertArrayEquals(TestSupport.pub(key), c.resolveByDID(did).publicKey());

        // …and its KEL comes back through the client's KelSource, verifiable.
        List<Map<String, Object>> events = c.kelSource().fetch(did);
        assertEquals(1, events.size());
        assertArrayEquals(TestSupport.pub(key), Kel.verifyKel(did, events).currentKey);
        assertNull(c.kelSource().fetch("did:aroha:Eunknown"));

        registry.duplicity.add(did);
        Exception dup = assertThrows(RegistryHttpException.class, () -> c.kelSource().fetch(did));
        assertEquals(409, ((RegistryHttpException) dup).statusCode());
    }

    @Test
    void fallbackOn5xxButNotOn4xx() throws Exception {
        AtomicInteger hits = new AtomicInteger();
        HttpServer failing = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        failing.createContext("/", ex -> {
            hits.incrementAndGet();
            FakeRegistry.reply(ex, 503, Map.of("error", "down"));
        });
        failing.start();
        HttpServer refusing = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        refusing.createContext("/", ex -> FakeRegistry.reply(ex, 400, Map.of("error", "bad request")));
        refusing.start();
        try {
            String failingUrl = "http://127.0.0.1:" + failing.getAddress().getPort();
            String refusingUrl = "http://127.0.0.1:" + refusing.getAddress().getPort();
            Ed25519PrivateKeyParameters key = TestSupport.seed(7);
            byte[] pub = TestSupport.pub(key);

            ArohaRegistryClient c = new ArohaRegistryClient(new Options().baseUrl(failingUrl + "/")
                .fallbackUrls(List.of(baseUrl)).apiKey(API_KEY));
            assertNotNull(c.register(DID.generateDid(pub), "bafy", pub, new RegisterOptions().privateKey(key)));
            assertEquals(1, c.listAgents(50, 0).size());
            assertTrue(hits.get() >= 2);

            ArohaRegistryClient c4 = new ArohaRegistryClient(new Options().baseUrl(refusingUrl)
                .fallbackUrls(List.of(baseUrl)).apiKey(API_KEY));
            assertEquals(400, assertThrows(RegistryHttpException.class, () -> c4.listAgents(50, 0)).statusCode());

            ArohaRegistryClient allDown = new ArohaRegistryClient(new Options().baseUrl(failingUrl).apiKey(API_KEY));
            assertEquals(503, assertThrows(RegistryHttpException.class, () -> allDown.listAgents(50, 0)).statusCode());
        } finally {
            failing.stop(0);
            refusing.stop(0);
        }
    }

    @Test
    void refusesPlainHttpToARemoteHost() {
        assertThrows(Endpoints.InsecureEndpointException.class,
            () -> new ArohaRegistryClient(new Options().baseUrl("http://registry.example.com")));
        assertThrows(Endpoints.InsecureEndpointException.class,
            () -> new ArohaRegistryClient(new Options().baseUrl("https://ok.example").fallbackUrls(List.of("http://mirror.example"))));
        assertDoesNotThrow(() -> new ArohaRegistryClient(new Options().baseUrl("http://registry.example.com").allowInsecureHttp(true)));
        assertEquals("https://r.example", ArohaRegistryClient.resolveRegistryUrl("https://r.example///"));
    }

    // ── In-process registry ──────────────────────────────────────────────────

    static final class FakeRegistry {
        final Map<String, Map<String, Object>> agents = new ConcurrentHashMap<>();
        final Map<String, String[]> challenges = new ConcurrentHashMap<>(); // nonce → {did, apiKey}
        final Map<String, List<Map<String, Object>>> kels = new ConcurrentHashMap<>();
        final Set<String> duplicity = ConcurrentHashMap.newKeySet();
        final AtomicInteger challengesIssued = new AtomicInteger();

        HttpServer start(int port) throws IOException {
            HttpServer s = HttpServer.create(new InetSocketAddress("127.0.0.1", port), 0);
            s.createContext("/v1/agents", this::agents);
            s.createContext("/v1/kel/", this::kel);
            s.start();
            return s;
        }

        static void reply(HttpExchange ex, int status, Object body) throws IOException {
            byte[] b = TestSupport.JSON.writeValueAsBytes(body);
            ex.getResponseHeaders().set("Content-Type", "application/json");
            ex.sendResponseHeaders(status, b.length);
            ex.getResponseBody().write(b);
            ex.close();
        }

        static String apiKey(HttpExchange ex) {
            String h = ex.getRequestHeaders().getFirst("Authorization");
            return h != null && h.startsWith("Bearer ") ? h.substring(7) : null;
        }

        static Map<String, Object> body(HttpExchange ex) throws IOException {
            byte[] b = ex.getRequestBody().readAllBytes();
            if (b.length == 0) return null;
            return TestSupport.JSON.readValue(b, new TypeReference<>() {});
        }

        static Map<String, String> query(HttpExchange ex) {
            Map<String, String> q = new HashMap<>();
            String raw = ex.getRequestURI().getRawQuery();
            if (raw == null) return q;
            for (String kv : raw.split("&")) {
                int i = kv.indexOf('=');
                if (i > 0) q.put(kv.substring(0, i), kv.substring(i + 1));
            }
            return q;
        }

        Map<String, Object> toApiRecord(Map<String, Object> row) {
            Map<String, Object> r = new LinkedHashMap<>();
            r.put("did", row.get("did"));
            r.put("didHash", row.get("didHash"));
            r.put("publishedBy", null);
            r.put("ownerAddress", "0x0000000000000000000000000000000000000000");
            r.put("manifestCID", row.get("manifestCID"));
            r.put("publicKeyB64", row.get("publicKeyB64"));
            r.put("stakedWei", "0");
            r.put("reputationScore", 5000);
            r.put("active", row.get("active"));
            r.put("registeredAt", row.get("registeredAt"));
            r.put("lastUpdatedAt", row.get("registeredAt"));
            r.put("capabilityIds", List.of("search", "book-flight"));
            r.put("endpointUrl", row.get("endpointUrl"));
            r.put("keyVersion", 1);
            r.put("keyRotatedAt", null);
            r.put("verified", false);
            r.put("verificationTier", "community");
            r.put("domain", null);
            r.put("orgSigned", false);
            r.put("visibility", "public");
            r.put("someFutureField", Map.of("ignored", true));
            return r;
        }

        void agents(HttpExchange ex) throws IOException {
            String path = ex.getRequestURI().getRawPath();
            String method = ex.getRequestMethod();
            String key = apiKey(ex);
            boolean authed = API_KEY.equals(key);
            String rest = path.substring("/v1/agents".length());

            if (method.equals("POST") && rest.equals("/challenge")) {
                if (!authed) { reply(ex, 401, Map.of("error", "Unauthorized")); return; }
                Map<String, Object> b = body(ex);
                if (b == null || !(b.get("did") instanceof String did)) { reply(ex, 400, Map.of("error", "did is required")); return; }
                String nonce = UUID.randomUUID().toString();
                challenges.put(nonce, new String[]{did, key});
                challengesIssued.incrementAndGet();
                reply(ex, 200, Map.of("nonce", nonce, "expiresAt", System.currentTimeMillis() + 300_000));
                return;
            }
            if (method.equals("POST") && (rest.isEmpty() || rest.equals("/"))) {
                if (!authed) { reply(ex, 401, Map.of("error", "Unauthorized")); return; }
                register(ex, key);
                return;
            }
            if (method.equals("GET") && (rest.isEmpty() || rest.equals("/"))) {
                Map<String, String> q = query(ex);
                List<Map<String, Object>> rows = new ArrayList<>();
                for (Map<String, Object> row : agents.values()) if (Boolean.TRUE.equals(row.get("active"))) rows.add(toApiRecord(row));
                if (q.containsKey("capabilities")) {
                    List<String> want = new ArrayList<>();
                    for (String c : q.get("capabilities").split(",")) want.add(URLDecoder.decode(c, StandardCharsets.UTF_8));
                    rows.removeIf(r -> !((List<?>) r.get("capabilityIds")).containsAll(want));
                    reply(ex, 200, rows);
                    return;
                }
                int limit = Integer.parseInt(q.getOrDefault("limit", "50"));
                int offset = Integer.parseInt(q.getOrDefault("offset", "0"));
                reply(ex, 200, rows.subList(Math.min(offset, rows.size()), Math.min(rows.size(), offset + limit)));
                return;
            }
            String[] parts = rest.substring(1).split("/");
            String id = URLDecoder.decode(parts[0], StandardCharsets.UTF_8);
            String didHash = id.startsWith("0x") ? id : ArohaRegistryClient.hashDID(id);
            Map<String, Object> row = agents.get(didHash);
            if (method.equals("GET") && parts.length == 1) {
                if (row == null) { reply(ex, 404, Map.of("error", "Not found")); return; }
                reply(ex, 200, toApiRecord(row));
                return;
            }
            if (!authed) { reply(ex, 401, Map.of("error", "Unauthorized")); return; }
            boolean owned = row != null && key.equals(row.get("owner"));
            if (method.equals("PUT") && parts.length == 2 && parts[1].equals("manifest")) {
                Map<String, Object> b = body(ex);
                if (b == null || !(b.get("manifestCID") instanceof String cid) || cid.isEmpty()) {
                    reply(ex, 400, Map.of("error", "manifestCID is required"));
                    return;
                }
                if (!owned) { reply(ex, 404, Map.of("error", "Not found or not owned by this key")); return; }
                row.put("manifestCID", cid);
                reply(ex, 200, Map.of("ok", true));
                return;
            }
            if (method.equals("DELETE") && parts.length == 1) {
                if (!owned) { reply(ex, 404, Map.of("error", "Not found or not owned by this key")); return; }
                row.put("active", false);
                reply(ex, 200, Map.of("ok", true));
                return;
            }
            reply(ex, 404, Map.of("error", "Not found"));
        }

        void register(HttpExchange ex, String apiKey) throws IOException {
            Map<String, Object> b = body(ex);
            if (b == null) { reply(ex, 400, Map.of("error", "Request body must be a JSON object")); return; }
            if (!(b.get("did") instanceof String did) || did.isEmpty() || !(b.get("manifestCID") instanceof String cid) || cid.isEmpty()) {
                reply(ex, 400, Map.of("error", "did, manifestCID, and publicKeyB64 are required"));
                return;
            }
            byte[] keyBytes;
            if (Kel.isInceptionDid(did)) {
                @SuppressWarnings("unchecked") List<Map<String, Object>> kel = (List<Map<String, Object>>) b.get("kel");
                if (kel == null) { reply(ex, 400, Map.of("error", did + " is a rotatable E-DID: include its Key Event Log as `kel`")); return; }
                try {
                    Kel.KelState st = Kel.verifyKel(did, kel);
                    if (!"agent".equals(st.kind)) { reply(ex, 400, Map.of("error", "a person E-DID is a principal")); return; }
                    keyBytes = st.currentKey;
                } catch (Kel.KelException e) {
                    reply(ex, 400, Map.of("error", e.getMessage()));
                    return;
                }
                kels.put(did, kel);
            } else {
                if (!(b.get("publicKeyB64") instanceof String pk)) { reply(ex, 400, Map.of("error", "did, manifestCID, and publicKeyB64 are required")); return; }
                keyBytes = Base64.getUrlDecoder().decode(pk);
                if (keyBytes.length != 32) { reply(ex, 400, Map.of("error", "publicKeyB64 must be a 32-byte Ed25519 public key")); return; }
                if (did.startsWith("did:aroha:z") && !Arrays.equals(DID.fromMultibase(did.substring(10)), keyBytes)) {
                    reply(ex, 400, Map.of("error", "publicKeyB64 is not the key this content-addressed DID encodes"));
                    return;
                }
                if (!(b.get("challengeNonce") instanceof String nonce) || !(b.get("challengeSignature") instanceof String sig)) {
                    reply(ex, 400, Map.of("error", "challengeNonce and challengeSignature are required"));
                    return;
                }
                String[] ch = challenges.remove(nonce);
                if (ch == null || !ch[0].equals(did) || !ch[1].equals(apiKey)) {
                    reply(ex, 403, Map.of("error", "challenge not found, already used, expired, or issued to a different API key"));
                    return;
                }
                // JSON.stringify({ action: "prove-ownership", did, nonce }), as the server builds it
                byte[] msg = ("{\"action\":\"prove-ownership\",\"did\":" + TestSupport.JSON.writeValueAsString(did)
                    + ",\"nonce\":" + TestSupport.JSON.writeValueAsString(nonce) + "}").getBytes(StandardCharsets.UTF_8);
                if (!Signing.verifyBytes(msg, Base64.getUrlDecoder().decode(sig), keyBytes)) {
                    reply(ex, 403, Map.of("error", "challenge signature does not verify against publicKeyB64"));
                    return;
                }
            }
            String didHash = ArohaRegistryClient.hashDID(did);
            Map<String, Object> existing = agents.get(didHash);
            if (existing != null && Boolean.TRUE.equals(existing.get("active"))) { reply(ex, 409, Map.of("error", "DID already registered")); return; }
            Map<String, Object> row = new LinkedHashMap<>();
            row.put("did", did);
            row.put("didHash", didHash);
            row.put("manifestCID", cid);
            row.put("publicKeyB64", Base64.getUrlEncoder().withoutPadding().encodeToString(keyBytes));
            row.put("endpointUrl", b.get("endpointUrl"));
            row.put("active", true);
            row.put("registeredAt", System.currentTimeMillis());
            row.put("owner", apiKey);
            agents.put(didHash, row);
            reply(ex, 201, Map.of("didHash", didHash));
        }

        void kel(HttpExchange ex) throws IOException {
            String did = URLDecoder.decode(ex.getRequestURI().getRawPath().substring("/v1/kel/".length()), StandardCharsets.UTF_8);
            if (duplicity.contains(did)) {
                reply(ex, 409, Map.of("error", did + " has a recorded duplicity alarm", "code", "duplicity"));
                return;
            }
            List<Map<String, Object>> events = kels.get(did);
            if (events == null) { reply(ex, 404, Map.of("error", "Not found")); return; }
            reply(ex, 200, Map.of("did", did, "events", events, "sequence", events.size() - 1));
        }
    }
}
