// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

package com.arohalabs.identity;

import com.arohalabs.TestSupport;
import com.arohalabs.identity.WebDID.Options;
import com.arohalabs.identity.WebDID.WebAgentKeyPair;
import com.arohalabs.identity.WebDID.WebDIDException;
import com.arohalabs.util.IsoTime;
import com.fasterxml.jackson.core.type.TypeReference;
import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.io.InputStream;
import java.net.InetSocketAddress;
import java.time.Duration;
import java.time.Instant;
import java.util.*;

import static org.junit.jupiter.api.Assertions.*;

/** did:aroha-web: a port of aroha-core resolveWebDID, checked against a TypeScript vector. */
class WebDIDTest {

    static WebDID.HttpsFetcher serve(Map<String, Object> doc) {
        return (url, timeout, max) -> TestSupport.JSON.writeValueAsBytes(doc);
    }

    static WebDID.DnsTxtLookup txt(String... records) {
        return domain -> List.of(records);
    }

    static Options opts() { return new Options().logger(m -> {}).useSystemDns(false); }

    @SuppressWarnings("unchecked")
    static Map<String, Object> copy(Map<String, Object> m) throws Exception {
        return TestSupport.JSON.readValue(TestSupport.JSON.writeValueAsBytes(m), Map.class);
    }

    @ParameterizedTest
    @ValueSource(strings = {
        "did:aroha-web:10.0.0.5:agent", "did:aroha-web:evil.com@10.0.0.5:agent", "did:aroha-web:example.com%2e:agent",
        "did:aroha-web:-bad.com:agent", "did:aroha-web:example.123:agent", "did:aroha-web:example.com:..:x",
        "did:aroha-web:example.com:Agents", "did:aroha-web:example.com:a?b", "did:aroha-web:"})
    void parseRejectsNonHostnamesAndBadPaths(String did) {
        assertThrows(WebDIDException.class, () -> WebDID.parseWebDID(did));
    }

    @Test
    void parseAcceptsHostnamesAndOptInIpv4() {
        assertEquals(new WebDID.Parsed("example.com", "agents/fx"), WebDID.parseWebDID("did:aroha-web:example.com:agents:fx"));
        assertEquals("agent", WebDID.parseWebDID("did:aroha-web:example.com").path());
        assertEquals("10.0.0.5", WebDID.parseWebDID("did:aroha-web:10.0.0.5:x", true).domain());
    }

    @Test
    @SuppressWarnings("unchecked")
    void typeScriptVectorResolvesIdentically() throws Exception {
        Map<String, Object> vec;
        try (InputStream in = WebDIDTest.class.getResourceAsStream("/web-did-ts-vector.json")) {
            vec = TestSupport.JSON.readValue(in, new TypeReference<Map<String, Object>>() {});
        }
        List<Map<String, Object>> cases = (List<Map<String, Object>>) vec.get("cases");
        assertEquals(12, cases.size());
        for (Map<String, Object> c : cases) {
            List<String> records = (List<String>) c.get("txt");
            var r = WebDID.resolveWebDID((String) vec.get("did"), opts()
                .fetch(serve((Map<String, Object>) vec.get("document")))
                .dnsResolver(d -> records)
                .nowMs(((Number) c.get("nowMs")).longValue()));
            Map<String, Object> expect = (Map<String, Object>) c.get("expect");
            List<Map<String, Object>> got = new ArrayList<>();
            for (var k : r.acceptedKeys()) {
                got.add(Map.of("verificationMethodId", k.verificationMethodId(),
                    "publicKeyMultibase", k.publicKeyMultibase(), "role", k.role()));
            }
            String where = c.get("name") + "@" + c.get("nowMs");
            assertEquals(expect.get("dnsVerified"), r.dnsVerified(), where);
            assertEquals(expect.get("keyTrusted"), r.keyTrusted(), where);
            assertEquals(expect.get("acceptedKeys"), got, where);
        }
    }

    @Test
    @SuppressWarnings("unchecked")
    void genesisAndRotation() {
        WebAgentKeyPair a = WebDID.generateWebAgent("example.com", "agents/fx", null);
        var vm = (Map<String, Object>) ((List<Object>) a.document().get("verificationMethod")).get(0);
        assertTrue(((String) vm.get("publicKeyMultibase")).startsWith("z"));
        var r = WebDID.resolveWebDID(a.did(), opts().fetch(serve(a.document())).dnsResolver(txt(a.dnsTxtRecord())));
        assertTrue(r.dnsVerified() && r.keyTrusted());
        assertArrayEquals(a.publicKey(), WebDID.selectWebDIDKey(r, null));

        Instant t0 = Instant.now();
        WebAgentKeyPair b = WebDID.rotateKey(a, Duration.ofHours(24), t0);
        var rec = (Map<String, Object>) ((List<Object>) ((Map<String, Object>) b.document().get("arohaWeb")).get("keyHistory")).get(0);
        assertEquals(2, rec.get("v"));
        assertEquals(a.did(), rec.get("did"));
        r = WebDID.resolveWebDID(b.did(), opts().fetch(serve(b.document())).dnsResolver(txt(b.dnsTxtRecord())).nowMs(t0.toEpochMilli() + 1000));
        List<byte[]> keys = WebDID.webDIDPublicKeys(r, null);
        assertEquals(2, keys.size());
        assertArrayEquals(b.publicKey(), keys.get(0));
        assertArrayEquals(a.publicKey(), keys.get(1));
        r = WebDID.resolveWebDID(b.did(), opts().fetch(serve(b.document())).dnsResolver(txt(a.dnsTxtRecord()))
            .nowMs(t0.plus(Duration.ofHours(25)).toEpochMilli()));
        assertTrue(r.keyTrusted());
        assertArrayEquals(b.publicKey(), WebDID.selectWebDIDKey(r, null));
    }

    @Test
    @SuppressWarnings("unchecked")
    void failClosedCases() throws Exception {
        WebAgentKeyPair a = WebDID.generateWebAgent("example.com", "x", null);
        WebAgentKeyPair other = WebDID.generateWebAgent("example.com", "x", null);

        var r = WebDID.resolveWebDID(a.did(), opts().fetch(serve(a.document())).verifyDns(false));
        assertFalse(r.dnsVerified(), "skipping DNS never reports dnsVerified");
        assertThrows(WebDIDException.class, () -> WebDID.resolveWebDID(a.did(), opts().fetch(serve(a.document()))));
        assertFalse(WebDID.resolveWebDID(a.did(), opts().fetch(serve(a.document())).allowNoDns(true)).dnsVerified());

        r = WebDID.resolveWebDID(a.did(), opts().fetch(serve(a.document())).dnsResolver(txt(other.dnsTxtRecord())));
        assertFalse(r.dnsVerified());
        assertTrue(r.acceptedKeys().isEmpty());
        var finalR = r;
        assertThrows(WebDIDException.class, () -> WebDID.selectWebDIDKey(finalR, null));
        r = WebDID.resolveWebDID(a.did(), opts().fetch(serve(a.document())).dnsResolver(d -> { throw new Exception("SERVFAIL"); }));
        assertTrue(r.acceptedKeys().isEmpty(), "a failed lookup is a miss, not a pass");

        Map<String, Object> doc = copy(a.document());
        ((Map<String, Object>) ((List<Object>) doc.get("verificationMethod")).get(0)).put("publicKeyMultibase",
            ((Map<String, Object>) ((List<Object>) other.document().get("verificationMethod")).get(0)).get("publicKeyMultibase"));
        WebDIDException e = assertThrows(WebDIDException.class,
            () -> WebDID.resolveWebDID(a.did(), opts().fetch(serve(doc)).dnsResolver(txt(a.dnsTxtRecord()))));
        assertTrue(e.getMessage().contains("keyCommitmentHash does not match"), e.getMessage());

        assertThrows(WebDIDException.class, () -> WebDID.resolveWebDID("did:aroha-web:example.com:y",
            opts().fetch(serve(a.document())).dnsResolver(txt(a.dnsTxtRecord()))));

        WebAgentKeyPair b = WebDID.rotateKey(a, Duration.ofHours(24), Instant.now());
        Map<String, Object> tampered = copy(b.document());
        var h = (Map<String, Object>) ((List<Object>) ((Map<String, Object>) tampered.get("arohaWeb")).get("keyHistory")).get(0);
        h.put("trustAfter", h.get("rotatedAt"));
        e = assertThrows(WebDIDException.class,
            () -> WebDID.resolveWebDID(b.did(), opts().fetch(serve(tampered)).dnsResolver(txt(a.dnsTxtRecord()))));
        assertTrue(e.getMessage().contains("invalid predecessor signature"), e.getMessage());

        e = assertThrows(WebDIDException.class, () -> WebDID.resolveWebDID(a.did(),
            opts().fetch((u, t, max) -> new byte[max + 1]).dnsResolver(txt(a.dnsTxtRecord()))));
        assertTrue(e.getMessage().contains("too large"), e.getMessage());
    }

    @Test
    void rotationPayloads() {
        Map<String, Object> rec = new HashMap<>(Map.of("v", 2, "did", "did:aroha-web:e.com:x", "newKeyHash", "ab",
            "predecessorKey", "zK", "rotatedAt", "2026-01-01T00:00:00.000Z", "trustAfter", "2026-01-02T00:00:00.000Z"));
        assertEquals("{\"did\":\"did:aroha-web:e.com:x\",\"newKeyHash\":\"ab\",\"predecessorKey\":\"zK\","
            + "\"rotatedAt\":\"2026-01-01T00:00:00.000Z\",\"trustAfter\":\"2026-01-02T00:00:00.000Z\",\"v\":2}",
            new String(WebDID.rotationSigningPayload(rec)));
        rec.remove("v");
        assertEquals("zKab2026-01-01T00:00:00.000Z", new String(WebDID.rotationSigningPayload(rec)));
        rec.put("v", 3);
        assertEquals("has unsupported version 3", WebDID.checkKeyRotation(rec, null).reason());
    }

    @Test
    void defaultFetchRefusesRedirectsAndCapsSize() throws Exception {
        HttpServer srv = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        srv.createContext("/", ex -> {
            String p = ex.getRequestURI().getPath();
            if (p.equals("/redirect")) {
                ex.getResponseHeaders().add("Location", "http://127.0.0.1:1/x");
                ex.sendResponseHeaders(302, -1);
            } else if (p.equals("/big")) {
                ex.sendResponseHeaders(200, 0); // chunked: no Content-Length
                ex.getResponseBody().write(new byte[WebDID.MAX_WEB_DID_DOCUMENT_BYTES + 1]);
            } else {
                ex.sendResponseHeaders(200, 2);
                ex.getResponseBody().write("{}".getBytes());
            }
            ex.close();
        });
        srv.start();
        try {
            String base = "http://127.0.0.1:" + srv.getAddress().getPort();
            Duration t = Duration.ofSeconds(5);
            assertEquals("{}", new String(WebDID.defaultFetch(base + "/ok", t, WebDID.MAX_WEB_DID_DOCUMENT_BYTES)));
            Exception e = assertThrows(WebDIDException.class, () -> WebDID.defaultFetch(base + "/redirect", t, WebDID.MAX_WEB_DID_DOCUMENT_BYTES));
            assertTrue(e.getMessage().contains("redirects are not followed"));
            e = assertThrows(WebDIDException.class, () -> WebDID.defaultFetch(base + "/big", t, WebDID.MAX_WEB_DID_DOCUMENT_BYTES));
            assertTrue(e.getMessage().contains("too large"));
        } finally {
            srv.stop(0);
        }
    }

    @Test
    void isoHelperRoundTrips() {
        assertEquals(1_700_000_000_123L, IsoTime.parseMillis(IsoTime.formatMillis(1_700_000_000_123L)));
    }
}
