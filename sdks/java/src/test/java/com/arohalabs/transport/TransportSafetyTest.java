// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

package com.arohalabs.transport;

import com.arohalabs.messages.DevMode;
import com.arohalabs.messages.NonceRegistry;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class TransportSafetyTest {

    @AfterEach
    void restoreEnv() { DevMode.setEnvLookupForTesting(null); }

    static ArohaServer server(String host, boolean devMode) {
        return new ArohaServer(host, 0, Map.of("id", "did:aroha:me"), "did:aroha:me", did -> null,
            new NonceRegistry(), (env, respond, stream) -> {}, devMode, 0);
    }

    @Test
    void devModeIsRefusedWithoutEnv() {
        DevMode.setEnvLookupForTesting(k -> null);
        DevMode.NotPermittedException e = assertThrows(DevMode.NotPermittedException.class, () -> server(null, true));
        assertTrue(e.getMessage().contains("AROHA_DEV_MODE=1"), e.getMessage());
        DevMode.setEnvLookupForTesting(k -> DevMode.ENV.equals(k) ? "1" : null);
        assertNotNull(server(null, true));
        DevMode.setEnvLookupForTesting(k -> null);
        assertNotNull(server(null, false));
    }

    @Test
    void defaultBindIsLoopback() {
        assertEquals("127.0.0.1", server(null, false).address().getHostString());
        assertEquals("0.0.0.0", server("0.0.0.0", false).address().getHostString());
    }

    @Test
    void oversizedBodyGets413() throws Exception {
        ArohaServer s = server(null, false);
        s.start();
        try {
            InetSocketAddress a = s.address();
            HttpClient c = HttpClient.newHttpClient();
            URI uri = URI.create("http://127.0.0.1:" + a.getPort() + "/aroha/v1");
            // Declared length over the cap: answered 413 without reading the body.
            try (java.net.Socket sock = new java.net.Socket("127.0.0.1", a.getPort())) {
                sock.getOutputStream().write(("POST /aroha/v1 HTTP/1.1\r\nHost: x\r\nContent-Length: "
                    + (ArohaServer.DEFAULT_MAX_BODY_BYTES + 1) + "\r\n\r\n").getBytes());
                sock.getOutputStream().flush();
                String status = new java.io.BufferedReader(new java.io.InputStreamReader(sock.getInputStream())).readLine();
                assertTrue(status.contains(" 413 "), status);
            }
            HttpResponse<String> r = c.send(HttpRequest.newBuilder(uri)
                .POST(HttpRequest.BodyPublishers.ofString("{nope")).build(), HttpResponse.BodyHandlers.ofString());
            assertEquals(400, r.statusCode());
        } finally {
            s.stop();
        }
    }

    @Test
    void loopbackDetection() {
        for (String h : new String[]{"localhost", "api.localhost", "127.0.0.1", "127.9.9.9", "::1", "[::1]"}) {
            assertTrue(Endpoints.isLoopbackHost(h), h);
        }
        for (String h : new String[]{"10.0.0.1", "example.com", "localhost.example.com", "128.0.0.1", "", null}) {
            assertFalse(Endpoints.isLoopbackHost(h), String.valueOf(h));
        }
    }

    @Test
    void clientRefusesPlainHttpToRemoteHosts() {
        assertNotNull(Endpoints.requireSecure("https://agent.example.com/aroha/v1", false));
        assertNotNull(Endpoints.requireSecure("http://127.0.0.1:3001/aroha/v1", false));
        assertNotNull(Endpoints.requireSecure("http://[::1]:3001/", false));
        Endpoints.InsecureEndpointException e = assertThrows(Endpoints.InsecureEndpointException.class,
            () -> Endpoints.requireSecure("http://agent.example.com/aroha/v1", false));
        assertTrue(e.getMessage().contains("allowInsecureHttp"));
        assertNotNull(Endpoints.requireSecure("http://10.1.2.3/aroha/v1", true));
        for (String bad : new String[]{"ftp://example.com", "file:///etc/hosts", "agent.example.com"}) {
            assertThrows(Endpoints.InsecureEndpointException.class, () -> Endpoints.requireSecure(bad, true), bad);
        }
        ArohaClient client = new ArohaClient();
        assertThrows(Endpoints.InsecureEndpointException.class,
            () -> client.send("http://agent.example.com/aroha/v1", Map.of()));
        assertThrows(Endpoints.InsecureEndpointException.class,
            () -> client.fetchDIDDocument("http://agent.example.com"));
    }
}
