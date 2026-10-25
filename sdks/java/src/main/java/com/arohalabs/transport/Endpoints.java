// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

package com.arohalabs.transport;

import java.net.InetAddress;
import java.net.URI;
import java.util.Locale;

/**
 * Outbound endpoint policy: https only, except loopback hosts
 * (127.0.0.0/8, ::1, localhost), unless the caller explicitly allows plain
 * http for a network it controls.
 */
public final class Endpoints {

    private Endpoints() {}

    /** Thrown when an endpoint is not https and is not explicitly allowed. */
    public static final class InsecureEndpointException extends IllegalArgumentException {
        public InsecureEndpointException(String message) { super(message); }
    }

    /** True for "localhost" (and *.localhost), 127.0.0.0/8 and ::1. Never resolves DNS. */
    public static boolean isLoopbackHost(String host) {
        if (host == null) return false;
        String h = host.toLowerCase(Locale.ROOT);
        if (h.startsWith("[") && h.endsWith("]")) h = h.substring(1, h.length() - 1);
        if (h.endsWith(".")) h = h.substring(0, h.length() - 1);
        if (h.isEmpty()) return false;
        if (h.equals("localhost") || h.endsWith(".localhost")) return true;
        if (!isIpLiteral(h)) return false;
        try {
            return InetAddress.getByName(h).isLoopbackAddress();
        } catch (Exception e) {
            return false;
        }
    }

    private static boolean isIpLiteral(String h) {
        return h.contains(":") || h.matches("\\d{1,3}(\\.\\d{1,3}){3}");
    }

    /**
     * Returns the parsed URI if it is https, or http to a loopback host, or
     * http to any host when {@code allowInsecureHttp}; throws otherwise. Any
     * other scheme is always refused.
     */
    public static URI requireSecure(String url, boolean allowInsecureHttp) {
        URI u;
        try {
            u = URI.create(url);
        } catch (Exception e) {
            throw new InsecureEndpointException("[Aroha] Unsupported endpoint URL '" + url + "': expected an https:// URL");
        }
        String scheme = u.getScheme() == null ? "" : u.getScheme().toLowerCase(Locale.ROOT);
        String host = u.getHost();
        if (host == null || host.isEmpty()) {
            throw new InsecureEndpointException("[Aroha] Unsupported endpoint URL '" + url + "': expected an https:// URL");
        }
        if (scheme.equals("https")) return u;
        if (scheme.equals("http")) {
            if (allowInsecureHttp || isLoopbackHost(host)) return u;
            throw new InsecureEndpointException("[Aroha] Refusing plain-http endpoint '" + url
                + "': messages would travel unencrypted. Use https, a loopback host, or "
                + "new ArohaClient(true) (allowInsecureHttp) for a network you control.");
        }
        throw new InsecureEndpointException("[Aroha] Unsupported endpoint URL '" + url + "': expected an https:// URL");
    }
}
