// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

package com.arohalabs.messages;

import java.util.Objects;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.UnaryOperator;

/**
 * Gate for switches that disable envelope verification
 * ({@code ArohaServer} devMode, {@link ArohaEnvelope.ValidateOptions#skipSignature}
 * without {@link ArohaEnvelope.ValidateOptions#acknowledgeUnauthenticated}).
 *
 * <p>They are refused unless the environment sets {@code AROHA_DEV_MODE=1};
 * when permitted, a one-time warning is printed to stderr. The TypeScript SDK
 * gates the same switches on {@code NODE_ENV=development}; that variable
 * means nothing outside Node, so the Java, Go and Python SDKs use
 * {@code AROHA_DEV_MODE}.
 */
public final class DevMode {

    /** Environment variable that must equal {@code "1"} to permit dev mode. */
    public static final String ENV = "AROHA_DEV_MODE";

    private static volatile UnaryOperator<String> envLookup = System::getenv;
    private static final Set<String> WARNED = ConcurrentHashMap.newKeySet();

    private DevMode() {}

    /** Thrown when a verification-disabling switch is requested without {@code AROHA_DEV_MODE=1}. */
    public static final class NotPermittedException extends IllegalStateException {
        public NotPermittedException(String message) { super(message); }
    }

    /** True when the environment sets {@code AROHA_DEV_MODE=1}. */
    public static boolean permitted() {
        String v = envLookup.apply(ENV);
        return v != null && v.trim().equals("1");
    }

    /**
     * Throws {@link NotPermittedException} unless {@code AROHA_DEV_MODE=1};
     * when permitted, prints a one-time warning per feature to stderr.
     */
    public static void require(String feature) {
        if (!permitted()) {
            String cur = envLookup.apply(ENV);
            throw new NotPermittedException("[Aroha] " + feature + " can only be enabled when " + ENV
                + "=1 (current: " + (cur == null ? "(unset)" : "\"" + cur + "\"") + "); remove it before deploying.");
        }
        if (WARNED.add(feature)) {
            System.err.println("[Aroha] WARNING: " + feature
                + " is ENABLED — cryptographic validation is bypassed. Never use dev mode in production.");
        }
    }

    /**
     * Replace the environment lookup — for tests only, since the JVM cannot
     * set environment variables. Pass {@code null} to restore {@link System#getenv(String)}.
     */
    public static void setEnvLookupForTesting(UnaryOperator<String> lookup) {
        envLookup = lookup == null ? System::getenv : Objects.requireNonNull(lookup);
        WARNED.clear();
    }
}
