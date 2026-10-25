// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

package com.arohalabs;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HexFormat;
import java.util.Map;

/** Shared helpers for the SDK's tests. */
public final class TestSupport {

    private TestSupport() {}

    public static final ObjectMapper JSON = new ObjectMapper();

    /**
     * A file in the monorepo, located relative to this SDK ({@code sdks/java}).
     * Surefire sets {@code basedir}; an IDE run usually has the module as cwd.
     */
    public static Path repoFile(String repoRelative) {
        Path base = Path.of(System.getProperty("basedir", System.getProperty("user.dir")));
        return base.resolve("../..").resolve(repoRelative).normalize();
    }

    public static boolean exists(Path p) {
        return Files.isRegularFile(p);
    }

    public static Map<String, Object> readJson(Path p) throws Exception {
        return JSON.readValue(Files.readAllBytes(p), new TypeReference<Map<String, Object>>() {});
    }

    public static Object parse(String json) throws Exception {
        return JSON.readValue(json, Object.class);
    }

    public static Ed25519PrivateKeyParameters keyFromHex(String hex) {
        return new Ed25519PrivateKeyParameters(HexFormat.of().parseHex(hex), 0);
    }

    /** Private key whose 32-byte seed is {@code b} repeated (the TS tests' {@code seed(b)}). */
    public static Ed25519PrivateKeyParameters seed(int b) {
        byte[] s = new byte[32];
        java.util.Arrays.fill(s, (byte) b);
        return new Ed25519PrivateKeyParameters(s, 0);
    }

    public static byte[] pub(Ed25519PrivateKeyParameters k) {
        return k.generatePublicKey().getEncoded();
    }
}
