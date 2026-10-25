// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

package com.arohalabs.crypto;

import com.arohalabs.TestSupport;
import com.fasterxml.jackson.core.type.TypeReference;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Envelope canonical bytes follow JavaScript key order: integer-like keys
 * first, numerically. Same vector as the Go SDK (crypto/canonical_intkey_test.go);
 * the expected string is the Python SDK's canonicalize_message output, which
 * is checked live against @aroha-sdk/core.
 */
class CanonicalIntegerKeyTest {

    static final String MESSAGE = "{\"type\":\"ArohaRequest\",\"body\":{\"params\":{\"10\":\"ten\",\"9\":\"nine\",\"2\":\"two\","
        + "\"01\":\"zero-one\",\"b\":1,\"a\":[{\"3\":1,\"x\":2}],\"4294967295\":\"max\"}},\"proof\":{\"x\":1}}";
    static final String CANONICAL = "{\"body\":{\"params\":{\"2\":\"two\",\"9\":\"nine\",\"10\":\"ten\",\"01\":\"zero-one\","
        + "\"4294967295\":\"max\",\"a\":[{\"3\":1,\"x\":2}],\"b\":1}},\"type\":\"ArohaRequest\"}";

    @Test
    void integerLikeKeysFollowJavaScriptOrder() throws Exception {
        Map<String, Object> msg = TestSupport.JSON.readValue(MESSAGE, new TypeReference<LinkedHashMap<String, Object>>() {});
        assertEquals(CANONICAL, new String(Signing.canonicalize(msg), StandardCharsets.UTF_8));
        assertEquals("{\"10\":1,\"9\":2}", Jcs.canonicalize(Map.of("10", 1, "9", 2)), "JCS proper is unchanged");

        Ed25519PrivateKeyParameters k = TestSupport.seed(5);
        Map<String, Object> signed = Signing.signMessage(msg, k, "did:aroha:x#key-1");
        assertTrue(Signing.verifyMessageSignature(signed, new Ed25519PublicKeyParameters(TestSupport.pub(k), 0)));

        assertTrue(Jcs.isArrayIndex("0"));
        assertTrue(Jcs.isArrayIndex("4294967294"));
        assertFalse(Jcs.isArrayIndex("4294967295"));
        assertFalse(Jcs.isArrayIndex("01"));
        assertFalse(Jcs.isArrayIndex("-1"));
        assertFalse(Jcs.isArrayIndex(""));
    }
}
