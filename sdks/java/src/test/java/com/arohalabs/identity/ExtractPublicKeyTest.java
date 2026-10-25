// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

package com.arohalabs.identity;

import com.arohalabs.TestSupport;
import com.arohalabs.util.IsoTime;
import org.junit.jupiter.api.Test;

import java.util.*;

import static org.junit.jupiter.api.Assertions.*;

/** DID.extractPublicKey: revokedKeys, keyHistory cool-down, controllerRecoveries (port of TS extractPublicKey). */
class ExtractPublicKeyTest {

    static final byte[] OLD = TestSupport.pub(TestSupport.seed(41));
    static final byte[] CUR = TestSupport.pub(TestSupport.seed(42));
    static final byte[] DEVICE = TestSupport.pub(TestSupport.seed(43));
    static final long T0 = 1_800_000_000_000L;
    static final long HOUR = 3_600_000L;

    static Map<String, Object> rotatedDoc() {
        Map<String, Object> doc = new HashMap<>();
        doc.put("id", "did:aroha:named");
        doc.put("verificationMethod", List.of(
            Map.of("id", "did:aroha:named#key-1", "publicKeyMultibase", DID.toMultibase(CUR)),
            Map.of("id", "#key-2", "publicKeyMultibase", DID.toMultibase(DEVICE))));
        doc.put("keyHistory", List.of(Map.of(
            "rotatedAt", IsoTime.formatMillis(T0),
            "trustAfter", IsoTime.formatMillis(T0 + 24 * HOUR),
            "predecessorKey", DID.toMultibase(OLD))));
        return doc;
    }

    static Map<String, Object> revocation(byte[] key) {
        return Map.of("keyMultibase", DID.toMultibase(key), "revokedAt", "2026-01-01T00:00:00Z", "reason", "lost");
    }

    @Test
    void coolDownReturnsThePredecessorUntilTrustAfter() {
        Map<String, Object> doc = rotatedDoc();
        assertArrayEquals(OLD, DID.extractPublicKey(doc, null, T0 + HOUR));
        assertArrayEquals(CUR, DID.extractPublicKey(doc, "#key-1", T0 + 25 * HOUR));
        assertArrayEquals(DEVICE, DID.extractPublicKey(doc, "did:aroha:named#key-2", T0 + HOUR), "device keys skip cool-down");
        assertThrows(IllegalArgumentException.class, () -> DID.extractPublicKey(doc, "#key-9", T0));
    }

    @Test
    void controllerInstalledKeySkipsTheCoolDown() {
        Map<String, Object> doc = rotatedDoc();
        doc.put("controllerRecoveries", List.of(Map.of(
            "newKeyMultibase", DID.toMultibase(CUR), "recoveredAt", IsoTime.formatMillis(T0 + 60_000))));
        assertArrayEquals(CUR, DID.extractPublicKey(doc, null, T0 + HOUR));
    }

    @Test
    void revocationIsEnforced() {
        Map<String, Object> doc = rotatedDoc();
        doc.put("revokedKeys", List.of(revocation(OLD)));
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
            () -> DID.extractPublicKey(doc, null, T0 + HOUR));
        assertTrue(e.getMessage().contains("no key is trusted"), e.getMessage());

        doc.put("revokedKeys", List.of(revocation(CUR), revocation(DEVICE)));
        e = assertThrows(IllegalArgumentException.class, () -> DID.extractPublicKey(doc, null, T0 + 25 * HOUR));
        assertTrue(e.getMessage().contains("was revoked"), e.getMessage());
        assertThrows(IllegalArgumentException.class, () -> DID.extractPublicKey(doc, "#key-2", T0));
        doc.remove("keyHistory");
        assertThrows(IllegalArgumentException.class, () -> DID.extractPublicKey(doc));
    }
}
