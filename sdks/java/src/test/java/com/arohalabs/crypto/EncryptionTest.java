// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

package com.arohalabs.crypto;

import com.arohalabs.TestSupport;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.junit.jupiter.api.Test;

import java.util.HexFormat;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class EncryptionTest {

    /**
     * Produced by aroha-core encryptBody (TypeScript, @noble/curves 1.9.7)
     * for a recipient whose Ed25519 seed is 32 bytes of 0x09. The Python and
     * Go SDKs carry the same vector.
     */
    static final Map<String, Object> TS_VECTOR = Map.of(
        "alg", "ECDH-ES+A256GCM",
        "epk", "ESD8db8bcWQ5_DcFzwqysk_v-SZyCXaZviTNmYdcW20",
        "iv", "ZZ40t9ssVRW__bVe",
        "ciphertext", "3nnruPHitEvAbmbgl1GCSpIrPYtWXlq_Mhn3tTkID-gtFliNP2c18XVGDgdvKb8GVJuDmXkHJWwqdSLYXu_pOtGTIgDeuA",
        "tag", "EC7kYlJ2VIwUA0SGHBj0Bg");

    @Test
    void typeScriptVectorDecrypts() throws Exception {
        Ed25519PrivateKeyParameters k = TestSupport.seed(9);
        assertEquals("fd1724385aa0c75b64fb78cd602fa1d991fdebf76b13c58ed702eac835e9f618",
            HexFormat.of().formatHex(TestSupport.pub(k)));
        Map<String, Object> out = Encryption.decryptBody(TS_VECTOR, k);
        assertEquals(10.5, out.get("amount"));
        assertEquals("héllo 😀", out.get("note"));
        assertEquals(Map.of("2", true, "10", List.of(1, 2.25)), out.get("nested"));
    }

    @Test
    void ed25519ConversionAgreesBetweenPublicAndPrivate() {
        for (int b : new int[]{9, 0, 255}) {
            Ed25519PrivateKeyParameters k = TestSupport.seed(b);
            assertArrayEquals(Encryption.toX25519(k.generatePublicKey()).getEncoded(),
                Encryption.toX25519(k).generatePublicKey().getEncoded());
        }
    }

    @Test
    void roundTripCarriesRawEpkAndNoKeyMaterial() throws Exception {
        Ed25519PrivateKeyParameters k = TestSupport.seed(9);
        Map<String, Object> enc = Encryption.encryptBody(Map.of("k", "v"), k.generatePublicKey());
        assertEquals(List.of("alg", "epk", "iv", "ciphertext", "tag"), List.copyOf(enc.keySet()));
        assertEquals(32, java.util.Base64.getUrlDecoder().decode((String) enc.get("epk")).length);
        assertEquals(Map.of("k", "v"), Encryption.decryptBody(enc, k));
        assertThrows(Exception.class, () -> Encryption.decryptBody(enc, TestSupport.seed(8)));
        var legacy = new java.util.HashMap<>(enc);
        legacy.put("alg", "A256GCM");
        assertThrows(IllegalArgumentException.class, () -> Encryption.decryptBody(legacy, k));
    }
}
