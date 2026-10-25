// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

package com.arohalabs.crypto;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.bouncycastle.crypto.agreement.X25519Agreement;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.X25519PublicKeyParameters;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Aroha Layer 3 — Body Encryption, byte-compatible with aroha-core
 * ({@code encryptBody} / {@code decryptBody} in
 * {@code packages/aroha-core/src/crypto/encryption.ts}).
 *
 * <ul>
 *   <li>The recipient's Ed25519 public key is mapped to X25519 via
 *       {@code u = (1 + y) / (1 - y) mod p}; its Ed25519 seed maps to the
 *       X25519 scalar {@code clamp(SHA-512(seed)[0..32])} — as
 *       {@code @noble/curves} edwardsToMontgomeryPub / Priv do.</li>
 *   <li>A fresh ephemeral X25519 key pair does ECDH; the AES-256-GCM key is
 *       {@code SHA-256(sharedSecret)}; no AAD; 12-byte IV; 16-byte tag.</li>
 *   <li>Wire fields: {@code alg} = "ECDH-ES+A256GCM", {@code epk} (raw
 *       32-byte X25519 public key), {@code iv}, {@code ciphertext},
 *       {@code tag} — all base64url without padding.</li>
 * </ul>
 */
public final class Encryption {

    private Encryption() {}

    public static final String ALG = "ECDH-ES+A256GCM";

    private static final String AES_GCM  = "AES/GCM/NoPadding";
    private static final int    TAG_BITS = 128;
    private static final int    IV_BYTES = 12;
    private static final BigInteger P = BigInteger.ONE.shiftLeft(255).subtract(BigInteger.valueOf(19));

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final SecureRandom RANDOM = new SecureRandom();

    // ── Key conversion ────────────────────────────────────────────────────────

    /** Maps an Ed25519 public key to its X25519 form. */
    public static X25519PublicKeyParameters toX25519(Ed25519PublicKeyParameters edPub) {
        byte[] le = edPub.getEncoded();
        le[31] &= 0x7f;
        BigInteger y = new BigInteger(1, reverse(le));
        if (y.compareTo(P) >= 0) throw new IllegalArgumentException("Ed25519 public key is not canonical");
        BigInteger den = BigInteger.ONE.subtract(y).mod(P);
        if (den.signum() == 0) throw new IllegalArgumentException("Ed25519 public key has no X25519 equivalent");
        BigInteger u = BigInteger.ONE.add(y).multiply(den.modInverse(P)).mod(P);
        byte[] be = u.toByteArray();
        byte[] fixed = new byte[32];
        int n = Math.min(be.length, 32);
        System.arraycopy(be, be.length - n, fixed, 32 - n, n);
        return new X25519PublicKeyParameters(reverse(fixed), 0);
    }

    /** Maps an Ed25519 private key (seed) to the matching X25519 private key. */
    public static X25519PrivateKeyParameters toX25519(Ed25519PrivateKeyParameters edPriv) {
        try {
            byte[] h = Arrays.copyOf(MessageDigest.getInstance("SHA-512").digest(edPriv.getEncoded()), 32);
            h[0] &= (byte) 248;
            h[31] &= 127;
            h[31] |= 64;
            return new X25519PrivateKeyParameters(h, 0);
        } catch (java.security.NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    // ── Encrypt ───────────────────────────────────────────────────────────────

    /** Encrypts a JSON body for the recipient's Ed25519 public key. */
    public static Map<String, Object> encryptBody(
            Map<String, Object> plaintext, Ed25519PublicKeyParameters recipient) throws Exception {
        return encryptBody(plaintext, toX25519(recipient));
    }

    /** Encrypts a JSON body for a recipient X25519 public key. */
    public static Map<String, Object> encryptBody(
            Map<String, Object> plaintext, X25519PublicKeyParameters recipient) throws Exception {
        X25519PrivateKeyParameters eph = new X25519PrivateKeyParameters(RANDOM);
        byte[] aesKey = deriveKey(eph, recipient);

        byte[] iv = new byte[IV_BYTES];
        RANDOM.nextBytes(iv);
        Cipher cipher = Cipher.getInstance(AES_GCM);
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(aesKey, "AES"), new GCMParameterSpec(TAG_BITS, iv));
        byte[] sealed = cipher.doFinal(MAPPER.writeValueAsBytes(plaintext));
        int tagOffset = sealed.length - TAG_BITS / 8;

        Base64.Encoder b64 = Base64.getUrlEncoder().withoutPadding();
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("alg",        ALG);
        result.put("epk",        b64.encodeToString(eph.generatePublicKey().getEncoded()));
        result.put("iv",         b64.encodeToString(iv));
        result.put("ciphertext", b64.encodeToString(Arrays.copyOfRange(sealed, 0, tagOffset)));
        result.put("tag",        b64.encodeToString(Arrays.copyOfRange(sealed, tagOffset, sealed.length)));
        return result;
    }

    // ── Decrypt ───────────────────────────────────────────────────────────────

    /** Decrypts with the recipient's Ed25519 private key. */
    public static Map<String, Object> decryptBody(
            Map<String, Object> encrypted, Ed25519PrivateKeyParameters recipient) throws Exception {
        return decryptBody(encrypted, toX25519(recipient));
    }

    /** Decrypts with the recipient's X25519 private key. Throws for any alg but ECDH-ES+A256GCM. */
    public static Map<String, Object> decryptBody(
            Map<String, Object> encrypted, X25519PrivateKeyParameters recipient) throws Exception {
        if (!ALG.equals(encrypted.get("alg"))) {
            throw new IllegalArgumentException("Unsupported encrypted body alg " + encrypted.get("alg") + "; expected " + ALG);
        }
        Base64.Decoder b64 = Base64.getUrlDecoder();
        byte[] epk        = b64.decode((String) encrypted.get("epk"));
        byte[] iv         = b64.decode((String) encrypted.get("iv"));
        byte[] ciphertext = b64.decode((String) encrypted.get("ciphertext"));
        byte[] tag        = b64.decode((String) encrypted.get("tag"));
        if (epk.length != 32 || iv.length != IV_BYTES || tag.length != TAG_BITS / 8) {
            throw new IllegalArgumentException("Malformed encrypted body");
        }
        byte[] aesKey = deriveKey(recipient, new X25519PublicKeyParameters(epk, 0));

        byte[] sealed = new byte[ciphertext.length + tag.length];
        System.arraycopy(ciphertext, 0, sealed, 0, ciphertext.length);
        System.arraycopy(tag, 0, sealed, ciphertext.length, tag.length);
        Cipher cipher = Cipher.getInstance(AES_GCM);
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(aesKey, "AES"), new GCMParameterSpec(TAG_BITS, iv));
        return MAPPER.readValue(cipher.doFinal(sealed), new TypeReference<LinkedHashMap<String, Object>>() {});
    }

    // ── Internals ─────────────────────────────────────────────────────────────

    private static byte[] deriveKey(X25519PrivateKeyParameters priv, X25519PublicKeyParameters pub) throws Exception {
        X25519Agreement ka = new X25519Agreement();
        ka.init(priv);
        byte[] shared = new byte[ka.getAgreementSize()];
        ka.calculateAgreement(pub, shared, 0); // throws for a low-order point (all-zero secret)
        return MessageDigest.getInstance("SHA-256").digest(shared);
    }

    private static byte[] reverse(byte[] b) {
        byte[] out = new byte[b.length];
        for (int i = 0; i < b.length; i++) out[b.length - 1 - i] = b[i];
        return out;
    }
}
