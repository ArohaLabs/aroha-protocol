// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

package com.arohalabs.crypto;

import com.arohalabs.util.IsoTime;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.crypto.signers.Ed25519Signer;

import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Aroha Layer 1/3 — Ed25519 Signing
 *
 * Signs and verifies Aroha message envelopes.
 *
 * The proof covers the canonical form of the message:
 *   - The "proof" field is excluded
 *   - RFC 8785 JCS (keys sorted by UTF-16 code unit, deep; ECMAScript
 *     number formatting), UTF-8 encoded — see {@link #canonicalize(Map)}
 *
 * proofValue is base64url-encoded (no padding) Ed25519 signature.
 */
public final class Signing {

    private Signing() {}

    // ── Sign ──────────────────────────────────────────────────────────────────

    /**
     * Adds a proof to the given message map (mutates the map).
     *
     * @param message             the message map (will have "proof" field added)
     * @param privateKey          Ed25519 private key
     * @param verificationMethodId  e.g. "did:aroha:alice#key-1"
     * @return the modified map (same reference)
     */
    public static Map<String, Object> signMessage(
            Map<String, Object> message,
            Ed25519PrivateKeyParameters privateKey,
            String verificationMethodId) throws Exception {

        // Remove any existing proof before canonicalizing
        message.remove("proof");

        byte[] canonical = canonicalize(message);
        byte[] sig = sign(canonical, privateKey);
        String proofValue = Base64.getUrlEncoder().withoutPadding().encodeToString(sig);

        Map<String, Object> proof = new LinkedHashMap<>();
        proof.put("created", IsoTime.now());
        proof.put("proofPurpose", "authentication");
        proof.put("proofValue", proofValue);
        proof.put("type", "Ed25519Signature2020");
        proof.put("verificationMethod", verificationMethodId);

        message.put("proof", proof);
        return message;
    }

    // ── Verify ────────────────────────────────────────────────────────────────

    /**
     * Verifies the proof on a message map.
     *
     * @param message    the full message map including "proof"
     * @param publicKey  Ed25519 public key of the sender
     * @return true if the signature is valid
     */
    @SuppressWarnings("unchecked")
    public static boolean verifyMessageSignature(
            Map<String, Object> message,
            Ed25519PublicKeyParameters publicKey) throws Exception {

        if (!(message.get("proof") instanceof Map<?, ?> proof)) return false;
        if (!(proof.get("proofValue") instanceof String proofValue)) return false;

        byte[] canonical;
        byte[] sig;
        try {
            canonical = canonicalize(message); // excludes proof
            sig = Base64.getUrlDecoder().decode(proofValue);
        } catch (IllegalArgumentException e) {
            return false; // not canonicalisable, or not base64url
        }
        return verify(canonical, sig, publicKey);
    }

    // ── Canonical Form ────────────────────────────────────────────────────────

    /**
     * Canonical UTF-8 bytes of a message, proof excluded: the TypeScript
     * {@code JSON.stringify(sortKeysDeep(msg))} ({@link Jcs#stringifySorted}).
     *
     * <p>That is RFC 8785 JCS (UTF-16 key order, ECMAScript number
     * formatting, JSON.stringify string escaping) except that integer-like
     * keys come first in numeric order, as JavaScript enumerates them — so a
     * body such as {@code {"10":1,"9":2}} signs the same bytes in every SDK. The earlier Java form went through
     * Jackson, which writes {@code 100.0} for a double and escapes control
     * characters in upper case, so a body containing a decimal amount signed
     * in one SDK failed to verify in the other.
     */
    public static byte[] canonicalize(Map<String, Object> message) {
        Map<String, Object> withoutProof = new LinkedHashMap<>(message);
        withoutProof.remove("proof");
        // JSON.stringify(sortKeysDeep(...)): JCS except that integer-like keys
        // come first in numeric order, as JavaScript enumerates them.
        return Jcs.stringifySorted(withoutProof).getBytes(java.nio.charset.StandardCharsets.UTF_8);
    }

    // ── Low-level Ed25519 ─────────────────────────────────────────────────────

    /** Raw Ed25519 signature over {@code data}. */
    public static byte[] signBytes(byte[] data, Ed25519PrivateKeyParameters key) {
        return sign(data, key);
    }

    /**
     * Raw Ed25519 verification against a 32-byte public key. False (never an
     * exception) for a malformed key or signature.
     */
    public static boolean verifyBytes(byte[] data, byte[] signature, byte[] publicKey) {
        if (publicKey == null || publicKey.length != 32 || signature == null || signature.length != 64) {
            return false;
        }
        try {
            return verify(data, signature, new Ed25519PublicKeyParameters(publicKey, 0));
        } catch (Exception e) {
            return false;
        }
    }

    private static byte[] sign(byte[] data, Ed25519PrivateKeyParameters key) {
        Ed25519Signer signer = new Ed25519Signer();
        signer.init(true, key);
        signer.update(data, 0, data.length);
        return signer.generateSignature();
    }

    private static boolean verify(byte[] data, byte[] signature, Ed25519PublicKeyParameters key) {
        try {
            Ed25519Signer signer = new Ed25519Signer();
            signer.init(false, key);
            signer.update(data, 0, data.length);
            return signer.verifySignature(signature);
        } catch (Exception e) {
            return false;
        }
    }
}
