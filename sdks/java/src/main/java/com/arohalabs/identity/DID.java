// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

package com.arohalabs.identity;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.Ed25519KeyPairGenerator;
import org.bouncycastle.crypto.params.Ed25519KeyGenerationParameters;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;

import com.arohalabs.util.IsoTime;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Objects;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Aroha Layer 1 — Identity
 *
 * Generates DID documents and Ed25519 key pairs conforming to:
 *   - W3C DID Core 1.0
 *   - Ed25519VerificationKey2020
 *   - Multibase base58btc encoding (z prefix)
 */
public final class DID {

    private DID() {}

    // Base58 alphabet (Bitcoin alphabet used by multibase btc58)
    private static final String BASE58_ALPHABET =
        "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

    // ── Key Generation ────────────────────────────────────────────────────────

    /**
     * Generates a fresh Ed25519 key pair.
     */
    public static Ed25519KeyPair generateKeyPair() {
        Ed25519KeyPairGenerator gen = new Ed25519KeyPairGenerator();
        gen.init(new Ed25519KeyGenerationParameters(new SecureRandom()));
        AsymmetricCipherKeyPair pair = gen.generateKeyPair();
        Ed25519PrivateKeyParameters priv = (Ed25519PrivateKeyParameters) pair.getPrivate();
        Ed25519PublicKeyParameters pub  = (Ed25519PublicKeyParameters)  pair.getPublic();
        return new Ed25519KeyPair(priv, pub);
    }

    /**
     * Builds a complete Aroha AgentIdentity: DID, DID Document, and key pair.
     *
     * @param agentId  unique identifier suffix (e.g. "expedia-flights-v2")
     * @param endpoint HTTPS endpoint of the agent's Aroha service
     */
    public static AgentIdentity generate(String agentId, String endpoint) {
        Ed25519KeyPair kp = generateKeyPair();
        String did = "did:aroha:" + agentId;
        String keyId = did + "#key-1";
        String publicKeyMultibase = toMultibase(kp.publicKey().getEncoded());

        Map<String, Object> doc = buildDocument(did, keyId, publicKeyMultibase, endpoint);
        return new AgentIdentity(did, keyId, doc, kp.privateKey(), kp.publicKey());
    }

    // ── DID Document Builder ──────────────────────────────────────────────────

    private static Map<String, Object> buildDocument(
            String did, String keyId, String publicKeyMultibase, String endpoint) {

        Map<String, Object> verificationMethod = new LinkedHashMap<>();
        verificationMethod.put("id", keyId);
        verificationMethod.put("type", "Ed25519VerificationKey2020");
        verificationMethod.put("controller", did);
        verificationMethod.put("publicKeyMultibase", publicKeyMultibase);

        Map<String, Object> service = new LinkedHashMap<>();
        service.put("id", did + "#aroha");
        service.put("type", "ArohaEndpoint");
        service.put("serviceEndpoint", endpoint);

        Map<String, Object> doc = new LinkedHashMap<>();
        doc.put("@context", List.of(
            "https://www.w3.org/ns/did/v1",
            "https://w3id.org/security/suites/ed25519-2020/v1"
        ));
        doc.put("id", did);
        doc.put("verificationMethod", List.of(verificationMethod));
        doc.put("authentication", List.of(keyId));
        doc.put("service", List.of(service));
        return doc;
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    /**
     * Encodes raw bytes as multibase base58btc (z prefix).
     */
    public static String toMultibase(byte[] bytes) {
        return "z" + encodeBase58(bytes);
    }

    /**
     * Decodes a multibase base58btc string (z prefix) to raw bytes.
     */
    public static byte[] fromMultibase(String multibase) {
        if (!multibase.startsWith("z")) {
            throw new IllegalArgumentException("Only base58btc (z-prefix) multibase is supported");
        }
        return decodeBase58(multibase.substring(1));
    }

    /**
     * The key that should verify a signature from the document's PRIMARY
     * verification method right now. See {@link #extractPublicKey(Map, String, long)}.
     */
    public static byte[] extractPublicKey(Map<String, Object> didDocument) {
        return extractPublicKey(didDocument, null, System.currentTimeMillis());
    }

    /** {@link #extractPublicKey(Map, String, long)} at the current time. */
    public static byte[] extractPublicKey(Map<String, Object> didDocument, String vmId) {
        return extractPublicKey(didDocument, vmId, System.currentTimeMillis());
    }

    /**
     * Port of aroha-core {@code extractPublicKey}: the key that should verify
     * a signature naming {@code vmId} ({@code did#frag} or {@code #frag};
     * null = the primary method) at {@code nowMs}.
     * <ul>
     *   <li>A key listed in {@code revokedKeys} is refused.</li>
     *   <li>For the primary method, while a {@code keyHistory} rotation is
     *       inside its cool-down ({@code trustAfter} in the future, or
     *       unparseable), the PREDECESSOR key is returned — unless the latest
     *       {@code controllerRecoveries} entry installed the current key and
     *       is at least as recent as the latest rotation. If that predecessor
     *       was revoked, no key is trusted.</li>
     *   <li>Non-primary (device) methods are subject to revocation only.</li>
     * </ul>
     * The document's authenticity is the caller's responsibility.
     */
    public static byte[] extractPublicKey(Map<String, Object> didDocument, String vmId, long nowMs) {
        Object id = didDocument.get("id");
        List<Map<String, Object>> methods = maps(didDocument.get("verificationMethod"));
        if (methods.isEmpty()) throw new IllegalArgumentException("DID " + id + " has no verification methods");
        int vm = selectVerificationMethod(didDocument, methods, vmId);
        String mb = (String) methods.get(vm).get("publicKeyMultibase");
        List<Map<String, Object>> history = maps(didDocument.get("keyHistory"));

        String candidate = mb;
        if (vm == 0 && !history.isEmpty() && !controllerInstalled(didDocument, history, mb)) {
            for (Map<String, Object> rotation : history) {
                Long trustAfter = IsoTime.parseMillis(rotation.get("trustAfter"));
                // JavaScript compares an unparseable date (NaN) false: keep walking back.
                if (trustAfter != null && nowMs >= trustAfter) break;
                candidate = (String) rotation.get("predecessorKey");
            }
            if (!Objects.equals(candidate, mb)) {
                Map<String, Object> r = revoked(didDocument, candidate);
                if (r != null) {
                    throw new IllegalArgumentException("DID " + id + " key rotation cool-down active until "
                        + history.get(0).get("trustAfter") + " and the predecessor key was revoked at "
                        + r.get("revokedAt") + " (" + r.get("reason") + ") — no key is trusted until the "
                        + "cool-down ends or the controller recovers the DID");
                }
            }
        }
        Map<String, Object> r = revoked(didDocument, candidate);
        if (r != null) {
            String shortKey = candidate.length() > 12 ? candidate.substring(0, 12) : candidate;
            throw new IllegalArgumentException("DID " + id + " key " + shortKey + "... was revoked at "
                + r.get("revokedAt") + ": " + r.get("reason"));
        }
        return fromMultibase(candidate);
    }

    @SuppressWarnings("unchecked")
    private static List<Map<String, Object>> maps(Object v) {
        List<Map<String, Object>> out = new ArrayList<>();
        if (v instanceof List<?> list) {
            for (Object o : list) if (o instanceof Map<?, ?> m) out.add((Map<String, Object>) m);
        }
        return out;
    }

    private static int selectVerificationMethod(Map<String, Object> doc, List<Map<String, Object>> methods, String vmId) {
        if (vmId == null || vmId.isEmpty()) return 0;
        Object id = doc.get("id");
        String absolute = vmId.startsWith("#") ? id + vmId : vmId;
        for (int i = 0; i < methods.size(); i++) {
            if (!(methods.get(i).get("id") instanceof String mid)) continue;
            if (mid.equals(absolute) || (mid.startsWith("#") && (id + mid).equals(absolute))) return i;
        }
        if (absolute.equals(id + "#key-1")) return 0;
        throw new IllegalArgumentException("DID " + id + " has no verification method " + vmId);
    }

    private static Map<String, Object> revoked(Map<String, Object> doc, String keyMultibase) {
        for (Map<String, Object> r : maps(doc.get("revokedKeys"))) {
            if (Objects.equals(r.get("keyMultibase"), keyMultibase)) return r;
        }
        return null;
    }

    private static boolean controllerInstalled(Map<String, Object> doc, List<Map<String, Object>> history, String keyMultibase) {
        List<Map<String, Object>> recs = maps(doc.get("controllerRecoveries"));
        if (recs.isEmpty() || !Objects.equals(recs.get(0).get("newKeyMultibase"), keyMultibase)) return false;
        if (history.isEmpty()) return true;
        Long rec = IsoTime.parseMillis(recs.get(0).get("recoveredAt"));
        Long rot = IsoTime.parseMillis(history.get(0).get("rotatedAt"));
        return rec != null && rot != null && rec >= rot;
    }

    /** Content-addressed DID {@code did:aroha:z<base58btc(publicKey)>} (TS {@code generateDid}). */
    public static String generateDid(byte[] publicKey) {
        return "did:aroha:" + toMultibase(publicKey);
    }

    /**
     * Extracts the Aroha service endpoint from a DID Document.
     */
    @SuppressWarnings("unchecked")
    public static String extractEndpoint(Map<String, Object> didDocument) {
        List<Map<String, Object>> services =
            (List<Map<String, Object>>) didDocument.get("service");
        if (services == null || services.isEmpty()) {
            throw new IllegalArgumentException("No service in DID Document");
        }
        return (String) services.get(0).get("serviceEndpoint");
    }

    // ── Base58 ────────────────────────────────────────────────────────────────

    /** base58btc (Bitcoin alphabet), leading zero bytes as leading '1's. */
    public static String encodeBase58(byte[] input) {
        int zeros = 0;
        while (zeros < input.length && input[zeros] == 0) zeros++;
        // Little-endian base-58 digits of the non-zero part.
        int[] digits = new int[input.length * 138 / 100 + 1];
        int digitLen = 0;
        for (int i = zeros; i < input.length; i++) {
            int carry = input[i] & 0xFF;
            for (int j = 0; j < digitLen; j++) {
                carry += digits[j] << 8;
                digits[j] = carry % 58;
                carry /= 58;
            }
            while (carry > 0) {
                digits[digitLen++] = carry % 58;
                carry /= 58;
            }
        }
        StringBuilder sb = new StringBuilder(zeros + digitLen);
        for (int i = 0; i < zeros; i++) sb.append('1');
        for (int i = digitLen - 1; i >= 0; i--) sb.append(BASE58_ALPHABET.charAt(digits[i]));
        return sb.toString();
    }

    /** Inverse of {@link #encodeBase58(byte[])}; throws on a non-alphabet character. */
    public static byte[] decodeBase58(String input) {
        int zeros = 0;
        while (zeros < input.length() && input.charAt(zeros) == '1') zeros++;
        int[] bytes = new int[input.length()];
        int byteLen = 0;
        for (int i = zeros; i < input.length(); i++) {
            int carry = BASE58_ALPHABET.indexOf(input.charAt(i));
            if (carry < 0) throw new IllegalArgumentException("Invalid base58 character: " + input.charAt(i));
            for (int j = 0; j < byteLen; j++) {
                carry += bytes[j] * 58;
                bytes[j] = carry & 0xFF;
                carry >>= 8;
            }
            while (carry > 0) {
                bytes[byteLen++] = carry & 0xFF;
                carry >>= 8;
            }
        }
        byte[] result = new byte[zeros + byteLen];
        for (int i = 0; i < byteLen; i++) {
            result[zeros + byteLen - 1 - i] = (byte) bytes[i];
        }
        return result;
    }

    // ── Value Objects ─────────────────────────────────────────────────────────

    public record Ed25519KeyPair(
        Ed25519PrivateKeyParameters privateKey,
        Ed25519PublicKeyParameters  publicKey
    ) {}

    public record AgentIdentity(
        String did,
        String keyId,
        Map<String, Object>           didDocument,
        Ed25519PrivateKeyParameters   privateKey,
        Ed25519PublicKeyParameters    publicKey
    ) {}
}
