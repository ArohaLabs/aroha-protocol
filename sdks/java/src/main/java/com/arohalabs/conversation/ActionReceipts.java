// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

package com.arohalabs.conversation;

import com.arohalabs.crypto.Jcs;
import com.arohalabs.identity.DID;

import java.util.*;
import java.util.regex.Pattern;

/**
 * Verifier for signed action receipts v1 and v2 (spec §12.6; TS
 * {@code packages/aroha-core/src/receipts/action-receipt.ts}). A receipt is
 * the acting agent's signed record of one action — executed or denied —
 * signed over JCS of the receipt minus {@code signature}.
 *
 * <p>Verification only. Each version refuses fields it does not define: a
 * signed claim this verifier never evaluated is a claim a reader may wrongly
 * assume was checked.
 */
public final class ActionReceipts {

    private ActionReceipts() {}

    public static final String ACTION_RECEIPT_PURPOSE = "aroha.action-receipt/v1";
    public static final String ACTION_RECEIPT_PURPOSE_V2 = "aroha.action-receipt/v2";

    private static final Pattern SHA256_HEX = Pattern.compile("^[0-9a-f]{64}$");

    private static final List<String> COMMON = List.of("v", "purpose", "agentDid", "action", "argsSha256", "at",
        "tainted", "provenance", "approval", "mandateId", "mandateGrantor", "correlationId", "signature");
    private static final Set<String> KNOWN_V1 = Set.copyOf(COMMON);
    private static final Set<String> KNOWN_V2;
    static {
        Set<String> s = new HashSet<>(COMMON);
        s.addAll(List.of("requesterDid", "principalDid", "executorDid", "presentedHash", "traceparent",
            "outcome", "denialReason", "roomId", "onBehalfOf"));
        KNOWN_V2 = Set.copyOf(s);
    }
    private static final Set<String> APPROVAL_V1 = Set.of("approverDid", "approvedAt", "approvalId");
    private static final Set<String> APPROVAL_V2 =
        Set.of("approverDid", "approvedAt", "approvalId", "presentedHash", "approverSignature");

    /** Resolves an agent DID to its 32-byte Ed25519 key, or null. */
    @FunctionalInterface
    public interface ReceiptKeyResolver {
        byte[] resolve(String did) throws Exception;
    }

    /** Verdict of {@link #verify}. */
    public record ReceiptVerification(boolean ok, Map<String, Object> receipt, String reason) {}

    /** Content-addressed {@code did:aroha:z…} → key; null for any other DID. */
    public static byte[] contentAddressedKey(String did) {
        if (did == null || !did.startsWith("did:aroha:z")) return null;
        try {
            return DID.fromMultibase(did.substring("did:aroha:".length()));
        } catch (Exception e) {
            return null;
        }
    }

    /** Structural check (TS {@code parseActionReceipt}). Null when well-formed, else the reason. */
    public static String checkShape(Object value) {
        if (!(value instanceof Map<?, ?> r)) return "receipt is not an object";
        boolean v1 = r.get("v") instanceof Number n1 && n1.doubleValue() == 1 && ACTION_RECEIPT_PURPOSE.equals(r.get("purpose"));
        boolean v2 = r.get("v") instanceof Number n2 && n2.doubleValue() == 2 && ACTION_RECEIPT_PURPOSE_V2.equals(r.get("purpose"));
        if (!v1 && !v2) return "unknown receipt version";
        for (String k : List.of("agentDid", "action", "argsSha256", "at", "signature")) {
            if (!Conversation.isNonEmpty(r.get(k))) return k + " must be a non-empty string";
        }
        if (!(r.get("tainted") instanceof Boolean)) return "tainted must be a boolean";
        if (r.containsKey("provenance")
                && !(r.get("provenance") instanceof List<?> p && p.stream().allMatch(x -> x instanceof String))) {
            return "provenance must be a list of strings";
        }
        for (String k : List.of("mandateId", "mandateGrantor", "correlationId")) {
            if (r.containsKey(k) && !(r.get(k) instanceof String)) return k + " must be a string";
        }
        if (r.containsKey("approval")) {
            if (!(r.get("approval") instanceof Map<?, ?> a)) return "approval must be an object";
            for (String k : List.of("approverDid", "approvedAt", "approvalId")) {
                if (!(a.get(k) instanceof String)) return "approval." + k + " must be a string";
            }
            Set<String> allowed = v2 ? APPROVAL_V2 : APPROVAL_V1;
            String extra = Conversation.unknownField(a, allowed);
            if (extra != null) return "approval has unknown field \"" + extra + "\"";
            if (a.containsKey("presentedHash") && !isSha256Hex(a.get("presentedHash"))) {
                return "approval.presentedHash must be SHA-256 hex";
            }
            if (a.containsKey("approverSignature") && !(a.get("approverSignature") instanceof String)) {
                return "approval.approverSignature must be a string";
            }
        }
        if (v2) {
            for (String k : List.of("requesterDid", "principalDid", "executorDid", "traceparent", "roomId", "onBehalfOf")) {
                if (r.containsKey(k) && !Conversation.isNonEmpty(r.get(k))) return k + " must be a non-empty string";
            }
            if (r.containsKey("presentedHash") && !isSha256Hex(r.get("presentedHash"))) return "presentedHash must be SHA-256 hex";
            Object outcome = r.get("outcome");
            if (!"executed".equals(outcome) && !"denied".equals(outcome)) return "outcome must be \"executed\" or \"denied\"";
            if ("denied".equals(outcome) && !Conversation.isNonEmpty(r.get("denialReason"))) {
                return "a denied receipt requires a denialReason";
            }
            if ("executed".equals(outcome) && r.containsKey("denialReason")) {
                return "an executed receipt must not carry a denialReason";
            }
        }
        String extra = Conversation.unknownField(r, v2 ? KNOWN_V2 : KNOWN_V1);
        if (extra != null) return "unknown field \"" + extra + "\" for this version";
        return null;
    }

    private static boolean isSha256Hex(Object x) {
        return x instanceof String s && SHA256_HEX.matcher(s).matches();
    }

    /**
     * Verify a receipt's signature against its agent's key. A receipt whose
     * agent cannot be resolved is refused, never accepted on its own say-so.
     */
    public static ReceiptVerification verify(Object receipt, ReceiptKeyResolver resolvePublicKey) {
        String problem = checkShape(receipt);
        if (problem != null) return new ReceiptVerification(false, null, "the action receipt is malformed: " + problem);
        Map<String, Object> r = Conversation.asMap(receipt);
        byte[] key;
        try {
            key = resolvePublicKey.resolve((String) r.get("agentDid"));
        } catch (Exception e) {
            key = null;
        }
        if (key == null) {
            return new ReceiptVerification(false, null, "the action receipt's agent " + r.get("agentDid") + " has no resolvable key");
        }
        if (!Conversation.verifySig(r.get("signature"), Conversation.signingBytes(r), key)) {
            return new ReceiptVerification(false, null, "the action receipt's signature does not verify");
        }
        return new ReceiptVerification(true, r, null);
    }

    /** SHA-256 hex of JCS of the content shown for approval (null → {@code {}}). */
    public static String hashPresentedContent(Object content) {
        return Conversation.sha256Hex(Jcs.canonicalizeToBytes(content == null ? Map.of() : content));
    }

    /**
     * Check a VERIFIED v2 receipt against the content a party says was
     * presented for approval. Null when every presentedHash it carries (top
     * level and in {@code approval}) matches; a receipt with none is refused.
     */
    public static String verifyPresentedHash(Map<String, Object> receipt, Object presentedContent) {
        if (!(receipt.get("v") instanceof Number v && v.doubleValue() == 2)) return "a v1 action receipt carries no presentedHash";
        List<Object> hashes = new ArrayList<>();
        if (receipt.get("presentedHash") != null) hashes.add(receipt.get("presentedHash"));
        if (receipt.get("approval") instanceof Map<?, ?> a && a.get("presentedHash") != null) hashes.add(a.get("presentedHash"));
        if (hashes.isEmpty()) return "the action receipt carries no presentedHash";
        String actual = hashPresentedContent(presentedContent);
        for (Object h : hashes) {
            if (!actual.equals(h)) return "the content presented for approval differs from what the receipt records";
        }
        return null;
    }
}
