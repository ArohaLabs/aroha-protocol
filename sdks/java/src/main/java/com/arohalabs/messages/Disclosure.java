// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

package com.arohalabs.messages;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

/**
 * ArohaDisclosure — a per-hop statement "I am an AI agent, and this is the
 * principal I act for" (TS {@code messages/disclosure.ts}).
 *
 * <p>Carried as the optional {@code disclosure} field of an envelope (where the
 * envelope signature covers it) and as the {@code disclosure} of a
 * conversation room. The signature proves the agent MADE the statement; it
 * does not prove {@code principalDid} authorised the agent — that is a
 * mandate chain's job.
 *
 * <p>Wire shape: {@code {v: 1, agentDid, principalDid, principalKind:
 * "person"|"organization", purpose (≤512 chars), hop (integer ≥ 0),
 * aiGenerated: true}}. Unknown fields are refused, not ignored.
 */
public final class Disclosure {

    private Disclosure() {}

    public static final int DISCLOSURE_VERSION = 1;
    public static final int MAX_DISCLOSURE_PURPOSE_LENGTH = 512;

    private static final Set<String> KNOWN_FIELDS =
        Set.of("v", "agentDid", "principalDid", "principalKind", "purpose", "hop", "aiGenerated");

    /** Build a disclosure object; throws {@link IllegalArgumentException} on input {@link #validate} refuses. */
    public static Map<String, Object> build(String agentDid, String principalDid, String principalKind,
                                            String purpose, int hop) {
        Map<String, Object> d = new LinkedHashMap<>();
        d.put("v", DISCLOSURE_VERSION);
        d.put("agentDid", agentDid);
        d.put("principalDid", principalDid);
        d.put("principalKind", principalKind);
        d.put("purpose", purpose);
        d.put("hop", hop);
        d.put("aiGenerated", true);
        String problem = validate(d, null);
        if (problem != null) throw new IllegalArgumentException("Invalid disclosure: " + problem);
        return d;
    }

    /** {@link #validate(Object, String)} without the sender check. */
    public static String validate(Object value) {
        return validate(value, null);
    }

    /**
     * Structural check of an untrusted disclosure. Null when valid, else the
     * reason. With {@code expectedAgentDid} (an envelope's {@code from}), also
     * refuses a disclosure made in another agent's name.
     */
    public static String validate(Object value, String expectedAgentDid) {
        if (!(value instanceof Map<?, ?> d)) return "disclosure is not an object";
        if (!(d.get("v") instanceof Number v) || v.doubleValue() != DISCLOSURE_VERSION) {
            return "unsupported disclosure version " + d.get("v");
        }
        for (String k : new String[]{"agentDid", "principalDid", "purpose"}) {
            if (!(d.get(k) instanceof String s) || s.isEmpty()) return k + " must be a non-empty string";
        }
        if (!((String) d.get("agentDid")).startsWith("did:") || !((String) d.get("principalDid")).startsWith("did:")) {
            return "agentDid and principalDid must be DIDs";
        }
        String purpose = (String) d.get("purpose");
        // JS string length counts UTF-16 code units, as String.length() does.
        if (purpose.length() > MAX_DISCLOSURE_PURPOSE_LENGTH) {
            return "purpose exceeds " + MAX_DISCLOSURE_PURPOSE_LENGTH + " characters";
        }
        Object kind = d.get("principalKind");
        if (!"person".equals(kind) && !"organization".equals(kind)) {
            return "principalKind must be \"person\" or \"organization\"";
        }
        if (!isNonNegativeInteger(d.get("hop"))) return "hop must be a non-negative integer";
        if (!Boolean.TRUE.equals(d.get("aiGenerated"))) return "aiGenerated must be true";
        for (Object k : d.keySet()) {
            if (!KNOWN_FIELDS.contains(k)) return "unknown field \"" + k + "\"";
        }
        if (expectedAgentDid != null && !expectedAgentDid.equals(d.get("agentDid"))) {
            return "disclosure names agent " + d.get("agentDid") + ", not the sender " + expectedAgentDid;
        }
        return null;
    }

    /** JavaScript {@code Number.isInteger(x) && x >= 0} on a decoded JSON value. */
    static boolean isNonNegativeInteger(Object x) {
        if (!(x instanceof Number n)) return false;
        double d = n.doubleValue();
        return Double.isFinite(d) && d == Math.floor(d) && d >= 0;
    }
}
