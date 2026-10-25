// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

package com.arohalabs.crypto;

import java.math.BigDecimal;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;

/**
 * RFC 8785 JSON Canonicalization Scheme (JCS), byte-for-byte compatible with
 * {@code canonicalizeJcs} in {@code @aroha-sdk/core} (crypto/jcs.ts).
 *
 * <p>Input is a JSON value tree as Jackson produces it when reading into
 * {@code Object}: {@link Map} (String keys), {@link Iterable} or array,
 * {@link String}, {@link Number}, {@link Boolean} and {@code null}.
 *
 * <p>The rules, and how each is met:
 * <ul>
 *   <li>Object keys sorted by UTF-16 code units. {@link String#compareTo} compares
 *       UTF-16 code units, which is exactly the RFC's ordering (not code-point
 *       or locale order).</li>
 *   <li>Numbers are serialised with the ECMAScript Number-to-String algorithm
 *       (ECMA-262 Number::toString): every number is first taken as an IEEE-754
 *       double, as JavaScript would, then written in its shortest round-trip
 *       form ({@code 100.0 -> "100"}, {@code 1e21 -> "1e+21"},
 *       {@code 1e-7 -> "1e-7"}, {@code -0 -> "0"}). NaN and infinities are
 *       rejected.</li>
 *   <li>Strings are escaped as JSON.stringify does: the two-character escapes
 *       for backspace, tab, newline, form feed, carriage return, quote and
 *       backslash; other control characters as a six-character escape with
 *       lowercase hex (backslash, "u00", two hex digits); nothing else.
 *       Lone surrogates are rejected (I-JSON, RFC 7493).</li>
 *   <li>No insignificant whitespace.</li>
 * </ul>
 *
 * <p>A Java {@code Map} cannot tell "absent" from "null"; a {@code null} map
 * value is written as {@code null}. Callers that model optional fields as
 * Java nulls must drop them before canonicalising (the SDK's
 * {@code ArohaMandateCredential} does this through a NON_NULL Jackson
 * mapper), which matches how JSON.stringify drops {@code undefined}.
 */
public final class Jcs {

    private Jcs() {}

    /** RFC 8785 canonical JSON text of {@code value}. */
    public static String canonicalize(Object value) {
        StringBuilder sb = new StringBuilder();
        write(sb, value, "$", JCS);
        return sb.toString();
    }

    /** UTF-8 bytes of {@link #canonicalize(Object)}. */
    public static byte[] canonicalizeToBytes(Object value) {
        return canonicalize(value).getBytes(StandardCharsets.UTF_8);
    }

    /**
     * Compact JSON in the map's own iteration order, with the same number and
     * string formatting as JCS — the equivalent of JavaScript's
     * {@code JSON.stringify(value)}. Used for token bodies, whose bytes are
     * not signed but are nicer to keep identical to the TypeScript SDK's.
     */
    public static String stringify(Object value) {
        StringBuilder sb = new StringBuilder();
        write(sb, value, "$", INSERTION);
        return sb.toString();
    }

    // ── Serialisation ────────────────────────────────────────────────────────

    private static final int INSERTION = 0, JCS = 1, JS_SORTED = 2;

    /**
     * Byte-exact port of TypeScript {@code JSON.stringify(sortKeysDeep(value))}
     * — the canonical form Aroha envelope signatures cover. Equal to
     * {@link #canonicalize(Object)} except for key order: JavaScript
     * enumerates "array index" keys (canonical decimal integers
     * 0 … 2^32-2) FIRST, in ascending numeric order, then the rest in UTF-16
     * order. {@code {"b":1,"10":2,"2":3}} becomes {@code {"2":3,"10":2,"b":1}}.
     */
    public static String stringifySorted(Object value) {
        StringBuilder sb = new StringBuilder();
        write(sb, value, "$", JS_SORTED);
        return sb.toString();
    }

    /** True for an ECMAScript array index: canonical decimal integer in [0, 2^32-2]. */
    public static boolean isArrayIndex(String k) {
        if (k.isEmpty() || k.length() > 10) return false;
        if (k.length() > 1 && k.charAt(0) == '0') return false;
        for (int i = 0; i < k.length(); i++) {
            char c = k.charAt(i);
            if (c < '0' || c > '9') return false;
        }
        return Long.parseLong(k) <= 4_294_967_294L;
    }

    private static void sortJsKeys(List<String> keys) {
        Collections.sort(keys);
        List<String> idx = new ArrayList<>(), rest = new ArrayList<>();
        for (String k : keys) (isArrayIndex(k) ? idx : rest).add(k);
        idx.sort(java.util.Comparator.comparingLong(Long::parseLong));
        keys.clear();
        keys.addAll(idx);
        keys.addAll(rest);
    }

    private static void write(StringBuilder sb, Object value, String path, int sort) {
        if (value == null) {
            sb.append("null");
        } else if (value instanceof Boolean b) {
            sb.append(b ? "true" : "false");
        } else if (value instanceof Number n) {
            sb.append(formatNumber(toDouble(n, path), path));
        } else if (value instanceof CharSequence s) {
            writeString(sb, s.toString(), path);
        } else if (value instanceof Map<?, ?> map) {
            List<String> keys = new ArrayList<>(map.size());
            for (Object k : map.keySet()) {
                if (!(k instanceof String ks)) {
                    throw new IllegalArgumentException("JCS: non-string object key at " + path);
                }
                keys.add(ks);
            }
            if (sort == JCS) Collections.sort(keys); // String.compareTo = UTF-16 code unit order
            else if (sort == JS_SORTED) sortJsKeys(keys);
            sb.append('{');
            boolean first = true;
            for (String k : keys) {
                if (!first) sb.append(',');
                first = false;
                writeString(sb, k, path + " (key)");
                sb.append(':');
                write(sb, map.get(k), path + "." + k, sort);
            }
            sb.append('}');
        } else if (value instanceof Iterable<?> it) {
            sb.append('[');
            int i = 0;
            for (Object v : it) {
                if (i > 0) sb.append(',');
                write(sb, v, path + "[" + i + "]", sort);
                i++;
            }
            sb.append(']');
        } else if (value instanceof Object[] arr) {
            write(sb, java.util.Arrays.asList(arr), path, sort);
        } else {
            throw new IllegalArgumentException(
                "JCS: value of type " + value.getClass().getName() + " at " + path + " is not JSON");
        }
    }

    private static double toDouble(Number n, String path) {
        // Every JSON number is an IEEE-754 double in JavaScript; convert
        // integers and decimals the same way so the output matches.
        if (n instanceof BigDecimal bd) return bd.doubleValue();
        if (n instanceof BigInteger bi) return bi.doubleValue();
        return n.doubleValue();
    }

    /**
     * ECMAScript Number::toString(10) for a finite double.
     *
     * <p>Java 19+ {@link Double#toString(double)} yields the shortest decimal
     * that round-trips (JDK-4511638), which is the digit string ECMAScript
     * also requires; only the layout (where the point goes, when to use an
     * exponent) differs, and is rebuilt here from the digits and exponent.
     */
    public static String formatNumber(double d) {
        return formatNumber(d, "$");
    }

    private static String formatNumber(double d, String path) {
        if (Double.isNaN(d) || Double.isInfinite(d)) {
            throw new IllegalArgumentException("JCS: non-finite number at " + path + " cannot be canonicalised");
        }
        if (d == 0) return "0"; // also -0
        boolean negative = d < 0;
        BigDecimal bd = new BigDecimal(Double.toString(Math.abs(d))).stripTrailingZeros();
        String digits = bd.unscaledValue().toString();
        int k = digits.length();
        // value = digits × 10^(-scale) = 0.digits × 10^n  ⇒  n = k - scale
        int n = k - bd.scale();

        // Java's algorithm prefers a 2-digit result when a 1-digit one exists
        // (javadoc of Double.toString: "when n = 1, let T be the set of all
        // decimals in R with length 2"); ECMAScript takes the 1-digit one. The
        // two only differ at the extremes of the subnormal range, e.g.
        // Double.MIN_VALUE is "4.9E-324" in Java and "5e-324" in JavaScript.
        if (k == 2) {
            double abs = Math.abs(d);
            BigDecimal exact = new BigDecimal(abs);
            int lo = digits.charAt(0) - '0';
            String best = null;
            int bestN = n;
            BigDecimal bestDist = null;
            for (int c = lo; c <= lo + 1; c++) {
                String cd = c == 10 ? "1" : Integer.toString(c);
                int cn = c == 10 ? n + 1 : n;
                BigDecimal cand = new BigDecimal(cd).scaleByPowerOfTen(cn - 1);
                if (cand.doubleValue() != abs) continue;
                BigDecimal dist = cand.subtract(exact).abs();
                if (bestDist == null || dist.compareTo(bestDist) < 0) {
                    best = cd; bestN = cn; bestDist = dist;
                }
            }
            if (best != null) { digits = best; k = 1; n = bestN; }
        }

        StringBuilder sb = new StringBuilder(24);
        if (negative) sb.append('-');
        if (k <= n && n <= 21) {
            sb.append(digits);
            for (int i = 0; i < n - k; i++) sb.append('0');
        } else if (0 < n && n <= 21) {
            sb.append(digits, 0, n).append('.').append(digits, n, k);
        } else if (-6 < n && n <= 0) {
            sb.append("0.");
            for (int i = 0; i < -n; i++) sb.append('0');
            sb.append(digits);
        } else {
            int e = n - 1;
            sb.append(digits.charAt(0));
            if (k > 1) sb.append('.').append(digits, 1, k);
            sb.append('e').append(e < 0 ? '-' : '+').append(Math.abs(e));
        }
        return sb.toString();
    }

    private static final char[] HEX = "0123456789abcdef".toCharArray();

    private static void writeString(StringBuilder sb, String s, String path) {
        sb.append('"');
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (Character.isHighSurrogate(c)) {
                if (i + 1 < s.length() && Character.isLowSurrogate(s.charAt(i + 1))) {
                    sb.append(c).append(s.charAt(++i));
                    continue;
                }
                throw new IllegalArgumentException("JCS: lone high surrogate in string at " + path);
            }
            if (Character.isLowSurrogate(c)) {
                throw new IllegalArgumentException("JCS: lone low surrogate in string at " + path);
            }
            switch (c) {
                case '"'  -> sb.append("\\\"");
                case '\\' -> sb.append("\\\\");
                case '\b' -> sb.append("\\b");
                case '\f' -> sb.append("\\f");
                case '\n' -> sb.append("\\n");
                case '\r' -> sb.append("\\r");
                case '\t' -> sb.append("\\t");
                default -> {
                    if (c < 0x20) {
                        sb.append("\\u00").append(HEX[c >> 4]).append(HEX[c & 0xF]);
                    } else {
                        sb.append(c);
                    }
                }
            }
        }
        sb.append('"');
    }
}
