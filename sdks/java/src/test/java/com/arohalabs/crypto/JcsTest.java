// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

package com.arohalabs.crypto;

import com.arohalabs.TestSupport;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import java.math.BigDecimal;
import java.nio.file.Path;
import java.util.*;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

class JcsTest {

    static final Path VECTORS = TestSupport.repoFile("packages/aroha-credentials/test-vectors/mandate-v2.json");

    @TestFactory
    @SuppressWarnings("unchecked")
    Stream<DynamicTest> sharedJcsVectors() throws Exception {
        assumeTrue(TestSupport.exists(VECTORS), "mandate-v2.json not found at " + VECTORS);
        List<Map<String, Object>> cases = (List<Map<String, Object>>) TestSupport.readJson(VECTORS).get("jcs");
        assertFalse(cases.isEmpty());
        return cases.stream().map(c -> DynamicTest.dynamicTest((String) c.get("name"), () ->
            assertEquals(c.get("expected"), Jcs.canonicalize(TestSupport.parse((String) c.get("input"))))));
    }

    @ParameterizedTest(name = "{0} -> {1}")
    @CsvSource(delimiter = '|', value = {
        "100.0                  | 100",
        "42.50                  | 42.5",
        "42.07                  | 42.07",
        "0.1                    | 0.1",
        "-0.0                   | 0",
        "1e21                   | 1e+21",
        "1e20                   | 100000000000000000000",
        "123456789012345680000  | 123456789012345680000",
        "1e-6                   | 0.000001",
        "1e-7                   | 1e-7",
        "1.5e-7                 | 1.5e-7",
        "-1.5                   | -1.5",
        "333333333.33333329     | 333333333.3333333",
        "1E30                   | 1e+30",
        "0.000000000000000000000000001 | 1e-27",
        "4.9E-324               | 5e-324",
        "1.7976931348623157E308 | 1.7976931348623157e+308",
        "9007199254740993       | 9007199254740992",
    })
    void ecmaScriptNumberFormatting(String input, String expected) {
        assertEquals(expected, Jcs.formatNumber(new BigDecimal(input.trim()).doubleValue()));
    }

    @Test
    void sumIsShortestRoundTrip() {
        assertEquals("0.30000000000000004", Jcs.formatNumber(0.1 + 0.2));
    }

    @Test
    void integerTypesFormatAsJavaScriptNumbers() {
        assertEquals("[1,9007199254740992,500]", Jcs.canonicalize(List.of(1, 9007199254740993L, new BigDecimal("500.00"))));
    }

    @Test
    void rejectsNonFiniteNumbers() {
        assertThrows(IllegalArgumentException.class, () -> Jcs.canonicalize(Double.NaN));
        assertThrows(IllegalArgumentException.class, () -> Jcs.canonicalize(Map.of("a", Double.POSITIVE_INFINITY)));
    }

    @Test
    void stringEscapingMatchesJsonStringify() {
        assertEquals("\"\\u000f\\n\\t\\b\\f\\r\\\"\\\\/\u007f\u00e9\"",
            Jcs.canonicalize("\u000f\n\t\b\f\r\"\\/\u007f\u00e9"));
        assertEquals("\"\\u001f\"", Jcs.canonicalize("\u001f"));
    }

    @Test
    void rejectsLoneSurrogates() {
        assertThrows(IllegalArgumentException.class, () -> Jcs.canonicalize("a\ud800b"));
        assertThrows(IllegalArgumentException.class, () -> Jcs.canonicalize("\udc00"));
        assertThrows(IllegalArgumentException.class, () -> Jcs.canonicalize(Map.of("\ud83d", 1)));
        assertEquals("\"\ud83d\ude00\"", Jcs.canonicalize("\ud83d\ude00"));
    }

    @Test
    void keysSortByUtf16CodeUnitsAtEveryDepth() {
        Map<String, Object> inner = new LinkedHashMap<>();
        inner.put("b", 1);
        inner.put("a", List.of(Map.of("z", true, "y", false)));
        Map<String, Object> outer = new LinkedHashMap<>();
        // U+1F600 (surrogate D83D) sorts BEFORE U+FB33 by code unit, after it by code point.
        outer.put("\ufb33", 1);
        outer.put("\ud83d\ude00", 2);
        outer.put("x", inner);
        assertEquals("{\"x\":{\"a\":[{\"y\":false,\"z\":true}],\"b\":1},\"\ud83d\ude00\":2,\"\ufb33\":1}",
            Jcs.canonicalize(outer));
    }

    @Test
    void nullMapValuesAreWrittenAndStringifyKeepsInsertionOrder() {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("z", null);
        m.put("a", 100.0);
        assertEquals("{\"a\":100,\"z\":null}", Jcs.canonicalize(m));
        assertEquals("{\"z\":null,\"a\":100}", Jcs.stringify(m));
    }

    @Test
    void rejectsNonJsonValues() {
        assertThrows(IllegalArgumentException.class, () -> Jcs.canonicalize(new Object()));
        assertThrows(IllegalArgumentException.class, () -> Jcs.canonicalize(Map.of(1, "a")));
    }
}
