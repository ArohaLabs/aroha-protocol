// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

package com.arohalabs.messages;

import com.arohalabs.TestSupport;
import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashSet;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

class MessageTypesTest {

    static final Path TYPES_TS = TestSupport.repoFile("packages/aroha-core/src/messages/types.ts");

    @Test
    void counts() {
        assertEquals(19, MessageTypes.ALL.size());
        assertEquals(28, MessageTypes.ErrorCode.ALL.size());
        assertEquals("https://aroha-labs.com/docs/errors#Aroha_FORBIDDEN",
            MessageTypes.ErrorCode.docsUrl(MessageTypes.ErrorCode.FORBIDDEN));
    }

    /** The Java constants are exactly the TypeScript reference's wire values. */
    @Test
    void matchTypeScriptReference() throws Exception {
        assumeTrue(TestSupport.exists(TYPES_TS), "types.ts not found at " + TYPES_TS);
        String src = Files.readString(TYPES_TS);

        String union = section(src, "export type ArohaMessageType =", ";");
        assertEquals(collect(union, "\\|\\s*\"([A-Za-z]+)\""), MessageTypes.ALL);

        String enumBody = section(src, "export enum ArohaErrorCode {", "\n}");
        assertEquals(collect(enumBody, "=\\s*\"([A-Za-z_]+)\""), MessageTypes.ErrorCode.ALL);
    }

    private static String section(String src, String start, String end) {
        int s = src.indexOf(start);
        assertTrue(s >= 0, start);
        int e = src.indexOf(end, s + start.length());
        return src.substring(s + start.length(), e);
    }

    private static Set<String> collect(String text, String regex) {
        Set<String> out = new HashSet<>();
        Matcher m = Pattern.compile(regex).matcher(text);
        while (m.find()) out.add(m.group(1));
        return out;
    }
}
