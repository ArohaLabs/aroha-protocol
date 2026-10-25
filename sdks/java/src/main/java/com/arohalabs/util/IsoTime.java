// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

package com.arohalabs.util;

import java.time.Instant;
import java.time.LocalDate;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;

/**
 * ISO 8601 timestamps the way the TypeScript SDK writes and reads them.
 *
 * <p>Writing: {@code Date.prototype.toISOString()} always emits millisecond
 * precision ({@code 2026-01-01T00:00:00.000Z}), while {@link Instant#toString()}
 * drops a zero fraction and may emit micro/nanoseconds. Timestamps are inside
 * signed bytes, so the exact form matters; {@link #format(Instant)} matches JS.
 *
 * <p>Reading: {@link #parseMillis(String)} accepts an instant with a zone
 * designator ({@code Z} or an offset) or a bare date (UTC midnight, as
 * {@code Date.parse} treats it), and returns null for anything else.
 */
public final class IsoTime {

    private IsoTime() {}

    private static final DateTimeFormatter JS_ISO =
        DateTimeFormatter.ofPattern("uuuu-MM-dd'T'HH:mm:ss.SSS'Z'").withZone(ZoneOffset.UTC);

    /** {@code toISOString()} form: UTC, exactly three fractional digits. */
    public static String format(Instant instant) {
        return JS_ISO.format(instant.truncatedTo(ChronoUnit.MILLIS));
    }

    /** {@code new Date(ms).toISOString()}. */
    public static String formatMillis(long epochMillis) {
        return format(Instant.ofEpochMilli(epochMillis));
    }

    /** Current time in {@code toISOString()} form. */
    public static String now() {
        return format(Instant.now());
    }

    /** Epoch milliseconds, or null when {@code s} is not a parseable ISO 8601 date. */
    public static Long parseMillis(Object s) {
        if (!(s instanceof String str) || str.isEmpty()) return null;
        try {
            return Instant.parse(str).toEpochMilli();
        } catch (Exception ignored) { /* try the next form */ }
        try {
            return OffsetDateTime.parse(str).toInstant().toEpochMilli();
        } catch (Exception ignored) { /* try the next form */ }
        try {
            return LocalDate.parse(str).atStartOfDay(ZoneOffset.UTC).toInstant().toEpochMilli();
        } catch (Exception ignored) { /* not a date */ }
        return null;
    }
}
