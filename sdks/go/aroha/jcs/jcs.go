// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

// Package jcs implements the RFC 8785 JSON Canonicalization Scheme.
//
// A signature is portable only if every SDK produces the same bytes for the
// same value. Mandate v2 tokens and Key Event Log events are signed over JCS,
// so this package must agree byte for byte with @aroha-sdk/core's
// canonicalizeJcs (packages/aroha-core/src/crypto/jcs.ts):
//
//   - Object keys are sorted by UTF-16 code units, not by UTF-8 bytes or code
//     points. The two orders differ for keys outside the Basic Multilingual
//     Plane (an astral key sorts by its surrogate pair, i.e. before U+E000).
//   - Numbers use the ECMAScript Number-to-String algorithm (ECMA-262
//     7.1.12.1): shortest round-trip digits, plain notation for decimal
//     exponents in [-6, 21), exponent notation with an explicit sign
//     otherwise, and -0 written as 0. strconv's 'g' format is NOT the same
//     rule (it switches to exponent form at different thresholds and pads the
//     exponent), so FormatNumber implements the ECMAScript rule directly.
//     NaN and infinities are rejected.
//   - Strings are escaped exactly as JSON.stringify escapes them: \b \t \n \f
//     \r \" \\ and \u00xx (lower-case hex) for the remaining C0 controls,
//     nothing else. In particular < > & U+2028 U+2029 are written literally;
//     encoding/json escapes all five, which is why this package never lets
//     encoding/json produce output bytes.
//   - Lone surrogates (an escaped \ud800 with no partner) and invalid UTF-8
//     are rejected: RFC 8785 requires I-JSON (RFC 7493).
//   - Duplicate object keys are rejected (I-JSON, RFC 7493 section 2.3).
//   - No insignificant whitespace.
package jcs

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

// Transform canonicalises a JSON text. The input is parsed strictly (see
// Parse) and re-serialised under RFC 8785.
func Transform(data []byte) ([]byte, error) {
	v, err := Parse(data)
	if err != nil {
		return nil, err
	}
	return Canonicalize(v)
}

// Canonicalize returns the RFC 8785 canonical form of v.
//
// The JSON data model values that Parse returns (nil, bool, float64,
// json.Number, string, []any, map[string]any) are serialised directly, as
// are Go integer types. Any other value (structs, typed maps and slices) is
// first encoded with encoding/json and re-parsed, so struct tags such as
// omitempty decide which fields exist; only the parsed data model is ever
// written out. A nil pointer, a nil map or a nil interface becomes null.
func Canonicalize(v any) ([]byte, error) {
	var buf bytes.Buffer
	if err := write(&buf, v, "$"); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// MustCanonicalize is Canonicalize for values known to be canonicalisable;
// it panics on error.
func MustCanonicalize(v any) []byte {
	b, err := Canonicalize(v)
	if err != nil {
		panic(err)
	}
	return b
}

func write(buf *bytes.Buffer, v any, path string) error { return writeMode(buf, v, path, false) }

// writeMode writes v; js selects JavaScript key order (see StringifySorted).
func writeMode(buf *bytes.Buffer, v any, path string, js bool) error {
	switch x := v.(type) {
	case nil:
		buf.WriteString("null")
	case bool:
		if x {
			buf.WriteString("true")
		} else {
			buf.WriteString("false")
		}
	case float64:
		s, err := FormatNumber(x)
		if err != nil {
			return fmt.Errorf("jcs: %s: %w", path, err)
		}
		buf.WriteString(s)
	case float32:
		return writeMode(buf, float64(x), path, js)
	case int:
		return writeMode(buf, float64(x), path, js)
	case int8:
		return writeMode(buf, float64(x), path, js)
	case int16:
		return writeMode(buf, float64(x), path, js)
	case int32:
		return writeMode(buf, float64(x), path, js)
	case int64:
		return writeMode(buf, float64(x), path, js)
	case uint:
		return writeMode(buf, float64(x), path, js)
	case uint8:
		return writeMode(buf, float64(x), path, js)
	case uint16:
		return writeMode(buf, float64(x), path, js)
	case uint32:
		return writeMode(buf, float64(x), path, js)
	case uint64:
		return writeMode(buf, float64(x), path, js)
	case json.Number:
		f, err := parseNumber(string(x))
		if err != nil {
			return fmt.Errorf("jcs: %s: %w", path, err)
		}
		return writeMode(buf, f, path, js)
	case string:
		return writeString(buf, x, path)
	case []any:
		if x == nil {
			buf.WriteString("null") // as encoding/json sends it
			return nil
		}
		buf.WriteByte('[')
		for i, e := range x {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := writeMode(buf, e, fmt.Sprintf("%s[%d]", path, i), js); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
	case map[string]any:
		if x == nil {
			buf.WriteString("null") // as encoding/json sends it
			return nil
		}
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		if js {
			sortJSKeys(keys)
		} else {
			SortKeys(keys)
		}
		buf.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := writeString(buf, k, path+" (key)"); err != nil {
				return err
			}
			buf.WriteByte(':')
			if err := writeMode(buf, x[k], path+"."+k, js); err != nil {
				return err
			}
		}
		buf.WriteByte('}')
	default:
		rv := reflect.ValueOf(v)
		if (rv.Kind() == reflect.Pointer || rv.Kind() == reflect.Map ||
			rv.Kind() == reflect.Slice || rv.Kind() == reflect.Interface) && rv.IsNil() {
			buf.WriteString("null")
			return nil
		}
		raw, err := json.Marshal(v)
		if err != nil {
			return fmt.Errorf("jcs: %s: %w", path, err)
		}
		parsed, err := Parse(raw)
		if err != nil {
			return fmt.Errorf("jcs: %s: %w", path, err)
		}
		return writeMode(buf, parsed, path, js)
	}
	return nil
}

// StringifySorted is a byte-exact port of TypeScript
// JSON.stringify(sortKeysDeep(value)) — the canonical form Aroha envelope
// signatures cover. It equals Canonicalize except for key order: JavaScript
// enumerates "array index" keys (canonical decimal integers 0 … 2^32-2)
// FIRST, in ascending numeric order, then the remaining keys in insertion
// order, which sortKeysDeep made UTF-16 order. So {"b":1,"10":2,"2":3}
// becomes {"2":3,"10":2,"b":1}, where JCS would give {"10":2,"2":3,"b":1}.
func StringifySorted(v any) ([]byte, error) {
	var buf bytes.Buffer
	if err := writeMode(&buf, v, "$", true); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// IsArrayIndex reports whether k is an ECMAScript array index: the canonical
// decimal string of an integer in [0, 2^32-2].
func IsArrayIndex(k string) bool {
	if k == "" || len(k) > 10 {
		return false
	}
	if len(k) > 1 && k[0] == '0' {
		return false
	}
	var n uint64
	for i := 0; i < len(k); i++ {
		c := k[i]
		if c < '0' || c > '9' {
			return false
		}
		n = n*10 + uint64(c-'0')
	}
	return n <= 4294967294
}

func sortJSKeys(keys []string) {
	SortKeys(keys)
	var idx, rest []string
	for _, k := range keys {
		if IsArrayIndex(k) {
			idx = append(idx, k)
		} else {
			rest = append(rest, k)
		}
	}
	sort.SliceStable(idx, func(i, j int) bool {
		if len(idx[i]) != len(idx[j]) {
			return len(idx[i]) < len(idx[j])
		}
		return idx[i] < idx[j]
	})
	copy(keys, append(idx, rest...))
}

// SortKeys sorts object keys in RFC 8785 order: by UTF-16 code units.
func SortKeys(keys []string) {
	sort.Slice(keys, func(i, j int) bool { return lessUTF16(keys[i], keys[j]) })
}

func lessUTF16(a, b string) bool {
	ua := utf16.Encode([]rune(a))
	ub := utf16.Encode([]rune(b))
	for i := 0; i < len(ua) && i < len(ub); i++ {
		if ua[i] != ub[i] {
			return ua[i] < ub[i]
		}
	}
	return len(ua) < len(ub)
}

const hexDigits = "0123456789abcdef"

func writeString(buf *bytes.Buffer, s, path string) error {
	if !utf8.ValidString(s) {
		return fmt.Errorf("jcs: %s: string is not valid UTF-8", path)
	}
	for _, r := range s {
		if r >= 0xD800 && r <= 0xDFFF {
			// Unreachable for a valid UTF-8 Go string, kept as a guard.
			return fmt.Errorf("jcs: %s: lone surrogate in string", path)
		}
	}
	buf.WriteByte('"')
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch c {
		case '"':
			buf.WriteString(`\"`)
		case '\\':
			buf.WriteString(`\\`)
		case '\b':
			buf.WriteString(`\b`)
		case '\f':
			buf.WriteString(`\f`)
		case '\n':
			buf.WriteString(`\n`)
		case '\r':
			buf.WriteString(`\r`)
		case '\t':
			buf.WriteString(`\t`)
		default:
			if c < 0x20 {
				buf.WriteString(`\u00`)
				buf.WriteByte(hexDigits[c>>4])
				buf.WriteByte(hexDigits[c&0xF])
			} else {
				buf.WriteByte(c)
			}
		}
	}
	buf.WriteByte('"')
	return nil
}

// FormatNumber serialises a float64 with the ECMAScript Number-to-String
// algorithm (ECMA-262 7.1.12.1), which RFC 8785 section 3.2.2.3 adopts.
func FormatNumber(f float64) (string, error) {
	if math.IsNaN(f) || math.IsInf(f, 0) {
		return "", errors.New("non-finite number cannot be canonicalised")
	}
	if f == 0 {
		return "0", nil // also -0
	}
	sign := ""
	if f < 0 {
		sign = "-"
		f = -f
	}
	// Shortest digits that round-trip, as d.ddddde±XX.
	e := strconv.FormatFloat(f, 'e', -1, 64)
	mant, expStr, ok := strings.Cut(e, "e")
	if !ok {
		return "", fmt.Errorf("unexpected float format %q", e)
	}
	digits := strings.Replace(mant, ".", "", 1)
	exp, err := strconv.Atoi(expStr)
	if err != nil {
		return "", err
	}
	k := len(digits)
	n := exp + 1 // value = 0.digits * 10^n

	var out string
	switch {
	case k <= n && n <= 21:
		out = digits + strings.Repeat("0", n-k)
	case 0 < n && n <= 21:
		out = digits[:n] + "." + digits[n:]
	case -6 < n && n <= 0:
		out = "0." + strings.Repeat("0", -n) + digits
	default:
		e := n - 1
		es := "+"
		if e < 0 {
			es = "-"
			e = -e
		}
		if k == 1 {
			out = digits + "e" + es + strconv.Itoa(e)
		} else {
			out = digits[:1] + "." + digits[1:] + "e" + es + strconv.Itoa(e)
		}
	}
	return sign + out, nil
}

// ─── Strict parser ────────────────────────────────────────────────────────────

// Parse decodes a JSON text into the JSON data model: nil, bool, float64,
// string, []any and map[string]any. Unlike encoding/json it rejects what
// RFC 8785 / I-JSON forbid instead of repairing it: duplicate object keys,
// lone surrogate escapes, invalid UTF-8, numbers outside float64 range, and
// trailing data. Numbers are converted to float64 with correct rounding (the
// same value JSON.parse produces).
func Parse(data []byte) (any, error) {
	p := &parser{data: data}
	p.skipWS()
	v, err := p.value(0)
	if err != nil {
		return nil, err
	}
	p.skipWS()
	if p.pos != len(p.data) {
		return nil, p.errorf("unexpected trailing data")
	}
	return v, nil
}

const maxDepth = 1000

type parser struct {
	data []byte
	pos  int
}

func (p *parser) errorf(format string, args ...any) error {
	return fmt.Errorf("jcs: parse error at offset %d: %s", p.pos, fmt.Sprintf(format, args...))
}

func (p *parser) skipWS() {
	for p.pos < len(p.data) {
		switch p.data[p.pos] {
		case ' ', '\t', '\n', '\r':
			p.pos++
		default:
			return
		}
	}
}

func (p *parser) value(depth int) (any, error) {
	if depth > maxDepth {
		return nil, p.errorf("nesting too deep")
	}
	if p.pos >= len(p.data) {
		return nil, p.errorf("unexpected end of input")
	}
	switch c := p.data[p.pos]; {
	case c == '{':
		return p.object(depth)
	case c == '[':
		return p.array(depth)
	case c == '"':
		return p.str()
	case c == 't':
		return p.literal("true", true)
	case c == 'f':
		return p.literal("false", false)
	case c == 'n':
		return p.literal("null", nil)
	case c == '-' || (c >= '0' && c <= '9'):
		return p.number()
	default:
		return nil, p.errorf("unexpected character %q", c)
	}
}

func (p *parser) literal(word string, v any) (any, error) {
	if !bytes.HasPrefix(p.data[p.pos:], []byte(word)) {
		return nil, p.errorf("invalid literal")
	}
	p.pos += len(word)
	return v, nil
}

func (p *parser) object(depth int) (any, error) {
	p.pos++ // {
	obj := map[string]any{}
	p.skipWS()
	if p.pos < len(p.data) && p.data[p.pos] == '}' {
		p.pos++
		return obj, nil
	}
	for {
		p.skipWS()
		if p.pos >= len(p.data) || p.data[p.pos] != '"' {
			return nil, p.errorf("expected object key")
		}
		k, err := p.str()
		if err != nil {
			return nil, err
		}
		if _, dup := obj[k]; dup {
			return nil, p.errorf("duplicate object key %q", k)
		}
		p.skipWS()
		if p.pos >= len(p.data) || p.data[p.pos] != ':' {
			return nil, p.errorf("expected ':'")
		}
		p.pos++
		p.skipWS()
		v, err := p.value(depth + 1)
		if err != nil {
			return nil, err
		}
		obj[k] = v
		p.skipWS()
		if p.pos >= len(p.data) {
			return nil, p.errorf("unterminated object")
		}
		switch p.data[p.pos] {
		case ',':
			p.pos++
		case '}':
			p.pos++
			return obj, nil
		default:
			return nil, p.errorf("expected ',' or '}'")
		}
	}
}

func (p *parser) array(depth int) (any, error) {
	p.pos++ // [
	arr := []any{}
	p.skipWS()
	if p.pos < len(p.data) && p.data[p.pos] == ']' {
		p.pos++
		return arr, nil
	}
	for {
		p.skipWS()
		v, err := p.value(depth + 1)
		if err != nil {
			return nil, err
		}
		arr = append(arr, v)
		p.skipWS()
		if p.pos >= len(p.data) {
			return nil, p.errorf("unterminated array")
		}
		switch p.data[p.pos] {
		case ',':
			p.pos++
		case ']':
			p.pos++
			return arr, nil
		default:
			return nil, p.errorf("expected ',' or ']'")
		}
	}
}

func hexVal(c byte) (rune, bool) {
	switch {
	case c >= '0' && c <= '9':
		return rune(c - '0'), true
	case c >= 'a' && c <= 'f':
		return rune(c-'a') + 10, true
	case c >= 'A' && c <= 'F':
		return rune(c-'A') + 10, true
	}
	return 0, false
}

func (p *parser) hex4() (rune, error) {
	if p.pos+4 > len(p.data) {
		return 0, p.errorf("truncated \\u escape")
	}
	var r rune
	for i := 0; i < 4; i++ {
		h, ok := hexVal(p.data[p.pos+i])
		if !ok {
			return 0, p.errorf("invalid \\u escape")
		}
		r = r<<4 | h
	}
	p.pos += 4
	return r, nil
}

func (p *parser) str() (string, error) {
	p.pos++ // opening quote
	var sb strings.Builder
	for {
		if p.pos >= len(p.data) {
			return "", p.errorf("unterminated string")
		}
		c := p.data[p.pos]
		switch {
		case c == '"':
			p.pos++
			return sb.String(), nil
		case c == '\\':
			p.pos++
			if p.pos >= len(p.data) {
				return "", p.errorf("unterminated escape")
			}
			esc := p.data[p.pos]
			p.pos++
			switch esc {
			case '"', '\\', '/':
				sb.WriteByte(esc)
			case 'b':
				sb.WriteByte('\b')
			case 'f':
				sb.WriteByte('\f')
			case 'n':
				sb.WriteByte('\n')
			case 'r':
				sb.WriteByte('\r')
			case 't':
				sb.WriteByte('\t')
			case 'u':
				r, err := p.hex4()
				if err != nil {
					return "", err
				}
				if r >= 0xDC00 && r <= 0xDFFF {
					return "", p.errorf("lone low surrogate in string")
				}
				if r >= 0xD800 && r <= 0xDBFF {
					if p.pos+2 > len(p.data) || p.data[p.pos] != '\\' || p.data[p.pos+1] != 'u' {
						return "", p.errorf("lone high surrogate in string")
					}
					p.pos += 2
					lo, err := p.hex4()
					if err != nil {
						return "", err
					}
					if lo < 0xDC00 || lo > 0xDFFF {
						return "", p.errorf("lone high surrogate in string")
					}
					r = utf16.DecodeRune(r, lo)
				}
				sb.WriteRune(r)
			default:
				return "", p.errorf("invalid escape \\%c", esc)
			}
		case c < 0x20:
			return "", p.errorf("unescaped control character in string")
		case c < utf8.RuneSelf:
			sb.WriteByte(c)
			p.pos++
		default:
			r, size := utf8.DecodeRune(p.data[p.pos:])
			if r == utf8.RuneError && size <= 1 {
				return "", p.errorf("invalid UTF-8 in string")
			}
			sb.WriteRune(r)
			p.pos += size
		}
	}
}

func (p *parser) number() (any, error) {
	start := p.pos
	d := p.data
	if p.pos < len(d) && d[p.pos] == '-' {
		p.pos++
	}
	if p.pos >= len(d) {
		return nil, p.errorf("invalid number")
	}
	if d[p.pos] == '0' {
		p.pos++
	} else if d[p.pos] >= '1' && d[p.pos] <= '9' {
		for p.pos < len(d) && d[p.pos] >= '0' && d[p.pos] <= '9' {
			p.pos++
		}
	} else {
		return nil, p.errorf("invalid number")
	}
	if p.pos < len(d) && d[p.pos] == '.' {
		p.pos++
		n := p.pos
		for p.pos < len(d) && d[p.pos] >= '0' && d[p.pos] <= '9' {
			p.pos++
		}
		if p.pos == n {
			return nil, p.errorf("invalid number: no digits after '.'")
		}
	}
	if p.pos < len(d) && (d[p.pos] == 'e' || d[p.pos] == 'E') {
		p.pos++
		if p.pos < len(d) && (d[p.pos] == '+' || d[p.pos] == '-') {
			p.pos++
		}
		n := p.pos
		for p.pos < len(d) && d[p.pos] >= '0' && d[p.pos] <= '9' {
			p.pos++
		}
		if p.pos == n {
			return nil, p.errorf("invalid number: no exponent digits")
		}
	}
	f, err := parseNumber(string(d[start:p.pos]))
	if err != nil {
		return nil, p.errorf("%v", err)
	}
	return f, nil
}

func parseNumber(s string) (float64, error) {
	f, err := strconv.ParseFloat(s, 64)
	if err != nil {
		var ne *strconv.NumError
		if errors.As(err, &ne) && errors.Is(ne.Err, strconv.ErrRange) && !math.IsInf(f, 0) {
			return f, nil // underflow to (signed) zero, as JSON.parse does
		}
		if math.IsInf(f, 0) {
			return 0, fmt.Errorf("number %s is outside the float64 range", s)
		}
		return 0, fmt.Errorf("invalid number %q", s)
	}
	return f, nil
}
