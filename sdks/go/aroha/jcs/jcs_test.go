// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

package jcs_test

import (
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ArohaLabs/aroha-protocol/sdks/go/aroha/jcs"
)

// RFC 8785 Appendix B: IEEE 754 bit patterns and their ECMAScript serialisation.
func TestFormatNumber_RFC8785AppendixB(t *testing.T) {
	cases := []struct {
		bits uint64
		want string
	}{
		{0x0000000000000000, "0"},
		{0x8000000000000000, "0"},
		{0x0000000000000001, "5e-324"},
		{0x8000000000000001, "-5e-324"},
		{0x7fefffffffffffff, "1.7976931348623157e+308"},
		{0xffefffffffffffff, "-1.7976931348623157e+308"},
		{0x4340000000000000, "9007199254740992"},
		{0xc340000000000000, "-9007199254740992"},
		{0x4430000000000000, "295147905179352830000"},
		{0x44b52d02c7e14af5, "9.999999999999997e+22"},
		{0x44b52d02c7e14af6, "1e+23"},
		{0x44b52d02c7e14af7, "1.0000000000000001e+23"},
		{0x444b1ae4d6e2ef4e, "999999999999999700000"},
		{0x444b1ae4d6e2ef4f, "999999999999999900000"},
		{0x444b1ae4d6e2ef50, "1e+21"},
		{0x3eb0c6f7a0b5ed8c, "9.999999999999997e-7"},
		{0x3eb0c6f7a0b5ed8d, "0.000001"},
		{0x41b3de4355555553, "333333333.3333332"},
		{0x41b3de4355555554, "333333333.33333325"},
		{0x41b3de4355555555, "333333333.3333333"},
		{0x41b3de4355555556, "333333333.3333334"},
		{0x41b3de4355555557, "333333333.33333343"},
		{0xbecbf647612f3696, "-0.0000033333333333333333"},
		{0x43143ff3c1cb0959, "1424953923781206.2"},
	}
	for _, c := range cases {
		got, err := jcs.FormatNumber(math.Float64frombits(c.bits))
		if err != nil {
			t.Errorf("%016x: %v", c.bits, err)
			continue
		}
		if got != c.want {
			t.Errorf("%016x: got %s, want %s", c.bits, got, c.want)
		}
	}
	for _, bits := range []uint64{0x7fffffffffffffff, 0x7ff0000000000000, 0xfff0000000000000} {
		if _, err := jcs.FormatNumber(math.Float64frombits(bits)); err == nil {
			t.Errorf("%016x: expected an error for a non-finite number", bits)
		}
	}
}

func TestFormatNumber_ExponentThresholds(t *testing.T) {
	cases := map[float64]string{
		1e20: "100000000000000000000", 1e21: "1e+21", 1e-6: "0.000001", 1e-7: "1e-7",
		0.1: "0.1", 42.07: "42.07", 100: "100", 1.5e300: "1.5e+300", 123e-20: "1.23e-18",
		-1: "-1", 0.000001234: "0.000001234",
	}
	for f, want := range cases {
		got, _ := jcs.FormatNumber(f)
		if got != want {
			t.Errorf("%v: got %s, want %s", f, got, want)
		}
	}
	if got, _ := jcs.FormatNumber(math.Copysign(0, -1)); got != "0" {
		t.Errorf("-0: got %s", got)
	}
}

func TestStrings_NoHTMLEscaping(t *testing.T) {
	got, err := jcs.Canonicalize(map[string]any{"s": "<a>&\u2028\u2029\x7f\x01"})
	if err != nil {
		t.Fatal(err)
	}
	want := "{\"s\":\"<a>&\u2028\u2029\x7f\\u0001\"}"
	if string(got) != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestKeySorting_UTF16(t *testing.T) {
	// U+1F600 (surrogates D83D DE00) sorts BEFORE U+FB33 in UTF-16 order,
	// though after it by code point / UTF-8 bytes.
	got, _ := jcs.Canonicalize(map[string]any{"\uFB33": 1, "\U0001F600": 2})
	if want := "{\"\U0001F600\":2,\"\uFB33\":1}"; string(got) != want {
		t.Errorf("got %s, want %s", got, want)
	}
}

func TestParse_RejectsWhatIJSONForbids(t *testing.T) {
	bad := []string{
		`{"a":1,"a":2}`,
		`"\ud800"`,
		`"\udc00"`,
		`"\ud800\u0041"`,
		"\"\xff\"",
		`1e400`,
		`-1e400`,
		`[1,]`,
		`{"a":1} x`,
		`01`,
		`1.`,
		`NaN`,
	}
	for _, s := range bad {
		if _, err := jcs.Transform([]byte(s)); err == nil {
			t.Errorf("%q: expected an error", s)
		}
	}
	if got, err := jcs.Transform([]byte(`"\ud83d\ude00"`)); err != nil || string(got) != "\"\U0001F600\"" {
		t.Errorf("surrogate pair: got %q, %v", got, err)
	}
	if got, err := jcs.Transform([]byte(`1e-400`)); err != nil || string(got) != "0" {
		t.Errorf("underflow: got %q, %v", got, err)
	}
}

func TestCanonicalize_StructsHonourOmitempty(t *testing.T) {
	type inner struct {
		B *float64 `json:"b,omitempty"`
		A string   `json:"a"`
	}
	got, err := jcs.Canonicalize(map[string]any{"x": inner{A: "<"}, "n": []string{"z"}})
	if err != nil {
		t.Fatal(err)
	}
	if want := `{"n":["z"],"x":{"a":"<"}}`; string(got) != want {
		t.Errorf("got %s, want %s", got, want)
	}
}

// Shared cross-SDK vectors produced by the TypeScript reference.
func TestSharedVectors(t *testing.T) {
	path := filepath.Join("..", "..", "..", "..", "packages", "aroha-credentials", "test-vectors", "mandate-v2.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("shared vectors not available: %v", err)
	}
	var vectors struct {
		JCS []struct {
			Name     string `json:"name"`
			Input    string `json:"input"`
			Expected string `json:"expected"`
		} `json:"jcs"`
	}
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatal(err)
	}
	if len(vectors.JCS) == 0 {
		t.Fatal("no jcs vectors")
	}
	for _, v := range vectors.JCS {
		got, err := jcs.Transform([]byte(v.Input))
		if err != nil {
			t.Errorf("%s: %v", v.Name, err)
			continue
		}
		if string(got) != v.Expected {
			t.Errorf("%s:\n got  %s\n want %s", v.Name, got, v.Expected)
		}
	}
}

// A nil map or slice is sent by encoding/json as null, so it must
// canonicalise as null too or the receiver's bytes differ from the signer's.
func TestCanonicalize_NilContainersAreNull(t *testing.T) {
	var m map[string]any
	var s []any
	got, err := jcs.Canonicalize(map[string]any{"m": m, "s": s, "t": []string(nil)})
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != `{"m":null,"s":null,"t":null}` {
		t.Errorf("got %s", got)
	}
}

func TestSortKeys(t *testing.T) {
	keys := []string{"b", "a", "\u00f6", "\r", "1"}
	jcs.SortKeys(keys)
	if got := strings.Join(keys, ","); got != "\r,1,a,b,\u00f6" {
		t.Errorf("got %q", got)
	}
}
