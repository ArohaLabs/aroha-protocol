// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

package identity_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ArohaLabs/aroha-protocol/sdks/go/aroha/identity"
)

func serveDoc(doc map[string]any) identity.WebDIDFetcher {
	return func(string, time.Duration, int64) ([]byte, error) { return json.Marshal(doc) }
}

func txtRecords(recs ...string) func(string) ([]string, error) {
	return func(string) ([]string, error) { return recs, nil }
}

func quiet(o identity.ResolveWebDIDOptions) identity.ResolveWebDIDOptions {
	o.Logger = func(string) {}
	return o
}

func deepCopy(t *testing.T, m map[string]any) map[string]any {
	t.Helper()
	b, _ := json.Marshal(m)
	var out map[string]any
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestWebDID_ParseRejectsNonHostnamesAndBadPaths(t *testing.T) {
	for _, did := range []string{
		"did:aroha-web:10.0.0.5:agent", "did:aroha-web:evil.com@10.0.0.5:agent", "did:aroha-web:example.com%2e:agent",
		"did:aroha-web:-bad.com:agent", "did:aroha-web:example.123:agent", "did:aroha-web:example.com:..:x",
		"did:aroha-web:example.com:Agents", "did:aroha-web:example.com:a?b", "did:aroha-web:", "did:aroha-web:host:80:x?",
	} {
		if _, _, err := identity.ParseWebDID(did, identity.WebDIDParseOptions{}); !errors.Is(err, identity.ErrWebDID) {
			t.Errorf("%s accepted", did)
		}
	}
	d, p, err := identity.ParseWebDID("did:aroha-web:example.com:agents:fx", identity.WebDIDParseOptions{})
	if err != nil || d != "example.com" || p != "agents/fx" {
		t.Fatalf("%s %s %v", d, p, err)
	}
	if _, p, _ := identity.ParseWebDID("did:aroha-web:example.com", identity.WebDIDParseOptions{}); p != "agent" {
		t.Fatalf("default path %q", p)
	}
	if _, _, err := identity.ParseWebDID("did:aroha-web:10.0.0.5:x", identity.WebDIDParseOptions{AllowIPLiteral: true}); err != nil {
		t.Fatal(err)
	}
}

func TestWebDID_TypeScriptVectorResolvesIdentically(t *testing.T) {
	raw, err := os.ReadFile("testdata/web-did-ts-vector.json")
	if err != nil {
		t.Fatal(err)
	}
	var vec struct {
		DID      string         `json:"did"`
		Document map[string]any `json:"document"`
		Cases    []struct {
			Name   string   `json:"name"`
			Txt    []string `json:"txt"`
			NowMs  int64    `json:"nowMs"`
			Expect struct {
				DNSVerified  bool `json:"dnsVerified"`
				KeyTrusted   bool `json:"keyTrusted"`
				AcceptedKeys []struct {
					VerificationMethodID string `json:"verificationMethodId"`
					PublicKeyMultibase   string `json:"publicKeyMultibase"`
					Role                 string `json:"role"`
				} `json:"acceptedKeys"`
			} `json:"expect"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(raw, &vec); err != nil {
		t.Fatal(err)
	}
	if len(vec.Cases) != 12 {
		t.Fatalf("cases: %d", len(vec.Cases))
	}
	for _, c := range vec.Cases {
		r, err := identity.ResolveWebDID(vec.DID, quiet(identity.ResolveWebDIDOptions{
			Fetch: serveDoc(vec.Document), DNSResolver: txtRecords(c.Txt...), Now: time.UnixMilli(c.NowMs),
		}))
		if err != nil {
			t.Fatalf("%s: %v", c.Name, err)
		}
		var want []identity.WebDIDAcceptedKey
		for _, k := range c.Expect.AcceptedKeys {
			want = append(want, identity.WebDIDAcceptedKey{VerificationMethodID: k.VerificationMethodID, PublicKeyMultibase: k.PublicKeyMultibase, Role: k.Role})
		}
		if r.DNSVerified != c.Expect.DNSVerified || r.KeyTrusted != c.Expect.KeyTrusted || !reflect.DeepEqual(r.AcceptedKeys, want) {
			t.Errorf("%s @%d: got %+v", c.Name, c.NowMs, r)
		}
	}
}

func TestWebDID_GenesisAndRotation(t *testing.T) {
	a, err := identity.GenerateWebAgent("example.com", "agents/fx", "")
	if err != nil {
		t.Fatal(err)
	}
	vm := a.Document["verificationMethod"].([]any)[0].(map[string]any)
	if !strings.HasPrefix(vm["publicKeyMultibase"].(string), "z") {
		t.Fatal("key is not base58 multibase")
	}
	r, err := identity.ResolveWebDID(a.DID, quiet(identity.ResolveWebDIDOptions{Fetch: serveDoc(a.Document), DNSResolver: txtRecords(a.DNSTXTRecord)}))
	if err != nil || !r.DNSVerified || !r.KeyTrusted {
		t.Fatalf("%+v %v", r, err)
	}
	t0 := time.Now()
	b, err := identity.RotateKey(a, 24*time.Hour, t0)
	if err != nil {
		t.Fatal(err)
	}
	rec := b.Document["arohaWeb"].(map[string]any)["keyHistory"].([]any)[0].(map[string]any)
	if rec["v"] != 2.0 || rec["did"] != a.DID {
		t.Fatalf("rotation record: %v", rec)
	}
	r, _ = identity.ResolveWebDID(b.DID, quiet(identity.ResolveWebDIDOptions{Fetch: serveDoc(b.Document), DNSResolver: txtRecords(b.DNSTXTRecord), Now: t0.Add(time.Second)}))
	if keys := identity.WebDIDPublicKeys(r, ""); len(keys) != 2 || !keys[0].Equal(b.PublicKey) || !keys[1].Equal(a.PublicKey) {
		t.Fatalf("cutover keys: %+v", r.AcceptedKeys)
	}
	r, _ = identity.ResolveWebDID(b.DID, quiet(identity.ResolveWebDIDOptions{Fetch: serveDoc(b.Document), DNSResolver: txtRecords(a.DNSTXTRecord), Now: t0.Add(25 * time.Hour)}))
	if k, err := identity.SelectWebDIDKey(r, ""); err != nil || !k.Equal(b.PublicKey) || !r.KeyTrusted {
		t.Fatalf("after cool-down: %+v %v", r, err)
	}
}

func TestWebDID_FailClosedCases(t *testing.T) {
	a, _ := identity.GenerateWebAgent("example.com", "x", "")
	other, _ := identity.GenerateWebAgent("example.com", "x", "")

	// DNS skipped → DNSVerified false.
	r, err := identity.ResolveWebDID(a.DID, quiet(identity.ResolveWebDIDOptions{Fetch: serveDoc(a.Document), SkipDNS: true}))
	if err != nil || r.DNSVerified {
		t.Fatalf("SkipDNS: %+v %v", r, err)
	}
	// No resolver → error unless AllowNoDNS.
	if _, err := identity.ResolveWebDID(a.DID, quiet(identity.ResolveWebDIDOptions{Fetch: serveDoc(a.Document), DisableSystemDNS: true})); err == nil {
		t.Fatal("no resolver accepted")
	}
	// DNS for another key → nothing accepted; a failing lookup too.
	r, _ = identity.ResolveWebDID(a.DID, quiet(identity.ResolveWebDIDOptions{Fetch: serveDoc(a.Document), DNSResolver: txtRecords(other.DNSTXTRecord)}))
	if r.DNSVerified || len(r.AcceptedKeys) != 0 {
		t.Fatalf("%+v", r)
	}
	if _, err := identity.SelectWebDIDKey(r, ""); err == nil {
		t.Fatal("selected a key with nothing accepted")
	}
	r, _ = identity.ResolveWebDID(a.DID, quiet(identity.ResolveWebDIDOptions{Fetch: serveDoc(a.Document),
		DNSResolver: func(string) ([]string, error) { return nil, errors.New("SERVFAIL") }}))
	if len(r.AcceptedKeys) != 0 {
		t.Fatal("failed lookup accepted a key")
	}
	// Served key that does not hash to the declared commitment.
	doc := deepCopy(t, a.Document)
	doc["verificationMethod"].([]any)[0].(map[string]any)["publicKeyMultibase"] =
		other.Document["verificationMethod"].([]any)[0].(map[string]any)["publicKeyMultibase"]
	if _, err := identity.ResolveWebDID(a.DID, quiet(identity.ResolveWebDIDOptions{Fetch: serveDoc(doc), DNSResolver: txtRecords(a.DNSTXTRecord)})); err == nil ||
		!strings.Contains(err.Error(), "keyCommitmentHash does not match") {
		t.Fatalf("self-declared hash trusted: %v", err)
	}
	// Document for another DID.
	if _, err := identity.ResolveWebDID("did:aroha-web:example.com:y", quiet(identity.ResolveWebDIDOptions{Fetch: serveDoc(a.Document), DNSResolver: txtRecords(a.DNSTXTRecord)})); err == nil {
		t.Fatal("foreign document accepted")
	}
	// Tampered rotation (shortened cool-down) and oversize document.
	b, _ := identity.RotateKey(a, 24*time.Hour, time.Time{})
	tampered := deepCopy(t, b.Document)
	h := tampered["arohaWeb"].(map[string]any)["keyHistory"].([]any)[0].(map[string]any)
	h["trustAfter"] = h["rotatedAt"]
	if _, err := identity.ResolveWebDID(b.DID, quiet(identity.ResolveWebDIDOptions{Fetch: serveDoc(tampered), DNSResolver: txtRecords(a.DNSTXTRecord)})); err == nil ||
		!strings.Contains(err.Error(), "invalid predecessor signature") {
		t.Fatalf("tampered rotation: %v", err)
	}
	big := func(_ string, _ time.Duration, max int64) ([]byte, error) { return make([]byte, max+1), nil }
	if _, err := identity.ResolveWebDID(a.DID, quiet(identity.ResolveWebDIDOptions{Fetch: big, DNSResolver: txtRecords(a.DNSTXTRecord)})); err == nil ||
		!strings.Contains(err.Error(), "too large") {
		t.Fatalf("oversize: %v", err)
	}
}

func TestWebDID_RotationPayloads(t *testing.T) {
	rec := map[string]any{"v": 2.0, "did": "did:aroha-web:e.com:x", "newKeyHash": "ab", "predecessorKey": "zK",
		"rotatedAt": "2026-01-01T00:00:00.000Z", "trustAfter": "2026-01-02T00:00:00.000Z"}
	got, err := identity.RotationSigningPayload(rec)
	want := `{"did":"did:aroha-web:e.com:x","newKeyHash":"ab","predecessorKey":"zK","rotatedAt":"2026-01-01T00:00:00.000Z","trustAfter":"2026-01-02T00:00:00.000Z","v":2}`
	if err != nil || string(got) != want {
		t.Fatalf("v2 payload %s %v", got, err)
	}
	delete(rec, "v")
	if got, _ := identity.RotationSigningPayload(rec); string(got) != "zKab2026-01-01T00:00:00.000Z" {
		t.Fatalf("v1 payload %s", got)
	}
	rec["v"] = 3.0
	if _, _, reason := identity.CheckKeyRotation(rec, ""); reason != "has unsupported version 3" {
		t.Fatalf("%q", reason)
	}
}

func TestWebDID_DefaultFetchRefusesRedirects(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/redirect":
			http.Redirect(w, r, "http://127.0.0.1:1/x", http.StatusFound)
		case "/big":
			w.(http.Flusher).Flush() // chunked: no Content-Length
			fmt.Fprint(w, strings.Repeat(" ", identity.MaxWebDIDDocumentBytes+1))
		default:
			fmt.Fprint(w, "{}")
		}
	}))
	defer srv.Close()
	fetch := identity.DefaultWebDIDFetchForTest
	if b, err := fetch(srv.URL+"/ok", 5*time.Second, identity.MaxWebDIDDocumentBytes); err != nil || string(b) != "{}" {
		t.Fatalf("%s %v", b, err)
	}
	if _, err := fetch(srv.URL+"/redirect", 5*time.Second, identity.MaxWebDIDDocumentBytes); err == nil || !strings.Contains(err.Error(), "redirects are not followed") {
		t.Fatalf("redirect: %v", err)
	}
	if _, err := fetch(srv.URL+"/big", 5*time.Second, identity.MaxWebDIDDocumentBytes); err == nil || !strings.Contains(err.Error(), "too large") {
		t.Fatalf("big: %v", err)
	}
}
