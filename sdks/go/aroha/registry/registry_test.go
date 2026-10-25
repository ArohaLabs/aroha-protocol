// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

package registry_test

// The client against an in-process registry that reproduces
// apps/registry-server's routes and response shapes (routes/agents.ts
// toApiRecord, the challenge exchange, routes/kel.ts GET /v1/kel/:did).

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/ArohaLabs/aroha-protocol/sdks/go/aroha/identity"
	"github.com/ArohaLabs/aroha-protocol/sdks/go/aroha/registry"
)

// Hashes computed with @noble/hashes keccak_256 (the registry's hashDID).
func TestHashDID_MatchesNobleKeccak256(t *testing.T) {
	cases := map[string]string{
		"": "0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
		"did:aroha:zHyx62wPQGyvXCoihZq1BrbUjBRh2LuNxWiiqMkfAuSZr": "0x9837d9637ebd7d185e3c76d520c6030169a8402caabc86d2c17b915bf6e4bae8",
		strings.Repeat("x", 200):                                  "0x3c3800defb6a25a70a2737e0716eeb5d270559ad3cad8f6abddac58802d7158e", // > one 136-byte block
	}
	for in, want := range cases {
		if got := registry.HashDID(in); got != want {
			t.Errorf("HashDID(%q) = %s, want %s", in, got, want)
		}
	}
}

func TestRegistrationChallengeMessage(t *testing.T) {
	got := string(registry.RegistrationChallengeMessage("did:aroha:a<&>", "n "))
	// JSON.stringify writes < > & and U+2028 literally.
	want := "{\"action\":\"prove-ownership\",\"did\":\"did:aroha:a<&>\",\"nonce\":\"n \"}"
	if got != want {
		t.Fatalf("got %s", got)
	}
}

// ─── Fake registry ────────────────────────────────────────────────────────────

type row struct {
	did, manifestCID, publicKeyB64, endpointURL, owner string
	caps                                               []string
	active                                             bool
}

type fakeRegistry struct {
	mu         sync.Mutex
	apiKey     string
	challenges map[string]string // nonce → did
	agents     map[string]*row   // didHash → row
	kels       map[string][]any
	duplicity  map[string]bool
	calls      []string
}

func newFake() *fakeRegistry {
	return &fakeRegistry{apiKey: "key-1", challenges: map[string]string{}, agents: map[string]*row{}, kels: map[string][]any{}, duplicity: map[string]bool{}}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// toAPIRecord mirrors routes/agents.ts toApiRecord, nulls included.
func toAPIRecord(hash string, r *row) map[string]any {
	var endpoint any
	if r.endpointURL != "" {
		endpoint = r.endpointURL
	}
	return map[string]any{
		"did": r.did, "didHash": hash, "publishedBy": nil,
		"ownerAddress": "0x0000000000000000000000000000000000000000",
		"manifestCID":  r.manifestCID, "publicKeyB64": r.publicKeyB64, "stakedWei": "0",
		"reputationScore": 5000, "active": r.active, "registeredAt": 1760000000000, "lastUpdatedAt": 1760000000000,
		"capabilityIds": r.caps, "endpointUrl": endpoint, "keyVersion": 1, "keyRotatedAt": nil,
		"verified": false, "verificationTier": "community", "domain": nil, "orgSigned": false, "visibility": "public",
	}
}

// challengeCanonicalString is the server's JSON.stringify({action, did, nonce}).
func challengeCanonicalString(did, nonce string) []byte {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(struct {
		Action string `json:"action"`
		DID    string `json:"did"`
		Nonce  string `json:"nonce"`
	}{"prove-ownership", did, nonce})
	return bytes.TrimRight(buf.Bytes(), "\n")
}

func (f *fakeRegistry) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, r.Method+" "+r.URL.RequestURI())
	authed := r.Header.Get("Authorization") == "Bearer "+f.apiKey
	path := r.URL.EscapedPath()

	switch {
	case r.Method == http.MethodPost && path == "/v1/agents/challenge":
		if !authed {
			writeJSON(w, 401, map[string]any{"error": "Unauthorized"})
			return
		}
		var body struct{ DID string }
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body.DID == "" {
			writeJSON(w, 400, map[string]any{"error": "did is required"})
			return
		}
		nonce := "nonce-" + string(rune('a'+len(f.challenges)))
		f.challenges[nonce] = body.DID
		writeJSON(w, 200, map[string]any{"nonce": nonce, "expiresAt": 1760000300000})

	case r.Method == http.MethodPost && path == "/v1/agents":
		if !authed {
			writeJSON(w, 401, map[string]any{"error": "Unauthorized"})
			return
		}
		var b struct {
			DID, ManifestCID, PublicKeyB64, EndpointURL, ChallengeNonce, ChallengeSignature string
		}
		_ = json.NewDecoder(r.Body).Decode(&b)
		if b.DID == "" || b.ManifestCID == "" || b.PublicKeyB64 == "" {
			writeJSON(w, 400, map[string]any{"error": "did, manifestCID, and publicKeyB64 are required"})
			return
		}
		key, err := base64.RawURLEncoding.DecodeString(b.PublicKeyB64)
		if err != nil || len(key) != 32 {
			writeJSON(w, 400, map[string]any{"error": "publicKeyB64 must be a base64url (or base64) encoded 32-byte Ed25519 public key"})
			return
		}
		if strings.HasPrefix(b.DID, "did:aroha:z") && !bytes.Equal(identity.ResolveContentAddressedKey(b.DID), key) {
			writeJSON(w, 400, map[string]any{"error": "publicKeyB64 is not the key this content-addressed DID encodes"})
			return
		}
		if !identity.IsInceptionDID(b.DID) {
			if b.ChallengeNonce == "" || b.ChallengeSignature == "" {
				writeJSON(w, 400, map[string]any{"error": "challengeNonce and challengeSignature are required"})
				return
			}
			if f.challenges[b.ChallengeNonce] != b.DID {
				writeJSON(w, 403, map[string]any{"error": "challenge not found, already used, expired, or issued to a different API key"})
				return
			}
			delete(f.challenges, b.ChallengeNonce)
			sig, err := base64.RawURLEncoding.DecodeString(b.ChallengeSignature)
			if err != nil || len(sig) != 64 || !ed25519.Verify(key, challengeCanonicalString(b.DID, b.ChallengeNonce), sig) {
				writeJSON(w, 403, map[string]any{"error": "challenge signature does not verify against publicKeyB64"})
				return
			}
		}
		hash := registry.HashDID(b.DID)
		if existing := f.agents[hash]; existing != nil && existing.active {
			writeJSON(w, 409, map[string]any{"error": "DID already registered"})
			return
		}
		f.agents[hash] = &row{did: b.DID, manifestCID: b.ManifestCID, publicKeyB64: b.PublicKeyB64, endpointURL: b.EndpointURL,
			owner: f.apiKey, caps: []string{"book-flight", "search"}, active: true}
		writeJSON(w, 201, map[string]any{"didHash": hash})

	case r.Method == http.MethodGet && path == "/v1/agents":
		out := []any{}
		if caps := r.URL.Query().Get("capabilities"); caps != "" {
			want := strings.Split(caps, ",")
			for h, a := range f.agents {
				ok := a.active
				for _, c := range want {
					c, _ = url.QueryUnescape(c)
					found := false
					for _, have := range a.caps {
						found = found || have == c
					}
					ok = ok && found
				}
				if ok {
					out = append(out, toAPIRecord(h, a))
				}
			}
		} else {
			for h, a := range f.agents {
				if a.active {
					out = append(out, toAPIRecord(h, a))
				}
			}
		}
		writeJSON(w, 200, out)

	case strings.HasPrefix(path, "/v1/agents/"):
		rest := strings.TrimPrefix(path, "/v1/agents/")
		param, _ := url.PathUnescape(strings.Split(rest, "/")[0])
		hash := param
		if !strings.HasPrefix(param, "0x") {
			hash = registry.HashDID(param)
		}
		a := f.agents[hash]
		switch {
		case r.Method == http.MethodGet && !strings.Contains(rest, "/"):
			if a == nil || !a.active {
				writeJSON(w, 404, map[string]any{"error": "Not found"})
				return
			}
			writeJSON(w, 200, toAPIRecord(hash, a))
		case r.Method == http.MethodPut && strings.HasSuffix(rest, "/manifest"):
			var b struct{ ManifestCID string }
			_ = json.NewDecoder(r.Body).Decode(&b)
			if !authed || a == nil || a.owner != f.apiKey {
				writeJSON(w, 404, map[string]any{"error": "Not found or not owned by this key"})
				return
			}
			a.manifestCID = b.ManifestCID
			writeJSON(w, 200, map[string]any{"ok": true})
		case r.Method == http.MethodDelete:
			if !authed || a == nil || !a.active {
				writeJSON(w, 404, map[string]any{"error": "Not found or not owned by this key"})
				return
			}
			a.active = false
			writeJSON(w, 200, map[string]any{"ok": true})
		default:
			writeJSON(w, 404, map[string]any{"error": "Not found"})
		}

	case r.Method == http.MethodGet && strings.HasPrefix(path, "/v1/kel/"):
		did, _ := url.PathUnescape(strings.TrimPrefix(path, "/v1/kel/"))
		if f.duplicity[did] {
			writeJSON(w, 409, map[string]any{"error": did + " has a recorded duplicity alarm", "code": "duplicity"})
			return
		}
		events, ok := f.kels[did]
		if !ok {
			writeJSON(w, 404, map[string]any{"error": "Not found"})
			return
		}
		writeJSON(w, 200, map[string]any{"did": did, "events": events, "sequence": len(events) - 1})

	default:
		writeJSON(w, 404, map[string]any{"error": "Not found"})
	}
}

func newAgent(t *testing.T) (string, ed25519.PublicKey, ed25519.PrivateKey) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return identity.DIDFromPublicKey(pub), pub, priv
}

// ─── Tests ────────────────────────────────────────────────────────────────────

func TestClient_RegisterResolveDiscoverUpdateDeactivate(t *testing.T) {
	fake := newFake()
	srv := httptest.NewServer(fake)
	defer srv.Close()
	ctx := context.Background()
	c, err := registry.New(registry.Options{BaseURL: srv.URL + "/", APIKey: "key-1"})
	if err != nil {
		t.Fatal(err)
	}

	did, pub, priv := newAgent(t)
	hash, err := c.Register(ctx, did, "bafy-manifest-1", pub, registry.RegisterOptions{PrivateKey: priv, EndpointURL: "https://agent.example"})
	if err != nil {
		t.Fatal(err)
	}
	if hash != registry.HashDID(did) {
		t.Fatalf("didHash %s", hash)
	}

	rec, err := c.Resolve(ctx, did)
	if err != nil || rec == nil {
		t.Fatalf("resolve: %v %v", rec, err)
	}
	k, err := rec.PublicKey()
	if err != nil || !bytes.Equal(k, pub) || rec.EndpointURL != "https://agent.example" || rec.StakedWei.String() != "0" || rec.KeyRotatedAt != nil {
		t.Fatalf("record: %+v (%v)", rec, err)
	}

	found, err := c.Discover(ctx, []string{"book-flight", "search"})
	if err != nil || len(found) != 1 || found[0].DID != did {
		t.Fatalf("discover: %+v %v", found, err)
	}
	if none, err := c.Discover(ctx, []string{"teleport"}); err != nil || len(none) != 0 {
		t.Fatalf("discover none: %+v %v", none, err)
	}
	all, err := c.List(ctx, 10, 0)
	if err != nil || len(all) != 1 {
		t.Fatalf("list: %+v %v", all, err)
	}

	if err := c.UpdateManifest(ctx, did, "bafy-manifest-2"); err != nil {
		t.Fatal(err)
	}
	if rec, _ := c.Resolve(ctx, did); rec.ManifestCID != "bafy-manifest-2" {
		t.Fatalf("manifest not updated: %s", rec.ManifestCID)
	}

	// Registering again: 409, surfaced as an HTTPError.
	_, err = c.Register(ctx, did, "bafy-manifest-1", pub, registry.RegisterOptions{PrivateKey: priv})
	var he *registry.HTTPError
	if !errors.As(err, &he) || he.StatusCode != 409 {
		t.Fatalf("duplicate registration: %v", err)
	}

	if err := c.Deactivate(ctx, did); err != nil {
		t.Fatal(err)
	}
	if rec, err := c.Resolve(ctx, did); rec != nil || err != nil {
		t.Fatalf("deactivated agent still resolves: %+v %v", rec, err)
	}
	// Resolve uses the didHash path, as @aroha-sdk/registry does.
	if !contains(fake.calls, "GET /v1/agents/"+registry.HashDID(did)) {
		t.Fatalf("calls: %v", fake.calls)
	}
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

func TestClient_RegisterWithExternalSigner(t *testing.T) {
	srv := httptest.NewServer(newFake())
	defer srv.Close()
	c, _ := registry.New(registry.Options{BaseURL: srv.URL, APIKey: "key-1"})
	did, pub, priv := newAgent(t)
	signed := 0
	_, err := c.Register(context.Background(), did, "bafy", pub, registry.RegisterOptions{Sign: func(m []byte) ([]byte, error) {
		signed++
		return ed25519.Sign(priv, m), nil
	}})
	if err != nil || signed != 1 {
		t.Fatalf("register with signer: %v (signed %d)", err, signed)
	}
}

func TestClient_RegisterRefusesBeforeTheRoundTrip(t *testing.T) {
	fake := newFake()
	srv := httptest.NewServer(fake)
	defer srv.Close()
	c, _ := registry.New(registry.Options{BaseURL: srv.URL, APIKey: "key-1"})
	ctx := context.Background()
	did, pub, priv := newAgent(t)
	_, otherPub, otherPriv := newAgent(t)

	if _, err := c.Register(ctx, did, "bafy", pub, registry.RegisterOptions{}); err == nil {
		t.Fatal("registered without proof of key possession")
	}
	if _, err := c.Register(ctx, did, "bafy", otherPub, registry.RegisterOptions{PrivateKey: otherPriv}); err == nil ||
		!strings.Contains(err.Error(), "content-addressed") {
		t.Fatalf("z-DID with someone else's key: %v", err)
	}
	if _, err := c.Register(ctx, did, "bafy", pub, registry.RegisterOptions{PrivateKey: otherPriv}); err == nil {
		t.Fatal("private key that does not match publicKey accepted")
	}
	_ = priv
	if len(fake.calls) != 0 {
		t.Fatalf("client-side refusals still called the registry: %v", fake.calls)
	}

	// A signer that signs with the wrong key is caught by the server (403).
	_, err := c.Register(ctx, did, "bafy", pub, registry.RegisterOptions{Sign: func(m []byte) ([]byte, error) { return ed25519.Sign(otherPriv, m), nil }})
	var he *registry.HTTPError
	if !errors.As(err, &he) || he.StatusCode != 403 {
		t.Fatalf("wrong-key signature: %v", err)
	}
	// Wrong API key: 401, not retried.
	bad, _ := registry.New(registry.Options{BaseURL: srv.URL, APIKey: "nope"})
	if _, err := bad.Register(ctx, did, "bafy", pub, registry.RegisterOptions{PrivateKey: priv}); !errors.As(err, &he) || he.StatusCode != 401 {
		t.Fatalf("bad API key: %v", err)
	}
}

func TestClient_FallbackOn5xxNotOn4xx(t *testing.T) {
	var downCalls int
	down := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		downCalls++
		writeJSON(w, 503, map[string]any{"error": "unavailable"})
	}))
	defer down.Close()
	fake := newFake()
	up := httptest.NewServer(fake)
	defer up.Close()
	ctx := context.Background()

	c, _ := registry.New(registry.Options{BaseURL: down.URL, FallbackURLs: []string{up.URL}, APIKey: "key-1"})
	did, pub, priv := newAgent(t)
	if _, err := c.Register(ctx, did, "bafy", pub, registry.RegisterOptions{PrivateKey: priv}); err != nil {
		t.Fatalf("fallback register: %v", err)
	}
	if rec, err := c.Resolve(ctx, did); err != nil || rec == nil {
		t.Fatalf("fallback resolve: %v", err)
	}
	if downCalls != 2 {
		t.Fatalf("primary tried %d times, want 2", downCalls)
	}

	// A 4xx from the primary is final.
	c2, _ := registry.New(registry.Options{BaseURL: up.URL, FallbackURLs: []string{down.URL}, APIKey: "key-1"})
	if err := c2.UpdateManifest(ctx, "did:aroha:unknown", "x"); err == nil {
		t.Fatal("update of unknown agent succeeded")
	}
	if downCalls != 2 {
		t.Fatalf("4xx was retried on the fallback")
	}
}

func TestClient_RefusesInsecureRegistry(t *testing.T) {
	if _, err := registry.New(registry.Options{BaseURL: "http://registry.example.com"}); err == nil {
		t.Fatal("plain http to a remote registry accepted")
	}
	if _, err := registry.New(registry.Options{BaseURL: "http://registry.example.com", AllowInsecureHTTP: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := registry.HTTPKelSource("http://registry.example.com", registry.KelSourceOptions{}); err == nil {
		t.Fatal("plain http KEL source accepted")
	}
}

func TestResolveRegistryURL(t *testing.T) {
	t.Setenv("AROHA_REGISTRY_URL", "")
	if got := registry.ResolveRegistryURL(""); got != registry.ManagedRegistryURL {
		t.Fatal(got)
	}
	t.Setenv("AROHA_REGISTRY_URL", "https://reg.example/")
	if got := registry.ResolveRegistryURL(""); got != "https://reg.example" {
		t.Fatal(got)
	}
	if got := registry.ResolveRegistryURL("https://mine.example//"); got != "https://mine.example" {
		t.Fatal(got)
	}
}

func TestHTTPKelSource(t *testing.T) {
	fake := newFake()
	const did = "did:aroha:EJ7fbQ1AmnFgT75YNmXR3inBGYoiq72N1c1FrNmNmYXVP"
	fake.kels[did] = []any{map[string]any{"v": 1, "type": "inception", "kind": "person"}}
	fake.duplicity["did:aroha:Eforked"] = true
	srv := httptest.NewServer(fake)
	defer srv.Close()

	src, err := registry.HTTPKelSource(srv.URL, registry.KelSourceOptions{})
	if err != nil {
		t.Fatal(err)
	}
	events, err := src(did)
	if err != nil || len(events) != 1 || events[0]["type"] != "inception" || events[0]["v"] != float64(1) {
		t.Fatalf("events: %v %v", events, err)
	}
	if events, err := src("did:aroha:Eunknown"); events != nil || err != nil {
		t.Fatalf("404 should be (nil, nil): %v %v", events, err)
	}
	var he *registry.HTTPError
	if _, err := src("did:aroha:Eforked"); !errors.As(err, &he) || he.StatusCode != 409 {
		t.Fatalf("409 must fail closed: %v", err)
	}

	// A registry answering for a different DID is refused.
	liar := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]any{"did": "did:aroha:Eother", "events": []any{}})
	}))
	defer liar.Close()
	lsrc, _ := registry.HTTPKelSource(liar.URL, registry.KelSourceOptions{})
	if _, err := lsrc(did); err == nil {
		t.Fatal("KEL for another DID accepted")
	}
}
