// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

package mandate_test

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ArohaLabs/aroha-protocol/sdks/go/aroha/identity"
	"github.com/ArohaLabs/aroha-protocol/sdks/go/aroha/jcs"
	"github.com/ArohaLabs/aroha-protocol/sdks/go/aroha/mandate"
)

// ── Shared cross-SDK vectors (packages/aroha-credentials/test-vectors) ───────

type vectorFile struct {
	Keys map[string]struct {
		PrivateKeyHex string `json:"privateKeyHex"`
		PublicKeyHex  string `json:"publicKeyHex"`
		DID           string `json:"did"`
	} `json:"keys"`
	Mandates []struct {
		Name                   string          `json:"name"`
		Signer                 string          `json:"signer"`
		Mandate                json.RawMessage `json:"mandate"`
		ExpectedSigningPayload string          `json:"expectedSigningPayload"`
		ExpectedSignature      string          `json:"expectedSignature"`
	} `json:"mandates"`
	Tokens []struct {
		Name     string `json:"name"`
		Token    string `json:"token"`
		VerifyAt string `json:"verifyAt"`
		Expected struct {
			Valid         bool   `json:"valid"`
			RootGrantor   string `json:"rootGrantor"`
			LeafMandateID string `json:"leafMandateId"`
			ReasonClass   string `json:"reasonClass"`
		} `json:"expected"`
	} `json:"tokens"`
}

func loadVectors(t *testing.T) *vectorFile {
	t.Helper()
	path := filepath.Join("..", "..", "..", "..", "packages", "aroha-credentials", "test-vectors", "mandate-v2.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("shared vectors not available: %v", err)
	}
	var v vectorFile
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatal(err)
	}
	return &v
}

func vectorKey(t *testing.T, v *vectorFile, name string) ed25519.PrivateKey {
	t.Helper()
	k := v.Keys[name]
	seed, err := hex.DecodeString(k.PrivateKeyHex)
	if err != nil {
		t.Fatal(err)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)
	if hex.EncodeToString(pub) != k.PublicKeyHex {
		t.Fatalf("%s: public key %x != %s", name, pub, k.PublicKeyHex)
	}
	if did := identity.DIDFromPublicKey(pub); did != k.DID {
		t.Fatalf("%s: DID %s != %s", name, did, k.DID)
	}
	return priv
}

func TestVectors_SigningPayloadAndSignature(t *testing.T) {
	v := loadVectors(t)
	if len(v.Mandates) == 0 {
		t.Fatal("no mandate vectors")
	}
	for _, mv := range v.Mandates {
		t.Run(mv.Name, func(t *testing.T) {
			var m mandate.SpendingMandate
			if err := json.Unmarshal(mv.Mandate, &m); err != nil {
				t.Fatal(err)
			}
			payload, err := mandate.SigningPayloadV2(m)
			if err != nil {
				t.Fatal(err)
			}
			if string(payload) != mv.ExpectedSigningPayload {
				t.Fatalf("payload\n got  %s\n want %s", payload, mv.ExpectedSigningPayload)
			}
			// Also straight from the vector's JSON, without the Go struct.
			fromRaw, err := jcs.Transform([]byte(`{"mandate":` + string(mv.Mandate) + `,"v":2}`))
			if err != nil || string(fromRaw) != mv.ExpectedSigningPayload {
				t.Fatalf("payload from raw JSON: %s (%v)", fromRaw, err)
			}
			sig := base64.RawURLEncoding.EncodeToString(ed25519.Sign(vectorKey(t, v, mv.Signer), payload))
			if sig != mv.ExpectedSignature {
				t.Fatalf("signature\n got  %s\n want %s", sig, mv.ExpectedSignature)
			}
		})
	}
}

func TestVectors_TokenVerdicts(t *testing.T) {
	v := loadVectors(t)
	if len(v.Tokens) == 0 {
		t.Fatal("no token vectors")
	}
	for _, tv := range v.Tokens {
		t.Run(tv.Name, func(t *testing.T) {
			at, err := time.Parse(time.RFC3339Nano, tv.VerifyAt)
			if err != nil {
				t.Fatal(err)
			}
			r := mandate.VerifyMandateChain(tv.Token, nil, mandate.ChainOptions{CheckOptions: mandate.CheckOptions{Now: at}})
			if r.Valid != tv.Expected.Valid {
				t.Fatalf("valid = %v (%s), want %v", r.Valid, r.Reason, tv.Expected.Valid)
			}
			if r.Valid {
				if r.RootGrantor != tv.Expected.RootGrantor {
					t.Errorf("rootGrantor = %s", r.RootGrantor)
				}
				if r.Mandate.MandateID != tv.Expected.LeafMandateID {
					t.Errorf("leaf = %s", r.Mandate.MandateID)
				}
				return
			}
			switch tv.Expected.ReasonClass {
			case "narrowing":
				if !strings.Contains(r.Reason, "Cannot attenuate") {
					t.Errorf("reason %q is not a narrowing failure", r.Reason)
				}
			case "time":
				if !strings.Contains(r.Reason, "expired") && !strings.Contains(r.Reason, "validity window") &&
					!strings.Contains(r.Reason, "not yet valid") && !strings.Contains(r.Reason, "in the future") {
					t.Errorf("reason %q is not a time failure", r.Reason)
				}
			default:
				t.Fatalf("unknown reasonClass %q", tv.Expected.ReasonClass)
			}
		})
	}
}

// A Go-issued chain attenuated from a TS-issued parent token verifies.
func TestVectors_AttenuateTSToken(t *testing.T) {
	v := loadVectors(t)
	parent, err := mandate.DecodeToken(v.Tokens[0].Token) // human → agent intent → provider cart
	if err != nil {
		t.Fatal(err)
	}
	provider := vectorKey(t, v, "provider")
	payment, err := mandate.AttenuateToPayment(parent, "did:aroha:merchant-a",
		mandate.SpendingConstraints{SpendLimitUSD: 10, AllowedMerchants: []string{"did:aroha:merchant-a"}}, provider, nil)
	if err != nil {
		t.Fatal(err)
	}
	if payment.Mandate.Constraints.SessionLimitUSD == nil || *payment.Mandate.Constraints.SessionLimitUSD != 42.07 {
		t.Errorf("sessionLimitUsd not inherited: %v", payment.Mandate.Constraints.SessionLimitUSD)
	}
	r := mandate.VerifyMandateChain(payment.Token, nil, mandate.ChainOptions{
		CheckOptions: mandate.CheckOptions{ExpectedRoot: v.Keys["human"].DID},
	})
	if !r.Valid || len(r.Chain) != 3 {
		t.Fatalf("%+v", r)
	}
}

// ── Wire shape ───────────────────────────────────────────────────────────────

func decodeTokenJSON(t *testing.T, token string) map[string]any {
	t.Helper()
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func TestWire_V2TokenShape(t *testing.T) {
	_, priv := mustKey(t)
	m, err := mandate.IssueIntent("did:aroha:g", "did:aroha:e",
		mandate.SpendingConstraints{SpendLimitUSD: 5}, priv, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	tok := decodeTokenJSON(t, m.Token)
	if tok["v"] != float64(2) {
		t.Errorf("v = %v", tok["v"])
	}
	if chain, ok := tok["chain"].([]any); !ok || len(chain) != 0 {
		t.Errorf("chain = %#v, want []", tok["chain"])
	}
	body := tok["mandate"].(map[string]any)
	c := body["constraints"].(map[string]any)
	if len(c) != 1 {
		t.Errorf("unset optional constraints must be absent, got %v", c)
	}
	for _, f := range []string{"issuedAt", "expiresAt"} {
		s, _ := body[f].(string)
		if _, err := time.Parse("2006-01-02T15:04:05.000Z", s); err != nil {
			t.Errorf("%s = %q is not toISOString format", f, s)
		}
	}
	if v, present := body["parentMandateId"]; !present || v != nil {
		t.Errorf("parentMandateId = %v (present %v), want null", v, present)
	}
	if n := strings.Count(string(mustJSON(t, body)), "null"); n != 1 {
		t.Errorf("only parentMandateId may be null, got %d nulls in %s", n, mustJSON(t, body))
	}
}

func mustJSON(t *testing.T, v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestWire_EmptyAllowedMerchantsIsNotAbsent(t *testing.T) {
	b, _ := json.Marshal(mandate.SpendingConstraints{SpendLimitUSD: 1, AllowedMerchants: []string{}})
	if string(b) != `{"spendLimitUsd":1,"allowedMerchants":[]}` {
		t.Errorf("got %s", b)
	}
	b, _ = json.Marshal(mandate.SpendingConstraints{SpendLimitUSD: 1})
	if string(b) != `{"spendLimitUsd":1}` {
		t.Errorf("got %s", b)
	}
}

// ── Chain verification ───────────────────────────────────────────────────────

type party struct {
	did  string
	pub  ed25519.PublicKey
	priv ed25519.PrivateKey
}

func newParty(t *testing.T) party {
	pub, priv := mustKey(t)
	return party{identity.DIDFromPublicKey(pub), pub, priv}
}

func chain3(t *testing.T) (human, agent, provider party, intent, cart *mandate.SignedMandate) {
	human, agent, provider = newParty(t), newParty(t), newParty(t)
	var err error
	intent, err = mandate.IssueIntent(human.did, agent.did, mandate.SpendingConstraints{
		SpendLimitUSD: 500, SessionLimitUSD: ptr(200.5), AllowedMerchants: []string{"m1", "m2"},
	}, human.priv, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	cart, err = mandate.AttenuateToCart(intent, provider.did,
		mandate.SpendingConstraints{SpendLimitUSD: 100, AllowedMerchants: []string{"m1"}}, agent.priv, nil)
	if err != nil {
		t.Fatal(err)
	}
	return
}

func TestChain_RevokedRootKillsLeaf(t *testing.T) {
	_, _, _, intent, cart := chain3(t)
	r := mandate.VerifyMandateChain(cart.Token, nil, mandate.ChainOptions{CheckOptions: mandate.CheckOptions{
		IsRevoked: func(id, grantor string) (bool, error) {
			return id == intent.Mandate.MandateID && grantor == intent.Mandate.Grantor, nil
		},
	}})
	if r.Valid || !strings.Contains(r.Reason, "has been revoked") {
		t.Fatalf("%+v", r)
	}
	r = mandate.VerifyMandateChain(cart.Token, nil, mandate.ChainOptions{CheckOptions: mandate.CheckOptions{
		IsRevoked: func(string, string) (bool, error) { return false, errors.New("down") },
	}})
	if r.Valid || !strings.Contains(r.Reason, "Revocation check failed") {
		t.Fatalf("revocation errors must fail closed: %+v", r)
	}
}

// Revocation identity is (grantor, mandateId): a look-alike mandate that reuses
// a revoked id under a different grantor is not reported revoked.
func TestChain_LookAlikeIDUnderAnotherGrantorIsNotRevoked(t *testing.T) {
	human, agent, other := newParty(t), newParty(t), newParty(t)
	original, err := mandate.IssueIntent(human.did, agent.did, mandate.SpendingConstraints{SpendLimitUSD: 50}, human.priv, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	revoked := map[string]bool{original.Mandate.Grantor + "#" + original.Mandate.MandateID: true}
	isRevoked := func(id, grantor string) (bool, error) { return revoked[grantor+"#"+id], nil }
	opts := mandate.ChainOptions{CheckOptions: mandate.CheckOptions{IsRevoked: isRevoked}}
	if r := mandate.VerifyMandateChain(original.Token, nil, opts); r.Valid {
		t.Fatal("revoked original accepted")
	}

	m := original.Mandate
	m.Grantor = other.did
	payload, err := mandate.SigningPayloadV2(m)
	if err != nil {
		t.Fatal(err)
	}
	tok := map[string]any{"v": 2, "mandate": m, "chain": []any{},
		"signature": base64.RawURLEncoding.EncodeToString(ed25519.Sign(other.priv, payload))}
	look := base64.RawURLEncoding.EncodeToString(mustJSON(t, tok))
	if r := mandate.VerifyMandateChain(look, nil, opts); !r.Valid || r.Mandate.MandateID != original.Mandate.MandateID {
		t.Fatalf("look-alike under another grantor must not be revoked: %+v", r)
	}
}

func TestChain_ExpectedRootGranteeAndDepth(t *testing.T) {
	human, _, provider, _, cart := chain3(t)
	if r := mandate.VerifyMandateChain(cart.Token, nil, mandate.ChainOptions{
		CheckOptions: mandate.CheckOptions{ExpectedRoot: human.did}, ExpectedGrantee: provider.did,
	}); !r.Valid {
		t.Fatalf("%+v", r)
	}
	if r := mandate.VerifyMandateChain(cart.Token, nil, mandate.ChainOptions{
		CheckOptions: mandate.CheckOptions{ExpectedRoot: "did:aroha:someone-else"},
	}); r.Valid || !strings.Contains(r.Reason, "Chain root mismatch") {
		t.Fatalf("%+v", r)
	}
	if r := mandate.VerifyMandateChain(cart.Token, nil, mandate.ChainOptions{ExpectedGrantee: "did:aroha:x"}); r.Valid {
		t.Fatal("grantee mismatch accepted")
	}
	if r := mandate.VerifyMandateChain(cart.Token, nil, mandate.ChainOptions{MaxDepth: 1}); r.Valid {
		t.Fatal("depth limit ignored")
	}
}

func TestChain_InheritanceAndExpiryClamp(t *testing.T) {
	_, _, _, intent, cart := chain3(t)
	if s := cart.Mandate.Constraints.SessionLimitUSD; s == nil || *s != 200.5 {
		t.Errorf("sessionLimitUsd not inherited: %v", s)
	}
	if cart.Mandate.ExpiresAt != intent.Mandate.ExpiresAt {
		t.Errorf("child expiry %s != parent %s", cart.Mandate.ExpiresAt, intent.Mandate.ExpiresAt)
	}
	if cart.Mandate.IssuedAt == "" {
		t.Error("issuedAt missing")
	}
}

func TestChain_TierCannotBroaden(t *testing.T) {
	_, _, provider, _, cart := chain3(t)
	payment, err := mandate.AttenuateToPayment(cart, "did:aroha:merchant",
		mandate.SpendingConstraints{SpendLimitUSD: 10, AllowedMerchants: []string{"m1"}}, provider.priv, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := mandate.AttenuateToCart(payment, "did:aroha:x",
		mandate.SpendingConstraints{SpendLimitUSD: 1, AllowedMerchants: []string{"m1"}}, provider.priv, nil); err == nil {
		t.Fatal("payment → cart accepted")
	}
}

func TestChain_TamperedAncestorRejected(t *testing.T) {
	_, _, _, _, cart := chain3(t)
	tok := decodeTokenJSON(t, cart.Token)
	root := tok["chain"].([]any)[0].(map[string]any)["mandate"].(map[string]any)
	root["constraints"].(map[string]any)["spendLimitUsd"] = 1e6
	raw, _ := json.Marshal(tok)
	r := mandate.VerifyMandateChain(base64.RawURLEncoding.EncodeToString(raw), nil, mandate.ChainOptions{})
	if r.Valid || !strings.Contains(r.Reason, "Invalid signature") {
		t.Fatalf("%+v", r)
	}
}

func TestChain_DecodeTokenThenAttenuate(t *testing.T) {
	_, _, provider, _, cart := chain3(t)
	decoded, err := mandate.DecodeToken(cart.Token)
	if err != nil {
		t.Fatal(err)
	}
	// Hand-rebuilt SignedMandate without Chain: ancestry comes from the token.
	rebuilt := &mandate.SignedMandate{Mandate: decoded.Mandate, Signature: decoded.Signature, Token: decoded.Token}
	payment, err := mandate.AttenuateToPayment(rebuilt, "did:aroha:merchant",
		mandate.SpendingConstraints{SpendLimitUSD: 10, AllowedMerchants: []string{"m1"}}, provider.priv, nil)
	if err != nil {
		t.Fatal(err)
	}
	if r := mandate.VerifyMandateChain(payment.Token, nil, mandate.ChainOptions{}); !r.Valid {
		t.Fatalf("%+v", r)
	}
}

func TestChain_NotBeforeTolerance(t *testing.T) {
	human, agent := newParty(t), newParty(t)
	future := time.Now().Add(10 * time.Second).UTC().Format("2006-01-02T15:04:05.000Z")
	m, err := mandate.IssueIntent(human.did, agent.did,
		mandate.SpendingConstraints{SpendLimitUSD: 1, ValidFrom: future}, human.priv, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if r := mandate.VerifyMandateChain(m.Token, nil, mandate.ChainOptions{}); !r.Valid {
		t.Fatalf("within default tolerance: %+v", r)
	}
	zero := time.Duration(0)
	if r := mandate.VerifyMandateChain(m.Token, nil, mandate.ChainOptions{
		CheckOptions: mandate.CheckOptions{ClockTolerance: &zero},
	}); r.Valid {
		t.Fatal("validFrom in the future accepted with zero tolerance")
	}
}

// ── Legacy v1 (read-only) ────────────────────────────────────────────────────

func v1Token(t *testing.T, body map[string]any, priv ed25519.PrivateKey) string {
	t.Helper()
	parsed, err := jcs.Parse(mustJSON(t, body))
	if err != nil {
		t.Fatal(err)
	}
	sig := ed25519.Sign(priv, jcs.MustCanonicalize(parsed))
	raw := mustJSON(t, map[string]any{"mandate": body, "signature": base64.RawURLEncoding.EncodeToString(sig)})
	return base64.RawURLEncoding.EncodeToString(raw)
}

func v1Body(tier string, parent any) map[string]any {
	return map[string]any{
		"mandateTier": tier, "constraints": map[string]any{"spendLimitUsd": 10},
		"grantee": "did:aroha:e", "grantor": "did:aroha:g",
		"issuedAt": "2026-01-01T00:00:00.000Z", "expiresAt": "2099-01-01T00:00:00.000Z",
		"parentMandateId": parent, "mandateId": "11111111-1111-4111-8111-111111111111",
	}
}

func TestLegacyV1(t *testing.T) {
	pub, priv := mustKey(t)
	root := v1Token(t, v1Body("intent", nil), priv)
	r := mandate.VerifyMandate(root, pub, "did:aroha:e", mandate.VerifyOptions{})
	if !r.Valid || !r.ChainVerified {
		t.Fatalf("v1 root: %+v", r)
	}
	if r := mandate.VerifyMandateChain(root, func(string) (ed25519.PublicKey, error) { return pub, nil }, mandate.ChainOptions{}); !r.Valid {
		t.Fatalf("v1 root via chain: %+v", r)
	}

	child := v1Token(t, v1Body("cart", "22222222-2222-4222-8222-222222222222"), priv)
	r = mandate.VerifyMandate(child, pub, "", mandate.VerifyOptions{})
	if !r.Valid || r.ChainVerified {
		t.Fatalf("v1 child via single key: %+v", r)
	}
	if r := mandate.VerifyMandateChain(child, func(string) (ed25519.PublicKey, error) { return pub, nil }, mandate.ChainOptions{}); r.Valid {
		t.Fatal("v1 child accepted by VerifyMandateChain")
	}
	if _, err := mandate.EnforceSpendingConstraints(child, pub, mandate.EnforceOptions{ProposedAmountUSD: 1, RequireChain: true}); err == nil {
		t.Fatal("RequireChain accepted a v1 child")
	}

	// A v1 parent that is not a root cannot be attenuated.
	decoded, err := mandate.DecodeToken(child)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := mandate.AttenuateToPayment(decoded, "did:aroha:x", mandate.SpendingConstraints{SpendLimitUSD: 1}, priv, nil); err == nil {
		t.Fatal("attenuated a non-root v1 mandate")
	}
	// A v1 root can: the child is v2 and embeds the v1 root as a v1 link.
	decodedRoot, _ := mandate.DecodeToken(root)
	cart, err := mandate.AttenuateToCart(decodedRoot, "did:aroha:p", mandate.SpendingConstraints{SpendLimitUSD: 5}, priv, nil)
	if err != nil {
		t.Fatal(err)
	}
	if cart.Chain[0].V != 1 {
		t.Errorf("embedded root link v = %d, want 1", cart.Chain[0].V)
	}
	if r := mandate.VerifyMandateChain(cart.Token, func(string) (ed25519.PublicKey, error) { return pub, nil }, mandate.ChainOptions{}); !r.Valid {
		t.Fatalf("v2 child of v1 root: %+v", r)
	}

	// A v1 token that smuggles in a chain is malformed.
	tok := decodeTokenJSON(t, root)
	tok["chain"] = []any{}
	if r := mandate.VerifyMandate(base64.RawURLEncoding.EncodeToString(mustJSON(t, tok)), pub, "", mandate.VerifyOptions{}); r.Valid {
		t.Fatal("v1 with chain accepted")
	}
}

func TestShapeRejections(t *testing.T) {
	pub, priv := mustKey(t)
	cases := map[string]func(b map[string]any){
		"missing issuedAt":     func(b map[string]any) { delete(b, "issuedAt") },
		"missing parent field": func(b map[string]any) { delete(b, "parentMandateId") },
		"bad tier":             func(b map[string]any) { b["mandateTier"] = "root" },
		"negative limit":       func(b map[string]any) { b["constraints"] = map[string]any{"spendLimitUsd": -1} },
		"null session limit": func(b map[string]any) {
			b["constraints"] = map[string]any{"spendLimitUsd": 1, "sessionLimitUsd": nil}
		},
		"merchants not strings": func(b map[string]any) {
			b["constraints"] = map[string]any{"spendLimitUsd": 1, "allowedMerchants": []any{1}}
		},
	}
	for name, mutate := range cases {
		body := v1Body("intent", nil)
		mutate(body)
		if r := mandate.VerifyMandate(v1Token(t, body, priv), pub, "", mandate.VerifyOptions{}); r.Valid ||
			!strings.HasPrefix(r.Reason, "Malformed token") {
			t.Errorf("%s: %+v", name, r)
		}
	}
	if r := mandate.VerifyMandate("eyJ2IjozfQ", pub, "", mandate.VerifyOptions{}); r.Reason != "Unsupported mandate token version: 3" {
		t.Errorf("v3: %q", r.Reason)
	}
}

// ── Narrowing (verifier side) ────────────────────────────────────────────────

func TestCheckNarrowing(t *testing.T) {
	cat := "travel"
	parent := mandate.SpendingConstraints{
		SpendLimitUSD: 100, SessionLimitUSD: ptr(50.0), RequireHumanApprovalAboveUSD: ptr(20.0),
		MerchantCategory: &cat, AllowedMerchants: []string{"a", "b"},
		ValidFrom: "2026-01-01T00:00:00.000Z", ValidUntil: "2026-12-31T00:00:00.000Z",
	}
	ok := parent
	ok.SpendLimitUSD = 10
	if err := mandate.CheckNarrowing(parent, ok, "intent", "cart"); err != nil {
		t.Fatalf("identical-but-smaller child rejected: %v", err)
	}
	bad := map[string]func(c *mandate.SpendingConstraints){
		"spend":       func(c *mandate.SpendingConstraints) { c.SpendLimitUSD = 101 },
		"no session":  func(c *mandate.SpendingConstraints) { c.SessionLimitUSD = nil },
		"no approval": func(c *mandate.SpendingConstraints) { c.RequireHumanApprovalAboveUSD = nil },
		"approval up": func(c *mandate.SpendingConstraints) { c.RequireHumanApprovalAboveUSD = ptr(21.0) },
		"currency":    func(c *mandate.SpendingConstraints) { c.Currency = "EUR" },
		"category":    func(c *mandate.SpendingConstraints) { c.MerchantCategory = nil },
		"merchants":   func(c *mandate.SpendingConstraints) { c.AllowedMerchants = nil },
		"merchant x":  func(c *mandate.SpendingConstraints) { c.AllowedMerchants = []string{"x"} },
		"until":       func(c *mandate.SpendingConstraints) { c.ValidUntil = "2027-01-01T00:00:00.000Z" },
		"no until":    func(c *mandate.SpendingConstraints) { c.ValidUntil = "" },
		"from":        func(c *mandate.SpendingConstraints) { c.ValidFrom = "2025-01-01T00:00:00.000Z" },
	}
	for name, mutate := range bad {
		c := ok
		mutate(&c)
		err := mandate.CheckNarrowing(parent, c, "intent", "cart")
		if err == nil || !strings.HasPrefix(err.Error(), "Cannot attenuate intent → cart: ") {
			t.Errorf("%s: err = %v", name, err)
		}
	}
	// An EMPTY parent merchant list means "no merchant": the child must stay empty.
	empty := mandate.SpendingConstraints{SpendLimitUSD: 1, AllowedMerchants: []string{}}
	if err := mandate.CheckNarrowing(empty, mandate.SpendingConstraints{SpendLimitUSD: 1, AllowedMerchants: []string{}}, "intent", "cart"); err != nil {
		t.Errorf("empty→empty: %v", err)
	}
	if err := mandate.CheckNarrowing(empty, mandate.SpendingConstraints{SpendLimitUSD: 1, AllowedMerchants: []string{"a"}}, "intent", "cart"); err == nil {
		t.Error("empty→[a] accepted")
	}
	if err := mandate.CheckNarrowing(empty, mandate.SpendingConstraints{SpendLimitUSD: 1}, "intent", "cart"); err == nil {
		t.Error("empty→unrestricted accepted")
	}
	// Message parity with TS, including JS number formatting.
	err := mandate.CheckNarrowing(mandate.SpendingConstraints{SpendLimitUSD: 42.5}, mandate.SpendingConstraints{SpendLimitUSD: 100}, "intent", "cart")
	if err == nil || err.Error() != "Cannot attenuate intent → cart: child spendLimitUsd (100) exceeds parent (42.5)" {
		t.Errorf("message: %v", err)
	}
}

// ── Enforcement ──────────────────────────────────────────────────────────────

func TestEnforceSpendingConstraints(t *testing.T) {
	_, _, provider, _, cart := chain3(t)
	opts := func(amount float64, merchant string) mandate.EnforceOptions {
		return mandate.EnforceOptions{ProposedAmountUSD: amount, MerchantDID: merchant, RequireChain: true}
	}
	if _, err := mandate.EnforceSpendingConstraints(cart.Token, nil, opts(50, "m1")); err == nil {
		t.Fatal("nil key accepted")
	}
	agentKey := cart.Chain[0].Mandate.Grantee // the cart's grantor
	pub := identity.ResolveContentAddressedKey(agentKey)
	if _, err := mandate.EnforceSpendingConstraints(cart.Token, pub, opts(50, "m1")); err != nil {
		t.Fatalf("valid spend: %v", err)
	}
	code := func(err error) string {
		var v *mandate.ConstraintViolation
		if errors.As(err, &v) {
			return v.Code
		}
		return ""
	}
	if _, err := mandate.EnforceSpendingConstraints(cart.Token, pub, opts(101, "m1")); code(err) != mandate.ViolationLimitExceeded {
		t.Errorf("over limit: %v", err)
	}
	if _, err := mandate.EnforceSpendingConstraints(cart.Token, pub, opts(5, "m2")); code(err) != mandate.ViolationMerchantNotAllowed {
		t.Errorf("merchant: %v", err)
	}
	if _, err := mandate.EnforceSpendingConstraints(cart.Token, pub, opts(5, "")); code(err) != mandate.ViolationMerchantNotAllowed {
		t.Errorf("missing merchant: %v", err)
	}
	if _, err := mandate.EnforceSpendingConstraints(cart.Token, pub, opts(-1, "m1")); code(err) != mandate.ViolationInvalidAmount {
		t.Errorf("negative amount: %v", err)
	}
	_ = provider
}

// ── E-DID roots via Key Event Logs ───────────────────────────────────────────

func kelInception(t *testing.T, kind string, cur, next ed25519.PrivateKey, controller string) (string, []identity.KelEvent) {
	t.Helper()
	ev := map[string]any{
		"v": 1, "type": "inception", "kind": kind,
		"keys":          []string{identity.ToMultibase(cur.Public().(ed25519.PublicKey))},
		"nextKeyDigest": identity.KeyDigest(next.Public().(ed25519.PublicKey)),
		"createdAt":     "2026-10-07T00:00:00.000Z",
	}
	if controller != "" {
		ev["controller"] = controller
	}
	parsed, err := jcs.Parse(mustJSON(t, ev))
	if err != nil {
		t.Fatal(err)
	}
	m := parsed.(map[string]any)
	m["sig"] = base64.RawURLEncoding.EncodeToString(ed25519.Sign(cur, jcs.MustCanonicalize(m)))
	did, err := identity.DIDFromInception(m)
	if err != nil {
		t.Fatal(err)
	}
	return did, []identity.KelEvent{m}
}

func TestChain_PersonRootViaKel(t *testing.T) {
	_, personKey := mustKey(t)
	_, personNext := mustKey(t)
	_, agentKey := mustKey(t)
	_, agentNext := mustKey(t)
	personDID, personKel := kelInception(t, "person", personKey, personNext, "")
	agentDID, agentKel := kelInception(t, "agent", agentKey, agentNext, personDID)
	source := identity.KelSourceFromLogs(personKel, agentKel)

	intent, err := mandate.IssueIntent(personDID, agentDID, mandate.SpendingConstraints{SpendLimitUSD: 100}, personKey, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	cart, err := mandate.AttenuateToCart(intent, "did:aroha:shop", mandate.SpendingConstraints{SpendLimitUSD: 10}, agentKey, nil)
	if err != nil {
		t.Fatal(err)
	}
	r := mandate.VerifyMandateChain(cart.Token, nil, mandate.ChainOptions{KelSource: source, ExpectedRootPerson: personDID})
	if !r.Valid {
		t.Fatalf("%+v", r)
	}
	// Without a KEL source the E-DIDs do not resolve.
	if r := mandate.VerifyMandateChain(cart.Token, nil, mandate.ChainOptions{}); r.Valid {
		t.Fatal("E-DID resolved without a KEL source")
	}
	// RequirePersonRoot needs a KelSource.
	if r := mandate.VerifyMandateChain(cart.Token, nil, mandate.ChainOptions{RequirePersonRoot: true}); r.Valid {
		t.Fatal("RequirePersonRoot without KelSource accepted")
	}
	// An agent-rooted chain is refused when a person root is required.
	agentRoot, err := mandate.IssueIntent(agentDID, "did:aroha:shop", mandate.SpendingConstraints{SpendLimitUSD: 1}, agentKey, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if r := mandate.VerifyMandateChain(agentRoot.Token, nil, mandate.ChainOptions{KelSource: source, RequirePersonRoot: true}); r.Valid ||
		!strings.Contains(r.Reason, "not a person") {
		t.Fatalf("%+v", r)
	}
	// NewKeyResolver resolves the E-DID's current key.
	resolve := mandate.NewKeyResolver(mandate.KeyResolverOptions{KelSource: source})
	if k, _ := resolve(personDID); !bytes.Equal(k, personKey.Public().(ed25519.PublicKey)) {
		t.Error("NewKeyResolver did not resolve the person key")
	}
}

// A forged root whose grantor is the LEAF grantor's DID, signed with the leaf
// key, must not verify: the caller-supplied key covers the leaf only, and
// every ancestor is resolved independently.
func TestVerifyMandate_LeafKeyDoesNotVouchForAncestors(t *testing.T) {
	leafPub, leafKey := mustKey(t)
	const agent = "did:aroha:agent" // named DID: not resolvable by the default resolver

	forgedRoot, err := mandate.IssueIntent(agent, agent, mandate.SpendingConstraints{SpendLimitUSD: 1e6}, leafKey, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	cart, err := mandate.AttenuateToCart(forgedRoot, "did:aroha:shop", mandate.SpendingConstraints{SpendLimitUSD: 1e6}, leafKey, nil)
	if err != nil {
		t.Fatal(err)
	}
	r := mandate.VerifyMandate(cart.Token, leafPub, "", mandate.VerifyOptions{})
	if r.Valid || !strings.Contains(r.Reason, "chain link 0") {
		t.Fatalf("forged root accepted: %+v", r)
	}
	if _, err := mandate.Verify(cart.Token, leafPub, ""); err == nil {
		t.Fatal("Verify accepted a forged root")
	}
}

func TestVerifyMandate_SelfCertifyingGrantorKeyMustMatch(t *testing.T) {
	human := newParty(t)
	otherPub, _ := mustKey(t)
	m, err := mandate.IssueIntent(human.did, "did:aroha:e", mandate.SpendingConstraints{SpendLimitUSD: 1}, human.priv, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if r := mandate.VerifyMandate(m.Token, otherPub, "", mandate.VerifyOptions{}); r.Valid ||
		!strings.Contains(r.Reason, "does not match the self-certifying grantor") {
		t.Fatalf("%+v", r)
	}
	if r := mandate.VerifyMandate(m.Token, human.pub, "", mandate.VerifyOptions{}); !r.Valid {
		t.Fatalf("%+v", r)
	}
}
