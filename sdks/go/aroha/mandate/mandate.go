// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

// Package mandate implements ArohaSpendingMandate — Ed25519-signed spending
// delegation tokens — at wire parity with @aroha-sdk/credentials
// (packages/aroha-credentials/src/mandate.ts).
//
// A mandate chain enforces:
//
//  1. Provenance: every mandate traces back, link by link, to a root intent
//     mandate. VerifyMandateChain proves it: each link is signed by its
//     grantor, each grantor is the previous link's grantee, and each
//     parentMandateId names the previous link. A v2 token CARRIES its
//     ancestors so a verifier can check this offline.
//  2. Monotonic narrowing (CheckNarrowing): a child's constraints must be a
//     subset of its parent's. Checked at attenuation time as a courtesy and
//     AGAIN by the verifier on every link — only the verifier-side check is a
//     security property, because the attenuating agent can skip its own.
//
// Token versions:
//
//	v1 (legacy, read-only) {mandate, signature}, signed over the sorted-key
//	   JSON of the body. Accepted by VerifyMandate; accepted by
//	   VerifyMandateChain only as a root (a v1 child cannot prove its origin).
//	v2 {v: 2, mandate, signature, chain}: chain is the signed ancestry, root
//	   first, excluding this mandate. Each v2 signature covers the RFC 8785
//	   (JCS) form of {"mandate": <body>, "v": 2}, so a v2 signature can never
//	   be replayed as a v1 one or vice versa.
//
// Signatures are verified over the mandate exactly as received (its JSON data
// model, canonicalised), never over a re-encoding of the Go struct, so fields
// this SDK does not model still verify.
//
// References: AP2 (Intent/Cart/Payment mandates);
// draft-niyikiza-oauth-attenuating-agent-tokens; RFC 8785.
package mandate

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/ArohaLabs/aroha-protocol/sdks/go/aroha/identity"
	"github.com/ArohaLabs/aroha-protocol/sdks/go/aroha/jcs"
	"github.com/google/uuid"
)

// TokenVersion is the mandate token version every issuing function produces.
const TokenVersion = 2

// DefaultClockTolerance is the allowed skew for NOT-BEFORE checks (issuedAt,
// validFrom). It is deliberately not applied to expiresAt / validUntil.
const DefaultClockTolerance = 30 * time.Second

// DefaultMaxDepth is the default maximum chain length, root and leaf included.
const DefaultMaxDepth = 8

// ─── Types ────────────────────────────────────────────────────────────────────

// SpendingConstraints defines the spend envelope for a mandate.
//
// Optional fields that are unset are ABSENT on the wire, never null. The one
// field where empty and absent differ is AllowedMerchants: nil means "no
// merchant restriction" and is omitted; a non-nil empty slice means "no
// merchant at all" and is encoded as [].
type SpendingConstraints struct {
	SpendLimitUSD                float64  `json:"spendLimitUsd"`
	SessionLimitUSD              *float64 `json:"sessionLimitUsd,omitempty"`
	RequireHumanApprovalAboveUSD *float64 `json:"requireHumanApprovalAboveUsd,omitempty"`
	// Currency defaults to USD when empty.
	Currency         string   `json:"currency,omitempty"`
	MerchantCategory *string  `json:"merchantCategory,omitempty"`
	AllowedMerchants []string `json:"allowedMerchants,omitempty"`
	ValidFrom        string   `json:"validFrom,omitempty"`
	ValidUntil       string   `json:"validUntil,omitempty"`
}

// MarshalJSON encodes the constraints with every unset optional field
// absent, and keeps a non-nil empty AllowedMerchants as [] (see the type doc).
func (c SpendingConstraints) MarshalJSON() ([]byte, error) {
	type plain SpendingConstraints // no methods: avoids recursion
	raw, err := json.Marshal(plain(c))
	if err != nil {
		return nil, err
	}
	if c.AllowedMerchants == nil || len(c.AllowedMerchants) > 0 {
		return raw, nil
	}
	// omitempty dropped the empty list; put it back.
	return append(raw[:len(raw)-1], []byte(`,"allowedMerchants":[]}`)...), nil
}

// MandateTier is the delegation level.
type MandateTier string

const (
	TierIntent  MandateTier = "intent"
	TierCart    MandateTier = "cart"
	TierPayment MandateTier = "payment"
)

// tierRank: a child may sit at its parent's tier or a narrower one, never a
// broader one.
var tierRank = map[MandateTier]int{TierIntent: 0, TierCart: 1, TierPayment: 2}

// SpendingMandate is the mandate body.
type SpendingMandate struct {
	MandateTier     MandateTier         `json:"mandateTier"`
	Constraints     SpendingConstraints `json:"constraints"`
	Grantee         string              `json:"grantee"`
	Grantor         string              `json:"grantor"`
	IssuedAt        string              `json:"issuedAt"`
	ExpiresAt       string              `json:"expiresAt"`
	ParentMandateID *string             `json:"parentMandateId"` // null for a root
	MandateID       string              `json:"mandateId"`
}

// ChainLink is one signed link of a mandate chain, as carried in a v2 token.
type ChainLink struct {
	// V is the signing rule THIS link's signature follows: 1 (legacy) or 2 (JCS).
	V         int
	Mandate   SpendingMandate
	Signature string
	raw       any // the mandate's JSON data model exactly as signed, when known
}

// MarshalJSON encodes the link with the mandate exactly as it was signed.
func (l ChainLink) MarshalJSON() ([]byte, error) {
	m, err := mandateValue(l.raw, l.Mandate)
	if err != nil {
		return nil, err
	}
	return marshalNoEscape(map[string]any{"v": l.V, "mandate": m, "signature": l.Signature})
}

// SignedMandate bundles a mandate with its signature, token and ancestry.
type SignedMandate struct {
	Mandate SpendingMandate
	// Signature is the base64url Ed25519 signature over the canonical mandate.
	Signature string
	// Token is the base64url serialised token for a message's credentialToken.
	Token string
	// V is the token version: 2 for everything this SDK issues, 1 for legacy.
	V int
	// Chain is the signed ancestry, root first, EXCLUDING this mandate. Empty
	// for a root; nil on legacy v1 tokens.
	Chain []ChainLink
	raw   any
}

// VerificationResult is the outcome of VerifyMandate / VerifyMandateChain.
type VerificationResult struct {
	Valid   bool
	Mandate *SpendingMandate
	Reason  string
	// ChainVerified is true only when every link from a root intent mandate
	// down to this one was verified. False for a legacy v1 child token, which
	// proves only that its immediate grantor signed it.
	ChainVerified bool
	// Chain is the verified chain, root first, including the leaf.
	Chain []SpendingMandate
	// RootGrantor is the grantor of the verified root mandate.
	RootGrantor string
}

// KeyResolver resolves the Ed25519 public key a DID signs with. Return
// (nil, nil) for an unknown DID; an error fails verification (fail closed).
// It must not trust anything inside the token being verified.
type KeyResolver func(did string) (ed25519.PublicKey, error)

// RevocationCheck reports whether the mandate mandateID issued by grantor was
// revoked. An error fails verification (fail closed).
//
// A mandateId is chosen by whoever mints the mandate, so on its own it names
// nothing: anyone can mint a valid mandate of their own that reuses someone
// else's id. The grantor is what the signature binds, so (grantor, mandateId)
// is the identity a shared revocation list must be keyed by.
type RevocationCheck func(mandateID, grantor string) (bool, error)

// CheckOptions are shared by VerifyMandate and VerifyMandateChain.
type CheckOptions struct {
	// IsRevoked is consulted for EVERY link: revoking the root kills the chain.
	IsRevoked RevocationCheck
	// ClockTolerance is the not-before skew allowance. nil = DefaultClockTolerance.
	ClockTolerance *time.Duration
	// Now overrides the current time (tests, replayed audits). Zero = time.Now().
	Now time.Time
	// ExpectedRoot, if set, must equal the chain root's grantor.
	ExpectedRoot string
}

// VerifyOptions configures VerifyMandate.
type VerifyOptions struct {
	CheckOptions
	// KeyRotatedAt rejects a leaf issued at or before the grantor's last key
	// rotation.
	KeyRotatedAt *time.Time
	// ResolveKey resolves the ANCESTORS of a v2 token (the leaf is checked
	// against the key passed to VerifyMandate). Default
	// ResolveContentAddressedKey.
	ResolveKey KeyResolver
}

// ChainOptions configures VerifyMandateChain.
type ChainOptions struct {
	CheckOptions
	// ExpectedGrantee, if set, must equal the leaf's grantee (normally you).
	ExpectedGrantee string
	// MaxDepth is the maximum number of links. 0 = DefaultMaxDepth.
	MaxDepth int
	// KelSource resolves did:aroha:E… DIDs through their verified Key Event
	// Logs: a grantor's signature is checked against its CURRENT key, and a
	// link whose grantor or grantee (or their controller) is revoked fails.
	// A missing, stale or forked log fails closed.
	KelSource identity.KelSource
	// KelStore is highest-seen KEL memory, used with KelSource.
	KelStore identity.KelStore
	// RequirePersonRoot requires the root grantor to be a non-revoked person
	// E-DID. Requires KelSource.
	RequirePersonRoot bool
	// ExpectedRootPerson implies RequirePersonRoot and pins the person DID.
	ExpectedRootPerson string
}

// ─── Key resolution ───────────────────────────────────────────────────────────

// ResolveContentAddressedKey is the default KeyResolver: it derives the key
// from a content-addressed did:aroha:z… DID and returns (nil, nil) for every
// other form, including named DIDs, which need a registry-backed resolver.
func ResolveContentAddressedKey(did string) (ed25519.PublicKey, error) {
	return identity.ResolveContentAddressedKey(did), nil
}

// KeyResolverOptions configures NewKeyResolver.
type KeyResolverOptions struct {
	// KelSource fetches KELs for did:aroha:E… DIDs; without it E-DIDs resolve to nil.
	KelSource identity.KelSource
	// KelStore rejects stale or forked logs.
	KelStore identity.KelStore
	// Fallback resolves every other DID form (named, registry-trusted).
	Fallback KeyResolver
}

// NewKeyResolver covers all three did:aroha: forms: E-DIDs from their
// verified KEL, z-DIDs from the DID itself, anything else via Fallback. The
// self-certifying forms never fall through to Fallback, so a registry cannot
// substitute a key for a DID that carries its own proof.
func NewKeyResolver(opts KeyResolverOptions) KeyResolver {
	var kel func(string) ed25519.PublicKey
	if opts.KelSource != nil {
		kel = identity.KelKeyResolver(opts.KelSource, identity.ResolveKelStateOptions{Store: opts.KelStore})
	}
	return func(did string) (ed25519.PublicKey, error) {
		if identity.IsInceptionDID(did) {
			if kel == nil {
				return nil, nil
			}
			return kel(did), nil
		}
		if k := identity.ResolveContentAddressedKey(did); k != nil {
			return k, nil
		}
		if opts.Fallback != nil {
			return opts.Fallback(did)
		}
		return nil, nil
	}
}

// ─── Issue ────────────────────────────────────────────────────────────────────

// IssueIntent issues a root Intent Mandate (v2 token, empty chain).
func IssueIntent(
	grantorDID, granteeDID string,
	constraints SpendingConstraints,
	privateKey ed25519.PrivateKey,
	ttl time.Duration,
) (*SignedMandate, error) {
	expires := time.Now().Add(ttl).UnixMilli()
	return issue(TierIntent, grantorDID, granteeDID, constraints, nil, privateKey, expires, []ChainLink{})
}

// AttenuateToCart narrows a mandate to a Cart Mandate.
//
// Runs, in order: inheritance (sessionLimitUsd, requireHumanApprovalAboveUsd,
// validFrom, validUntil and currency that the parent sets and the caller
// omits are copied from the parent); CheckNarrowing; then signs a child
// whose token embeds the parent's chain plus the parent itself. The child
// never outlives its parent: ttl nil or 0 means "the parent's expiry".
func AttenuateToCart(
	parent *SignedMandate,
	granteeDID string,
	narrowed SpendingConstraints,
	grantorKey ed25519.PrivateKey,
	ttl *time.Duration,
) (*SignedMandate, error) {
	return attenuate(TierCart, parent, granteeDID, narrowed, grantorKey, ttl)
}

// AttenuateToPayment narrows a mandate to a single-transaction Payment
// Mandate. Same inheritance, narrowing and expiry rules as AttenuateToCart.
func AttenuateToPayment(
	parent *SignedMandate,
	granteeDID string,
	narrowed SpendingConstraints,
	grantorKey ed25519.PrivateKey,
	ttl *time.Duration,
) (*SignedMandate, error) {
	return attenuate(TierPayment, parent, granteeDID, narrowed, grantorKey, ttl)
}

func attenuate(
	tier MandateTier,
	parent *SignedMandate,
	granteeDID string,
	narrowed SpendingConstraints,
	grantorKey ed25519.PrivateKey,
	ttl *time.Duration,
) (*SignedMandate, error) {
	if parent == nil {
		return nil, errors.New("parent mandate is nil")
	}
	parentTier := parent.Mandate.MandateTier
	pr, ok := tierRank[parentTier]
	if !ok {
		return nil, fmt.Errorf("parent mandateTier %q is invalid", parentTier)
	}
	if tierRank[tier] < pr {
		return nil, fmt.Errorf("Cannot attenuate %s → %s: a child cannot be a broader tier than its parent", parentTier, tier)
	}

	constraints := inheritConstraints(parent.Mandate.Constraints, narrowed)
	if err := CheckNarrowing(parent.Mandate.Constraints, constraints, string(parentTier), string(tier)); err != nil {
		return nil, err
	}

	chain, err := ancestryIncludingParent(parent)
	if err != nil {
		return nil, err
	}

	parentExpiry, err := isoMillis(parent.Mandate.ExpiresAt)
	if err != nil {
		return nil, fmt.Errorf("parent expiresAt: %w", err)
	}
	// An ABSOLUTE instant: converting back to a relative TTL would read the
	// clock twice and could land the child a tick past its parent.
	expiry := parentExpiry
	if ttl != nil && *ttl != 0 {
		if e := time.Now().Add(*ttl).UnixMilli(); e < expiry {
			expiry = e
		}
	}
	pid := parent.Mandate.MandateID
	return issue(tier, parent.Mandate.Grantee, granteeDID, constraints, &pid, grantorKey, expiry, chain)
}

// ancestryIncludingParent returns the chain a child of parent must carry:
// the parent's own ancestry followed by the parent. It prefers parent.Chain,
// falls back to decoding parent.Token, and accepts a legacy v1 parent only
// if it is a root (a v1 child's ancestors were never transmitted).
func ancestryIncludingParent(parent *SignedMandate) ([]ChainLink, error) {
	version := parent.V
	ancestors := parent.Chain
	raw := parent.raw
	if ancestors == nil && parent.Token != "" {
		if leaf, anc, reason := parseToken(parent.Token); reason == "" && leaf.Mandate.MandateID == parent.Mandate.MandateID {
			version = leaf.V
			if leaf.V == 2 {
				ancestors = anc
			}
			if raw == nil {
				raw = leaf.raw
			}
		}
	}
	v := 1
	if version == 2 {
		v = 2
	}
	if ancestors == nil {
		if parent.Mandate.ParentMandateID != nil {
			return nil, errors.New("Cannot attenuate a legacy v1 mandate that is not a root: its ancestry was never embedded, " +
				"so the child could not be verified back to the human. Re-issue the chain from the root.")
		}
		ancestors = []ChainLink{}
	}
	out := make([]ChainLink, 0, len(ancestors)+1)
	out = append(out, ancestors...)
	return append(out, ChainLink{V: v, Mandate: parent.Mandate, Signature: parent.Signature, raw: raw}), nil
}

// DecodeToken decodes a mandate token without verifying it (use
// VerifyMandateChain for that) — e.g. to attenuate a received token further.
func DecodeToken(token string) (*SignedMandate, error) {
	leaf, anc, reason := parseToken(token)
	if reason != "" {
		return nil, errors.New(reason)
	}
	sm := &SignedMandate{Mandate: leaf.Mandate, Signature: leaf.Signature, Token: token, V: leaf.V, raw: leaf.raw}
	if leaf.V == 2 {
		sm.Chain = anc
	}
	return sm, nil
}

func issue(
	tier MandateTier,
	grantorDID, granteeDID string,
	constraints SpendingConstraints,
	parentID *string,
	privateKey ed25519.PrivateKey,
	expiresAtMs int64,
	chain []ChainLink,
) (*SignedMandate, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("private key is %d bytes, want %d", len(privateKey), ed25519.PrivateKeySize)
	}
	if reason := checkConstraintsStruct(constraints); reason != "" {
		return nil, fmt.Errorf("Invalid spending constraints: %s", reason)
	}
	m := SpendingMandate{
		MandateTier:     tier,
		Constraints:     constraints,
		Grantee:         granteeDID,
		Grantor:         grantorDID,
		IssuedAt:        formatISO(time.Now().UnixMilli()),
		ExpiresAt:       formatISO(expiresAtMs),
		ParentMandateID: parentID,
		MandateID:       uuid.New().String(),
	}
	// The body we sign is exactly the body a verifier will decode.
	raw, err := toDataModel(m)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(mustMarshal(raw), &m); err != nil {
		return nil, err
	}
	payload, err := jcs.Canonicalize(map[string]any{"mandate": raw, "v": 2})
	if err != nil {
		return nil, err
	}
	sig := base64.RawURLEncoding.EncodeToString(ed25519.Sign(privateKey, payload))
	if chain == nil {
		chain = []ChainLink{}
	}
	tokenJSON, err := marshalNoEscape(map[string]any{"v": TokenVersion, "mandate": raw, "signature": sig, "chain": chain})
	if err != nil {
		return nil, err
	}
	return &SignedMandate{
		Mandate:   m,
		Signature: sig,
		Token:     base64.RawURLEncoding.EncodeToString(tokenJSON),
		V:         2,
		Chain:     chain,
		raw:       raw,
	}, nil
}

// SigningPayloadV2 returns the exact bytes a v2 mandate signature covers:
// RFC 8785 JCS of {"mandate": <body>, "v": 2}.
func SigningPayloadV2(m SpendingMandate) ([]byte, error) {
	raw, err := toDataModel(m)
	if err != nil {
		return nil, err
	}
	return jcs.Canonicalize(map[string]any{"mandate": raw, "v": 2})
}

// ─── Verify ───────────────────────────────────────────────────────────────────

// Verify is the original single-key API: it verifies token against the
// LEAF grantor's publicKey with default options and returns the leaf mandate.
//
// For a v2 token the embedded chain must also verify, with ancestor keys
// derived from content-addressed DIDs; use VerifyMandate with
// VerifyOptions.ResolveKey for other DID forms. A legacy v1 child token is
// accepted WITHOUT proof of its ancestry — gate money on VerifyMandateChain.
func Verify(token string, publicKey ed25519.PublicKey, expectedGrantee string) (*SpendingMandate, error) {
	r := VerifyMandate(token, publicKey, expectedGrantee, VerifyOptions{})
	if !r.Valid {
		return nil, errors.New(r.Reason)
	}
	return r.Mandate, nil
}

// VerifyMandate verifies a token against ONE caller-supplied key (the
// leaf's grantor). It proves the leaf was signed by that key, is within its
// time window, is not revoked and (optionally) names expectedGrantee. For a
// v2 token it ALSO verifies the embedded chain back to a root. For a legacy
// v1 child token it cannot prove human authorisation: ChainVerified is false.
func VerifyMandate(token string, publicKey ed25519.PublicKey, expectedGrantee string, opts VerifyOptions) VerificationResult {
	leaf, ancestors, reason := parseToken(token)
	if reason != "" {
		return invalid(reason)
	}
	m := leaf.Mandate
	now, tol := opts.CheckOptions.clock()

	if p := checkTimeWindow(m, now, tol); p != "" {
		return invalid(p)
	}
	if expectedGrantee != "" && m.Grantee != expectedGrantee {
		return invalid("Mandate grantee mismatch: expected " + expectedGrantee)
	}
	if opts.KeyRotatedAt != nil {
		var issued int64
		if ms, err := isoMillis(m.IssuedAt); err == nil {
			issued = ms
		}
		if issued <= opts.KeyRotatedAt.UnixMilli() {
			return invalid("Mandate was signed with a since-rotated key")
		}
	}
	ancestorResolver := opts.ResolveKey
	if ancestorResolver == nil {
		ancestorResolver = ResolveContentAddressedKey
	}
	// A self-certifying grantor (did:aroha:z… or did:aroha:E…) carries its own
	// key: the caller-supplied key must be the one the DID resolves to.
	if identity.IsContentAddressedDID(m.Grantor) || identity.IsInceptionDID(m.Grantor) {
		derived, err := ancestorResolver(m.Grantor)
		if identity.IsContentAddressedDID(m.Grantor) && derived == nil && err == nil {
			derived = identity.ResolveContentAddressedKey(m.Grantor)
		}
		if err != nil {
			return invalid("Key resolution failed for grantor " + m.Grantor)
		}
		if derived != nil && !bytes.Equal(derived, publicKey) {
			return invalid("Supplied public key does not match the self-certifying grantor DID " + m.Grantor)
		}
	}
	if p := checkLinkSignature(leaf, publicKey); p != "" {
		return invalid(p)
	}
	if p := checkRevocation(m, opts.IsRevoked); p != "" {
		return invalid(p)
	}

	if leaf.V == 1 {
		isRoot := m.ParentMandateID == nil
		if opts.ExpectedRoot != "" {
			if !isRoot {
				return invalid("Legacy v1 token carries no ancestry; cannot prove the expected root")
			}
			if m.Grantor != opts.ExpectedRoot {
				return invalid(fmt.Sprintf("Chain root mismatch: expected %s, got %s", opts.ExpectedRoot, m.Grantor))
			}
		}
		if isRoot && m.MandateTier != TierIntent {
			return invalid(fmt.Sprintf("A root mandate must be an intent mandate, got %s", m.MandateTier))
		}
		if isRoot {
			return VerificationResult{Valid: true, Mandate: &m, ChainVerified: true, Chain: []SpendingMandate{m}, RootGrantor: m.Grantor}
		}
		return VerificationResult{Valid: true, Mandate: &m, ChainVerified: false}
	}

	// The caller vouched for the LEAF's key only. Every ancestor is resolved
	// independently — even one whose grantor DID equals the leaf's — so a
	// forged root "signed by" the leaf grantor cannot borrow the leaf key.
	return verifyLinksWithLeafKey(append(ancestors, leaf), ancestorResolver, publicKey, ChainOptions{
		CheckOptions:    opts.CheckOptions,
		ExpectedGrantee: expectedGrantee,
	})
}

// VerifyMandateChain verifies a token all the way back to its root — the
// check a payee must run before moving money. For every link, root first:
// the signature verifies against resolveKey(grantor); the root has no
// parent, is an intent, and matches ExpectedRoot; each child's grantor is
// its parent's grantee, parentMandateId names the parent, its tier is not
// broader, its constraints narrow the parent's, and it does not outlive the
// parent; every link is inside its time window and not revoked. A legacy v1
// token is accepted only if it is itself a root. resolveKey nil means
// ResolveContentAddressedKey.
func VerifyMandateChain(token string, resolveKey KeyResolver, opts ChainOptions) VerificationResult {
	leaf, ancestors, reason := parseToken(token)
	if reason != "" {
		return invalid(reason)
	}
	if leaf.V == 1 && leaf.Mandate.ParentMandateID != nil {
		return invalid("Legacy v1 token carries no ancestry; it cannot be verified back to a root")
	}
	if resolveKey == nil {
		resolveKey = ResolveContentAddressedKey
	}
	return verifyLinks(append(ancestors, leaf), resolveKey, opts)
}

type kelResult struct {
	state *identity.KelState
	err   string
}

func verifyLinks(links []ChainLink, resolveKey KeyResolver, opts ChainOptions) VerificationResult {
	return verifyLinksWithLeafKey(links, resolveKey, nil, opts)
}

// verifyLinksWithLeafKey verifies links; when leafKey is non-nil it is used
// for the LAST link only, and every other link resolves through resolveKey.
func verifyLinksWithLeafKey(links []ChainLink, resolveKey KeyResolver, leafKey ed25519.PublicKey, opts ChainOptions) VerificationResult {
	now, tol := opts.CheckOptions.clock()
	maxDepth := opts.MaxDepth
	if maxDepth <= 0 {
		maxDepth = DefaultMaxDepth
	}
	if len(links) == 0 {
		return invalid("Empty mandate chain")
	}
	if len(links) > maxDepth {
		return invalid(fmt.Sprintf("Mandate chain has %d links; maximum is %d", len(links), maxDepth))
	}
	requirePerson := opts.RequirePersonRoot || opts.ExpectedRootPerson != ""
	if requirePerson && opts.KelSource == nil {
		return invalid("requirePersonRoot needs a kelSource to verify the root person's KEL")
	}
	var kelStateOf func(string) kelResult
	if opts.KelSource != nil {
		cache := map[string]kelResult{}
		kelStateOf = func(did string) kelResult {
			if r, ok := cache[did]; ok {
				return r
			}
			var r kelResult
			st, err := identity.ResolveKelState(did, opts.KelSource, identity.ResolveKelStateOptions{Store: opts.KelStore, RequireController: true})
			switch {
			case err != nil:
				r.err = "Key Event Log rejected: " + err.Error()
			case st == nil:
				r.err = "no Key Event Log available"
			case st.Revoked:
				r.err = "identity has been revoked"
			case st.ControllerRevoked:
				r.err = fmt.Sprintf("controller %s has been revoked", st.Controller)
			default:
				r.state = st
			}
			cache[did] = r
			return r
		}
	}

	seen := map[string]bool{}
	for i, link := range links {
		m := link.Mandate
		where := fmt.Sprintf("chain link %d (%s %s)", i, m.MandateTier, m.MandateID)
		fail := func(reason string) VerificationResult { return invalid(where + ": " + reason) }

		if seen[m.MandateID] {
			return fail("mandateId repeats within the chain")
		}
		seen[m.MandateID] = true

		// Signature first: nothing below means anything until we know who wrote it.
		var key ed25519.PublicKey
		var grantorKel *identity.KelState
		if leafKey != nil && i == len(links)-1 {
			key = leafKey
		} else if kelStateOf != nil && identity.IsInceptionDID(m.Grantor) {
			r := kelStateOf(m.Grantor)
			if r.err != "" {
				return fail(fmt.Sprintf("grantor %s: %s", m.Grantor, r.err))
			}
			grantorKel = r.state
			key = r.state.CurrentKey
		} else {
			k, err := resolveKey(m.Grantor)
			if err != nil {
				return fail("Key resolution failed for grantor " + m.Grantor)
			}
			key = k
		}
		if key == nil {
			return fail("Cannot resolve public key for grantor " + m.Grantor)
		}
		if p := checkLinkSignature(link, key); p != "" {
			return fail(p)
		}

		// The grantee holds this link's authority: if it was revoked, so was that.
		if kelStateOf != nil && identity.IsInceptionDID(m.Grantee) {
			if r := kelStateOf(m.Grantee); r.err != "" {
				return fail(fmt.Sprintf("grantee %s: %s", m.Grantee, r.err))
			}
		}

		if i == 0 {
			if m.ParentMandateID != nil {
				return fail("first link has a parentMandateId — the token does not carry its full ancestry back to a root")
			}
			if m.MandateTier != TierIntent {
				return fail(fmt.Sprintf("a root mandate must be an intent mandate, got %s", m.MandateTier))
			}
			if opts.ExpectedRoot != "" && m.Grantor != opts.ExpectedRoot {
				return fail(fmt.Sprintf("Chain root mismatch: expected %s, got %s", opts.ExpectedRoot, m.Grantor))
			}
			if requirePerson {
				if grantorKel == nil {
					return fail(fmt.Sprintf("root grantor %s is not a person identity (did:aroha:E…)", m.Grantor))
				}
				if grantorKel.Kind != "person" {
					return fail(fmt.Sprintf("root grantor %s is an %s, not a person", m.Grantor, grantorKel.Kind))
				}
				if opts.ExpectedRootPerson != "" && m.Grantor != opts.ExpectedRootPerson {
					return fail(fmt.Sprintf("Chain root mismatch: expected person %s, got %s", opts.ExpectedRootPerson, m.Grantor))
				}
			}
		} else {
			p := links[i-1].Mandate
			if m.Grantor != p.Grantee {
				return fail(fmt.Sprintf("grantor %s is not the parent's grantee %s", m.Grantor, p.Grantee))
			}
			if m.ParentMandateID == nil || *m.ParentMandateID != p.MandateID {
				pid := "null"
				if m.ParentMandateID != nil {
					pid = *m.ParentMandateID
				}
				return fail(fmt.Sprintf("parentMandateId %s does not match the parent's mandateId %s", pid, p.MandateID))
			}
			if tierRank[m.MandateTier] < tierRank[p.MandateTier] {
				return fail(fmt.Sprintf("tier %s is broader than the parent's %s", m.MandateTier, p.MandateTier))
			}
			if err := CheckNarrowing(p.Constraints, m.Constraints, string(p.MandateTier), string(m.MandateTier)); err != nil {
				return fail(err.Error())
			}
			ce, _ := isoMillis(m.ExpiresAt)
			pe, _ := isoMillis(p.ExpiresAt)
			if ce > pe {
				return fail(fmt.Sprintf("expiresAt %s outlives the parent's %s", m.ExpiresAt, p.ExpiresAt))
			}
		}

		if p := checkTimeWindow(m, now, tol); p != "" {
			return fail(p)
		}
		if p := checkRevocation(m, opts.IsRevoked); p != "" {
			return fail(p)
		}
	}

	leaf := links[len(links)-1].Mandate
	if opts.ExpectedGrantee != "" && leaf.Grantee != opts.ExpectedGrantee {
		return invalid("Mandate grantee mismatch: expected " + opts.ExpectedGrantee)
	}
	chain := make([]SpendingMandate, len(links))
	for i, l := range links {
		chain[i] = l.Mandate
	}
	return VerificationResult{
		Valid: true, Mandate: &leaf, ChainVerified: true, Chain: chain, RootGrantor: links[0].Mandate.Grantor,
	}
}

func invalid(reason string) VerificationResult {
	return VerificationResult{Valid: false, Reason: reason}
}

func (o CheckOptions) clock() (nowMs, tolMs int64) {
	now := o.Now
	if now.IsZero() {
		now = time.Now()
	}
	tol := DefaultClockTolerance
	if o.ClockTolerance != nil {
		tol = *o.ClockTolerance
	}
	return now.UnixMilli(), tol.Milliseconds()
}

// ─── Enforcement ──────────────────────────────────────────────────────────────

// Violation codes returned in ConstraintViolation.Code.
const (
	ViolationMandateInvalid      = "MANDATE_INVALID"
	ViolationLimitExceeded       = "LIMIT_EXCEEDED"
	ViolationMerchantNotAllowed  = "MERCHANT_NOT_ALLOWED"
	ViolationInvalidAmount       = "INVALID_AMOUNT"
	ViolationRedemptionExhausted = "REDEMPTION_LIMIT_EXCEEDED"
)

// ConstraintViolation is returned by EnforceSpendingConstraints.
type ConstraintViolation struct {
	Code    string
	Message string
}

func (e *ConstraintViolation) Error() string { return e.Message }

// EnforceOptions configures EnforceSpendingConstraints.
type EnforceOptions struct {
	CheckOptions
	ExpectedGrantee string
	// MerchantDID is checked against allowedMerchants when the mandate restricts them.
	MerchantDID       string
	ProposedAmountUSD float64
	KeyRotatedAt      *time.Time
	ResolveKey        KeyResolver
	// RequireChain demands the token verify back to a root. Set it at any gate
	// that moves real money.
	RequireChain bool
}

// EnforceSpendingConstraints verifies a token AND asserts the proposed
// spend is within its constraints. Call it at the payment gate.
func EnforceSpendingConstraints(token string, grantorPublicKey ed25519.PublicKey, opts EnforceOptions) (*SpendingMandate, error) {
	r := VerifyMandate(token, grantorPublicKey, opts.ExpectedGrantee, VerifyOptions{
		CheckOptions: opts.CheckOptions, KeyRotatedAt: opts.KeyRotatedAt, ResolveKey: opts.ResolveKey,
	})
	if !r.Valid {
		return nil, &ConstraintViolation{ViolationMandateInvalid, "Mandate invalid: " + r.Reason}
	}
	if opts.RequireChain && !r.ChainVerified {
		return nil, &ConstraintViolation{ViolationMandateInvalid,
			"Mandate invalid: token does not carry a chain verifiable back to a root mandate"}
	}
	c := r.Mandate.Constraints
	amt := opts.ProposedAmountUSD
	if math.IsNaN(amt) || math.IsInf(amt, 0) || amt < 0 {
		return nil, &ConstraintViolation{ViolationInvalidAmount,
			fmt.Sprintf("Proposed amount %s is not a finite, non-negative number", fmtNum(amt))}
	}
	if amt > c.SpendLimitUSD {
		return nil, &ConstraintViolation{ViolationLimitExceeded,
			fmt.Sprintf("Proposed $%s exceeds mandate limit $%s", fmtNum(amt), fmtNum(c.SpendLimitUSD))}
	}
	if c.AllowedMerchants != nil {
		if opts.MerchantDID == "" {
			return nil, &ConstraintViolation{ViolationMerchantNotAllowed,
				"merchantDID is required when the mandate restricts allowedMerchants"}
		}
		allowed := false
		for _, m := range c.AllowedMerchants {
			if m == opts.MerchantDID {
				allowed = true
				break
			}
		}
		if !allowed {
			return nil, &ConstraintViolation{ViolationMerchantNotAllowed,
				fmt.Sprintf("Merchant %s is not in the mandate's allowed merchant list", opts.MerchantDID)}
		}
	}
	return r.Mandate, nil
}

// ─── Narrowing ────────────────────────────────────────────────────────────────

// inheritConstraints copies the optional limits a child omits from its
// parent. allowedMerchants and merchantCategory are NOT inherited: a caller
// must restate a merchant restriction explicitly (omitting it is an error).
func inheritConstraints(parent, child SpendingConstraints) SpendingConstraints {
	if child.SessionLimitUSD == nil && parent.SessionLimitUSD != nil {
		v := *parent.SessionLimitUSD
		child.SessionLimitUSD = &v
	}
	if child.RequireHumanApprovalAboveUSD == nil && parent.RequireHumanApprovalAboveUSD != nil {
		v := *parent.RequireHumanApprovalAboveUSD
		child.RequireHumanApprovalAboveUSD = &v
	}
	if child.ValidFrom == "" {
		child.ValidFrom = parent.ValidFrom
	}
	if child.ValidUntil == "" {
		child.ValidUntil = parent.ValidUntil
	}
	if child.Currency == "" {
		child.Currency = parent.Currency
	}
	return child
}

func isAmount(f float64) bool { return !math.IsNaN(f) && !math.IsInf(f, 0) && f >= 0 }

func currencyOrUSD(c string) string {
	if c == "" {
		return "USD"
	}
	return c
}

// CheckNarrowing returns nil when child is a subset of parent, or an error
// saying why not. Whenever the PARENT sets an optional limit the child must
// set it too, at an equal or narrower value. It runs at attenuation time and,
// as the security control, on every link inside VerifyMandateChain. Messages
// match @aroha-sdk/credentials checkNarrowing.
func CheckNarrowing(parent, child SpendingConstraints, parentTier, childTier string) error {
	prefix := fmt.Sprintf("Cannot attenuate %s → %s", parentTier, childTier)
	fail := func(format string, args ...any) error {
		return errors.New(prefix + ": " + fmt.Sprintf(format, args...))
	}

	if !isAmount(child.SpendLimitUSD) {
		return fail("child spendLimitUsd must be a finite, non-negative number")
	}
	if child.SpendLimitUSD > parent.SpendLimitUSD {
		return fail("child spendLimitUsd (%s) exceeds parent (%s)", fmtNum(child.SpendLimitUSD), fmtNum(parent.SpendLimitUSD))
	}
	if parent.SessionLimitUSD != nil {
		if child.SessionLimitUSD == nil {
			return fail("parent sets sessionLimitUsd (%s) but child omits it", fmtNum(*parent.SessionLimitUSD))
		}
		if !isAmount(*child.SessionLimitUSD) || *child.SessionLimitUSD > *parent.SessionLimitUSD {
			return fail("child sessionLimitUsd exceeds parent")
		}
	}
	if parent.RequireHumanApprovalAboveUSD != nil {
		if child.RequireHumanApprovalAboveUSD == nil {
			return fail("parent sets an approval threshold (requireHumanApprovalAboveUsd %s) but child omits it",
				fmtNum(*parent.RequireHumanApprovalAboveUSD))
		}
		if !isAmount(*child.RequireHumanApprovalAboveUSD) || *child.RequireHumanApprovalAboveUSD > *parent.RequireHumanApprovalAboveUSD {
			return fail("child approval threshold exceeds parent")
		}
	}
	if currencyOrUSD(child.Currency) != currencyOrUSD(parent.Currency) {
		return fail("child currency %q differs from parent %q", currencyOrUSD(child.Currency), currencyOrUSD(parent.Currency))
	}
	if parent.AllowedMerchants != nil {
		if child.AllowedMerchants == nil {
			return fail("parent restricts allowedMerchants but child sets none")
		}
		// A non-empty parent list requires the child to name at least one
		// merchant; an EMPTY parent list ("no merchant at all") keeps the
		// child empty via the subset check below.
		if len(parent.AllowedMerchants) > 0 && len(child.AllowedMerchants) == 0 {
			return fail("parent restricts allowedMerchants but child sets none")
		}
		set := make(map[string]struct{}, len(parent.AllowedMerchants))
		for _, m := range parent.AllowedMerchants {
			set[m] = struct{}{}
		}
		for _, m := range child.AllowedMerchants {
			if _, ok := set[m]; !ok {
				return fail("child allowedMerchants contains %q not in parent", m)
			}
		}
	}
	if parent.MerchantCategory != nil {
		if child.MerchantCategory == nil {
			return fail("child merchantCategory must not widen parent's %q restriction", *parent.MerchantCategory)
		}
		if *child.MerchantCategory != *parent.MerchantCategory {
			return fail("child merchantCategory %q does not match parent %q", *child.MerchantCategory, *parent.MerchantCategory)
		}
	}
	if parent.ValidUntil != "" {
		if child.ValidUntil == "" {
			return fail("parent sets validUntil (%s) but child omits it", parent.ValidUntil)
		}
		c, cerr := isoMillis(child.ValidUntil)
		p, perr := isoMillis(parent.ValidUntil)
		if cerr != nil || (perr == nil && c > p) {
			return fail("child validUntil (%s) extends beyond parent (%s)", child.ValidUntil, parent.ValidUntil)
		}
	}
	if parent.ValidFrom != "" {
		if child.ValidFrom == "" {
			return fail("parent sets validFrom (%s) but child omits it", parent.ValidFrom)
		}
		c, cerr := isoMillis(child.ValidFrom)
		p, perr := isoMillis(parent.ValidFrom)
		if cerr != nil || (perr == nil && c < p) {
			return fail("child validFrom (%s) precedes parent (%s)", child.ValidFrom, parent.ValidFrom)
		}
	}
	return nil
}

// ─── Checks ───────────────────────────────────────────────────────────────────

func checkLinkSignature(link ChainLink, publicKey ed25519.PublicKey) string {
	sig, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(link.Signature, "="))
	if err != nil || len(sig) != ed25519.SignatureSize || len(publicKey) != ed25519.PublicKeySize {
		return "Signature verification error"
	}
	m, err := mandateValue(link.raw, link.Mandate)
	if err != nil {
		return "Signature verification error"
	}
	var msg []byte
	if link.V == 2 {
		msg, err = jcs.Canonicalize(map[string]any{"mandate": m, "v": 2})
	} else {
		// v1 signed JSON.stringify(sortKeys(body)), which for any well-formed
		// body is byte-identical to its JCS form.
		msg, err = jcs.Canonicalize(m)
	}
	if err != nil {
		return "Signature verification error"
	}
	if !ed25519.Verify(publicKey, msg, sig) {
		return "Invalid signature"
	}
	return ""
}

func checkRevocation(m SpendingMandate, isRevoked RevocationCheck) string {
	if isRevoked == nil {
		return ""
	}
	revoked, err := isRevoked(m.MandateID, m.Grantor)
	if err != nil {
		// An unreachable revocation service is not evidence of non-revocation.
		return fmt.Sprintf("Revocation check failed for mandate %s", m.MandateID)
	}
	if revoked {
		return fmt.Sprintf("Mandate %s has been revoked", m.MandateID)
	}
	return ""
}

// checkTimeWindow: expiry-side checks are strict; not-before checks get tol.
func checkTimeWindow(m SpendingMandate, now, tol int64) string {
	if e, err := isoMillis(m.ExpiresAt); err != nil || e < now {
		return "Mandate expired"
	}
	if i, err := isoMillis(m.IssuedAt); err != nil || i > now+tol {
		return fmt.Sprintf("Mandate issuedAt %s is in the future", m.IssuedAt)
	}
	if vf := m.Constraints.ValidFrom; vf != "" {
		if t, err := isoMillis(vf); err != nil || t > now+tol {
			return fmt.Sprintf("Mandate not yet valid (validFrom %s)", vf)
		}
	}
	if vu := m.Constraints.ValidUntil; vu != "" {
		if t, err := isoMillis(vu); err != nil || t < now {
			return fmt.Sprintf("Mandate validity window has ended (validUntil %s)", vu)
		}
	}
	return ""
}

// ─── Token parsing and shape validation ───────────────────────────────────────

// parseToken returns the leaf and its ancestors (root first; empty for v1),
// or a human-readable reason the token was rejected.
func parseToken(token string) (leaf ChainLink, ancestors []ChainLink, reason string) {
	data, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(token, "="))
	if err != nil {
		return leaf, nil, "Malformed token"
	}
	v, err := jcs.Parse(data)
	if err != nil {
		return leaf, nil, "Malformed token"
	}
	raw, ok := v.(map[string]any)
	if !ok {
		return leaf, nil, "Malformed token"
	}
	version := 1
	if rv, present := raw["v"]; present {
		switch rv {
		case float64(1):
			version = 1
		case float64(2):
			version = 2
		default:
			return leaf, nil, fmt.Sprintf("Unsupported mandate token version: %s", jsString(rv))
		}
	}
	if _, hasChain := raw["chain"]; version == 1 && hasChain {
		return leaf, nil, "Malformed token: chain present without v: 2"
	}
	leaf, r := toLink(version, raw)
	if r != "" {
		return leaf, nil, "Malformed token: " + r
	}
	ancestors = []ChainLink{}
	if version == 2 {
		rawChain, ok := raw["chain"].([]any)
		if !ok {
			return leaf, nil, "Malformed token: v2 token requires a chain array"
		}
		for i, e := range rawChain {
			entry, ok := e.(map[string]any)
			lv := 0
			if ok {
				switch entry["v"] {
				case float64(1):
					lv = 1
				case float64(2):
					lv = 2
				}
			}
			if lv == 0 {
				return leaf, nil, fmt.Sprintf("Malformed token: chain[%d] is not a versioned link", i)
			}
			link, r := toLink(lv, entry)
			if r != "" {
				return leaf, nil, fmt.Sprintf("Malformed token: chain[%d]: %s", i, r)
			}
			ancestors = append(ancestors, link)
		}
	}
	return leaf, ancestors, ""
}

func toLink(v int, raw map[string]any) (ChainLink, string) {
	sig, ok := raw["signature"].(string)
	if !ok {
		return ChainLink{}, "signature missing"
	}
	if r := checkMandateShape(raw["mandate"]); r != "" {
		return ChainLink{}, r
	}
	var m SpendingMandate
	if err := json.Unmarshal(mustMarshal(raw["mandate"]), &m); err != nil {
		return ChainLink{}, "mandate cannot be decoded"
	}
	return ChainLink{V: v, Mandate: m, Signature: sig, raw: raw["mandate"]}, ""
}

func isISODate(v any) bool {
	s, ok := v.(string)
	if !ok {
		return false
	}
	_, err := identity.ParseISOTime(s)
	return err == nil
}

func isAmountValue(v any) bool {
	f, ok := v.(float64)
	return ok && isAmount(f)
}

// checkMandateShape validates a decoded mandate body: a missing or mistyped
// field must never turn a comparison into a silent pass.
func checkMandateShape(v any) string {
	m, ok := v.(map[string]any)
	if !ok {
		return "mandate is not an object"
	}
	// A task mandate is not a spending mandate, whatever else it carries: the
	// tiers overlap and a v1 task signature covers the same sorted-JSON bytes
	// as a v1 spending one. Refuse the type marker outright (TS, Python too).
	if _, isTask := m["mandateType"]; isTask {
		return "mandateType present: this is a task mandate, not a spending mandate"
	}
	switch m["mandateTier"] {
	case "intent", "cart", "payment":
	default:
		return "mandateTier is invalid"
	}
	for _, f := range []string{"grantor", "grantee", "mandateId"} {
		if s, ok := m[f].(string); !ok || s == "" {
			return f + " is missing"
		}
	}
	if !isISODate(m["issuedAt"]) {
		return "issuedAt is not a date"
	}
	if !isISODate(m["expiresAt"]) {
		return "expiresAt is not a date"
	}
	pid, present := m["parentMandateId"]
	if _, isStr := pid.(string); !present || (pid != nil && !isStr) {
		return "parentMandateId is invalid"
	}
	return checkConstraintsShape(m["constraints"])
}

func checkConstraintsShape(v any) string {
	c, ok := v.(map[string]any)
	if !ok {
		return "constraints is not an object"
	}
	if !isAmountValue(c["spendLimitUsd"]) {
		return "constraints.spendLimitUsd must be a finite, non-negative number"
	}
	for _, f := range []string{"sessionLimitUsd", "requireHumanApprovalAboveUsd"} {
		if x, present := c[f]; present && !isAmountValue(x) {
			return "constraints." + f + " must be a finite, non-negative number"
		}
	}
	if x, present := c["currency"]; present {
		if _, ok := x.(string); !ok {
			return "constraints.currency must be a string"
		}
	}
	if x, present := c["merchantCategory"]; present && x != nil {
		if _, ok := x.(string); !ok {
			return "constraints.merchantCategory must be a string or null"
		}
	}
	if x, present := c["allowedMerchants"]; present && x != nil {
		arr, ok := x.([]any)
		if ok {
			for _, e := range arr {
				if _, isStr := e.(string); !isStr {
					ok = false
					break
				}
			}
		}
		if !ok {
			return "constraints.allowedMerchants must be an array of DIDs or null"
		}
	}
	for _, f := range []string{"validFrom", "validUntil"} {
		if x, present := c[f]; present && !isISODate(x) {
			return "constraints." + f + " must be an ISO 8601 date"
		}
	}
	return ""
}

// checkConstraintsStruct is the issuance-side shape check.
func checkConstraintsStruct(c SpendingConstraints) string {
	if !isAmount(c.SpendLimitUSD) {
		return "constraints.spendLimitUsd must be a finite, non-negative number"
	}
	if c.SessionLimitUSD != nil && !isAmount(*c.SessionLimitUSD) {
		return "constraints.sessionLimitUsd must be a finite, non-negative number"
	}
	if c.RequireHumanApprovalAboveUSD != nil && !isAmount(*c.RequireHumanApprovalAboveUSD) {
		return "constraints.requireHumanApprovalAboveUsd must be a finite, non-negative number"
	}
	if c.ValidFrom != "" && !isISODate(c.ValidFrom) {
		return "constraints.validFrom must be an ISO 8601 date"
	}
	if c.ValidUntil != "" && !isISODate(c.ValidUntil) {
		return "constraints.validUntil must be an ISO 8601 date"
	}
	return ""
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

func formatISO(ms int64) string {
	return time.UnixMilli(ms).UTC().Format(identity.ISOTimeLayout)
}

func isoMillis(s string) (int64, error) {
	t, err := identity.ParseISOTime(s)
	if err != nil {
		return 0, err
	}
	return t.UnixMilli(), nil
}

// fmtNum formats a number the way JavaScript's String(n) does.
func fmtNum(f float64) string {
	if math.IsNaN(f) {
		return "NaN"
	}
	if math.IsInf(f, 1) {
		return "Infinity"
	}
	if math.IsInf(f, -1) {
		return "-Infinity"
	}
	s, _ := jcs.FormatNumber(f)
	return s
}

func jsString(v any) string {
	switch x := v.(type) {
	case nil:
		return "null"
	case string:
		return x
	case float64:
		return fmtNum(x)
	case bool:
		if x {
			return "true"
		}
		return "false"
	}
	return fmt.Sprint(v)
}

// toDataModel converts a value to the JSON data model via its JSON encoding.
func toDataModel(v any) (any, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return jcs.Parse(b)
}

// mandateValue is the mandate exactly as signed when known, else the struct's
// own encoding.
func mandateValue(raw any, m SpendingMandate) (any, error) {
	if raw != nil {
		return raw, nil
	}
	return toDataModel(m)
}

func mustMarshal(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}

func marshalNoEscape(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}
