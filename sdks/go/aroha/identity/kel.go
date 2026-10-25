// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

package identity

// Rotatable, self-certifying identifiers (did:aroha:E…) and their Key Event
// Logs — the read side only. This file verifies logs produced by
// @aroha-sdk/core (packages/aroha-core/src/identity/kel.ts); it does not
// create or extend them.
//
//   did:aroha:E<base58btc(sha256(JCS(inception event without "sig")))>
//
// The identifier commits to the inception event, which names the current key
// and a digest of the NEXT key (pre-rotation). Every later event is
// hash-chained to its predecessor and authorised as follows:
//
//   rotate   signed by the pre-committed next key, revealed in the event
//   recover  agents only: unsigned, sealed in the controller person's KEL
//   revoke   controller-sealed (agents) or signed by the revealed next key
//   anchor   persons only: signed by the current key; carries seals
//
// Events are parsed into the JSON data model (map[string]any) and digested
// and verified over the RFC 8785 canonical form of exactly what was received,
// so unknown fields are covered by the digest just as they are in the
// TypeScript reference.

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"math"
	"strings"
	"sync"
	"time"

	"github.com/ArohaLabs/aroha-protocol/sdks/go/aroha/jcs"
)

// KelVersion is the KEL event format version every event carries as "v".
const KelVersion = 1

// KelEvent is one event of a Key Event Log in the JSON data model, exactly as
// received (see ParseKel). Its digest and signature cover every field.
type KelEvent = map[string]any

// KelSeal is a seal a person places in their own KEL (inside an anchor
// event) to authorise one event in one of their agents' KELs.
type KelSeal struct {
	DID    string `json:"did"`
	Seq    int    `json:"seq"`
	Digest string `json:"digest"`
}

// KelKeyEstablishment records that from Seq on, Keys were current.
type KelKeyEstablishment struct {
	Seq  int      `json:"seq"`
	Keys []string `json:"keys"`
}

// KelState is the result of replaying a verified KEL.
type KelState struct {
	DID        string
	Kind       string // "person" or "agent"
	Controller string // agents only; "" when absent
	// CurrentKeys are the multibase keys valid right now (empty once revoked).
	CurrentKeys []string
	// CurrentKey is the raw key of CurrentKeys[0], or nil once revoked.
	CurrentKey ed25519.PublicKey
	// NextKeyDigest is the outstanding pre-rotation commitment ("" once revoked).
	NextKeyDigest string
	Revoked       bool
	Sequence      int
	LastDigest    string
	Digests       []string
	KeyHistory    []KelKeyEstablishment
	Seals         []KelSeal
	Events        []KelEvent
	// ControllerState is the controller's verified state, when it was resolved.
	ControllerState *KelState
	// ControllerRevoked is true when the controller's KEL was resolved and the
	// controller has revoked itself; callers deciding authority treat this
	// like Revoked.
	ControllerRevoked bool
}

// KelErrorCode classifies a KEL failure. Values match @aroha-sdk/core.
type KelErrorCode string

const (
	KelInvalid               KelErrorCode = "invalid"
	KelStale                 KelErrorCode = "stale"
	KelDuplicity             KelErrorCode = "duplicity"
	KelControllerUnavailable KelErrorCode = "controller-unavailable"
)

// KelError is returned for every KEL verification failure.
type KelError struct {
	Code    KelErrorCode
	Message string
}

func (e *KelError) Error() string { return e.Message }

func kelErr(code KelErrorCode, format string, args ...any) *KelError {
	return &KelError{Code: code, Message: fmt.Sprintf(format, args...)}
}

// KelSource fetches the KEL for a DID (registry, peer, cache). Return
// (nil, nil) when no log is known.
type KelSource func(did string) ([]KelEvent, error)

// VerifyKelOptions configures VerifyKel.
type VerifyKelOptions struct {
	// ResolveControllerKel is the source of the CONTROLLER's KEL. Required to
	// verify recover and controller-revoke events.
	ResolveControllerKel KelSource
	// RequireController fails with controller-unavailable when an agent names
	// a controller whose KEL cannot be obtained, even if no event needs it.
	RequireController bool
}

// ParseKel decodes a JSON array of KEL events strictly (RFC 8785 / I-JSON
// rules: no duplicate keys, no lone surrogates).
func ParseKel(data []byte) ([]KelEvent, error) {
	v, err := jcs.Parse(data)
	if err != nil {
		return nil, err
	}
	arr, ok := v.([]any)
	if !ok {
		return nil, errors.New("KEL must be a JSON array")
	}
	out := make([]KelEvent, len(arr))
	for i, e := range arr {
		m, ok := e.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("KEL event %d is not an object", i)
		}
		out[i] = m
	}
	return out, nil
}

// ─── Digests and identifiers ─────────────────────────────────────────────────

// SHA256Digest returns "E" + base58btc(sha256(b)), the digest encoding used
// throughout KELs.
func SHA256Digest(b []byte) string {
	sum := sha256.Sum256(b)
	return "E" + encodeBase58(sum[:])
}

// KeyDigest is the pre-rotation commitment for a public key.
func KeyDigest(publicKey []byte) string { return SHA256Digest(publicKey) }

func decodeDigest(v any) []byte {
	d, ok := v.(string)
	if !ok || !strings.HasPrefix(d, "E") {
		return nil
	}
	b, err := decodeBase58(d[1:])
	if err != nil || len(b) != 32 || "E"+encodeBase58(b) != d {
		return nil
	}
	return b
}

func signingBody(ev KelEvent) map[string]any {
	body := make(map[string]any, len(ev))
	for k, v := range ev {
		if k != "sig" {
			body[k] = v
		}
	}
	return body
}

// EventSigningBytes returns the bytes a KEL event's signature covers:
// JCS of the event with "sig" removed.
func EventSigningBytes(ev KelEvent) ([]byte, error) {
	return jcs.Canonicalize(signingBody(ev))
}

// EventDigest is sha256 over JCS of the event with "sig" removed.
func EventDigest(ev KelEvent) (string, error) {
	b, err := EventSigningBytes(ev)
	if err != nil {
		return "", err
	}
	return SHA256Digest(b), nil
}

// DIDFromInception returns the DID an inception event creates.
func DIDFromInception(inception KelEvent) (string, error) {
	d, err := EventDigest(inception)
	if err != nil {
		return "", err
	}
	return DIDPrefix + d, nil
}

// InceptionDigestFromDID returns the 32-byte inception digest an E-DID
// commits to, or nil for any other DID.
func InceptionDigestFromDID(did string) []byte {
	if !strings.HasPrefix(did, DIDPrefix) {
		return nil
	}
	suffix := did[len(DIDPrefix):]
	if strings.ContainsAny(suffix, ".:") {
		return nil
	}
	return decodeDigest(suffix)
}

// IsInceptionDID reports whether did is the rotatable, self-certifying form
// did:aroha:E<base58btc(32 bytes)>. Strict: the suffix must decode to exactly
// 32 bytes and re-encode to itself, so did:aroha:Echo is never mistaken for one.
func IsInceptionDID(did string) bool { return InceptionDigestFromDID(did) != nil }

// ─── Shape checks ────────────────────────────────────────────────────────────

func decodeKey(v any) []byte {
	k, ok := v.(string)
	if !ok || !strings.HasPrefix(k, "z") {
		return nil
	}
	b, err := FromMultibase(k)
	if err != nil || len(b) != 32 || ToMultibase(b) != k {
		return nil
	}
	return b
}

type mbKey struct {
	multibase string
	bytes     []byte
}

func singleKey(v any, where string) (mbKey, error) {
	arr, ok := v.([]any)
	if !ok {
		if s, ok2 := v.([]string); ok2 {
			arr = make([]any, len(s))
			for i := range s {
				arr[i] = s[i]
			}
			ok = true
		}
	}
	if !ok || len(arr) != 1 {
		return mbKey{}, kelErr(KelInvalid, "%s: keys must be an array of exactly one Ed25519 key in KEL v1", where)
	}
	b := decodeKey(arr[0])
	if b == nil {
		return mbKey{}, kelErr(KelInvalid, "%s: keys[0] is not a multibase Ed25519 public key", where)
	}
	return mbKey{multibase: arr[0].(string), bytes: b}, nil
}

func requireDigest(v any, where, field string) (string, error) {
	if decodeDigest(v) == nil {
		return "", kelErr(KelInvalid, "%s: %s is not an E-digest", where, field)
	}
	return v.(string), nil
}

func requireTime(v any, where, field string) error {
	s, ok := v.(string)
	if !ok {
		return kelErr(KelInvalid, "%s: %s is not an ISO 8601 timestamp", where, field)
	}
	if _, err := ParseISOTime(s); err != nil {
		return kelErr(KelInvalid, "%s: %s is not an ISO 8601 timestamp", where, field)
	}
	return nil
}

// ParseISOTime parses the timestamp forms Aroha emits: RFC 3339 with or
// without fractional seconds (JavaScript's toISOString produces
// 2006-01-02T15:04:05.000Z), and a bare date, read as UTC midnight like
// JavaScript's Date.parse.
func ParseISOTime(s string) (time.Time, error) {
	if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
		return t, nil
	}
	return time.Parse("2006-01-02", s)
}

// isNumber reports whether v is a JSON number equal to want.
func isNumber(v any, want float64) bool {
	f, ok := v.(float64)
	return ok && f == want
}

func asInt(v any) (int, bool) {
	f, ok := v.(float64)
	if !ok || math.Trunc(f) != f || math.IsInf(f, 0) || f > 1<<53 || f < -(1<<53) {
		return 0, false
	}
	return int(f), true
}

func verifySig(ev KelEvent, publicKey []byte) bool {
	sig, ok := ev["sig"].(string)
	if !ok {
		return false
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(sig, "="))
	if err != nil || len(raw) != ed25519.SignatureSize || len(publicKey) != ed25519.PublicKeySize {
		return false
	}
	msg, err := EventSigningBytes(ev)
	if err != nil {
		return false
	}
	return ed25519.Verify(publicKey, msg, raw)
}

func safeDigest(ev KelEvent, where string) (string, error) {
	d, err := EventDigest(ev)
	if err != nil {
		return "", kelErr(KelInvalid, "%s: event cannot be canonicalised (%v)", where, err)
	}
	return d, nil
}

// ─── Verification ────────────────────────────────────────────────────────────

// VerifyKel replays a KEL and returns the identity's current state. It is a
// port of @aroha-sdk/core verifyKel and applies the same checks in the same
// order; every failure is a *KelError.
func VerifyKel(did string, events []KelEvent, opts VerifyKelOptions) (*KelState, error) {
	if !IsInceptionDID(did) {
		return nil, kelErr(KelInvalid, "%s is not an inception (E-form) DID", did)
	}
	if len(events) == 0 {
		return nil, kelErr(KelInvalid, "empty KEL")
	}

	inc := events[0]
	if inc == nil || !isNumber(inc["v"], KelVersion) || inc["type"] != "inception" {
		return nil, kelErr(KelInvalid, "event 0 is not a v1 inception event")
	}
	kind, _ := inc["kind"].(string)
	if kind != "person" && kind != "agent" {
		return nil, kelErr(KelInvalid, "inception: kind must be \"person\" or \"agent\"")
	}
	const where0 = "inception"
	k0, err := singleKey(inc["keys"], where0)
	if err != nil {
		return nil, err
	}
	next0, err := requireDigest(inc["nextKeyDigest"], where0, "nextKeyDigest")
	if err != nil {
		return nil, err
	}
	if err := requireTime(inc["createdAt"], where0, "createdAt"); err != nil {
		return nil, err
	}
	controller := ""
	if c, present := inc["controller"]; present {
		if kind == "person" {
			return nil, kelErr(KelInvalid, "inception: a person has no controller")
		}
		cs, ok := c.(string)
		if !ok || !IsInceptionDID(cs) {
			return nil, kelErr(KelInvalid, "inception: controller must be a person E-DID")
		}
		controller = cs
	}

	incDigest, err := safeDigest(inc, where0)
	if err != nil {
		return nil, err
	}
	if DIDPrefix+incDigest != did {
		return nil, kelErr(KelInvalid, "inception digest does not match %s — the inception event was altered or belongs to another DID", did)
	}
	if !verifySig(inc, k0.bytes) {
		return nil, kelErr(KelInvalid, "inception: signature does not verify against its own key")
	}
	if next0 == KeyDigest(k0.bytes) {
		return nil, kelErr(KelInvalid, "inception: next-key commitment equals the current key — pre-rotation would protect nothing")
	}

	state := &KelState{
		DID:           did,
		Kind:          kind,
		Controller:    controller,
		CurrentKeys:   []string{k0.multibase},
		CurrentKey:    k0.bytes,
		NextKeyDigest: next0,
		Sequence:      0,
		LastDigest:    incDigest,
		Digests:       []string{incDigest},
		KeyHistory:    []KelKeyEstablishment{{Seq: 0, Keys: []string{k0.multibase}}},
		Seals:         []KelSeal{},
		Events:        []KelEvent{inc},
	}

	type sealNeed struct {
		seq    int
		digest string
	}
	var needsSeal []sealNeed

	setKeys := func(k mbKey, next string, seq int) {
		state.CurrentKeys = []string{k.multibase}
		state.CurrentKey = k.bytes
		state.NextKeyDigest = next
		state.KeyHistory = append(state.KeyHistory, KelKeyEstablishment{Seq: seq, Keys: []string{k.multibase}})
	}

	for i := 1; i < len(events); i++ {
		ev := events[i]
		where := fmt.Sprintf("event %d", i)
		if ev == nil || !isNumber(ev["v"], KelVersion) {
			return nil, kelErr(KelInvalid, "%s: not a v1 KEL event", where)
		}
		typ, _ := ev["type"].(string)
		if typ == "inception" {
			return nil, kelErr(KelInvalid, "%s: a second inception", where)
		}
		if state.Revoked {
			return nil, kelErr(KelInvalid, "%s: event after revocation", where)
		}
		if evDID, _ := ev["did"].(string); evDID != did {
			return nil, kelErr(KelInvalid, "%s: names DID %v, not %s", where, ev["did"], did)
		}
		if !isNumber(ev["seq"], float64(i)) {
			return nil, kelErr(KelInvalid, "%s: seq %v out of order", where, ev["seq"])
		}
		if prior, _ := ev["prior"].(string); prior != state.LastDigest {
			return nil, kelErr(KelInvalid, "%s: prior digest does not chain to event %d", where, i-1)
		}
		if err := requireTime(ev["at"], where, "at"); err != nil {
			return nil, err
		}
		digest, err := safeDigest(ev, where)
		if err != nil {
			return nil, err
		}
		_, hasSig := ev["sig"]

		switch typ {
		case "rotate":
			k, err := singleKey(ev["keys"], where)
			if err != nil {
				return nil, err
			}
			next, err := requireDigest(ev["nextKeyDigest"], where, "nextKeyDigest")
			if err != nil {
				return nil, err
			}
			if KeyDigest(k.bytes) != state.NextKeyDigest {
				return nil, kelErr(KelInvalid, "%s: rotation key does not match the pre-rotation commitment", where)
			}
			if !verifySig(ev, k.bytes) {
				return nil, kelErr(KelInvalid, "%s: rotation is not signed by the pre-committed next key", where)
			}
			if next == KeyDigest(k.bytes) {
				return nil, kelErr(KelInvalid, "%s: next-key commitment equals the new current key", where)
			}
			setKeys(k, next, i)
		case "recover":
			if state.Kind != "agent" || state.Controller == "" {
				return nil, kelErr(KelInvalid, "%s: recover is only defined for agents with a controller", where)
			}
			if ev["auth"] != "controller" {
				return nil, kelErr(KelInvalid, "%s: recover must be controller-authorised", where)
			}
			if hasSig {
				return nil, kelErr(KelInvalid, "%s: recover carries no signature (it is anchored)", where)
			}
			k, err := singleKey(ev["keys"], where)
			if err != nil {
				return nil, err
			}
			next, err := requireDigest(ev["nextKeyDigest"], where, "nextKeyDigest")
			if err != nil {
				return nil, err
			}
			if next == KeyDigest(k.bytes) {
				return nil, kelErr(KelInvalid, "%s: next-key commitment equals the new current key", where)
			}
			setKeys(k, next, i)
			needsSeal = append(needsSeal, sealNeed{i, digest})
		case "revoke":
			if r, present := ev["reason"]; present {
				if _, ok := r.(string); !ok {
					return nil, kelErr(KelInvalid, "%s: reason must be a string", where)
				}
			}
			switch ev["auth"] {
			case "next-key":
				revealed := decodeKey(ev["revealedKey"])
				if revealed == nil {
					return nil, kelErr(KelInvalid, "%s: revealedKey is not an Ed25519 key", where)
				}
				if KeyDigest(revealed) != state.NextKeyDigest {
					return nil, kelErr(KelInvalid, "%s: revealed key does not match the pre-rotation commitment", where)
				}
				if !verifySig(ev, revealed) {
					return nil, kelErr(KelInvalid, "%s: revocation is not signed by the pre-committed next key", where)
				}
			case "controller":
				if state.Kind != "agent" || state.Controller == "" {
					return nil, kelErr(KelInvalid, "%s: controller revocation on an identity with no controller", where)
				}
				if hasSig {
					return nil, kelErr(KelInvalid, "%s: a controller revocation carries no signature (it is anchored)", where)
				}
				needsSeal = append(needsSeal, sealNeed{i, digest})
			default:
				return nil, kelErr(KelInvalid, "%s: unknown revoke auth", where)
			}
			state.Revoked = true
			state.CurrentKeys = []string{}
			state.CurrentKey = nil
			state.NextKeyDigest = ""
		case "anchor":
			if state.Kind != "person" {
				return nil, kelErr(KelInvalid, "%s: only persons anchor", where)
			}
			rawSeals, ok := ev["seals"].([]any)
			if !ok {
				return nil, kelErr(KelInvalid, "%s: seals must be an array", where)
			}
			seals := make([]KelSeal, 0, len(rawSeals))
			for _, rs := range rawSeals {
				m, ok := rs.(map[string]any)
				if !ok {
					return nil, kelErr(KelInvalid, "%s: malformed seal", where)
				}
				sd, okDID := m["did"].(string)
				seq, okSeq := asInt(m["seq"])
				if !okDID || !IsInceptionDID(sd) || !okSeq || seq < 1 || decodeDigest(m["digest"]) == nil {
					return nil, kelErr(KelInvalid, "%s: malformed seal", where)
				}
				seals = append(seals, KelSeal{DID: sd, Seq: seq, Digest: m["digest"].(string)})
			}
			if state.CurrentKey == nil || !verifySig(ev, state.CurrentKey) {
				return nil, kelErr(KelInvalid, "%s: anchor is not signed by the current key", where)
			}
			state.Seals = append(state.Seals, seals...)
		default:
			return nil, kelErr(KelInvalid, "%s: unknown event type %v", where, ev["type"])
		}

		state.Sequence = i
		state.LastDigest = digest
		state.Digests = append(state.Digests, digest)
		state.Events = append(state.Events, ev)
	}

	if state.Controller != "" {
		needController := len(needsSeal) > 0 || opts.RequireController
		var controllerEvents []KelEvent
		if opts.ResolveControllerKel != nil {
			evs, err := opts.ResolveControllerKel(state.Controller)
			if err != nil {
				var ke *KelError
				if errors.As(err, &ke) && ke.Code != KelControllerUnavailable {
					return nil, err
				}
				evs = nil
			}
			controllerEvents = evs
		}
		if len(controllerEvents) == 0 {
			if needController {
				if len(needsSeal) > 0 {
					return nil, kelErr(KelControllerUnavailable,
						"%s has controller-authorised events but the controller %s's KEL is unavailable", did, state.Controller)
				}
				return nil, kelErr(KelControllerUnavailable, "controller %s's KEL is unavailable", state.Controller)
			}
		} else {
			ctl, err := VerifyKel(state.Controller, controllerEvents, VerifyKelOptions{})
			if err != nil {
				return nil, err
			}
			if ctl.Kind != "person" {
				return nil, kelErr(KelInvalid, "controller %s is not a person", state.Controller)
			}
			var mine []KelSeal
			for _, s := range ctl.Seals {
				if s.DID == did {
					mine = append(mine, s)
				}
			}
			// Authorisation before comparison: an unanchored "controller" event
			// is junk, not evidence of a fork.
			for _, need := range needsSeal {
				found := false
				for _, s := range mine {
					if s.Seq == need.seq && s.Digest == need.digest {
						found = true
						break
					}
				}
				if !found {
					return nil, kelErr(KelInvalid,
						"event %d claims controller authority but is not anchored in %s's KEL", need.seq, state.Controller)
				}
			}
			for _, seal := range mine {
				if seal.Seq > state.Sequence {
					return nil, kelErr(KelStale,
						"controller anchored %s event %d, but the log provided ends at %d", did, seal.Seq, state.Sequence)
				}
				if state.Digests[seal.Seq] != seal.Digest {
					return nil, kelErr(KelDuplicity,
						"controller anchored a different event at %s seq %d than the log provided", did, seal.Seq)
				}
			}
			state.ControllerState = ctl
			state.ControllerRevoked = ctl.Revoked
		}
	}
	return state, nil
}

// KeysAtSequence returns the key(s) that were current at sequence seq of a
// verified log.
func KeysAtSequence(state *KelState, seq int) ([]string, error) {
	if seq < 0 || seq > state.Sequence {
		return nil, kelErr(KelInvalid, "seq %d is outside %s's log (0..%d)", seq, state.DID, state.Sequence)
	}
	keys := state.KeyHistory[0].Keys
	for _, est := range state.KeyHistory {
		if est.Seq > seq {
			break
		}
		keys = est.Keys
	}
	return keys, nil
}

// ─── Freshness: KelStore, duplicity, stale logs ──────────────────────────────

// DuplicityEvidence records two different events seen at one position.
type DuplicityEvidence struct {
	DID        string
	Seq        int
	Digests    [2]string // [already seen, conflicting]
	DetectedAt string
}

// KelStore is a verifier's memory per DID: the longest verified log and any
// duplicity detected. Back it with durable storage in long-lived verifiers.
type KelStore interface {
	Get(did string) ([]KelEvent, error)
	Put(did string, events []KelEvent) error
	RecordDuplicity(evidence DuplicityEvidence) error
	GetDuplicity(did string) (*DuplicityEvidence, error)
}

// InMemoryKelStore is a process-local KelStore. Safe for concurrent use.
type InMemoryKelStore struct {
	mu     sync.Mutex
	logs   map[string][]KelEvent
	alarms map[string]DuplicityEvidence
}

// NewInMemoryKelStore returns an empty store.
func NewInMemoryKelStore() *InMemoryKelStore {
	return &InMemoryKelStore{logs: map[string][]KelEvent{}, alarms: map[string]DuplicityEvidence{}}
}

func (s *InMemoryKelStore) Get(did string) ([]KelEvent, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.logs[did], nil
}

func (s *InMemoryKelStore) Put(did string, events []KelEvent) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.logs[did] = append([]KelEvent(nil), events...)
	return nil
}

func (s *InMemoryKelStore) RecordDuplicity(e DuplicityEvidence) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.alarms[e.DID]; !ok {
		s.alarms[e.DID] = e
	}
	return nil
}

func (s *InMemoryKelStore) GetDuplicity(did string) (*DuplicityEvidence, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if e, ok := s.alarms[did]; ok {
		return &e, nil
	}
	return nil, nil
}

// AcceptKelOptions configures AcceptKel.
type AcceptKelOptions struct {
	VerifyKelOptions
	// UseStored answers from the longer stored log instead of failing with
	// "stale" when the offered log is shorter (TS onStale: "use-stored").
	UseStored bool
}

// AcceptKel verifies events and reconciles them with what store has seen
// for did: a recorded duplicity alarm refuses the DID; the log must verify
// before it is compared; disagreement at a common sequence records and
// returns duplicity; a shorter log is stale (see UseStored); a longer log is
// stored.
func AcceptKel(did string, events []KelEvent, store KelStore, opts AcceptKelOptions) (*KelState, error) {
	alarm, err := store.GetDuplicity(did)
	if err != nil {
		return nil, err
	}
	if alarm != nil {
		return nil, kelErr(KelDuplicity, "%s has a recorded duplicity alarm at seq %d (since %s)", did, alarm.Seq, alarm.DetectedAt)
	}
	stored, err := store.Get(did)
	if err != nil {
		return nil, err
	}
	useStored := opts.UseStored && len(stored) > 0

	state, err := VerifyKel(did, events, opts.VerifyKelOptions)
	if err != nil {
		var ke *KelError
		if errors.As(err, &ke) && ke.Code == KelStale && useStored && len(stored) > len(events) {
			return VerifyKel(did, stored, opts.VerifyKelOptions)
		}
		return nil, err
	}

	if len(stored) > 0 {
		common := len(stored)
		if len(state.Digests) < common {
			common = len(state.Digests)
		}
		for i := 0; i < common; i++ {
			seen, err := EventDigest(stored[i])
			if err != nil {
				return nil, err
			}
			if seen != state.Digests[i] {
				ev := DuplicityEvidence{
					DID: did, Seq: i, Digests: [2]string{seen, state.Digests[i]},
					DetectedAt: time.Now().UTC().Format(ISOTimeLayout),
				}
				if err := store.RecordDuplicity(ev); err != nil {
					return nil, err
				}
				return nil, kelErr(KelDuplicity, "%s: two different events at seq %d — the log was forked", did, i)
			}
		}
		if len(state.Digests) < len(stored) {
			if useStored {
				return VerifyKel(did, stored, opts.VerifyKelOptions)
			}
			return nil, kelErr(KelStale, "%s: offered log ends at seq %d, but seq %d has already been seen",
				did, state.Sequence, len(stored)-1)
		}
	}
	if len(stored) == 0 || len(state.Events) > len(stored) {
		if err := store.Put(did, state.Events); err != nil {
			return nil, err
		}
	}
	return state, nil
}

// ISOTimeLayout is JavaScript's Date.prototype.toISOString format (always UTC,
// millisecond precision). Format UTC times with it.
const ISOTimeLayout = "2006-01-02T15:04:05.000Z"

// KelSourceFromLogs returns a KelSource over logs already held, indexed by
// the DID each log's inception hashes to; the longer log wins on a clash.
func KelSourceFromLogs(logs ...[]KelEvent) KelSource {
	byDID := map[string][]KelEvent{}
	for _, log := range logs {
		if len(log) == 0 || log[0]["type"] != "inception" {
			continue
		}
		did, err := DIDFromInception(log[0])
		if err != nil {
			continue
		}
		if existing, ok := byDID[did]; !ok || len(log) > len(existing) {
			byDID[did] = log
		}
	}
	return func(did string) ([]KelEvent, error) { return byDID[did], nil }
}

// ResolveKelStateOptions configures ResolveKelState.
type ResolveKelStateOptions struct {
	// Store is highest-seen memory; strongly recommended for long-lived verifiers.
	Store KelStore
	// RequireController: see VerifyKelOptions.RequireController.
	RequireController bool
}

// ResolveKelState fetches, verifies and (with a store) reconciles the KEL for
// an E-DID, including its controller's. Returns (nil, nil) when did is not
// an E-DID or no log can be found.
func ResolveKelState(did string, source KelSource, opts ResolveKelStateOptions) (*KelState, error) {
	if !IsInceptionDID(did) {
		return nil, nil
	}
	store := opts.Store
	fetch := func(d string) ([]KelEvent, error) {
		log, err := source(d)
		if err != nil {
			log = nil
		}
		if len(log) == 0 && store != nil {
			if log, err = store.Get(d); err != nil {
				return nil, err
			}
		}
		if len(log) == 0 {
			return nil, nil
		}
		return log, nil
	}
	events, err := fetch(did)
	if err != nil || events == nil {
		return nil, err
	}
	resolveController := func(cdid string) ([]KelEvent, error) {
		log, err := fetch(cdid)
		if err != nil || log == nil || store == nil {
			return log, err
		}
		ctl, err := AcceptKel(cdid, log, store, AcceptKelOptions{UseStored: true})
		if err != nil {
			return nil, err
		}
		return ctl.Events, nil
	}
	vopts := VerifyKelOptions{ResolveControllerKel: resolveController, RequireController: opts.RequireController}
	if store != nil {
		return AcceptKel(did, events, store, AcceptKelOptions{VerifyKelOptions: vopts, UseStored: true})
	}
	return VerifyKel(did, events, vopts)
}

// KelKeyResolver returns the CURRENT key of an E-DID from its verified KEL,
// or nil when the DID is not an E-DID, has no log, fails verification, or it
// or its controller is revoked (fail closed).
func KelKeyResolver(source KelSource, opts ResolveKelStateOptions) func(did string) ed25519.PublicKey {
	return func(did string) ed25519.PublicKey {
		state, err := ResolveKelState(did, source, opts)
		if err != nil || state == nil || state.Revoked || state.ControllerRevoked || state.CurrentKey == nil {
			return nil
		}
		return state.CurrentKey
	}
}
