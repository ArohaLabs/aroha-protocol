// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

// Package conversation verifies the objects of the Aroha Conversation and
// Memory Profile (spec aroha-1.0 §12): signed rooms, consent records with
// per-event signatures in a hash chain, and authored turns. It is the
// verification side of packages/aroha-core/src/conversation, checked against
// the shared vectors in spec-public/vectors/conversation-v1.json.
//
// Every signature is Ed25519 over the UTF-8 bytes of the RFC 8785 (JCS) form
// of the object with its signature field removed (rooms), of a consent-event
// payload (consent records), or of the turn signature payload (turns);
// signatures are base64url without padding. Each object carries a purpose
// tag inside the signed bytes, so a signature for one kind of object never
// verifies as another.
//
// Objects are verified exactly as received: pass the JSON data model
// (map[string]any, e.g. from Parse), raw JSON ([]byte or json.RawMessage),
// or a value whose JSON encoding is the object. Shape rules refuse unknown
// fields, so nothing signed goes unchecked.
//
// Key resolution is the caller's (KeyResolver). A signer's kind — person or
// agent — comes from the resolver (a verified Key Event Log), never from the
// message: see KelResolver and ResolveSpeakerKind.
//
// A signature proves possession of a key the signer's KEL names. It does not
// prove a person was present when a runtime used a person key it holds for
// them.
package conversation

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"regexp"
	"strings"

	"github.com/ArohaLabs/aroha-protocol/sdks/go/aroha/identity"
	"github.com/ArohaLabs/aroha-protocol/sdks/go/aroha/jcs"
	"github.com/ArohaLabs/aroha-protocol/sdks/go/aroha/messages"
)

// Purpose tags carried inside the signed bytes.
const (
	RoomPurpose         = "aroha.room/v1"
	ConsentPurpose      = "aroha.consent/v1"
	ConsentEventPurpose = "aroha.consent-event/v1"
	TurnPurpose         = "aroha.turn/v1"
)

// Member kinds.
const (
	KindPerson = "person"
	KindAgent  = "agent"
)

// Consent purposes a record may ask about.
const (
	PurposeTranscriptRetention = "transcript_retention"
	PurposeAgentUseOfMessages  = "agent_use_of_messages"
	PurposeMemoryWrite         = "memory_write"
	PurposeProviderProcessing  = "provider_processing"
)

// ConsentPurposes lists every known consent purpose.
var ConsentPurposes = []string{PurposeTranscriptRetention, PurposeAgentUseOfMessages, PurposeMemoryWrite, PurposeProviderProcessing}

// ─── Types ────────────────────────────────────────────────────────────────────

// RoomMember is one member of a room. Membership is [JoinedEpoch, LeftEpoch).
type RoomMember struct {
	DID         string `json:"did"`
	Kind        string `json:"kind"`
	PrincipalID string `json:"principalId,omitempty"`
	DisplayName string `json:"displayName"`
	// Role is host, guest, own, invited or delegated.
	Role        string `json:"role"`
	JoinedEpoch int    `json:"joinedEpoch"`
	// LeftEpoch is nil while the member is present.
	LeftEpoch *int `json:"leftEpoch,omitempty"`
	// ConsentRef is the recordId of the member's consent record; required
	// for a person guest.
	ConsentRef string `json:"consentRef,omitempty"`
}

// RoomMemoryPolicy says what the room's agent may read and write.
type RoomMemoryPolicy struct {
	PersonalRead  bool   `json:"personalRead"`
	PersonalWrite bool   `json:"personalWrite"`
	RoomMemory    string `json:"roomMemory"`          // "off" | "consented"
	AgentRead     string `json:"agentRead,omitempty"` // "none" (default) | "members"
}

// Room is a room record (aroha.room/v1), signed by its owner's PERSON key.
type Room struct {
	V                 int                 `json:"v"`
	Purpose           string              `json:"purpose"`
	RoomID            string              `json:"roomId"`
	ThreadID          string              `json:"threadId"`
	OwnerDID          string              `json:"ownerDid"`
	Epoch             int                 `json:"epoch"`
	Members           []RoomMember        `json:"members"`
	HistoryVisibility string              `json:"historyVisibility"` // "joined" | "shared"
	Invocation        string              `json:"invocation"`        // "explicit" | "implicit"
	MemoryPolicy      RoomMemoryPolicy    `json:"memoryPolicy"`
	Disclosure        messages.Disclosure `json:"disclosure"`
	UpdatedAt         string              `json:"updatedAt"`
	Signature         string              `json:"signature"`
}

// ConsentEvent is one signed event of a consent record.
type ConsentEvent struct {
	Event    string   `json:"event"` // "given" | "withdrawn"
	Purposes []string `json:"purposes"`
	At       string   `json:"at"`
	ActorDID string   `json:"actorDid"`
	Epoch    int      `json:"epoch"`
	Sig      string   `json:"sig"`
}

// ConsentRecord is an append-only, hash-chained list of events, each signed
// by its own actor — so an earlier event cannot be altered, inserted or
// removed without breaking a signature the appender does not hold.
type ConsentRecord struct {
	V               int            `json:"v"`
	Purpose         string         `json:"purpose"`
	RecordID        string         `json:"recordId"`
	SubjectDID      string         `json:"subjectDid"`
	RoomID          string         `json:"roomId"`
	Purposes        []string       `json:"purposes"`
	WithdrawalRoute string         `json:"withdrawalRoute"`
	Events          []ConsentEvent `json:"events"`
}

// Turn is an authored turn: the turn signature payload fields plus author,
// content and signature.
type Turn struct {
	ThreadID        string   `json:"threadId"`
	RoomID          string   `json:"roomId"`
	Epoch           int      `json:"epoch"`
	At              string   `json:"at"`
	ContentHash     string   `json:"contentHash"`
	AddressedTo     []string `json:"addressedTo"`
	AuthorDID       string   `json:"authorDid"`
	Content         string   `json:"content"`
	AuthorSignature string   `json:"authorSignature"`
}

// ResolvedSigner is a DID's current key and its identity kind.
type ResolvedSigner struct {
	PublicKey ed25519.PublicKey
	// Kind is KindPerson or KindAgent, from the KEL — never from the message.
	Kind string
}

// KeyResolver resolves a DID to its current key and kind. Return (nil, nil)
// for an unknown DID; an error is treated the same way (fail closed).
type KeyResolver func(did string) (*ResolvedSigner, error)

// Verified is a verified object and the signer that vouched for it (for a
// consent record, the subject).
type Verified[T any] struct {
	Value  T
	Signer ResolvedSigner
}

// ─── Resolution ───────────────────────────────────────────────────────────────

// ResolveSpeakerKind is the speaker-kind rule: the kind recorded in the
// DID's verified KEL inception. Anything that cannot be resolved that way is
// an agent — the unproven case gets the lesser authority, never the greater.
func ResolveSpeakerKind(kelKind string) string {
	if kelKind == KindPerson {
		return KindPerson
	}
	return KindAgent
}

// KelResolver resolves did:aroha:E… DIDs through their verified Key Event
// Logs: the current key and the inception's kind. A DID without a
// verifiable, unrevoked log (or whose controller revoked itself) resolves to
// nil.
func KelResolver(source identity.KelSource) KeyResolver {
	return func(did string) (*ResolvedSigner, error) {
		if source == nil || !identity.IsInceptionDID(did) {
			return nil, nil
		}
		events, err := source(did)
		if err != nil || len(events) == 0 {
			return nil, err
		}
		st, err := identity.VerifyKel(did, events, identity.VerifyKelOptions{ResolveControllerKel: source})
		if err != nil {
			return nil, err
		}
		if st.Revoked || st.ControllerRevoked || st.CurrentKey == nil {
			return nil, nil
		}
		return &ResolvedSigner{PublicKey: st.CurrentKey, Kind: ResolveSpeakerKind(st.Kind)}, nil
	}
}

// WithContentAddressedAgents resolves content-addressed did:aroha:z… DIDs
// from the DID itself, always as KindAgent (no KEL proves a person), and
// every other DID through next.
func WithContentAddressedAgents(next KeyResolver) KeyResolver {
	return func(did string) (*ResolvedSigner, error) {
		if k := identity.ResolveContentAddressedKey(did); k != nil {
			return &ResolvedSigner{PublicKey: k, Kind: KindAgent}, nil
		}
		if next == nil {
			return nil, nil
		}
		return next(did)
	}
}

func resolveSigner(resolve KeyResolver, did string) *ResolvedSigner {
	if resolve == nil {
		return nil
	}
	s, err := resolve(did)
	if err != nil || s == nil || len(s.PublicKey) != ed25519.PublicKeySize {
		return nil
	}
	return s
}

// ─── Shared helpers ───────────────────────────────────────────────────────────

// Parse decodes JSON strictly (RFC 8785 / I-JSON) into the data model.
func Parse(data []byte) (any, error) { return jcs.Parse(data) }

// dataModel converts the accepted input forms to the JSON data model.
func dataModel(v any) (any, error) {
	switch x := v.(type) {
	case nil:
		return nil, nil
	case map[string]any:
		return x, nil
	case []byte:
		return jcs.Parse(x)
	case json.RawMessage:
		return jcs.Parse(x)
	}
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return jcs.Parse(b)
}

func asObject(v any) (map[string]any, error) {
	dm, err := dataModel(v)
	if err != nil {
		return nil, err
	}
	m, _ := dm.(map[string]any)
	return m, nil
}

var sha256Hex = regexp.MustCompile(`^[0-9a-f]{64}$`)

func isNonEmpty(x any) bool {
	s, ok := x.(string)
	return ok && s != ""
}

func isDID(x any) bool {
	s, ok := x.(string)
	return ok && strings.HasPrefix(s, "did:") && s != ""
}

func isEpoch(x any) bool {
	f, ok := x.(float64)
	return ok && f >= 0 && f == math.Trunc(f) && f <= math.MaxInt32
}

func isISO(x any) bool {
	s, ok := x.(string)
	if !ok {
		return false
	}
	_, err := identity.ParseISOTime(s)
	return err == nil
}

func isoMillis(x any) int64 {
	t, _ := identity.ParseISOTime(x.(string))
	return t.UnixMilli()
}

func unknownField(obj map[string]any, known map[string]bool) string {
	for _, k := range sortedKeys(obj) {
		if !known[k] {
			return k
		}
	}
	return ""
}

func sortedKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	jcs.SortKeys(keys)
	return keys
}

func setOf(keys ...string) map[string]bool {
	s := make(map[string]bool, len(keys))
	for _, k := range keys {
		s[k] = true
	}
	return s
}

func without(obj map[string]any, key string) map[string]any {
	out := make(map[string]any, len(obj))
	for k, v := range obj {
		if k != key {
			out[k] = v
		}
	}
	return out
}

// SigningBytes is the JCS form of an object with its "signature" field
// removed — what a room record's signature covers.
func SigningBytes(obj any) ([]byte, error) {
	m, err := asObject(obj)
	if err != nil {
		return nil, err
	}
	if m == nil {
		return nil, errors.New("not an object")
	}
	return jcs.Canonicalize(without(m, "signature"))
}

func verifySig(sigB64 string, msg []byte, pub ed25519.PublicKey) bool {
	sig, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(sigB64, "="))
	if err != nil || len(sig) != ed25519.SignatureSize || len(pub) != ed25519.PublicKeySize {
		return false
	}
	return ed25519.Verify(pub, msg, sig)
}

func decodeInto(raw map[string]any, out any) error {
	b, err := json.Marshal(raw)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, out)
}

// ─── Room ─────────────────────────────────────────────────────────────────────

var (
	roomFields = setOf("v", "purpose", "roomId", "threadId", "ownerDid", "epoch", "members", "historyVisibility",
		"invocation", "memoryPolicy", "disclosure", "updatedAt", "signature")
	memberFields = setOf("did", "kind", "principalId", "displayName", "role", "joinedEpoch", "leftEpoch", "consentRef")
	policyFields = setOf("personalRead", "personalWrite", "roomMemory", "agentRead")
	roles        = setOf("host", "guest", "own", "invited", "delegated")
)

// CheckRoomShape applies the structural rules for a room record. With
// requireSignature false it accepts an unsigned record (before signing).
func CheckRoomShape(value any, requireSignature bool) error {
	r, err := asObject(value)
	if err != nil {
		return err
	}
	if p := checkRoomShape(r, requireSignature); p != "" {
		return errors.New(p)
	}
	return nil
}

func checkRoomShape(r map[string]any, requireSignature bool) string {
	if r == nil {
		return "room is not an object"
	}
	if r["v"] != float64(1) || r["purpose"] != RoomPurpose {
		return "not an aroha.room/v1 record"
	}
	if k := unknownField(r, roomFields); k != "" {
		return fmt.Sprintf("unknown field %q", k)
	}
	for _, k := range []string{"roomId", "threadId"} {
		if !isNonEmpty(r[k]) {
			return k + " must be a non-empty string"
		}
	}
	if !isDID(r["ownerDid"]) {
		return "ownerDid must be a DID"
	}
	if !isEpoch(r["epoch"]) {
		return "epoch must be a non-negative integer"
	}
	if hv := r["historyVisibility"]; hv != "joined" && hv != "shared" {
		return "historyVisibility is invalid"
	}
	if inv := r["invocation"]; inv != "explicit" && inv != "implicit" {
		return "invocation is invalid"
	}
	if !isISO(r["updatedAt"]) {
		return "updatedAt must be an ISO 8601 date"
	}
	mp, ok := r["memoryPolicy"].(map[string]any)
	if !ok {
		return "memoryPolicy must be an object"
	}
	if unknownField(mp, policyFields) != "" {
		return "memoryPolicy has an unknown field"
	}
	if _, ok := mp["personalRead"].(bool); !ok {
		return "memoryPolicy.personalRead/personalWrite must be booleans"
	}
	if _, ok := mp["personalWrite"].(bool); !ok {
		return "memoryPolicy.personalRead/personalWrite must be booleans"
	}
	if rm := mp["roomMemory"]; rm != "off" && rm != "consented" {
		return "memoryPolicy.roomMemory is invalid"
	}
	if ar, present := mp["agentRead"]; present && ar != "none" && ar != "members" {
		return "memoryPolicy.agentRead is invalid"
	}
	if _, err := messages.ValidateDisclosure(r["disclosure"], ""); err != nil {
		return "disclosure: " + err.Error()
	}
	members, ok := r["members"].([]any)
	if !ok || len(members) == 0 {
		return "members must be a non-empty array"
	}
	epoch := r["epoch"].(float64)
	seen := map[string]bool{}
	hosts := 0
	for i, mv := range members {
		where := fmt.Sprintf("members[%d]", i)
		m, ok := mv.(map[string]any)
		if !ok {
			return where + " is not an object"
		}
		if k := unknownField(m, memberFields); k != "" {
			return fmt.Sprintf("%s has unknown field %q", where, k)
		}
		if !isDID(m["did"]) {
			return where + ".did must be a DID"
		}
		did := m["did"].(string)
		if seen[did] {
			return where + ".did appears twice"
		}
		seen[did] = true
		if k := m["kind"]; k != KindPerson && k != KindAgent {
			return where + ".kind is invalid"
		}
		if role, _ := m["role"].(string); !roles[role] {
			return where + ".role is invalid"
		}
		if _, ok := m["displayName"].(string); !ok {
			return where + ".displayName must be a string"
		}
		if pid, present := m["principalId"]; present && !isNonEmpty(pid) {
			return where + ".principalId must be a non-empty string"
		}
		if !isEpoch(m["joinedEpoch"]) || m["joinedEpoch"].(float64) > epoch {
			return where + ".joinedEpoch must be an integer ≤ epoch"
		}
		if left, present := m["leftEpoch"]; present {
			if !isEpoch(left) || left.(float64) <= m["joinedEpoch"].(float64) || left.(float64) > epoch {
				return where + ".leftEpoch must be an integer in (joinedEpoch, epoch]"
			}
		}
		cref, hasRef := m["consentRef"]
		if hasRef && !isNonEmpty(cref) {
			return where + ".consentRef must be a non-empty string"
		}
		if m["role"] == "guest" && m["kind"] == KindPerson && !hasRef {
			return where + ": a person guest requires a consentRef"
		}
		if m["role"] == "host" {
			hosts++
			if did != r["ownerDid"] || m["kind"] != KindPerson {
				return where + ": the host must be the owner, a person"
			}
		}
	}
	if hosts != 1 {
		return "exactly one member must have role host"
	}
	if requireSignature && !isNonEmpty(r["signature"]) {
		return "signature is missing"
	}
	return ""
}

// VerifyRoom verifies a room record: shape, the owner resolves to a PERSON,
// and the signature verifies under the owner's current key. A room signed by
// an agent key is refused — a room is the host person's statement of who may
// speak.
func VerifyRoom(room any, resolve KeyResolver) (*Verified[Room], error) {
	r, err := asObject(room)
	if err != nil {
		return nil, fmt.Errorf("malformed room: %w", err)
	}
	if p := checkRoomShape(r, true); p != "" {
		return nil, errors.New("malformed room: " + p)
	}
	owner := r["ownerDid"].(string)
	signer := resolveSigner(resolve, owner)
	if signer == nil {
		return nil, fmt.Errorf("room owner %s has no resolvable key", owner)
	}
	if signer.Kind != KindPerson {
		return nil, fmt.Errorf("room owner %s is not a person", owner)
	}
	msg, err := jcs.Canonicalize(without(r, "signature"))
	if err != nil || !verifySig(r["signature"].(string), msg, signer.PublicKey) {
		return nil, errors.New("room signature does not verify")
	}
	var out Room
	if err := decodeInto(r, &out); err != nil {
		return nil, fmt.Errorf("malformed room: %w", err)
	}
	return &Verified[Room]{Value: out, Signer: *signer}, nil
}

// MembersAt returns the room's members at epoch: joinedEpoch ≤ epoch < leftEpoch.
func (r *Room) MembersAt(epoch int) []RoomMember {
	var out []RoomMember
	for _, m := range r.Members {
		if m.JoinedEpoch <= epoch && (m.LeftEpoch == nil || epoch < *m.LeftEpoch) {
			out = append(out, m)
		}
	}
	return out
}

// IsMemberAt reports whether did was a member of the room at epoch.
func (r *Room) IsMemberAt(did string, epoch int) bool {
	for _, m := range r.MembersAt(epoch) {
		if m.DID == did {
			return true
		}
	}
	return false
}

// ─── Consent ──────────────────────────────────────────────────────────────────

var (
	consentFields = setOf("v", "purpose", "recordId", "subjectDid", "roomId", "purposes", "withdrawalRoute", "events")
	eventFields   = setOf("event", "purposes", "at", "actorDid", "epoch", "sig")
	purposeSet    = setOf(ConsentPurposes...)
)

func isPurposeList(x any) bool {
	arr, ok := x.([]any)
	if !ok || len(arr) == 0 {
		return false
	}
	seen := map[string]bool{}
	for _, p := range arr {
		s, ok := p.(string)
		if !ok || !purposeSet[s] || seen[s] {
			return false
		}
		seen[s] = true
	}
	return true
}

// ConsentEventHash is the SHA-256 hex of the JCS form of a whole event (sig
// included) — the next event's prevHash.
func ConsentEventHash(event any) (string, error) {
	dm, err := dataModel(event)
	if err != nil {
		return "", err
	}
	b, err := jcs.Canonicalize(dm)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

// ConsentEventSigningBytes returns the exact bytes event index of a consent
// record is signed over: JCS of {purpose: "aroha.consent-event/v1", recordId,
// subjectDid, roomId, purposes, withdrawalRoute, index, prevHash, entry:
// <the event minus sig>}. It binds the event to the record's identity and
// terms, to its position, and to the previous event.
func ConsentEventSigningBytes(record any, index int) ([]byte, error) {
	c, err := asObject(record)
	if err != nil {
		return nil, err
	}
	if c == nil {
		return nil, errors.New("consent record is not an object")
	}
	events, _ := c["events"].([]any)
	if index < 0 || index >= len(events) {
		return nil, fmt.Errorf("consent record has no event %d", index)
	}
	entry, ok := events[index].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("events[%d] is not an object", index)
	}
	var prev any
	if index > 0 {
		h, err := ConsentEventHash(events[index-1])
		if err != nil {
			return nil, err
		}
		prev = h
	}
	return jcs.Canonicalize(map[string]any{
		"purpose":         ConsentEventPurpose,
		"recordId":        c["recordId"],
		"subjectDid":      c["subjectDid"],
		"roomId":          c["roomId"],
		"purposes":        c["purposes"],
		"withdrawalRoute": c["withdrawalRoute"],
		"index":           index,
		"prevHash":        prev,
		"entry":           without(entry, "sig"),
	})
}

// CheckConsentShape applies the structural and event-order rules for a
// consent record (signatures are not checked).
func CheckConsentShape(value any) error {
	c, err := asObject(value)
	if err != nil {
		return err
	}
	if p := checkConsentShape(c); p != "" {
		return errors.New(p)
	}
	return nil
}

func checkConsentShape(c map[string]any) string {
	if c == nil {
		return "consent record is not an object"
	}
	if c["v"] != float64(1) || c["purpose"] != ConsentPurpose {
		return "not an aroha.consent/v1 record"
	}
	if k := unknownField(c, consentFields); k != "" {
		return fmt.Sprintf("unknown field %q", k)
	}
	if !isNonEmpty(c["recordId"]) || !isNonEmpty(c["roomId"]) {
		return "recordId and roomId must be non-empty strings"
	}
	if !isDID(c["subjectDid"]) {
		return "subjectDid must be a DID"
	}
	if !isPurposeList(c["purposes"]) {
		return "purposes must be a non-empty list of known purposes without repeats"
	}
	if !isNonEmpty(c["withdrawalRoute"]) {
		return "withdrawalRoute must be a non-empty string"
	}
	events, ok := c["events"].([]any)
	if !ok || len(events) == 0 {
		return "events must be a non-empty array"
	}
	asked := map[string]bool{}
	for _, p := range c["purposes"].([]any) {
		asked[p.(string)] = true
	}
	last := int64(math.MinInt64)
	lastEpoch := float64(-1)
	for i, ev := range events {
		where := fmt.Sprintf("events[%d]", i)
		e, ok := ev.(map[string]any)
		if !ok {
			return where + " is not an object"
		}
		if k := unknownField(e, eventFields); k != "" {
			return fmt.Sprintf("%s has unknown field %q", where, k)
		}
		if kind := e["event"]; kind != "given" && kind != "withdrawn" {
			return where + ".event is invalid"
		}
		if !isPurposeList(e["purposes"]) {
			return where + ".purposes is invalid"
		}
		for _, p := range e["purposes"].([]any) {
			if !asked[p.(string)] {
				return where + " names a purpose the record does not ask about"
			}
		}
		if !isISO(e["at"]) {
			return where + ".at must be an ISO 8601 date"
		}
		t := isoMillis(e["at"])
		if t < last {
			return where + " is earlier than the event before it"
		}
		last = t
		if !isEpoch(e["epoch"]) || e["epoch"].(float64) < lastEpoch {
			return where + ".epoch must be a non-negative integer, not decreasing"
		}
		lastEpoch = e["epoch"].(float64)
		if !isDID(e["actorDid"]) {
			return where + ".actorDid must be a DID"
		}
		if !isNonEmpty(e["sig"]) {
			return where + ".sig is missing"
		}
		// Only the subject can GIVE consent; a room member may withdraw it.
		if e["event"] == "given" && e["actorDid"] != c["subjectDid"] {
			return where + ": only the subject can give consent"
		}
	}
	if events[0].(map[string]any)["event"] != "given" {
		return `the first event must be "given"`
	}
	return ""
}

// VerifyConsent verifies a consent record: shape, then EVERY event's
// signature against its own actor's key (each actor must resolve to a
// person). When any event's actor is not the subject, room is REQUIRED, and
// that actor must have been a member of the room at the event's epoch — a
// member who has left cannot withdraw on someone's behalf. Pass a room that
// VerifyRoom accepted. The result's Signer is the subject.
func VerifyConsent(record any, resolve KeyResolver, room *Room) (*Verified[ConsentRecord], error) {
	c, err := asObject(record)
	if err != nil {
		return nil, fmt.Errorf("malformed consent record: %w", err)
	}
	if p := checkConsentShape(c); p != "" {
		return nil, errors.New("malformed consent record: " + p)
	}
	if room != nil && room.RoomID != c["roomId"] {
		return nil, errors.New("consent record is for a different room")
	}
	subject := c["subjectDid"].(string)
	var subjectSigner *ResolvedSigner
	for i, ev := range c["events"].([]any) {
		e := ev.(map[string]any)
		actor := e["actorDid"].(string)
		epoch := int(e["epoch"].(float64))
		if actor != subject {
			if room == nil {
				return nil, fmt.Errorf("events[%d] is by %s, not the subject; the room record is required to check membership", i, actor)
			}
			if epoch > room.Epoch || !room.IsMemberAt(actor, epoch) {
				return nil, fmt.Errorf("events[%d]: %s was not a room member at epoch %d", i, actor, epoch)
			}
		}
		signer := resolveSigner(resolve, actor)
		if signer == nil {
			return nil, fmt.Errorf("events[%d]: actor %s has no resolvable key", i, actor)
		}
		if signer.Kind != KindPerson {
			return nil, fmt.Errorf("events[%d]: actor %s is not a person", i, actor)
		}
		msg, err := ConsentEventSigningBytes(c, i)
		if err != nil || !verifySig(e["sig"].(string), msg, signer.PublicKey) {
			return nil, fmt.Errorf("events[%d]: signature does not verify", i)
		}
		if actor == subject {
			subjectSigner = signer
		}
	}
	var out ConsentRecord
	if err := decodeInto(c, &out); err != nil {
		return nil, fmt.Errorf("malformed consent record: %w", err)
	}
	// The first event is "given", which only the subject can sign.
	return &Verified[ConsentRecord]{Value: out, Signer: *subjectSigner}, nil
}

// EffectiveConsent replays a VERIFIED record's events in order and returns
// the purposes currently granted (given minus later withdrawn).
func EffectiveConsent(record *ConsentRecord) map[string]bool {
	granted := map[string]bool{}
	if record == nil {
		return granted
	}
	for _, e := range record.Events {
		for _, p := range e.Purposes {
			if e.Event == "given" {
				granted[p] = true
			} else {
				delete(granted, p)
			}
		}
	}
	return granted
}

// ─── Turns ────────────────────────────────────────────────────────────────────

var turnFields = setOf("threadId", "roomId", "epoch", "at", "contentHash", "addressedTo", "authorDid", "content", "authorSignature")

// TurnContentHash is the SHA-256 hex of the UTF-8 bytes of a turn's content.
func TurnContentHash(content string) string {
	sum := sha256.Sum256([]byte(content))
	return hex.EncodeToString(sum[:])
}

// TurnSigningBytes returns the exact bytes a turn signature covers: JCS of
// {purpose: "aroha.turn/v1", threadId, roomId, epoch, at, contentHash,
// addressedTo}.
func TurnSigningBytes(turn any) ([]byte, error) {
	t, err := asObject(turn)
	if err != nil {
		return nil, err
	}
	if t == nil {
		return nil, errors.New("turn is not an object")
	}
	return turnSigningBytes(t)
}

func turnSigningBytes(t map[string]any) ([]byte, error) {
	return jcs.Canonicalize(map[string]any{
		"purpose":     TurnPurpose,
		"threadId":    t["threadId"],
		"roomId":      t["roomId"],
		"epoch":       t["epoch"],
		"at":          t["at"],
		"contentHash": t["contentHash"],
		"addressedTo": t["addressedTo"],
	})
}

func checkTurnShape(t map[string]any) string {
	if t == nil {
		return "turn is not an object"
	}
	if k := unknownField(t, turnFields); k != "" {
		return fmt.Sprintf("unknown field %q", k)
	}
	if !isNonEmpty(t["threadId"]) || !isNonEmpty(t["roomId"]) {
		return "threadId and roomId must be non-empty strings"
	}
	if !isEpoch(t["epoch"]) {
		return "epoch must be a non-negative integer"
	}
	if !isISO(t["at"]) {
		return "at must be an ISO 8601 date"
	}
	if h, ok := t["contentHash"].(string); !ok || !sha256Hex.MatchString(h) {
		return "contentHash must be SHA-256 hex"
	}
	addressed, ok := t["addressedTo"].([]any)
	if !ok {
		return "addressedTo must be an array of DIDs"
	}
	for _, a := range addressed {
		if !isDID(a) {
			return "addressedTo must be an array of DIDs"
		}
	}
	if !isDID(t["authorDid"]) {
		return "authorDid must be a DID"
	}
	if _, ok := t["content"].(string); !ok {
		return "content must be a string"
	}
	if !isNonEmpty(t["authorSignature"]) {
		return "authorSignature is missing"
	}
	return ""
}

// VerifyTurn verifies an authored turn: shape, contentHash matches content,
// (with room) the turn is for that room and thread and its author was a
// member at the turn's epoch, and the signature verifies under the author's
// current key. The result's Signer.Kind is the speaker kind — from the
// resolver, never from the turn.
func VerifyTurn(turn any, resolve KeyResolver, room *Room) (*Verified[Turn], error) {
	t, err := asObject(turn)
	if err != nil {
		return nil, fmt.Errorf("malformed turn: %w", err)
	}
	if p := checkTurnShape(t); p != "" {
		return nil, errors.New("malformed turn: " + p)
	}
	if TurnContentHash(t["content"].(string)) != t["contentHash"] {
		return nil, errors.New("turn content does not match contentHash")
	}
	author := t["authorDid"].(string)
	if room != nil {
		if room.RoomID != t["roomId"] || room.ThreadID != t["threadId"] {
			return nil, errors.New("turn is for a different room or thread")
		}
		epoch := int(t["epoch"].(float64))
		if !room.IsMemberAt(author, epoch) {
			return nil, fmt.Errorf("%s was not a room member at epoch %d", author, epoch)
		}
	}
	signer := resolveSigner(resolve, author)
	if signer == nil {
		return nil, fmt.Errorf("turn author %s has no resolvable key", author)
	}
	msg, err := turnSigningBytes(t)
	if err != nil || !verifySig(t["authorSignature"].(string), msg, signer.PublicKey) {
		return nil, errors.New("turn signature does not verify")
	}
	var out Turn
	if err := decodeInto(t, &out); err != nil {
		return nil, fmt.Errorf("malformed turn: %w", err)
	}
	return &Verified[Turn]{Value: out, Signer: *signer}, nil
}
