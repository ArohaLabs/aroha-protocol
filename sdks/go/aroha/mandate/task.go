// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

package mandate

// Task mandates (ArohaTaskMandateBody) — non-monetary, or task-plus-spend
// ("hybrid"), delegation tokens. A port of the task-mandate half of
// @aroha-sdk/credentials (packages/aroha-credentials/src/mandate.ts):
// issueTaskMandate, attenuateTaskMandate, verifyTaskMandate,
// checkTaskConstraints, checkTaskDataAccess, enforceTaskConstraints and
// checkTaskNarrowing.
//
// Token formats:
//
//	v2 {v: 2, mandate, signature}: signature over the RFC 8785 (JCS) form of
//	   {"mandate": <body>, "purpose": "aroha.task-mandate/v2", "v": 2}. The
//	   purpose tag means a task-mandate signature verifies as nothing else —
//	   not a spending mandate, whose v2 payload has no purpose, and not a v1
//	   token. Issued now.
//	v1 {mandate, signature}: legacy, read-only, signed over
//	   JSON.stringify(sortKeys(body)).
//
// A task token carries one link: multi-hop task chains are verified in
// TypeScript by @aroha-sdk/delegation's verifyTaskMandateChain, which this
// SDK does not port. CheckTaskNarrowing is the per-link rule that verifier
// applies, exported so a Go chain walker applies the same one.

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"sort"
	"strings"
	"time"

	"github.com/ArohaLabs/aroha-protocol/sdks/go/aroha/jcs"
	"github.com/google/uuid"
)

// TaskMandateTokenVersion is the token version IssueTaskMandate produces.
const TaskMandateTokenVersion = 2

// TaskMandatePurpose is the domain-separation tag inside every v2
// task-mandate signature.
const TaskMandatePurpose = "aroha.task-mandate/v2"

// DefaultTaskMandateTTL is the lifetime IssueTaskMandate uses when ttl is 0.
const DefaultTaskMandateTTL = time.Hour

// ─── Types ────────────────────────────────────────────────────────────────────

// TaskMandateType: "task" (no spend) or "hybrid" (task + spending constraints).
type TaskMandateType string

const (
	TaskTypeTask   TaskMandateType = "task"
	TaskTypeHybrid TaskMandateType = "hybrid"
)

// TaskMandateTier is the delegation level of a task mandate.
type TaskMandateTier string

const (
	TaskTierIntent    TaskMandateTier = "intent"
	TaskTierCart      TaskMandateTier = "cart"
	TaskTierExecution TaskMandateTier = "execution"
)

// DataAccessLevel is the access a mandate grants to one data resource.
// "write" is write WITHOUT read: levels are compared as sets of rights.
type DataAccessLevel string

const (
	DataAccessNone      DataAccessLevel = "none"
	DataAccessRead      DataAccessLevel = "read"
	DataAccessWrite     DataAccessLevel = "write"
	DataAccessReadWrite DataAccessLevel = "read-write"
)

// Output handling policies, narrowest first.
const (
	OutputInternalOnly = "internal-only"
	OutputUserOnly     = "user-only"
	OutputShareable    = "shareable"
)

// ComputeLimit is a compute ceiling; every set field is an independent limit.
type ComputeLimit struct {
	LLMTokens       *float64 `json:"llmTokens,omitempty"`
	WebRequests     *float64 `json:"webRequests,omitempty"`
	ExecutionTimeMs *float64 `json:"executionTimeMs,omitempty"`
	CPUSeconds      *float64 `json:"cpuSeconds,omitempty"`
}

// TaskConstraints are the resource limits and safety controls of a task
// mandate (TaskConstraints in packages/aroha-core/src/messages/types.ts).
// An unset field is ABSENT on the wire and means "no limit" — which is why
// CheckTaskNarrowing treats a child omitting a field its parent sets as
// widening.
//
// The one field where empty and absent differ is DataAccess: nil means "no
// data-access limit" and is omitted; a non-nil empty map means "no access to
// any resource" and is encoded as {}.
type TaskConstraints struct {
	// OnBehalfOf (conversation profile) is the room member this grant acts
	// for. A child must keep a parent's value verbatim.
	OnBehalfOf string `json:"onBehalfOf,omitempty"`
	// RoomID (conversation profile) is the room this grant is bound to.
	RoomID string `json:"roomId,omitempty"`
	// ActionLimits caps invocations per capability ID.
	ActionLimits map[string]float64 `json:"actionLimits,omitempty"`
	ComputeLimit *ComputeLimit      `json:"computeLimit,omitempty"`
	// DataAccess maps a resource key to its access level; a resource missing
	// from a non-nil map has no access.
	DataAccess map[string]DataAccessLevel `json:"dataAccess,omitempty"`
	// OutputHandling is one of the Output* constants.
	OutputHandling string `json:"outputHandling,omitempty"`
	// ReversibleOnly refuses every capability whose reversibility is
	// "irreversible" (or undeclared).
	ReversibleOnly bool `json:"reversibleOnly,omitempty"`
	// HumanGates lists capabilities that need a human approval first.
	HumanGates           []string `json:"humanGates,omitempty"`
	CheckpointIntervalMs *float64 `json:"checkpointIntervalMs,omitempty"`
	RequireSandbox       bool     `json:"requireSandbox,omitempty"`
	// MaxDelegationDepth limits sub-delegation below this mandate (0 = none).
	// Enforced by a chain verifier, not by CheckTaskNarrowing.
	MaxDelegationDepth *int `json:"maxDelegationDepth,omitempty"`
}

// MarshalJSON writes the set fields in a fixed order (onBehalfOf and roomId
// first, then the order of the TypeScript interface) and keeps a non-nil
// empty DataAccess as {}.
func (c TaskConstraints) MarshalJSON() ([]byte, error) {
	var w objWriter
	if c.OnBehalfOf != "" {
		w.field("onBehalfOf", c.OnBehalfOf)
	}
	if c.RoomID != "" {
		w.field("roomId", c.RoomID)
	}
	if c.ActionLimits != nil {
		w.field("actionLimits", c.ActionLimits)
	}
	if c.ComputeLimit != nil {
		w.field("computeLimit", c.ComputeLimit)
	}
	if c.DataAccess != nil {
		w.field("dataAccess", c.DataAccess)
	}
	if c.OutputHandling != "" {
		w.field("outputHandling", c.OutputHandling)
	}
	if c.ReversibleOnly {
		w.field("reversibleOnly", true)
	}
	if c.HumanGates != nil {
		w.field("humanGates", c.HumanGates)
	}
	if c.CheckpointIntervalMs != nil {
		w.field("checkpointIntervalMs", *c.CheckpointIntervalMs)
	}
	if c.RequireSandbox {
		w.field("requireSandbox", true)
	}
	if c.MaxDelegationDepth != nil {
		w.field("maxDelegationDepth", *c.MaxDelegationDepth)
	}
	return w.bytes()
}

// InvariantAmount is a bound maximum amount.
type InvariantAmount struct {
	Amount   float64 `json:"amount"`
	Currency string  `json:"currency"`
}

// MandateInvariants bind one specific transaction (design spec §9.1 Layer 1).
// nil and empty differ for Payee: a non-nil empty list binds "no payee".
type MandateInvariants struct {
	Payee []string `json:"payee,omitempty"`
	// Parameters values are strings, numbers or booleans, compared exactly.
	Parameters map[string]any   `json:"parameters,omitempty"`
	MaxAmount  *InvariantAmount `json:"maxAmount,omitempty"`
	// Expiry is ISO 8601.
	Expiry string `json:"expiry,omitempty"`
}

// MarshalJSON keeps a non-nil empty Payee as [].
func (i MandateInvariants) MarshalJSON() ([]byte, error) {
	var w objWriter
	if i.Payee != nil {
		w.field("payee", i.Payee)
	}
	if i.Parameters != nil {
		w.field("parameters", i.Parameters)
	}
	if i.MaxAmount != nil {
		w.field("maxAmount", i.MaxAmount)
	}
	if i.Expiry != "" {
		w.field("expiry", i.Expiry)
	}
	return w.bytes()
}

// TaskMandate is the task-mandate body (ArohaTaskMandateBody).
type TaskMandate struct {
	MandateType TaskMandateType `json:"mandateType"`
	MandateTier TaskMandateTier `json:"mandateTier"`
	// Allowed is the explicit list of permitted capability IDs.
	Allowed []string `json:"allowed"`
	// Blocked lists explicit denials; they override Allowed.
	Blocked         []string        `json:"blocked,omitempty"`
	TaskConstraints TaskConstraints `json:"taskConstraints"`
	// SpendingConstraints is set on a hybrid mandate.
	SpendingConstraints *SpendingConstraints `json:"spendingConstraints,omitempty"`
	Invariants          *MandateInvariants   `json:"invariants,omitempty"`
	Grantee             string               `json:"grantee"`
	Grantor             string               `json:"grantor"`
	IssuedAt            string               `json:"issuedAt"`
	ExpiresAt           string               `json:"expiresAt"`
	ParentMandateID     *string              `json:"parentMandateId"` // null for a root
	MandateID           string               `json:"mandateId"`
}

// MarshalJSON writes the body in the field order the TypeScript issuer uses,
// so a Go-issued token is byte-identical to a TypeScript-issued one with the
// same content.
func (m TaskMandate) MarshalJSON() ([]byte, error) {
	var w objWriter
	w.field("mandateType", m.MandateType)
	w.field("mandateTier", m.MandateTier)
	if m.Allowed == nil {
		w.field("allowed", []string{})
	} else {
		w.field("allowed", m.Allowed)
	}
	if m.Blocked != nil {
		w.field("blocked", m.Blocked)
	}
	w.field("taskConstraints", m.TaskConstraints)
	if m.SpendingConstraints != nil {
		w.field("spendingConstraints", m.SpendingConstraints)
	}
	if m.Invariants != nil {
		w.field("invariants", m.Invariants)
	}
	w.field("grantee", m.Grantee)
	w.field("grantor", m.Grantor)
	w.field("issuedAt", m.IssuedAt)
	w.field("expiresAt", m.ExpiresAt)
	w.field("parentMandateId", m.ParentMandateID)
	w.field("mandateId", m.MandateID)
	return w.bytes()
}

// SignedTaskMandate bundles a task mandate with its signature and token.
type SignedTaskMandate struct {
	Mandate TaskMandate
	// Signature is the base64url Ed25519 signature.
	Signature string
	// Token is the base64url serialised token.
	Token string
	// V is the signing rule Signature follows: 2 (issued now) or 1 (legacy).
	V   int
	raw any
}

// TaskVerificationResult is the outcome of VerifyTaskMandate.
type TaskVerificationResult struct {
	Valid   bool
	Mandate *TaskMandate
	Reason  string
}

// TaskIssueOptions are the optional inputs of IssueTaskMandate.
type TaskIssueOptions struct {
	Blocked []string
	// SpendingConstraints makes the mandate "hybrid".
	SpendingConstraints *SpendingConstraints
	// ParentMandateID is empty for a root.
	ParentMandateID string
	// Tier defaults to TaskTierIntent.
	Tier       TaskMandateTier
	Invariants *MandateInvariants
	// ExpiresAt, when set, overrides ttl (an absolute instant; attenuation
	// uses it so a child never lands a tick past its parent).
	ExpiresAt time.Time
	// IssuedAt and MandateID override the clock and the random UUID. For
	// reproducible test vectors only.
	IssuedAt  time.Time
	MandateID string
}

// TaskAttenuateOptions are the optional inputs of AttenuateTaskMandate.
type TaskAttenuateOptions struct {
	// Blocked is merged with (never replaces) the parent's blocked list.
	Blocked []string
	// SpendingConstraints defaults to the parent's.
	SpendingConstraints *SpendingConstraints
	// Invariants are NOT inherited: a parent's must be restated.
	Invariants *MandateInvariants
}

// TaskVerifyOptions configures VerifyTaskMandate.
type TaskVerifyOptions struct {
	// Now overrides the current time. Zero = time.Now().
	Now time.Time
	// ClockTolerance is the not-before skew for issuedAt. nil = DefaultClockTolerance.
	ClockTolerance *time.Duration
	// IsRevoked is keyed by (mandateId, grantor); an error fails closed.
	IsRevoked RevocationCheck
}

// ─── Issue / attenuate ────────────────────────────────────────────────────────

// IssueTaskMandate issues a root task mandate (or, with opts.ParentMandateID,
// a child — prefer AttenuateTaskMandate, which checks narrowing). ttl 0 means
// DefaultTaskMandateTTL.
func IssueTaskMandate(
	grantorDID, granteeDID string,
	allowed []string,
	taskConstraints TaskConstraints,
	privateKey ed25519.PrivateKey,
	ttl time.Duration,
	opts TaskIssueOptions,
) (*SignedTaskMandate, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("private key is %d bytes, want %d", len(privateKey), ed25519.PrivateKeySize)
	}
	now := opts.IssuedAt
	if now.IsZero() {
		now = time.Now()
	}
	expires := opts.ExpiresAt
	if expires.IsZero() {
		if ttl == 0 {
			ttl = DefaultTaskMandateTTL
		}
		expires = now.Add(ttl)
	}
	mandateType := TaskTypeTask
	if opts.SpendingConstraints != nil {
		mandateType = TaskTypeHybrid
	}
	tier := opts.Tier
	if tier == "" {
		tier = TaskTierIntent
	}
	var parentID *string
	if opts.ParentMandateID != "" {
		p := opts.ParentMandateID
		parentID = &p
	}
	id := opts.MandateID
	if id == "" {
		id = uuid.New().String()
	}
	m := TaskMandate{
		MandateType:         mandateType,
		MandateTier:         tier,
		Allowed:             allowed,
		Blocked:             opts.Blocked,
		TaskConstraints:     taskConstraints,
		SpendingConstraints: opts.SpendingConstraints,
		Invariants:          opts.Invariants,
		Grantee:             granteeDID,
		Grantor:             grantorDID,
		IssuedAt:            formatISO(now.UnixMilli()),
		ExpiresAt:           formatISO(expires.UnixMilli()),
		ParentMandateID:     parentID,
		MandateID:           id,
	}
	body, err := marshalNoEscape(m)
	if err != nil {
		return nil, err
	}
	// The body we sign is exactly the body a verifier will decode.
	raw, err := jcs.Parse(body)
	if err != nil {
		return nil, err
	}
	if err := CheckTaskMandateShape(raw); err != nil {
		return nil, fmt.Errorf("Invalid task mandate: %w", err)
	}
	var decoded TaskMandate
	if err := json.Unmarshal(body, &decoded); err != nil {
		return nil, err
	}
	payload, err := TaskMandateSigningPayloadV2(raw)
	if err != nil {
		return nil, err
	}
	sig := base64.RawURLEncoding.EncodeToString(ed25519.Sign(privateKey, payload))

	var tok objWriter
	tok.field("v", TaskMandateTokenVersion)
	tok.field("mandate", json.RawMessage(body))
	tok.field("signature", sig)
	tokenJSON, err := tok.bytes()
	if err != nil {
		return nil, err
	}
	return &SignedTaskMandate{
		Mandate:   decoded,
		Signature: sig,
		Token:     base64.RawURLEncoding.EncodeToString(tokenJSON),
		V:         2,
		raw:       raw,
	}, nil
}

// AttenuateTaskMandate issues a narrower child of parent, signed by the
// parent's grantee (grantorKey).
//
// Inheritance: the parent's blocked list is merged with opts.Blocked; its
// spendingConstraints apply when opts.SpendingConstraints is nil; its
// onBehalfOf and roomId apply when narrowed leaves them empty. Invariants are
// never inherited. The result must pass CheckTaskNarrowing. The child never
// outlives its parent: ttl 0 means "the parent's expiry". The child's tier is
// cart under an intent parent, execution otherwise.
func AttenuateTaskMandate(
	parent *SignedTaskMandate,
	granteeDID string,
	narrowedAllowed []string,
	narrowed TaskConstraints,
	grantorKey ed25519.PrivateKey,
	ttl time.Duration,
	opts TaskAttenuateOptions,
) (*SignedTaskMandate, error) {
	if parent == nil {
		return nil, errors.New("parent task mandate is nil")
	}
	p := parent.Mandate
	blocked := mergeLists(p.Blocked, opts.Blocked)
	spending := opts.SpendingConstraints
	if spending == nil {
		spending = p.SpendingConstraints
	}
	if narrowed.OnBehalfOf == "" {
		narrowed.OnBehalfOf = p.TaskConstraints.OnBehalfOf
	}
	if narrowed.RoomID == "" {
		narrowed.RoomID = p.TaskConstraints.RoomID
	}
	if err := CheckTaskNarrowing(&p, TaskNarrowingChild{
		Allowed:             narrowedAllowed,
		Blocked:             blocked,
		TaskConstraints:     narrowed,
		SpendingConstraints: spending,
		Invariants:          opts.Invariants,
	}); err != nil {
		return nil, err
	}
	parentExpiry, err := isoMillis(p.ExpiresAt)
	if err != nil {
		return nil, fmt.Errorf("parent expiresAt: %w", err)
	}
	expiry := parentExpiry
	if ttl != 0 {
		if e := time.Now().Add(ttl).UnixMilli(); e < expiry {
			expiry = e
		}
	}
	tier := TaskTierExecution
	if p.MandateTier == TaskTierIntent {
		tier = TaskTierCart
	}
	return IssueTaskMandate(p.Grantee, granteeDID, narrowedAllowed, narrowed, grantorKey, 0, TaskIssueOptions{
		ExpiresAt:           time.UnixMilli(expiry),
		Blocked:             blocked,
		SpendingConstraints: spending,
		ParentMandateID:     p.MandateID,
		Tier:                tier,
		Invariants:          opts.Invariants,
	})
}

// mergeLists is the order-preserving union of two optional lists; nil when
// both are nil.
func mergeLists(a, b []string) []string {
	if a == nil && b == nil {
		return nil
	}
	out := []string{}
	seen := map[string]bool{}
	for _, list := range [][]string{a, b} {
		for _, s := range list {
			if !seen[s] {
				seen[s] = true
				out = append(out, s)
			}
		}
	}
	return out
}

// TaskMandateSigningPayloadV2 returns the exact bytes a v2 task-mandate
// signature covers: JCS of {"mandate": <body>, "purpose":
// "aroha.task-mandate/v2", "v": 2}. body is a TaskMandate or the mandate's
// JSON data model (as decoded from a token).
func TaskMandateSigningPayloadV2(body any) ([]byte, error) {
	raw, err := taskDataModel(body)
	if err != nil {
		return nil, err
	}
	return jcs.Canonicalize(map[string]any{"mandate": raw, "purpose": TaskMandatePurpose, "v": 2})
}

func taskDataModel(body any) (any, error) {
	switch b := body.(type) {
	case TaskMandate:
		return toDataModel(b)
	case *TaskMandate:
		return toDataModel(*b)
	}
	return body, nil
}

// DecodeTaskToken decodes a task-mandate token WITHOUT verifying it (use
// VerifyTaskMandate for that) — e.g. to attenuate a received token.
func DecodeTaskToken(token string) (*SignedTaskMandate, error) {
	raw, version, reason := parseTaskToken(token)
	if reason != "" {
		return nil, errors.New(reason)
	}
	var m TaskMandate
	if err := json.Unmarshal(mustMarshal(raw["mandate"]), &m); err != nil {
		return nil, errors.New("Malformed token: mandate cannot be decoded")
	}
	return &SignedTaskMandate{Mandate: m, Signature: raw["signature"].(string), Token: token, V: version, raw: raw["mandate"]}, nil
}

// ─── Verify ───────────────────────────────────────────────────────────────────

// VerifyTaskMandate verifies a task-mandate token against the grantor's
// public key: shape, time window (expiry strict, issuedAt with clock
// tolerance), grantee (when expectedGrantee is set), signature and, with a
// hook, revocation. It never panics on hostile input.
func VerifyTaskMandate(token string, publicKey ed25519.PublicKey, expectedGrantee string, opts TaskVerifyOptions) TaskVerificationResult {
	raw, version, reason := parseTaskToken(token)
	if reason != "" {
		return TaskVerificationResult{Reason: reason}
	}
	fail := func(r string) TaskVerificationResult { return TaskVerificationResult{Reason: r} }
	var m TaskMandate
	if err := json.Unmarshal(mustMarshal(raw["mandate"]), &m); err != nil {
		return fail("Malformed token: mandate cannot be decoded")
	}

	now := opts.Now
	if now.IsZero() {
		now = time.Now()
	}
	tol := DefaultClockTolerance
	if opts.ClockTolerance != nil {
		tol = *opts.ClockTolerance
	}
	nowMs := now.UnixMilli()
	expires, _ := isoMillis(m.ExpiresAt) // shape-checked
	issued, _ := isoMillis(m.IssuedAt)
	if expires < nowMs {
		return fail("Task mandate expired")
	}
	if issued > nowMs+tol.Milliseconds() {
		return fail(fmt.Sprintf("Task mandate issuedAt %s is in the future", m.IssuedAt))
	}
	if expires < issued {
		return fail("Task mandate expires before it was issued")
	}
	if expectedGrantee != "" && m.Grantee != expectedGrantee {
		return fail("Grantee mismatch: expected " + expectedGrantee)
	}
	if !verifyTaskSignature(version, raw["mandate"], raw["signature"].(string), publicKey) {
		return fail("Invalid signature")
	}
	if r := checkTaskRevocation(m, opts.IsRevoked); r != "" {
		return fail(r)
	}
	return TaskVerificationResult{Valid: true, Mandate: &m}
}

// parseTaskToken decodes and shape-checks a token, returning its JSON object
// and signing-rule version, or the reason it was refused.
func parseTaskToken(token string) (map[string]any, int, string) {
	if token == "" {
		return nil, 0, "Malformed token"
	}
	data, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(token, "="))
	if err != nil {
		return nil, 0, "Malformed token"
	}
	v, err := jcs.Parse(data)
	if err != nil {
		return nil, 0, "Malformed token"
	}
	raw, ok := v.(map[string]any)
	if !ok {
		return nil, 0, "Malformed token"
	}
	if s, ok := raw["signature"].(string); !ok || s == "" {
		return nil, 0, "Malformed token: signature missing"
	}
	version := 0
	switch rv, present := raw["v"]; {
	case !present || rv == float64(1):
		version = 1
	case rv == float64(2):
		version = 2
	default:
		return nil, 0, fmt.Sprintf("Unsupported task mandate token version: %s", jsString(rv))
	}
	if err := CheckTaskMandateShape(raw["mandate"]); err != nil {
		return nil, 0, "Malformed token: " + err.Error()
	}
	return raw, version, ""
}

func verifyTaskSignature(version int, mandate any, signature string, publicKey ed25519.PublicKey) bool {
	sig, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(signature, "="))
	if err != nil || len(sig) != ed25519.SignatureSize || len(publicKey) != ed25519.PublicKeySize {
		return false
	}
	var msg []byte
	if version == 2 {
		msg, err = TaskMandateSigningPayloadV2(mandate)
	} else {
		msg, err = jcs.StringifySorted(mandate)
	}
	return err == nil && ed25519.Verify(publicKey, msg, sig)
}

// VerifyTaskMandateSignature checks one signed task mandate's signature under
// the rule v names (2, else 1). The mandate is a TaskMandate or its JSON data
// model; pass the data model as received to verify fields this SDK does not
// model.
func VerifyTaskMandateSignature(v int, mandate any, signature string, publicKey ed25519.PublicKey) bool {
	raw, err := taskDataModel(mandate)
	if err != nil {
		return false
	}
	if v != 2 {
		v = 1
	}
	return verifyTaskSignature(v, raw, signature, publicKey)
}

func checkTaskRevocation(m TaskMandate, isRevoked RevocationCheck) string {
	if isRevoked == nil {
		return ""
	}
	revoked, err := isRevoked(m.MandateID, m.Grantor)
	if err != nil {
		return "Revocation check failed for task mandate " + m.MandateID
	}
	if revoked {
		return fmt.Sprintf("Task mandate %s has been revoked", m.MandateID)
	}
	return ""
}

// ─── Shape ────────────────────────────────────────────────────────────────────

func isStringArray(v any) bool {
	arr, ok := v.([]any)
	if !ok {
		return false
	}
	for _, e := range arr {
		if _, ok := e.(string); !ok {
			return false
		}
	}
	return true
}

// CheckTaskMandateShape validates a decoded task-mandate body (its JSON data
// model): every field the enforcement code later compares must have the
// right type, because a missing limit must never read as "no limit
// exceeded". Messages match @aroha-sdk/credentials checkTaskMandateShape.
//
// Beyond the TypeScript checks it also refuses mistyped humanGates,
// outputHandling, checkpointIntervalMs, requireSandbox and maxDelegationDepth
// (which must be a non-negative integer), fields TypeScript reads without
// checking.
func CheckTaskMandateShape(v any) error {
	if r := checkTaskMandateShape(v); r != "" {
		return errors.New(r)
	}
	return nil
}

func checkTaskMandateShape(v any) string {
	m, ok := v.(map[string]any)
	if !ok {
		return "mandate is not an object"
	}
	if t := m["mandateType"]; t != "task" && t != "hybrid" {
		return "mandateType is invalid"
	}
	switch m["mandateTier"] {
	case "intent", "cart", "execution":
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
	if !isStringArray(m["allowed"]) {
		return "allowed must be an array of capability ids"
	}
	if b, present := m["blocked"]; present && !isStringArray(b) {
		return "blocked must be an array of capability ids"
	}

	tc, ok := m["taskConstraints"].(map[string]any)
	if !ok {
		return "taskConstraints is not an object"
	}
	if x, present := tc["actionLimits"]; present {
		al, ok := x.(map[string]any)
		if !ok {
			return "taskConstraints.actionLimits must be an object"
		}
		for _, cap := range sortedKeys(al) {
			if !isAmountValue(al[cap]) {
				return fmt.Sprintf("taskConstraints.actionLimits[%q] must be a finite, non-negative number", cap)
			}
		}
	}
	if x, present := tc["computeLimit"]; present {
		cl, ok := x.(map[string]any)
		if !ok {
			return "taskConstraints.computeLimit must be an object"
		}
		for _, f := range computeFields {
			if v, present := cl[f]; present && !isAmountValue(v) {
				return "taskConstraints.computeLimit." + f + " must be a finite, non-negative number"
			}
		}
	}
	if x, present := tc["dataAccess"]; present {
		da, ok := x.(map[string]any)
		if !ok {
			return "taskConstraints.dataAccess must be an object"
		}
		for _, res := range sortedKeys(da) {
			switch da[res] {
			case "none", "read", "read-write", "write":
			default:
				return fmt.Sprintf("taskConstraints.dataAccess[%q] is invalid", res)
			}
		}
	}
	if x, present := tc["reversibleOnly"]; present {
		if _, ok := x.(bool); !ok {
			return "taskConstraints.reversibleOnly must be a boolean"
		}
	}
	for _, f := range []string{"onBehalfOf", "roomId"} {
		if x, present := tc[f]; present {
			if s, ok := x.(string); !ok || s == "" {
				return "taskConstraints." + f + " must be a non-empty string"
			}
		}
	}
	if x, present := tc["humanGates"]; present && !isStringArray(x) {
		return "taskConstraints.humanGates must be an array of capability ids"
	}
	if x, present := tc["outputHandling"]; present {
		if _, ok := x.(string); !ok {
			return "taskConstraints.outputHandling must be a string"
		}
	}
	if x, present := tc["checkpointIntervalMs"]; present && !isAmountValue(x) {
		return "taskConstraints.checkpointIntervalMs must be a finite, non-negative number"
	}
	if x, present := tc["requireSandbox"]; present {
		if _, ok := x.(bool); !ok {
			return "taskConstraints.requireSandbox must be a boolean"
		}
	}
	if x, present := tc["maxDelegationDepth"]; present {
		f, ok := x.(float64)
		if !ok || f < 0 || f != math.Trunc(f) || f > math.MaxInt32 {
			return "taskConstraints.maxDelegationDepth must be a non-negative integer"
		}
	}

	if sc, present := m["spendingConstraints"]; m["mandateType"] == "hybrid" || present {
		if r := checkConstraintsShape(sc); r != "" {
			return "spendingConstraints: " + r
		}
	}
	if inv, present := m["invariants"]; present {
		if _, ok := inv.(map[string]any); !ok {
			return "invariants must be an object"
		}
		// Decoded into MandateInvariants below; refuse what would not decode.
		var tmp MandateInvariants
		if err := json.Unmarshal(mustMarshal(inv), &tmp); err != nil {
			return "invariants are malformed"
		}
	}
	return ""
}

var computeFields = []string{"llmTokens", "webRequests", "executionTimeMs", "cpuSeconds"}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// ─── Enforcement ──────────────────────────────────────────────────────────────

// Task constraint violation codes (TaskConstraintViolation.Code).
const (
	TaskViolationMandateInvalid         = "MANDATE_INVALID"
	TaskViolationCapabilityNotPermitted = "CAPABILITY_NOT_PERMITTED"
	TaskViolationReversibility          = "REVERSIBILITY_VIOLATION"
	TaskViolationHumanGateRequired      = "HUMAN_GATE_REQUIRED"
	TaskViolationActionLimitExceeded    = "ACTION_LIMIT_EXCEEDED"
	TaskViolationComputeLimitExceeded   = "COMPUTE_LIMIT_EXCEEDED"
	TaskViolationDataAccess             = "DATA_ACCESS_VIOLATION"
	TaskViolationSandboxRequired        = "SANDBOX_REQUIRED"
	TaskViolationDelegationDepth        = "DELEGATION_DEPTH_EXCEEDED"
	TaskViolationContextMismatch        = "CONTEXT_MISMATCH"
)

// TaskConstraintViolation is a refused task action.
type TaskConstraintViolation struct {
	Code    string
	Message string
}

func (e *TaskConstraintViolation) Error() string { return e.Message }

func taskViolation(code, format string, args ...any) *TaskConstraintViolation {
	return &TaskConstraintViolation{Code: code, Message: fmt.Sprintf(format, args...)}
}

// ComputeUsage is the compute a session has consumed so far.
type ComputeUsage struct {
	LLMTokens   float64
	WebRequests float64
	WallClockMs float64
}

// Capability reversibility classes.
const (
	ReversibilityFull         = "full"
	ReversibilitySemi         = "semi"
	ReversibilityIrreversible = "irreversible"
)

// TaskActionRequest is one requested action, checked against a VERIFIED task
// mandate by CheckTaskConstraints.
type TaskActionRequest struct {
	RequestedCapability string
	// CurrentActionCounts are this session's invocations per capability.
	CurrentActionCounts map[string]float64
	// CurrentCompute, when set, is checked against computeLimit.
	CurrentCompute *ComputeUsage
	// CapabilityReversibility: "full", "semi" or "irreversible". Empty is
	// "irreversible" (fail closed under reversibleOnly).
	CapabilityReversibility string
	// DataAccess declares the data the action touches. nil = touches none.
	// Valid levels are read, write and read-write.
	DataAccess map[string]DataAccessLevel
	// HumanApproved is set ONLY after a human approved this action.
	HumanApproved bool
	// RoomID and OnBehalfOf come from the runtime's own room record, never
	// from the request body. Required to match when the mandate binds them.
	RoomID     string
	OnBehalfOf string
}

// CheckTaskConstraints checks a requested action against an ALREADY-VERIFIED
// task mandate: room / on-behalf-of binding, allowed / blocked capability,
// reversibleOnly, humanGates, actionLimits, computeLimit (when the caller
// reports consumption) and dataAccess. It returns nil when the action is
// within the mandate.
func CheckTaskConstraints(m *TaskMandate, req TaskActionRequest) *TaskConstraintViolation {
	if m == nil {
		return taskViolation(TaskViolationMandateInvalid, "Task mandate is nil")
	}
	tc := m.TaskConstraints
	cap := req.RequestedCapability

	// A grant bound to one room and one member is refused for any other,
	// including a request that names no room or member at all.
	if tc.RoomID != "" && req.RoomID != tc.RoomID {
		return taskViolation(TaskViolationContextMismatch, "The mandate is bound to room %s; the request is from %s",
			tc.RoomID, orDefault(req.RoomID, "no room"))
	}
	if tc.OnBehalfOf != "" && req.OnBehalfOf != tc.OnBehalfOf {
		return taskViolation(TaskViolationContextMismatch, "The mandate acts on behalf of %s; the request is for %s",
			tc.OnBehalfOf, orDefault(req.OnBehalfOf, "nobody named"))
	}

	if !contains(m.Allowed, cap) {
		return taskViolation(TaskViolationCapabilityNotPermitted, "Capability %q is not in the mandate's allowed list", cap)
	}
	if contains(m.Blocked, cap) {
		return taskViolation(TaskViolationCapabilityNotPermitted, "Capability %q is explicitly blocked by the mandate", cap)
	}

	if tc.ReversibleOnly {
		rev := req.CapabilityReversibility
		if rev == "" {
			rev = ReversibilityIrreversible
		}
		if rev == ReversibilityIrreversible {
			return taskViolation(TaskViolationReversibility, "Capability %q is irreversible but mandate requires reversibleOnly", cap)
		}
	}

	if contains(tc.HumanGates, cap) && !req.HumanApproved {
		return taskViolation(TaskViolationHumanGateRequired, "Capability %q requires human approval (humanGate)", cap)
	}

	if limit, ok := tc.ActionLimits[cap]; ok {
		current := req.CurrentActionCounts[cap]
		if current >= limit {
			return taskViolation(TaskViolationActionLimitExceeded, "Action limit exceeded for %q: %s/%s", cap, fmtNum(current), fmtNum(limit))
		}
	}

	if cl := tc.ComputeLimit; cl != nil && req.CurrentCompute != nil {
		cc := req.CurrentCompute
		if cl.LLMTokens != nil && cc.LLMTokens >= *cl.LLMTokens {
			return taskViolation(TaskViolationComputeLimitExceeded, "LLM token budget exhausted (%s max)", fmtNum(*cl.LLMTokens))
		}
		if cl.WebRequests != nil && cc.WebRequests >= *cl.WebRequests {
			return taskViolation(TaskViolationComputeLimitExceeded, "Web request budget exhausted (%s max)", fmtNum(*cl.WebRequests))
		}
		if cl.ExecutionTimeMs != nil && cc.WallClockMs >= *cl.ExecutionTimeMs {
			return taskViolation(TaskViolationComputeLimitExceeded, "Execution time budget exhausted (%sms max)", fmtNum(*cl.ExecutionTimeMs))
		}
	}

	return CheckTaskDataAccess(&tc, req.DataAccess)
}

// dataRights models each access level as the set of rights it grants.
var dataRights = map[DataAccessLevel]struct{ read, write bool }{
	DataAccessNone:      {false, false},
	DataAccessRead:      {true, false},
	DataAccessWrite:     {false, true},
	DataAccessReadWrite: {true, true},
}

// CheckTaskDataAccess is the dataAccess rule of CheckTaskConstraints on its
// own. It returns nil when every requested resource is granted with the
// rights asked for, or when the mandate sets no dataAccess map.
func CheckTaskDataAccess(tc *TaskConstraints, requested map[string]DataAccessLevel) *TaskConstraintViolation {
	if tc == nil || tc.DataAccess == nil || requested == nil {
		return nil
	}
	for _, res := range sortedKeys(requested) {
		wanted := requested[res]
		granted, ok := tc.DataAccess[res]
		if !ok {
			granted = DataAccessNone
		}
		g, gok := dataRights[granted]
		w, wok := dataRights[wanted]
		// An unknown requested level fails closed rather than reading as "none".
		if !gok || !wok || (w.read && !g.read) || (w.write && !g.write) {
			return taskViolation(TaskViolationDataAccess, "Data access %q on %q exceeds the mandate's grant (%s)", wanted, res, granted)
		}
	}
	return nil
}

// EnforceTaskOptions configures EnforceTaskConstraints.
type EnforceTaskOptions struct {
	TaskActionRequest
	// ExpectedGrantee is your own DID; empty skips the check.
	ExpectedGrantee string
	IsRevoked       RevocationCheck
	// Now overrides the current time. Zero = time.Now().
	Now time.Time
}

// EnforceTaskConstraints verifies a task-mandate token AND checks the
// requested action against it. Call it at your capability gate before any
// side effect. Every refusal is a *TaskConstraintViolation.
func EnforceTaskConstraints(token string, grantorPublicKey ed25519.PublicKey, opts EnforceTaskOptions) (*TaskMandate, error) {
	r := VerifyTaskMandate(token, grantorPublicKey, opts.ExpectedGrantee, TaskVerifyOptions{IsRevoked: opts.IsRevoked, Now: opts.Now})
	if !r.Valid {
		return nil, taskViolation(TaskViolationMandateInvalid, "Task mandate invalid: %s", r.Reason)
	}
	if v := CheckTaskConstraints(r.Mandate, opts.TaskActionRequest); v != nil {
		return nil, v
	}
	return r.Mandate, nil
}

// ─── Narrowing ────────────────────────────────────────────────────────────────

// TaskNarrowingChild is the child side CheckTaskNarrowing compares.
type TaskNarrowingChild struct {
	Allowed             []string
	Blocked             []string
	TaskConstraints     TaskConstraints
	SpendingConstraints *SpendingConstraints
	Invariants          *MandateInvariants
	// ExpiresAt (ISO 8601) is empty only at issuance, before it is chosen.
	ExpiresAt string
}

// narrowingChild is the narrowing view of a signed child mandate.
func (m TaskMandate) narrowingChild() TaskNarrowingChild {
	return TaskNarrowingChild{
		Allowed: m.Allowed, Blocked: m.Blocked, TaskConstraints: m.TaskConstraints,
		SpendingConstraints: m.SpendingConstraints, Invariants: m.Invariants, ExpiresAt: m.ExpiresAt,
	}
}

// CheckTaskNarrowingMandates is CheckTaskNarrowing for two signed mandates.
func CheckTaskNarrowingMandates(parent, child *TaskMandate) error {
	if child == nil {
		return errors.New("Cannot attenuate task mandate: child is nil")
	}
	return CheckTaskNarrowing(parent, child.narrowingChild())
}

var outputRank = map[string]int{OutputInternalOnly: 0, OutputUserOnly: 1, OutputShareable: 2}

// CheckTaskNarrowing returns nil when child is equal to or narrower than
// parent, or an error saying why not. For every constraint: if the PARENT
// sets it, the child must set it too, to an equal or narrower value —
// omission is widening. It runs at attenuation time and, as the security
// control, in a chain verifier on every link. Not checked here:
// maxDelegationDepth and grantor/grantee/parentMandateId linkage, which need
// the whole chain. Messages match @aroha-sdk/credentials checkTaskNarrowing.
func CheckTaskNarrowing(parent *TaskMandate, child TaskNarrowingChild) error {
	const prefix = "Cannot attenuate task mandate"
	fail := func(format string, args ...any) error {
		return errors.New(prefix + ": " + fmt.Sprintf(format, args...))
	}
	if parent == nil {
		return fail("parent is nil")
	}
	ptc, ctc := parent.TaskConstraints, child.TaskConstraints

	// allowed ⊆ parent.allowed
	for _, cap := range child.Allowed {
		if !contains(parent.Allowed, cap) {
			return fail("child allowed includes %q which is not in parent's allowed list", cap)
		}
	}
	// blocked ⊇ parent.blocked
	for _, cap := range parent.Blocked {
		if !contains(child.Blocked, cap) {
			return fail("child drops parent's blocked capability %q", cap)
		}
	}

	// A parent limit binds every capability the child can still invoke.
	if ptc.ActionLimits != nil {
		for _, cap := range sortedKeys(ptc.ActionLimits) {
			parentLimit := ptc.ActionLimits[cap]
			if !contains(child.Allowed, cap) {
				continue
			}
			childLimit, ok := ctc.ActionLimits[cap]
			if !ok {
				return fail("parent sets actionLimits[%q] (%s) but child omits it", cap, fmtNum(parentLimit))
			}
			if !isAmount(childLimit) || childLimit > parentLimit {
				return fail("child actionLimits[%q] (%s) exceeds parent (%s)", cap, fmtNum(childLimit), fmtNum(parentLimit))
			}
		}
	}

	if ptc.ComputeLimit != nil {
		pc := computeValues(ptc.ComputeLimit)
		cc := computeValues(ctc.ComputeLimit)
		for i, f := range computeFields {
			if pc[i] == nil {
				continue
			}
			if cc[i] == nil {
				return fail("parent sets computeLimit.%s (%s) but child omits it", f, fmtNum(*pc[i]))
			}
			if !isAmount(*cc[i]) || *cc[i] > *pc[i] {
				return fail("child %s (%s) exceeds parent (%s)", f, fmtNum(*cc[i]), fmtNum(*pc[i]))
			}
		}
	}

	// Inside a dataAccess map a missing key means "no access"; leaving the
	// WHOLE map out means "no limit", which is widening.
	if ptc.DataAccess != nil {
		if ctc.DataAccess == nil {
			return fail("parent restricts dataAccess but child omits it")
		}
		for _, res := range sortedKeys(ctc.DataAccess) {
			childAccess := ctc.DataAccess[res]
			parentAccess, ok := ptc.DataAccess[res]
			if !ok {
				parentAccess = DataAccessNone
			}
			c, cok := dataRights[childAccess]
			p, pok := dataRights[parentAccess]
			if !cok || !pok || (c.read && !p.read) || (c.write && !p.write) {
				return fail("child dataAccess[%q] (%s) exceeds parent (%s)", res, childAccess, parentAccess)
			}
		}
	}

	if ptc.ReversibleOnly && !ctc.ReversibleOnly {
		return fail("parent requires reversibleOnly but child does not")
	}
	if ptc.RequireSandbox && !ctc.RequireSandbox {
		return fail("parent requires requireSandbox but child does not")
	}

	// A parent's room / member binding is kept verbatim.
	for _, f := range []struct{ name, p, c string }{
		{"onBehalfOf", ptc.OnBehalfOf, ctc.OnBehalfOf},
		{"roomId", ptc.RoomID, ctc.RoomID},
	} {
		if f.p != "" && f.c != f.p {
			return fail("child %s (%s) does not keep the parent's %s (%s)", f.name, orDefault(f.c, "unset"), f.name, f.p)
		}
	}

	// Only gates on capabilities the child can still invoke matter.
	for _, cap := range ptc.HumanGates {
		if contains(child.Allowed, cap) && !contains(ctc.HumanGates, cap) {
			return fail("child drops parent's human gate on %q", cap)
		}
	}

	if ptc.OutputHandling != "" {
		p, pok := outputRank[ptc.OutputHandling]
		c, cok := outputRank[ctc.OutputHandling]
		if ctc.OutputHandling == "" || !cok || !pok || c > p {
			return fail("child outputHandling (%s) is wider than parent (%s)", orDefault(ctc.OutputHandling, "unset"), ptc.OutputHandling)
		}
	}

	// The child may check in more often, never less.
	if ptc.CheckpointIntervalMs != nil {
		c := ctc.CheckpointIntervalMs
		if c == nil || !isAmount(*c) || *c > *ptc.CheckpointIntervalMs {
			cs := "unset"
			if c != nil {
				cs = fmtNum(*c)
			}
			return fail("child checkpointIntervalMs (%s) is longer than parent (%s)", cs, fmtNum(*ptc.CheckpointIntervalMs))
		}
	}

	if parent.SpendingConstraints != nil {
		if child.SpendingConstraints == nil {
			return fail("parent sets spendingConstraints but child omits them")
		}
		if err := CheckNarrowing(*parent.SpendingConstraints, *child.SpendingConstraints, "task", "task"); err != nil {
			return fail("spendingConstraints: %s", err.Error())
		}
	}

	// A parent's instance binding can only be tightened or kept.
	if pi := parent.Invariants; pi != nil {
		ci := child.Invariants
		if ci == nil {
			return fail("parent has invariants but child drops them entirely")
		}
		if pi.Payee != nil {
			if ci.Payee == nil {
				return fail("parent restricts payee but child has no payee invariant")
			}
			for _, p := range ci.Payee {
				if !contains(pi.Payee, p) {
					return fail("child payee %q is not in parent's payee list", p)
				}
			}
		}
		if pi.MaxAmount != nil {
			if ci.MaxAmount == nil {
				return fail("parent has maxAmount invariant but child has none")
			}
			if ci.MaxAmount.Currency != pi.MaxAmount.Currency {
				return fail("child maxAmount currency (%s) differs from parent (%s)", ci.MaxAmount.Currency, pi.MaxAmount.Currency)
			}
			if !isAmount(ci.MaxAmount.Amount) || ci.MaxAmount.Amount > pi.MaxAmount.Amount {
				return fail("child maxAmount (%s) exceeds parent (%s)", fmtNum(ci.MaxAmount.Amount), fmtNum(pi.MaxAmount.Amount))
			}
		}
		for _, key := range sortedKeys(pi.Parameters) {
			cv, ok := ci.Parameters[key]
			if !ok || !strictEqual(cv, pi.Parameters[key]) {
				return fail("child parameter %q does not match parent's fixed value", key)
			}
		}
		if pi.Expiry != "" {
			if ci.Expiry == "" {
				return fail("parent has expiry invariant but child has none")
			}
			c, cerr := isoMillis(ci.Expiry)
			p, perr := isoMillis(pi.Expiry)
			if cerr != nil || (perr == nil && c > p) {
				return fail("child expiry (%s) exceeds parent (%s)", ci.Expiry, pi.Expiry)
			}
		}
	}

	if child.ExpiresAt != "" {
		c, cerr := isoMillis(child.ExpiresAt)
		p, perr := isoMillis(parent.ExpiresAt)
		// An unparseable date on either side fails closed.
		if cerr != nil || perr != nil || c > p {
			return fail("child expiry (%s) extends beyond parent (%s)", child.ExpiresAt, parent.ExpiresAt)
		}
	}
	return nil
}

func computeValues(c *ComputeLimit) [4]*float64 {
	if c == nil {
		return [4]*float64{}
	}
	return [4]*float64{c.LLMTokens, c.WebRequests, c.ExecutionTimeMs, c.CPUSeconds}
}

// strictEqual is JavaScript === for invariant parameter values: equal
// strings, booleans or numbers; any object or array is unequal (JavaScript
// compares those by reference).
func strictEqual(a, b any) bool {
	na, aNum := asFloat(a)
	nb, bNum := asFloat(b)
	if aNum || bNum {
		return aNum && bNum && na == nb
	}
	switch x := a.(type) {
	case string:
		y, ok := b.(string)
		return ok && x == y
	case bool:
		y, ok := b.(bool)
		return ok && x == y
	case nil:
		return b == nil
	}
	return false
}

func asFloat(v any) (float64, bool) {
	switch x := v.(type) {
	case float64:
		return x, true
	case float32:
		return float64(x), true
	case int:
		return float64(x), true
	case int32:
		return float64(x), true
	case int64:
		return float64(x), true
	case json.Number:
		f, err := x.Float64()
		return f, err == nil
	}
	return 0, false
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

func orDefault(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

// ─── Ordered JSON objects ─────────────────────────────────────────────────────

// objWriter writes a JSON object with keys in call order (encoding/json
// sorts map keys, but token bytes follow the TypeScript issuer's order).
type objWriter struct {
	buf bytes.Buffer
	err error
}

func (w *objWriter) field(key string, v any) {
	if w.err != nil {
		return
	}
	if w.buf.Len() == 0 {
		w.buf.WriteByte('{')
	} else {
		w.buf.WriteByte(',')
	}
	k, err := marshalNoEscape(key)
	if err != nil {
		w.err = err
		return
	}
	val, err := marshalNoEscape(v)
	if err != nil {
		w.err = err
		return
	}
	w.buf.Write(k)
	w.buf.WriteByte(':')
	w.buf.Write(val)
}

func (w *objWriter) bytes() ([]byte, error) {
	if w.err != nil {
		return nil, w.err
	}
	if w.buf.Len() == 0 {
		return []byte("{}"), nil
	}
	w.buf.WriteByte('}')
	return w.buf.Bytes(), nil
}
