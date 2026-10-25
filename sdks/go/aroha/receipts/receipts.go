// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

// Package receipts verifies signed action receipts v1 and v2 (spec aroha-1.0
// §12.6): the acting agent's signed statement of what it did (or was refused)
// — taint, approver, mandate, and in v2 the requester, principal, executor,
// presented-content hash, room binding and outcome. A port of the
// verification side of packages/aroha-core/src/receipts/action-receipt.ts,
// checked against spec-public/vectors/conversation-v1.json.
//
// A receipt's signature is Ed25519 over the UTF-8 bytes of the RFC 8785 (JCS)
// form of the receipt minus its signature, base64url without padding. The
// purpose tag is inside the signed bytes. The signature proves the agent's
// key made the claims; it does not prove the claims are true.
package receipts

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/ArohaLabs/aroha-protocol/sdks/go/aroha/jcs"
)

// Purpose tags of the two receipt versions.
const (
	PurposeV1 = "aroha.action-receipt/v1"
	PurposeV2 = "aroha.action-receipt/v2"
)

// Outcomes of a v2 receipt.
const (
	OutcomeExecuted = "executed"
	OutcomeDenied   = "denied"
)

// Approval is the human approval behind an action.
type Approval struct {
	ApproverDID string `json:"approverDid"`
	ApprovedAt  string `json:"approvedAt"`
	ApprovalID  string `json:"approvalId"`
	// PresentedHash (v2) is the SHA-256 hex of the JCS form of what the
	// approver was shown.
	PresentedHash string `json:"presentedHash,omitempty"`
	// ApproverSignature (v2) is carried as evidence; it is not checked here.
	ApproverSignature string `json:"approverSignature,omitempty"`
}

// Receipt is a parsed v1 or v2 action receipt.
type Receipt struct {
	V              int       `json:"v"`
	Purpose        string    `json:"purpose"`
	AgentDID       string    `json:"agentDid"`
	Action         string    `json:"action"`
	ArgsSHA256     string    `json:"argsSha256"`
	At             string    `json:"at"`
	Tainted        bool      `json:"tainted"`
	Provenance     []string  `json:"provenance,omitempty"`
	Approval       *Approval `json:"approval,omitempty"`
	MandateID      string    `json:"mandateId,omitempty"`
	MandateGrantor string    `json:"mandateGrantor,omitempty"`
	CorrelationID  string    `json:"correlationId,omitempty"`
	// v2 only.
	RequesterDID  string `json:"requesterDid,omitempty"`
	PrincipalDID  string `json:"principalDid,omitempty"`
	ExecutorDID   string `json:"executorDid,omitempty"`
	PresentedHash string `json:"presentedHash,omitempty"`
	Traceparent   string `json:"traceparent,omitempty"`
	Outcome       string `json:"outcome,omitempty"`
	DenialReason  string `json:"denialReason,omitempty"`
	RoomID        string `json:"roomId,omitempty"`
	OnBehalfOf    string `json:"onBehalfOf,omitempty"`
	Signature     string `json:"signature"`
}

// KeyResolver returns the agent's current Ed25519 key, or nil when unknown.
type KeyResolver func(did string) (ed25519.PublicKey, error)

var (
	sha256Hex   = regexp.MustCompile(`^[0-9a-f]{64}$`)
	commonKeys  = []string{"v", "purpose", "agentDid", "action", "argsSha256", "at", "tainted", "provenance", "approval", "mandateId", "mandateGrantor", "correlationId", "signature"}
	v2OnlyKeys  = []string{"requesterDid", "principalDid", "executorDid", "presentedHash", "traceparent", "outcome", "denialReason", "roomId", "onBehalfOf"}
	knownV1     = setOf(commonKeys...)
	knownV2     = setOf(append(append([]string{}, commonKeys...), v2OnlyKeys...)...)
	approvalV1  = setOf("approverDid", "approvedAt", "approvalId")
	approvalV2  = setOf("approverDid", "approvedAt", "approvalId", "presentedHash", "approverSignature")
	errMalformd = errors.New("the action receipt is malformed")
)

func setOf(keys ...string) map[string]bool {
	s := make(map[string]bool, len(keys))
	for _, k := range keys {
		s[k] = true
	}
	return s
}

func dataModel(v any) (any, error) {
	switch x := v.(type) {
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

func nonEmpty(x any) bool {
	s, ok := x.(string)
	return ok && s != ""
}

func outcomeProblem(outcome, denialReason any, hasReason bool) string {
	if outcome != OutcomeExecuted && outcome != OutcomeDenied {
		return `outcome must be "executed" or "denied"`
	}
	if outcome == OutcomeDenied && !nonEmpty(denialReason) {
		return "a denied receipt requires a denialReason"
	}
	if outcome == OutcomeExecuted && hasReason {
		return "an executed receipt must not carry a denialReason"
	}
	return ""
}

// CheckShape is the structural check of an untrusted receipt. Every field is
// type-checked, and each version refuses fields it does not define. It
// returns the reason a receipt is malformed, or "" when it is well-formed.
func CheckShape(value any) string {
	dm, err := dataModel(value)
	if err != nil {
		return err.Error()
	}
	r, ok := dm.(map[string]any)
	if !ok {
		return "receipt is not an object"
	}
	isV1 := r["v"] == float64(1) && r["purpose"] == PurposeV1
	isV2 := r["v"] == float64(2) && r["purpose"] == PurposeV2
	if !isV1 && !isV2 {
		return "unknown receipt version"
	}
	for _, k := range []string{"agentDid", "action", "argsSha256", "at", "signature"} {
		if !nonEmpty(r[k]) {
			return k + " must be a non-empty string"
		}
	}
	if _, ok := r["tainted"].(bool); !ok {
		return "tainted must be a boolean"
	}
	if p, present := r["provenance"]; present {
		arr, ok := p.([]any)
		if !ok {
			return "provenance must be a list of strings"
		}
		for _, e := range arr {
			if _, ok := e.(string); !ok {
				return "provenance must be a list of strings"
			}
		}
	}
	for _, k := range []string{"mandateId", "mandateGrantor", "correlationId"} {
		if x, present := r[k]; present {
			if _, ok := x.(string); !ok {
				return k + " must be a string"
			}
		}
	}
	if a, present := r["approval"]; present {
		ap, ok := a.(map[string]any)
		if !ok {
			return "approval must be an object"
		}
		for _, k := range []string{"approverDid", "approvedAt", "approvalId"} {
			if _, ok := ap[k].(string); !ok {
				return "approval." + k + " must be a string"
			}
		}
		allowed := approvalV1
		if isV2 {
			allowed = approvalV2
		}
		for k := range ap {
			if !allowed[k] {
				return fmt.Sprintf("approval has unknown field %q for this version", k)
			}
		}
		if ph, present := ap["presentedHash"]; present {
			if s, ok := ph.(string); !ok || !sha256Hex.MatchString(s) {
				return "approval.presentedHash must be SHA-256 hex"
			}
		}
		if s, present := ap["approverSignature"]; present {
			if _, ok := s.(string); !ok {
				return "approval.approverSignature must be a string"
			}
		}
	}
	if isV2 {
		for _, k := range []string{"requesterDid", "principalDid", "executorDid", "traceparent", "roomId", "onBehalfOf"} {
			if x, present := r[k]; present && !nonEmpty(x) {
				return k + " must be a non-empty string"
			}
		}
		if ph, present := r["presentedHash"]; present {
			if s, ok := ph.(string); !ok || !sha256Hex.MatchString(s) {
				return "presentedHash must be SHA-256 hex"
			}
		}
		_, hasReason := r["denialReason"]
		if p := outcomeProblem(r["outcome"], r["denialReason"], hasReason); p != "" {
			return p
		}
	}
	known := knownV1
	if isV2 {
		known = knownV2
	}
	for k := range r {
		if !known[k] {
			return fmt.Sprintf("unknown field %q for this version", k)
		}
	}
	return ""
}

// SigningBytes returns the exact bytes a receipt's signature covers: JCS of
// the receipt minus its signature.
func SigningBytes(receipt any) ([]byte, error) {
	dm, err := dataModel(receipt)
	if err != nil {
		return nil, err
	}
	r, ok := dm.(map[string]any)
	if !ok {
		return nil, errMalformd
	}
	body := make(map[string]any, len(r))
	for k, v := range r {
		if k != "signature" {
			body[k] = v
		}
	}
	return jcs.Canonicalize(body)
}

// Verify checks a receipt's shape and its signature against its agent's key.
// A receipt whose agent cannot be resolved is refused, never accepted on its
// own say-so.
func Verify(receipt any, resolve KeyResolver) (*Receipt, error) {
	dm, err := dataModel(receipt)
	if err != nil {
		return nil, errMalformd
	}
	if p := CheckShape(dm); p != "" {
		return nil, fmt.Errorf("%w: %s", errMalformd, p)
	}
	r := dm.(map[string]any)
	agent := r["agentDid"].(string)
	var key ed25519.PublicKey
	if resolve != nil {
		if k, err := resolve(agent); err == nil {
			key = k
		}
	}
	if len(key) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("the action receipt's agent %s has no resolvable key", agent)
	}
	sig, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(r["signature"].(string), "="))
	if err != nil {
		return nil, errors.New("the action receipt's signature is not base64url")
	}
	if len(sig) != ed25519.SignatureSize {
		return nil, errors.New("the action receipt's signature has the wrong length")
	}
	msg, err := SigningBytes(r)
	if err != nil || !ed25519.Verify(key, msg, sig) {
		return nil, errors.New("the action receipt's signature does not verify")
	}
	var out Receipt
	b, _ := json.Marshal(r)
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, fmt.Errorf("%w: %v", errMalformd, err)
	}
	return &out, nil
}

func sha256JCS(v any) (string, error) {
	if v == nil {
		v = map[string]any{}
	}
	dm, err := dataModel(v)
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

// HashArgs is the argument digest a receipt carries: SHA-256 hex over the
// JCS form of the arguments (nil means {}).
func HashArgs(args any) (string, error) { return sha256JCS(args) }

// HashPresentedContent is the presentedHash digest: SHA-256 hex over the JCS
// form of exactly what the approver was shown (nil means {}).
func HashPresentedContent(content any) (string, error) { return sha256JCS(content) }

// VerifyPresentedHash checks a VERIFIED v2 receipt against the content a
// party says was presented for approval. It returns "" when every
// presentedHash the receipt carries (top level and in the approval) equals
// HashPresentedContent(content), otherwise the reason. A receipt with no
// presentedHash makes no statement about what was shown and is refused.
func VerifyPresentedHash(r *Receipt, presentedContent any) string {
	if r == nil || r.V != 2 {
		return "a v1 action receipt carries no presentedHash"
	}
	var hashes []string
	if r.PresentedHash != "" {
		hashes = append(hashes, r.PresentedHash)
	}
	if r.Approval != nil && r.Approval.PresentedHash != "" {
		hashes = append(hashes, r.Approval.PresentedHash)
	}
	if len(hashes) == 0 {
		return "the action receipt carries no presentedHash"
	}
	actual, err := HashPresentedContent(presentedContent)
	if err != nil {
		return "the presented content cannot be canonicalised"
	}
	for _, h := range hashes {
		if h != actual {
			return "the content presented for approval differs from what the receipt records"
		}
	}
	return ""
}

// RequireApprovalIfTainted is the downstream policy: an action derived from
// untrusted input must carry a human approval. It returns "" when the
// VERIFIED receipt satisfies it.
func RequireApprovalIfTainted(r *Receipt) string {
	if r == nil || !r.Tainted {
		return ""
	}
	if r.Approval != nil && r.Approval.ApproverDID != "" && r.Approval.ApprovalID != "" {
		return ""
	}
	return "The action was derived from untrusted input and carries no human approval."
}

// Matches checks that a VERIFIED receipt describes this action: the same
// agent, action name and arguments. It returns "" on a match.
func Matches(r *Receipt, agentDID, action string, args any) string {
	if r.AgentDID != agentDID {
		return fmt.Sprintf("the action receipt is for %s, not %s", r.AgentDID, agentDID)
	}
	if r.Action != action {
		return fmt.Sprintf("the action receipt is for %q, not %q", r.Action, action)
	}
	if h, err := HashArgs(args); err != nil || h != r.ArgsSHA256 {
		return "the action receipt does not match the action's arguments"
	}
	return ""
}
