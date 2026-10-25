// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

package messages

// ArohaDisclosure — a per-hop statement "I am an AI agent, and this is the
// principal I act for". A port of packages/aroha-core/src/messages/disclosure.ts.
//
// It travels as the optional `disclosure` field of an envelope (covered by
// the envelope signature, so it cannot be stripped or edited in transit) and
// as the `disclosure` of a conversation Room. The signature proves the agent
// made the statement; it does not prove the principal authorised the agent —
// that is a mandate chain's job.

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strings"
	"unicode/utf16"
)

// DisclosureVersion is the wire version of the disclosure object.
const DisclosureVersion = 1

// MaxDisclosurePurposeLength bounds `purpose` (in UTF-16 code units, as
// JavaScript counts string length).
const MaxDisclosurePurposeLength = 512

// Principal kinds.
const (
	PrincipalPerson       = "person"
	PrincipalOrganization = "organization"
)

// Disclosure is an ArohaDisclosure.
type Disclosure struct {
	V int `json:"v"`
	// AgentDID is the disclosing agent. In an envelope it MUST equal `from`.
	AgentDID string `json:"agentDid"`
	// PrincipalDID is the person or organisation the agent acts for.
	PrincipalDID string `json:"principalDid"`
	// PrincipalKind is PrincipalPerson or PrincipalOrganization.
	PrincipalKind string `json:"principalKind"`
	// Purpose is a short statement of what the agent is doing.
	Purpose string `json:"purpose"`
	// Hop is the position in the agent chain: 0 = addressed directly.
	Hop int `json:"hop"`
	// AIGenerated is always true.
	AIGenerated bool `json:"aiGenerated"`
}

// DisclosureInput is everything BuildDisclosure needs; Hop defaults to 0.
type DisclosureInput struct {
	AgentDID      string
	PrincipalDID  string
	PrincipalKind string
	Purpose       string
	Hop           int
}

// BuildDisclosure builds a disclosure, refusing input ValidateDisclosure
// would refuse.
func BuildDisclosure(in DisclosureInput) (*Disclosure, error) {
	d := &Disclosure{
		V: DisclosureVersion, AgentDID: in.AgentDID, PrincipalDID: in.PrincipalDID,
		PrincipalKind: in.PrincipalKind, Purpose: in.Purpose, Hop: in.Hop, AIGenerated: true,
	}
	if _, err := ValidateDisclosure(d, ""); err != nil {
		return nil, fmt.Errorf("Invalid disclosure: %w", err)
	}
	return d, nil
}

// Map returns the disclosure in the JSON data model, for embedding in an
// envelope or a room record.
func (d Disclosure) Map() map[string]any {
	return map[string]any{
		"v": float64(d.V), "agentDid": d.AgentDID, "principalDid": d.PrincipalDID,
		"principalKind": d.PrincipalKind, "purpose": d.Purpose, "hop": float64(d.Hop), "aiGenerated": d.AIGenerated,
	}
}

var disclosureFields = map[string]bool{
	"v": true, "agentDid": true, "principalDid": true, "principalKind": true, "purpose": true, "hop": true, "aiGenerated": true,
}

// ValidateDisclosure structurally checks an untrusted disclosure (its JSON
// data model, or a *Disclosure / Disclosure). With a non-empty
// expectedAgentDID (an envelope's `from`) it also refuses a disclosure made
// in another agent's name. Unknown fields are refused, not ignored. Error
// messages match @aroha-sdk/core validateDisclosure.
func ValidateDisclosure(value any, expectedAgentDID string) (*Disclosure, error) {
	switch x := value.(type) {
	case Disclosure:
		value = x.Map()
	case *Disclosure:
		if x == nil {
			return nil, errors.New("disclosure is not an object")
		}
		value = x.Map()
	}
	d, ok := value.(map[string]any)
	if !ok {
		return nil, errors.New("disclosure is not an object")
	}
	if v, ok := d["v"].(float64); !ok || v != DisclosureVersion {
		return nil, fmt.Errorf("unsupported disclosure version %s", jsValueString(d["v"]))
	}
	for _, k := range []string{"agentDid", "principalDid", "purpose"} {
		if s, ok := d[k].(string); !ok || s == "" {
			return nil, fmt.Errorf("%s must be a non-empty string", k)
		}
	}
	agent, principal, purpose := d["agentDid"].(string), d["principalDid"].(string), d["purpose"].(string)
	if !strings.HasPrefix(agent, "did:") || !strings.HasPrefix(principal, "did:") {
		return nil, errors.New("agentDid and principalDid must be DIDs")
	}
	if len(utf16.Encode([]rune(purpose))) > MaxDisclosurePurposeLength {
		return nil, fmt.Errorf("purpose exceeds %d characters", MaxDisclosurePurposeLength)
	}
	kind := d["principalKind"]
	if kind != PrincipalPerson && kind != PrincipalOrganization {
		return nil, errors.New(`principalKind must be "person" or "organization"`)
	}
	hop, ok := d["hop"].(float64)
	if !ok || hop < 0 || hop != math.Trunc(hop) || hop > math.MaxInt32 {
		return nil, errors.New("hop must be a non-negative integer")
	}
	if d["aiGenerated"] != true {
		return nil, errors.New("aiGenerated must be true")
	}
	for k := range d {
		if !disclosureFields[k] {
			return nil, fmt.Errorf("unknown field %q", k)
		}
	}
	if expectedAgentDID != "" && agent != expectedAgentDID {
		return nil, fmt.Errorf("disclosure names agent %s, not the sender %s", agent, expectedAgentDID)
	}
	return &Disclosure{
		V: DisclosureVersion, AgentDID: agent, PrincipalDID: principal, PrincipalKind: kind.(string),
		Purpose: purpose, Hop: int(hop), AIGenerated: true,
	}, nil
}

// jsValueString renders a JSON value the way JavaScript's String() does,
// for error messages.
func jsValueString(v any) string {
	switch x := v.(type) {
	case nil:
		return "undefined"
	case string:
		return x
	case bool:
		if x {
			return "true"
		}
		return "false"
	case float64:
		b, _ := json.Marshal(x)
		return string(b)
	}
	return fmt.Sprint(v)
}
