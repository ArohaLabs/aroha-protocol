// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

// Package orchestrator — Capability Schema Negotiation (CSN)
//
// Aroha's superior alternative to ANP's meta-protocol:
//
//	ANP: LLM generates NEW protocol → both sides code-generate → fragile
//	Aroha CSN:
//	  1. Structural JSON Schema matching first (deterministic, no LLM)
//	  2. LLM only when structurally ambiguous (score 0.5–0.85)
//	  3. Maps to an EXISTING typed Aroha capability
//	  4. Transaction terms negotiated in the same round
//	  5. Agreed schema SHA-256 cached → zero-latency on repeat calls
package orchestrator

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/ArohaLabs/aroha-protocol/sdks/go/aroha/jcs"
)

// ── Schema matching ───────────────────────────────────────────────────────────

// SchemaCompatibilityScore computes a 0–1 structural match score.
//
// ≥ 0.85  → confident match, no LLM needed
// 0.5–0.85 → ambiguous, LLM fallback recommended
// < 0.5   → incompatible
func SchemaCompatibilityScore(desired, available map[string]any) float64 {
	desiredProps := getProps(desired)
	availableProps := getProps(available)
	required := getRequired(desired)

	if len(desiredProps) == 0 {
		return 1.0
	}

	var matchScore, totalWeight float64

	for key, dField := range desiredProps {
		weight := 0.4
		if _, req := required[key]; req {
			weight = 1.0
		}
		totalWeight += weight

		aField, ok := availableProps[key]
		if !ok {
			continue
		}

		dType := fieldType(dField)
		aType := fieldType(aField)

		switch {
		case dType == "" || aType == "" || dType == aType:
			matchScore += weight
		case typesCompatible(dType, aType):
			matchScore += weight * 0.7
		}
	}

	if totalWeight == 0 {
		return 1.0
	}
	return matchScore / totalWeight
}

func getProps(schema map[string]any) map[string]any {
	if p, ok := schema["properties"].(map[string]any); ok {
		return p
	}
	return map[string]any{}
}

func getRequired(schema map[string]any) map[string]struct{} {
	out := map[string]struct{}{}
	switch r := schema["required"].(type) {
	case []any: // decoded from JSON
		for _, v := range r {
			if s, ok := v.(string); ok {
				out[s] = struct{}{}
			}
		}
	case []string: // built in Go
		for _, s := range r {
			out[s] = struct{}{}
		}
	}
	return out
}

func fieldType(field any) string {
	if m, ok := field.(map[string]any); ok {
		if t, ok := m["type"].(string); ok {
			return t
		}
	}
	return ""
}

func typesCompatible(a, b string) bool {
	numeric := map[string]bool{"number": true, "integer": true}
	return numeric[a] && numeric[b]
}

// SchemaHash returns the SHA-256 hex of the canonical schema — used as cache key.
func SchemaHash(schema map[string]any) string {
	// Same bytes as @aroha-orchestrator schemaHash (JSON.stringify of the
	// key-sorted schema), i.e. RFC 8785 JCS; fall back for values JCS rejects.
	b, err := jcs.Canonicalize(schema)
	if err != nil {
		b, _ = json.Marshal(sortedMap(schema))
	}
	h := sha256.Sum256(b)
	return fmt.Sprintf("%x", h)
}

func sortedMap(v any) any {
	switch t := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		out := make(map[string]any, len(t))
		for _, k := range keys {
			out[k] = sortedMap(t[k])
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, item := range t {
			out[i] = sortedMap(item)
		}
		return out
	default:
		return v
	}
}

// ── Capability registry ───────────────────────────────────────────────────────

const confidentThreshold = 0.85

// CapabilityEntry describes a single registered capability.
type CapabilityEntry struct {
	Name           string
	Description    string
	InputSchema    map[string]any
	OutputSchema   map[string]any
	SupportsSaga   bool
	DefaultPricing map[string]any
	DefaultSLA     map[string]any
}

// CapabilityMatch is a scored match result.
type CapabilityMatch struct {
	Entry     *CapabilityEntry
	Score     float64
	Confident bool
}

// CapabilityRegistry holds the provider's registered capabilities.
type CapabilityRegistry struct {
	caps map[string]*CapabilityEntry
}

// NewCapabilityRegistry creates an empty registry.
func NewCapabilityRegistry() *CapabilityRegistry {
	return &CapabilityRegistry{caps: map[string]*CapabilityEntry{}}
}

// Register adds a capability to the registry.
func (r *CapabilityRegistry) Register(e *CapabilityEntry) {
	r.caps[e.Name] = e
}

// Get returns a capability by name.
func (r *CapabilityRegistry) Get(name string) *CapabilityEntry {
	return r.caps[name]
}

// List returns all registered capabilities.
func (r *CapabilityRegistry) List() []*CapabilityEntry {
	out := make([]*CapabilityEntry, 0, len(r.caps))
	for _, e := range r.caps {
		out = append(out, e)
	}
	return out
}

// FindByInputSchema returns the best-matching capability for a desired schema.
func (r *CapabilityRegistry) FindByInputSchema(desired map[string]any) *CapabilityMatch {
	var best *CapabilityMatch
	for _, e := range r.caps {
		score := SchemaCompatibilityScore(desired, e.InputSchema)
		if best == nil || score > best.Score {
			m := &CapabilityMatch{Entry: e, Score: score, Confident: score >= confidentThreshold}
			best = m
		}
	}
	return best
}

// FindCandidates returns all capabilities above minScore, sorted descending.
func (r *CapabilityRegistry) FindCandidates(desired map[string]any, minScore float64) []CapabilityMatch {
	var results []CapabilityMatch
	for _, e := range r.caps {
		score := SchemaCompatibilityScore(desired, e.InputSchema)
		if score >= minScore {
			results = append(results, CapabilityMatch{Entry: e, Score: score, Confident: score >= confidentThreshold})
		}
	}
	sort.Slice(results, func(i, j int) bool { return results[i].Score > results[j].Score })
	return results
}

// ── Discovery cache ───────────────────────────────────────────────────────────

// CacheEntry stores a resolved schema → capability mapping.
type CacheEntry struct {
	CapabilityName     string
	AgreedSchema       map[string]any
	MatchMethod        string
	CompatibilityScore float64
	CachedAt           time.Time
	HitCount           int
}

// DiscoveryCache is a SHA-256 content-addressed in-memory cache.
type DiscoveryCache struct {
	store map[string]*CacheEntry
}

// NewDiscoveryCache creates an empty cache.
func NewDiscoveryCache() *DiscoveryCache {
	return &DiscoveryCache{store: map[string]*CacheEntry{}}
}

func (c *DiscoveryCache) key(agentDID, hash string) string {
	return agentDID + ":" + hash
}

// Get returns a cache entry or nil.
func (c *DiscoveryCache) Get(agentDID, hash string) *CacheEntry {
	e := c.store[c.key(agentDID, hash)]
	if e != nil {
		e.HitCount++
	}
	return e
}

// Put stores a resolved mapping.
func (c *DiscoveryCache) Put(agentDID, hash, capabilityName string, agreedSchema map[string]any, matchMethod string, score float64) {
	c.store[c.key(agentDID, hash)] = &CacheEntry{
		CapabilityName:     capabilityName,
		AgreedSchema:       agreedSchema,
		MatchMethod:        matchMethod,
		CompatibilityScore: score,
		CachedAt:           time.Now(),
	}
}

// Invalidate removes cache entries for an agent (optionally for a specific capability).
func (c *DiscoveryCache) Invalidate(agentDID, capabilityName string) {
	prefix := agentDID + ":"
	for k, e := range c.store {
		if strings.HasPrefix(k, prefix) {
			if capabilityName == "" || e.CapabilityName == capabilityName {
				delete(c.store, k)
			}
		}
	}
}

// ── LLM matcher interface ─────────────────────────────────────────────────────

// LLMCandidate is passed to an ICapabilityMatcher.
type LLMCandidate struct {
	Name        string
	Description string
	InputSchema map[string]any
}

// ICapabilityMatcher is the optional LLM adapter for intent-based fallback.
type ICapabilityMatcher interface {
	Match(ctx context.Context, intent string, candidates []LLMCandidate) (string, error)
}

// ── Request / result types ────────────────────────────────────────────────────

// DiscoveryRequest is passed to CapabilityNegotiator.Discover.
type DiscoveryRequest struct {
	CapabilityIntent          string
	DesiredSchema             map[string]any // {input: {...}, output?: {...}}
	ProposedTerms             map[string]any
	RequestCapabilityManifest bool
}

// DiscoveryResult is returned by CapabilityNegotiator.Discover.
type DiscoveryResult struct {
	ResolvedCapability string
	AgreedSchema       map[string]any
	AgreedTerms        map[string]any
	MatchMethod        string
	CompatibilityScore float64
	CapabilityManifest map[string]any
	Rounds             int
}

// ── Requestor: CapabilityNegotiator ──────────────────────────────────────────

// SendFn is the async transport function passed to CapabilityNegotiator.
type SendFn func(ctx context.Context, endpoint string, envelope map[string]any) (map[string]any, error)

// BuildEnvelopeFn builds a signed Aroha envelope.
type BuildEnvelopeFn func(msgType, from, to string, body map[string]any, correlationID string, privateKey []byte) (map[string]any, error)

// CapabilityNegotiator implements the requestor side of CSN.
type CapabilityNegotiator struct {
	send            SendFn
	buildEnvelope   BuildEnvelopeFn
	orchestratorDID string
	privateKey      []byte
	cache           *DiscoveryCache
}

// NewCapabilityNegotiator creates a requestor-side negotiator.
func NewCapabilityNegotiator(
	send SendFn,
	buildEnvelope BuildEnvelopeFn,
	orchestratorDID string,
	privateKey []byte,
	cache *DiscoveryCache,
) *CapabilityNegotiator {
	if cache == nil {
		cache = NewDiscoveryCache()
	}
	return &CapabilityNegotiator{
		send:            send,
		buildEnvelope:   buildEnvelope,
		orchestratorDID: orchestratorDID,
		privateKey:      privateKey,
		cache:           cache,
	}
}

// Discover resolves a capability with a remote provider agent.
func (n *CapabilityNegotiator) Discover(
	ctx context.Context,
	agentEndpoint, agentDID string,
	req *DiscoveryRequest,
) (*DiscoveryResult, error) {
	var h string
	if req.DesiredSchema != nil {
		h = SchemaHash(req.DesiredSchema)
	}

	// ── 1. Cache lookup ───────────────────────────────────────────────────────
	if h != "" {
		if cached := n.cache.Get(agentDID, h); cached != nil {
			return &DiscoveryResult{
				ResolvedCapability: cached.CapabilityName,
				AgreedSchema:       cached.AgreedSchema,
				AgreedTerms:        map[string]any{},
				MatchMethod:        "cache",
				CompatibilityScore: cached.CompatibilityScore,
				Rounds:             0,
			}, nil
		}
	}

	// ── 2. Send ArohaNegotiate ─────────────────────────────────────────────────
	correlationID := fmt.Sprintf("csn-%d", time.Now().UnixNano())
	capability := req.CapabilityIntent
	if capability == "" {
		capability = "unknown"
	}
	body := map[string]any{
		"capability":    capability,
		"proposedTerms": req.ProposedTerms,
		"csn": map[string]any{
			"capabilityIntent":          req.CapabilityIntent,
			"desiredSchema":             req.DesiredSchema,
			"schemaHash":                h,
			"requestCapabilityManifest": req.RequestCapabilityManifest,
		},
	}
	envelope, err := n.buildEnvelope("ArohaNegotiate", n.orchestratorDID, agentDID, body, correlationID, n.privateKey)
	if err != nil {
		return nil, err
	}
	response, err := n.send(ctx, agentEndpoint, envelope)
	if err != nil {
		return nil, err
	}
	if response == nil {
		return nil, fmt.Errorf("no response from %s during CSN discovery", agentDID)
	}

	msgType, _ := response["type"].(string)
	respBody, _ := response["body"].(map[string]any)

	if msgType == "ArohaError" {
		msg, _ := respBody["message"].(string)
		return nil, fmt.Errorf("CSN failed: %s", msg)
	}

	// ── 3. ArohaAccept ─────────────────────────────────────────────────────────
	if msgType == "ArohaAccept" {
		csn, _ := respBody["csn"].(map[string]any)
		resolved := strVal(csn, "resolvedCapability", strVal(respBody, "capability", ""))
		method := strVal(csn, "matchMethod", "schema")
		compat, _ := csn["compatibilityScore"].(float64)
		agreedSch, _ := csn["agreedSchema"].(map[string]any)
		if agreedSch == nil {
			agreedSch = req.DesiredSchema
		}
		if h != "" && agreedSch != nil {
			n.cache.Put(agentDID, h, resolved, agreedSch, method, compat)
		}
		manifest, _ := csn["capabilityManifest"].(map[string]any)
		terms, _ := respBody["acceptedTerms"].(map[string]any)
		return &DiscoveryResult{
			ResolvedCapability: resolved,
			AgreedSchema:       agreedSch,
			AgreedTerms:        terms,
			MatchMethod:        method,
			CompatibilityScore: compat,
			CapabilityManifest: manifest,
			Rounds:             1,
		}, nil
	}

	// ── 4. Counter-offer ──────────────────────────────────────────────────────
	if msgType == "ArohaCounterOffer" {
		csn, _ := respBody["csn"].(map[string]any)
		resolved := strVal(csn, "resolvedCapability", strVal(respBody, "capability", ""))
		if resolved != "" {
			revisedTerms, _ := respBody["revisedTerms"].(map[string]any)
			acceptBody := map[string]any{
				"capability":    resolved,
				"acceptedTerms": revisedTerms,
			}
			acceptEnv, err := n.buildEnvelope("ArohaAccept", n.orchestratorDID, agentDID, acceptBody, correlationID, n.privateKey)
			if err != nil {
				return nil, err
			}
			if _, err := n.send(ctx, agentEndpoint, acceptEnv); err != nil {
				return nil, err
			}
			agreedSch, _ := csn["agreedSchema"].(map[string]any)
			if agreedSch == nil {
				agreedSch = req.DesiredSchema
			}
			if h != "" && agreedSch != nil {
				n.cache.Put(agentDID, h, resolved, agreedSch, "schema", 0)
			}
			manifest, _ := csn["capabilityManifest"].(map[string]any)
			return &DiscoveryResult{
				ResolvedCapability: resolved,
				AgreedSchema:       agreedSch,
				AgreedTerms:        revisedTerms,
				MatchMethod:        "schema",
				CapabilityManifest: manifest,
				Rounds:             2,
			}, nil
		}
	}

	return nil, fmt.Errorf("CSN negotiation with %s did not produce a capability agreement", agentDID)
}

func strVal(m map[string]any, key, fallback string) string {
	if m == nil {
		return fallback
	}
	if v, ok := m[key].(string); ok && v != "" {
		return v
	}
	return fallback
}

// ── Provider: CSNHandler ──────────────────────────────────────────────────────

// CSNHandler implements the provider side of CSN.
type CSNHandler struct {
	registry      *CapabilityRegistry
	agentDID      string
	privateKey    []byte
	buildEnvelope BuildEnvelopeFn
	llmMatcher    ICapabilityMatcher
	serveManifest bool
}

// NewCSNHandler creates a provider-side CSN handler.
func NewCSNHandler(
	registry *CapabilityRegistry,
	agentDID string,
	privateKey []byte,
	buildEnvelope BuildEnvelopeFn,
	llmMatcher ICapabilityMatcher,
) *CSNHandler {
	return &CSNHandler{
		registry:      registry,
		agentDID:      agentDID,
		privateKey:    privateKey,
		buildEnvelope: buildEnvelope,
		llmMatcher:    llmMatcher,
		serveManifest: true,
	}
}

// Handle processes an inbound ArohaNegotiate envelope and returns a reply.
func (h *CSNHandler) Handle(ctx context.Context, inbound map[string]any, senderDID string) (map[string]any, error) {
	body, _ := inbound["body"].(map[string]any)
	csn, _ := body["csn"].(map[string]any)
	corrID, _ := inbound["correlationId"].(string)

	matchMethod := "schema"
	var matched *struct {
		Name  string
		Score float64
	}

	// ── 1. Structural schema matching ─────────────────────────────────────────
	desiredSchema, _ := csn["desiredSchema"].(map[string]any)
	var desiredInput map[string]any
	if desiredSchema != nil {
		desiredInput, _ = desiredSchema["input"].(map[string]any)
	}
	if desiredInput != nil {
		result := h.registry.FindByInputSchema(desiredInput)
		if result != nil && result.Score >= 0.5 {
			matched = &struct {
				Name  string
				Score float64
			}{result.Entry.Name, result.Score}
			matchMethod = "schema"
		}
	}

	// ── 2. LLM fallback (ambiguous range) ─────────────────────────────────────
	intent, _ := csn["capabilityIntent"].(string)
	if (matched == nil || matched.Score < 0.85) && intent != "" && h.llmMatcher != nil {
		schema := desiredInput
		if schema == nil {
			schema = map[string]any{}
		}
		rawCandidates := h.registry.FindCandidates(schema, 0.0)
		candidates := make([]LLMCandidate, len(rawCandidates))
		for i, c := range rawCandidates {
			candidates[i] = LLMCandidate{
				Name:        c.Entry.Name,
				Description: c.Entry.Description,
				InputSchema: c.Entry.InputSchema,
			}
		}
		if len(candidates) > 0 {
			llmName, err := h.llmMatcher.Match(ctx, intent, candidates)
			if err == nil && llmName != "" && h.registry.Get(llmName) != nil {
				matched = &struct {
					Name  string
					Score float64
				}{llmName, 0.75}
				matchMethod = "intent"
			}
		}
	}

	// ── 3. Direct name lookup ─────────────────────────────────────────────────
	capName, _ := body["capability"].(string)
	if matched == nil && capName != "" && capName != "unknown" {
		if e := h.registry.Get(capName); e != nil {
			matched = &struct {
				Name  string
				Score float64
			}{e.Name, 1.0}
			matchMethod = "schema"
		}
	}

	// ── No match → ArohaError ──────────────────────────────────────────────────
	if matched == nil {
		return h.buildEnvelope("ArohaError", h.agentDID, senderDID, map[string]any{
			"code":      "Aroha_UNKNOWN_CAPABILITY",
			"message":   "No capability matched the provided intent or schema",
			"retryable": false,
		}, corrID, h.privateKey)
	}

	entry := h.registry.Get(matched.Name)

	// ── 4. Agreed schema ──────────────────────────────────────────────────────
	agreedSchema := map[string]any{"input": entry.InputSchema}
	if entry.OutputSchema != nil {
		agreedSchema["output"] = entry.OutputSchema
	}

	// ── 5. Manifest if requested ──────────────────────────────────────────────
	var manifest map[string]any
	if reqManifest, _ := csn["requestCapabilityManifest"].(bool); reqManifest && h.serveManifest {
		manifest = h.buildManifest()
	}

	// ── 6. Terms ──────────────────────────────────────────────────────────────
	acceptedTerms := map[string]any{}
	if entry.DefaultPricing != nil {
		acceptedTerms["price"] = entry.DefaultPricing
	}
	if entry.DefaultSLA != nil {
		acceptedTerms["sla"] = entry.DefaultSLA
	}
	if proposed, ok := body["proposedTerms"].(map[string]any); ok {
		for k, v := range proposed {
			acceptedTerms[k] = v
		}
	}

	schemaHash, _ := csn["schemaHash"].(string)
	acceptBody := map[string]any{
		"capability":    matched.Name,
		"acceptedTerms": acceptedTerms,
		"csn": map[string]any{
			"resolvedCapability": matched.Name,
			"agreedSchema":       agreedSchema,
			"schemaHash":         schemaHash,
			"matchMethod":        matchMethod,
			"compatibilityScore": matched.Score,
			"capabilityManifest": manifest,
		},
	}
	return h.buildEnvelope("ArohaAccept", h.agentDID, senderDID, acceptBody, corrID, h.privateKey)
}

func (h *CSNHandler) buildManifest() map[string]any {
	caps := make([]map[string]any, 0, len(h.registry.caps))
	for _, e := range h.registry.caps {
		caps = append(caps, map[string]any{
			"name":         e.Name,
			"description":  e.Description,
			"inputSchema":  e.InputSchema,
			"outputSchema": e.OutputSchema,
			"supportsSaga": e.SupportsSaga,
		})
	}
	return map[string]any{
		"agentDID":     h.agentDID,
		"capabilities": caps,
		"generatedAt":  time.Now().UTC().Format(time.RFC3339),
	}
}
