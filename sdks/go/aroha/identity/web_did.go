// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

// did:aroha-web: — DNS-anchored web identity. A port of aroha-core
// identity/web-did.ts (generateWebAgent, rotateKey, resolveWebDID).
//
// Two channels must agree before a key is accepted:
//
//	HTTPS   — GET https://{domain}/.well-known/aroha/agents/{path}/did.json
//	DNS TXT — _aroha.{domain} IN TXT "v=aroha1; path={path}; keyhash={sha256hex(pubkey)}"
//
// The document uses the TypeScript wire shape: verificationMethod[] with
// base58btc publicKeyMultibase and arohaWeb.{domain, path,
// keyCommitmentHash, keyHistory}, keyHistory newest first. Rotation records
// are the TypeScript KeyRotationRecord: v2 signs the JCS of {did,
// newKeyHash, predecessorKey, rotatedAt, trustAfter, v: 2}; legacy v1 signs
// predecessorKey + newKeyHash + rotatedAt.

package identity

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/ArohaLabs/aroha-protocol/sdks/go/aroha/jcs"
)

// MaxWebDIDDocumentBytes is the default cap on a DID document's size (64 KiB).
const MaxWebDIDDocumentBytes = 64 * 1024

// WebDIDPathPattern is the path grammar: lowercase [a-z0-9-] segments, "/"-separated.
var WebDIDPathPattern = regexp.MustCompile(`^[a-z0-9-]+(/[a-z0-9-]+)*$`)

var (
	webLabel = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
	webIPv4  = regexp.MustCompile(`^\d{1,3}(?:\.\d{1,3}){3}$`)
	allDigit = regexp.MustCompile(`^\d+$`)
)

const webDIDPrefix = "did:aroha-web:"

// ErrWebDID wraps every did:aroha-web validation or resolution failure.
var ErrWebDID = errors.New("did:aroha-web")

func webErr(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrWebDID, fmt.Sprintf(format, args...))
}

// WebDIDParseOptions controls DID parsing.
type WebDIDParseOptions struct {
	// AllowIPLiteral accepts an IPv4 literal as the domain. Off by default: an
	// IP literal has no DNS name to anchor the key commitment, and it turns
	// the resolver into a fetcher of arbitrary internal addresses.
	AllowIPLiteral bool
}

// AssertWebDIDDomain returns an error unless domain is a DNS hostname (or,
// opted in, an IPv4 literal).
func AssertWebDIDDomain(domain string, opts WebDIDParseOptions) error {
	d := strings.ToLower(domain)
	if len(d) == 0 || len(d) > 253 {
		return webErr("domain has an invalid length: %s", domain)
	}
	if webIPv4.MatchString(d) {
		if opts.AllowIPLiteral {
			ok := true
			for _, o := range strings.Split(d, ".") {
				if n, _ := strconv.Atoi(o); n > 255 {
					ok = false
				}
			}
			if ok {
				return nil
			}
		}
		return webErr("domain must be a hostname, not an IP literal: %s", domain)
	}
	labels := strings.Split(d, ".")
	for _, l := range labels {
		if !webLabel.MatchString(l) {
			return webErr("domain is not a valid hostname: %s", domain)
		}
	}
	if allDigit.MatchString(labels[len(labels)-1]) {
		return webErr("domain is not a valid hostname: %s", domain)
	}
	return nil
}

// ParseWebDID splits did:aroha-web:domain[:path] (path defaults to "agent")
// and validates both parts.
func ParseWebDID(did string, opts WebDIDParseOptions) (domain, path string, err error) {
	if !strings.HasPrefix(did, webDIDPrefix) {
		return "", "", webErr("not a did:aroha-web: identifier: %s", did)
	}
	rest := did[len(webDIDPrefix):]
	if i := strings.Index(rest, ":"); i == -1 {
		domain, path = rest, "agent"
	} else {
		domain, path = rest[:i], strings.ReplaceAll(rest[i+1:], ":", "/")
	}
	if err := AssertWebDIDDomain(domain, opts); err != nil {
		return "", "", err
	}
	if !WebDIDPathPattern.MatchString(path) {
		return "", "", webErr("path must match %s: %s", WebDIDPathPattern, path)
	}
	return domain, path, nil
}

// BuildWebDID returns did:aroha-web:{domain}:{path with "/" as ":"}.
func BuildWebDID(domain, path string) string {
	return webDIDPrefix + domain + ":" + strings.ReplaceAll(path, "/", ":")
}

// IsWebDID reports whether did uses the did:aroha-web method.
func IsWebDID(did string) bool { return strings.HasPrefix(did, webDIDPrefix) }

// WellKnownPath is /.well-known/aroha/agents/{path}/did.json.
func WellKnownPath(did string) (string, error) {
	_, path, err := ParseWebDID(did, WebDIDParseOptions{})
	if err != nil {
		return "", err
	}
	return "/.well-known/aroha/agents/" + path + "/did.json", nil
}

// WellKnownURL is the https URL the DID document is served at.
func WellKnownURL(did string, opts WebDIDParseOptions) (string, error) {
	domain, path, err := ParseWebDID(did, opts)
	if err != nil {
		return "", err
	}
	return "https://" + domain + "/.well-known/aroha/agents/" + path + "/did.json", nil
}

// KeyCommitmentHash is the lowercase hex SHA-256 of a raw public key.
func KeyCommitmentHash(publicKey []byte) string {
	h := sha256.Sum256(publicKey)
	return hex.EncodeToString(h[:])
}

// DNSTXTValue is the TXT value to publish at _aroha.{domain}.
func DNSTXTValue(did string, publicKey []byte) (string, error) {
	_, path, err := ParseWebDID(did, WebDIDParseOptions{})
	if err != nil {
		return "", err
	}
	return "v=aroha1; path=" + path + "; keyhash=" + KeyCommitmentHash(publicKey), nil
}

// ParseDNSTXT extracts path and keyhash from an aroha1 TXT value.
func ParseDNSTXT(txt string) (path, keyhash string, ok bool) {
	if !strings.Contains(txt, "v=aroha1") {
		return "", "", false
	}
	fields := map[string]string{}
	for _, part := range strings.Split(txt, ";") {
		eq := strings.Index(part, "=")
		if eq == -1 {
			continue
		}
		fields[strings.TrimSpace(part[:eq])] = strings.TrimSpace(part[eq+1:])
	}
	if fields["path"] == "" || fields["keyhash"] == "" {
		return "", "", false
	}
	return fields["path"], fields["keyhash"], true
}

// ── Rotation records ──────────────────────────────────────────────────────────

// RotationSigningPayload is the exact bytes a rotation record's
// predecessorSignature covers (port of rotationSigningPayload).
func RotationSigningPayload(record map[string]any) ([]byte, error) {
	if isNumber(record["v"], 2) {
		did, _ := record["did"].(string)
		if did == "" {
			return nil, webErr("v2 key rotation record is missing its did")
		}
		return jcs.Canonicalize(map[string]any{
			"did":            did,
			"newKeyHash":     record["newKeyHash"],
			"predecessorKey": record["predecessorKey"],
			"rotatedAt":      record["rotatedAt"],
			"trustAfter":     record["trustAfter"],
			"v":              2,
		})
	}
	return []byte(jsString(record["predecessorKey"]) + jsString(record["newKeyHash"]) + jsString(record["rotatedAt"])), nil
}

// jsString renders a value the way JavaScript string concatenation would
// for the cases a rotation record can hold (strings, missing fields).
func jsString(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case nil:
		return "undefined"
	default:
		b, _ := json.Marshal(x)
		return string(b)
	}
}

// BuildRotationRecord returns a signed v2 rotation record.
func BuildRotationRecord(did string, oldPrivateKey ed25519.PrivateKey, newPublicKey []byte, now time.Time, coolDown time.Duration) (map[string]any, error) {
	rec := map[string]any{
		"v":                    2,
		"did":                  did,
		"rotatedAt":            isoMs(now),
		"trustAfter":           isoMs(now.Add(coolDown)),
		"predecessorKey":       ToMultibase(oldPrivateKey.Public().(ed25519.PublicKey)),
		"newKeyHash":           KeyCommitmentHash(newPublicKey),
		"predecessorSignature": "",
	}
	// Normalise to the JSON data model (v as float64) before signing.
	norm, err := toJSONMap(rec)
	if err != nil {
		return nil, err
	}
	payload, err := RotationSigningPayload(norm)
	if err != nil {
		return nil, err
	}
	norm["predecessorSignature"] = base64.RawURLEncoding.EncodeToString(ed25519.Sign(oldPrivateKey, payload))
	return norm, nil
}

// CheckKeyRotation verifies a rotation record (port of checkKeyRotation).
// deprecated is true for a legacy v1 (not DID-bound) record.
func CheckKeyRotation(rotation map[string]any, expectedDID string) (valid, deprecated bool, reason string) {
	v, hasV := rotation["v"]
	deprecated = !isNumber(v, 2)
	if hasV && v != nil && !isNumber(v, 2) {
		return false, deprecated, fmt.Sprintf("has unsupported version %v", v)
	}
	if isNumber(v, 2) && expectedDID != "" && rotation["did"] != expectedDID {
		return false, deprecated, fmt.Sprintf("was signed for %v, not %s", rotation["did"], expectedDID)
	}
	pk, _ := rotation["predecessorKey"].(string)
	pub, err := FromMultibase(pk)
	sigStr, _ := rotation["predecessorSignature"].(string)
	sig, serr := base64.RawURLEncoding.DecodeString(strings.TrimRight(sigStr, "="))
	payload, perr := RotationSigningPayload(rotation)
	if err != nil || serr != nil || perr != nil || len(pub) != ed25519.PublicKeySize ||
		!ed25519.Verify(ed25519.PublicKey(pub), payload, sig) {
		return false, deprecated, "has invalid predecessor signature"
	}
	return true, deprecated, ""
}

// VerifyKeyRotation reports whether a rotation record verifies; for a v2
// record with expectedDID set, it must also be signed for that DID.
func VerifyKeyRotation(rotation map[string]any, expectedDID string) bool {
	ok, _, _ := CheckKeyRotation(rotation, expectedDID)
	return ok
}

// ── Generate / rotate ─────────────────────────────────────────────────────────

// WebAgentKeyPair is a did:aroha-web identity: serve Document at
// WellKnownURL and publish DNSTXTRecord at _aroha.{domain}.
type WebAgentKeyPair struct {
	DID          string
	PrivateKey   ed25519.PrivateKey
	PublicKey    ed25519.PublicKey
	Document     map[string]any
	DNSTXTRecord string
	WellKnownURL string
}

// GenerateWebAgent creates a new did:aroha-web identity with the TypeScript
// document shape. endpoint defaults to https://{domain}/aroha/v1.
func GenerateWebAgent(domain, path, endpoint string) (*WebAgentKeyPair, error) {
	did := BuildWebDID(domain, path)
	if _, _, err := ParseWebDID(did, WebDIDParseOptions{}); err != nil {
		return nil, err
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	if endpoint == "" {
		endpoint = "https://" + domain + "/aroha/v1"
	}
	keyID := did + "#key-1"
	now := isoMs(time.Now())
	doc, err := toJSONMap(map[string]any{
		"@context": []any{
			"https://www.w3.org/ns/did/v1",
			"https://w3id.org/security/suites/ed25519-2020/v1",
			"https://aroha-labs.com/contexts/aroha-web/v1",
		},
		"id": did,
		"verificationMethod": []any{map[string]any{
			"id": keyID, "type": "Ed25519VerificationKey2020", "controller": did, "publicKeyMultibase": ToMultibase(pub),
		}},
		"authentication":  []any{keyID},
		"assertionMethod": []any{keyID},
		"keyAgreement":    []any{keyID},
		"service": []any{map[string]any{
			"id": did + "#aroha", "type": "ArohaEndpoint", "serviceEndpoint": endpoint,
		}},
		"created": now,
		"updated": now,
		"arohaWeb": map[string]any{
			"domain": domain, "path": path, "keyCommitmentHash": KeyCommitmentHash(pub), "keyHistory": []any{},
		},
	})
	if err != nil {
		return nil, err
	}
	txt, _ := DNSTXTValue(did, pub)
	url, _ := WellKnownURL(did, WebDIDParseOptions{})
	return &WebAgentKeyPair{DID: did, PrivateKey: priv, PublicKey: pub, Document: doc, DNSTXTRecord: txt, WellKnownURL: url}, nil
}

// RotateKey replaces the primary key; the old key signs a v2 rotation
// record that is prepended to arohaWeb.keyHistory. coolDown 0 = 24 h.
func RotateKey(current *WebAgentKeyPair, coolDown time.Duration, now time.Time) (*WebAgentKeyPair, error) {
	if coolDown == 0 {
		coolDown = 24 * time.Hour
	}
	if now.IsZero() {
		now = time.Now()
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	doc, err := toJSONMap(current.Document) // deep copy
	if err != nil {
		return nil, err
	}
	web, _ := doc["arohaWeb"].(map[string]any)
	if web == nil {
		return nil, webErr("document has no arohaWeb section")
	}
	domain, _ := web["domain"].(string)
	path, _ := web["path"].(string)
	did := BuildWebDID(domain, path)
	rec, err := BuildRotationRecord(did, current.PrivateKey, pub, now, coolDown)
	if err != nil {
		return nil, err
	}
	vms, _ := doc["verificationMethod"].([]any)
	keyID := did + "#key-1"
	if len(vms) > 0 {
		if m, ok := vms[0].(map[string]any); ok {
			if id, ok := m["id"].(string); ok {
				keyID = id
			}
		}
	}
	newVMs := []any{map[string]any{
		"id": keyID, "type": "Ed25519VerificationKey2020", "controller": did, "publicKeyMultibase": ToMultibase(pub),
	}}
	if len(vms) > 1 {
		newVMs = append(newVMs, vms[1:]...)
	}
	doc["verificationMethod"] = newVMs
	doc["updated"] = isoMs(now)
	hist, _ := web["keyHistory"].([]any)
	web["keyCommitmentHash"] = KeyCommitmentHash(pub)
	web["keyHistory"] = append([]any{rec}, hist...)
	txt, _ := DNSTXTValue(did, pub)
	url, _ := WellKnownURL(did, WebDIDParseOptions{})
	return &WebAgentKeyPair{DID: did, PrivateKey: priv, PublicKey: pub, Document: doc, DNSTXTRecord: txt, WellKnownURL: url}, nil
}

// ── Resolve ───────────────────────────────────────────────────────────────────

// WebDIDAcceptedKey is one key a verifier may accept for the DID right now.
// Role is "current", "predecessor", "anchored" or "additional" (see aroha-core).
type WebDIDAcceptedKey struct {
	VerificationMethodID string
	PublicKeyMultibase   string
	Role                 string
}

// WebDIDResolutionResult is the outcome of ResolveWebDID.
type WebDIDResolutionResult struct {
	Document map[string]any
	// DNSVerified is true only if a DNS TXT commitment matched a key in the
	// verified chain; always false when DNS was not checked.
	DNSVerified bool
	// KeyTrusted: the CURRENT primary key is accepted and past its cool-down.
	KeyTrusted  bool
	TrustReason string
	// AcceptedKeys lists every key a verifier may accept now, newest first.
	// Empty means nothing is accepted (fail closed).
	AcceptedKeys        []WebDIDAcceptedKey
	DeprecatedRotations bool
}

// WebDIDFetcher fetches the DID document; it must not follow redirects and
// must not return more than maxBytes (ResolveWebDID re-checks the size).
type WebDIDFetcher func(url string, timeout time.Duration, maxBytes int64) ([]byte, error)

// ResolveWebDIDOptions configures ResolveWebDID. The zero value checks DNS
// with the system resolver.
type ResolveWebDIDOptions struct {
	// SkipDNS resolves HTTPS-only (logged); DNSVerified is then false.
	SkipDNS bool
	// DNSResolver returns the TXT strings of _aroha.{domain}. Default:
	// net.LookupTXT, unless DisableSystemDNS.
	DNSResolver func(domain string) ([]string, error)
	// DisableSystemDNS requires DNSResolver (tests); with neither,
	// resolution fails unless AllowNoDNS.
	DisableSystemDNS bool
	// AllowNoDNS resolves HTTPS-only when no DNS resolver is available.
	AllowNoDNS     bool
	AllowIPLiteral bool
	// Fetch replaces the HTTPS fetch (tests).
	Fetch WebDIDFetcher
	// FetchTimeout defaults to 10 s; MaxDocumentBytes to 64 KiB.
	FetchTimeout     time.Duration
	MaxDocumentBytes int64
	// Now overrides the clock.
	Now time.Time
	// LegacyMinCoolDownHours floors a v1 record's unsigned cool-down. nil = 24.
	LegacyMinCoolDownHours *float64
	// Logger receives warnings (HTTPS-only mode, v1 records). Default stderr.
	Logger func(string)
}

func defaultWebDIDFetch(url string, timeout time.Duration, maxBytes int64) ([]byte, error) {
	client := &http.Client{
		Timeout: timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return errors.New("redirects are not followed")
		},
	}
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, fmt.Errorf("HTTP %d from %s", resp.StatusCode, url)
	}
	if resp.ContentLength > maxBytes {
		return nil, fmt.Errorf("DID document at %s is too large (%d bytes > %d)", url, resp.ContentLength, maxBytes)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > maxBytes {
		return nil, fmt.Errorf("DID document at %s is too large (> %d bytes)", url, maxBytes)
	}
	return body, nil
}

func systemTXT(domain string) ([]string, error) {
	return net.LookupTXT("_aroha." + domain) // Go joins split TXT strings
}

// ResolveWebDID resolves a did:aroha-web identifier exactly as aroha-core
// resolveWebDID does:
//
//  1. fetch the document over https (no redirects, size cap, timeout); its
//     id must equal did; the primary key is hashed here and must equal
//     arohaWeb.keyCommitmentHash when that field is present;
//  2. verify arohaWeb.keyHistory newest first: each record's predecessor
//     signature (v2 bound to did), record 0 commits to the current key and
//     record i to record i-1's predecessorKey, rotatedAt non-increasing;
//  3. the NEWEST chain key whose hash _aroha.{domain} commits to is the
//     anchor; no anchor → DNSVerified false and no accepted keys;
//  4. accepted keys and KeyTrusted follow the cool-down rules.
func ResolveWebDID(did string, opts ResolveWebDIDOptions) (*WebDIDResolutionResult, error) {
	logf := opts.Logger
	if logf == nil {
		logf = func(m string) { fmt.Fprintln(os.Stderr, m) }
	}
	now := opts.Now
	if now.IsZero() {
		now = time.Now()
	}
	nowMs := float64(now.UnixMilli())
	parseOpts := WebDIDParseOptions{AllowIPLiteral: opts.AllowIPLiteral}
	url, err := WellKnownURL(did, parseOpts)
	if err != nil {
		return nil, err
	}
	timeout := opts.FetchTimeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	maxBytes := opts.MaxDocumentBytes
	if maxBytes <= 0 {
		maxBytes = MaxWebDIDDocumentBytes
	}

	// ── Step 1: fetch ─────────────────────────────────────────────────────────
	fetch := opts.Fetch
	if fetch == nil {
		fetch = defaultWebDIDFetch
	}
	body, err := fetch(url, timeout, maxBytes)
	if err != nil {
		return nil, webErr("failed to resolve %s: %v", did, err)
	}
	if int64(len(body)) > maxBytes {
		return nil, webErr("DID document at %s is too large (> %d bytes)", url, maxBytes)
	}
	var parsed any
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil, webErr("failed to resolve %s: document at %s is not JSON", did, url)
	}
	doc, ok := parsed.(map[string]any)
	if !ok {
		return nil, webErr("failed to resolve %s: document at %s is not an object", did, url)
	}
	if doc["id"] != did {
		return nil, webErr("DID mismatch: document claims %v, expected %s", doc["id"], did)
	}
	vms, _ := doc["verificationMethod"].([]any)
	if len(vms) == 0 {
		return nil, webErr("DID %s: document has no verification methods", did)
	}
	primary, ok := vms[0].(map[string]any)
	if !ok {
		return nil, webErr("DID %s: document has no verification methods", did)
	}
	currentKey, _ := primary["publicKeyMultibase"].(string)
	currentRaw, err := FromMultibase(currentKey)
	if err != nil {
		return nil, webErr("DID %s: primary key is not a base58btc multibase key", did)
	}
	web, _ := doc["arohaWeb"].(map[string]any)
	if declared, present := web["keyCommitmentHash"]; present && declared != nil && declared != KeyCommitmentHash(currentRaw) {
		return nil, webErr("DID %s: arohaWeb.keyCommitmentHash does not match the primary key", did)
	}

	// ── Step 2: rotation chain ────────────────────────────────────────────────
	var history []map[string]any
	if raw, present := web["keyHistory"]; present && raw != nil {
		list, ok := raw.([]any)
		if !ok {
			return nil, webErr("DID %s: arohaWeb.keyHistory is malformed", did)
		}
		for _, r := range list {
			m, ok := r.(map[string]any)
			if !ok {
				return nil, webErr("DID %s: arohaWeb.keyHistory is malformed", did)
			}
			history = append(history, m)
		}
	}
	deprecated := false
	for i, r := range history {
		valid, dep, reason := CheckKeyRotation(r, did)
		if !valid {
			return nil, webErr("DID %s: key rotation record (rotatedAt %v) %s", did, r["rotatedAt"], reason)
		}
		deprecated = deprecated || dep
		successor := currentKey
		if i > 0 {
			successor, _ = history[i-1]["predecessorKey"].(string)
		}
		sRaw, serr := FromMultibase(successor)
		if serr != nil || r["newKeyHash"] != KeyCommitmentHash(sRaw) {
			if i == 0 {
				return nil, webErr("DID %s: keyHistory[0] does not commit to the current primary key", did)
			}
			return nil, webErr("DID %s: keyHistory[%d] does not commit to keyHistory[%d].predecessorKey — the rotation chain is broken", did, i, i-1)
		}
		if i > 0 && dateMs(r["rotatedAt"]) > dateMs(history[i-1]["rotatedAt"]) {
			return nil, webErr("DID %s: keyHistory is not newest-first at index %d", did, i)
		}
	}
	if deprecated {
		logf(fmt.Sprintf("[aroha] %s: keyHistory contains legacy v1 rotation records (not DID-bound); re-rotate to upgrade", did))
	}

	n := len(history)
	chain := make([]string, 0, n+1)
	for i := n - 1; i >= 0; i-- {
		pk, _ := history[i]["predecessorKey"].(string)
		chain = append(chain, pk)
	}
	chain = append(chain, currentKey)
	legacyHours := 24.0
	if opts.LegacyMinCoolDownHours != nil {
		legacyHours = *opts.LegacyMinCoolDownHours
	}
	legacyFloor := legacyHours * 3_600_000
	effectiveTrustAfter := func(r map[string]any) float64 {
		signed := dateMs(r["trustAfter"])
		if isNumber(r["v"], 2) {
			return signed
		}
		if math.IsNaN(signed) {
			signed = 0
		}
		return math.Max(signed, dateMs(r["rotatedAt"])+legacyFloor) // NaN-propagating like Math.max
	}
	introducedBy := func(j int) map[string]any { return history[n-j] }

	// ── Step 3: DNS ───────────────────────────────────────────────────────────
	domain, path, _ := ParseWebDID(did, parseOpts)
	var txt []string
	checked := false
	if !opts.SkipDNS {
		resolver := opts.DNSResolver
		if resolver == nil && !opts.DisableSystemDNS {
			resolver = systemTXT
		}
		if resolver != nil {
			recs, rerr := resolver(domain)
			if rerr != nil {
				recs = nil // lookup failed — no commitment found, fail closed below
			}
			txt, checked = recs, true
		} else if !opts.AllowNoDNS {
			return nil, webErr("cannot verify %s: no DNS resolver available for the _aroha.%s TXT key-commitment; "+
				"pass DNSResolver, or AllowNoDNS for tests/dev only", did, domain)
		}
	}
	if !checked {
		logf(fmt.Sprintf("[aroha] %s: resolved HTTPS-only — DNS key-commitment NOT checked (AllowNoDNS / SkipDNS)", did))
	}

	var accepted []WebDIDAcceptedKey
	primaryID, _ := primary["id"].(string)
	primaryID = absoluteVMID(did, primaryID)
	addAdditional := func(hashes map[string]bool) {
		for _, raw := range vms[1:] {
			vm, ok := raw.(map[string]any)
			if !ok {
				continue
			}
			mb, _ := vm["publicKeyMultibase"].(string)
			id, _ := vm["id"].(string)
			if hashes != nil {
				b, err := FromMultibase(mb)
				if err != nil || !hashes[KeyCommitmentHash(b)] {
					continue
				}
			}
			accepted = append(accepted, WebDIDAcceptedKey{absoluteVMID(did, id), mb, "additional"})
		}
	}
	dnsVerified := false
	anchor := len(chain) - 1
	if !checked {
		addAdditional(nil)
	} else {
		hashes := map[string]bool{}
		for _, t := range txt {
			if p, h, ok := ParseDNSTXT(t); ok && p == path {
				hashes[h] = true
			}
		}
		anchor = -1
		for j := len(chain) - 1; j >= 0; j-- {
			if b, err := FromMultibase(chain[j]); err == nil && hashes[KeyCommitmentHash(b)] {
				anchor = j
				break
			}
		}
		dnsVerified = anchor >= 0
		if dnsVerified {
			addAdditional(hashes)
		}
	}

	// ── Step 4: primary-slot keys accepted now ────────────────────────────────
	keyTrusted := false
	trustReason := ""
	last := len(chain) - 1
	prepend := func(k WebDIDAcceptedKey) { accepted = append([]WebDIDAcceptedKey{k}, accepted...) }
	switch {
	case anchor < 0:
		trustReason = fmt.Sprintf("No DNS TXT key-commitment at _aroha.%s matches any key in the document's rotation chain", domain)
	case anchor == last:
		prepend(WebDIDAcceptedKey{primaryID, currentKey, "current"})
		if n > 0 && nowMs < effectiveTrustAfter(history[0]) {
			pred := WebDIDAcceptedKey{primaryID, chain[last-1], "predecessor"}
			accepted = append(accepted[:1], append([]WebDIDAcceptedKey{pred}, accepted[1:]...)...)
			trustReason = "Key rotation cool-down active until " + msISO(effectiveTrustAfter(history[0]))
		} else {
			keyTrusted = true
		}
	default:
		cur := anchor
		for cur < last && nowMs >= effectiveTrustAfter(introducedBy(cur+1)) {
			cur++
		}
		role := "anchored"
		if cur == last {
			role = "current"
		}
		prepend(WebDIDAcceptedKey{primaryID, chain[cur], role})
		if cur == last {
			keyTrusted = true
		} else {
			trustReason = "DNS commits to an earlier key; the newer key is not trusted until its rotation cool-down ends (" +
				msISO(effectiveTrustAfter(introducedBy(cur+1))) + ") or DNS is updated"
		}
	}
	return &WebDIDResolutionResult{
		Document: doc, DNSVerified: dnsVerified, KeyTrusted: keyTrusted, TrustReason: trustReason,
		AcceptedKeys: accepted, DeprecatedRotations: deprecated,
	}, nil
}

// WebDIDPublicKeys returns the keys that may verify a signature naming
// verificationMethodID ("" = the primary method), newest first.
func WebDIDPublicKeys(r *WebDIDResolutionResult, verificationMethodID string) []ed25519.PublicKey {
	did, _ := r.Document["id"].(string)
	wanted := ""
	if verificationMethodID != "" {
		wanted = absoluteVMID(did, verificationMethodID)
	} else {
		wanted = did + "#key-1"
		if vms, _ := r.Document["verificationMethod"].([]any); len(vms) > 0 {
			if m, ok := vms[0].(map[string]any); ok {
				if id, ok := m["id"].(string); ok {
					wanted = absoluteVMID(did, id)
				}
			}
		}
	}
	var out []ed25519.PublicKey
	for _, k := range r.AcceptedKeys {
		if k.VerificationMethodID == wanted {
			if b, err := FromMultibase(k.PublicKeyMultibase); err == nil {
				out = append(out, ed25519.PublicKey(b))
			}
		}
	}
	return out
}

// SelectWebDIDKey returns the newest accepted key, or an error when none is
// accepted — map that to "unknown sender", never to another key.
func SelectWebDIDKey(r *WebDIDResolutionResult, verificationMethodID string) (ed25519.PublicKey, error) {
	keys := WebDIDPublicKeys(r, verificationMethodID)
	if len(keys) == 0 {
		name := verificationMethodID
		if name == "" {
			name = "the primary verification method"
		}
		msg := fmt.Sprintf("DID %v: no accepted key for %s", r.Document["id"], name)
		if r.TrustReason != "" {
			msg += " (" + r.TrustReason + ")"
		}
		return nil, webErr("%s", msg)
	}
	return keys[0], nil
}

// ── helpers ───────────────────────────────────────────────────────────────────

func absoluteVMID(did, id string) string {
	if strings.HasPrefix(id, "#") {
		return did + id
	}
	return id
}

// dateMs is Date.parse: NaN (comparing false both ways) when unparseable.
func dateMs(v any) float64 {
	s, ok := v.(string)
	if !ok {
		return math.NaN()
	}
	t, err := ParseISOTime(s)
	if err != nil {
		return math.NaN()
	}
	return float64(t.UnixMilli())
}

func msISO(ms float64) string {
	if math.IsNaN(ms) {
		return "Invalid Date"
	}
	return isoMs(time.UnixMilli(int64(ms)))
}

func isoMs(t time.Time) string { return t.UTC().Format("2006-01-02T15:04:05.000Z") }

func toJSONMap(v any) (map[string]any, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	var out map[string]any
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, err
	}
	return out, nil
}
