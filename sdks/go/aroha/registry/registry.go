// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

// Package registry is a client for the Aroha registry HTTP API
// (apps/registry-server): register, discover and resolve agents, and fetch
// Key Event Logs. A port of @aroha-sdk/registry's ArohaHttpRegistry and
// httpKelSource (packages/aroha-registry/src/http-registry.ts).
//
// Endpoints used:
//
//	POST   /v1/agents/challenge          one-time nonce for proof of key possession
//	POST   /v1/agents                    register
//	GET    /v1/agents/:didHash           resolve
//	GET    /v1/agents?capabilities=a,b   discover by capability
//	GET    /v1/agents?limit=&offset=     list
//	PUT    /v1/agents/:didHash/manifest  update the manifest CID
//	DELETE /v1/agents/:didHash           deactivate
//	GET    /v1/kel/:did                  Key Event Log
//
// Registration proves key possession for every DID except a rotatable
// did:aroha:E… (whose key comes from its Key Event Log): the client asks for
// a nonce and signs the UTF-8 bytes of
// {"action":"prove-ownership","did":<did>,"nonce":<nonce>}.
//
// Registry URLs must be https or a loopback host unless AllowInsecureHTTP is
// set: the API key rides every request, and a resolved record decides which
// key an agent is trusted under.
package registry

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/ArohaLabs/aroha-protocol/sdks/go/aroha/identity"
	"github.com/ArohaLabs/aroha-protocol/sdks/go/aroha/jcs"
	"github.com/ArohaLabs/aroha-protocol/sdks/go/aroha/transport"
)

// ManagedRegistryURL is the Aroha-managed registry (@aroha-sdk/core
// AROHA_MANAGED_REGISTRY_URL). Override per process with AROHA_REGISTRY_URL.
const ManagedRegistryURL = "https://aroha-registry.aroha-labs.workers.dev"

// DefaultTimeout bounds each HTTP request when no HTTPClient is supplied.
const DefaultTimeout = 30 * time.Second

// ResolveRegistryURL returns override, else $AROHA_REGISTRY_URL, else
// ManagedRegistryURL, without trailing slashes.
func ResolveRegistryURL(override string) string {
	u := override
	if u == "" {
		u = strings.TrimSpace(os.Getenv("AROHA_REGISTRY_URL"))
	}
	if u == "" {
		u = ManagedRegistryURL
	}
	return strings.TrimRight(u, "/")
}

// HashDID is the registry's agent key: "0x" + hex(keccak256(UTF-8(did))).
func HashDID(did string) string {
	h := keccak256([]byte(did))
	return "0x" + hex.EncodeToString(h[:])
}

// RegistrationChallengeMessage is the exact bytes a registrant signs to prove
// it holds the agent key: JSON.stringify({action: "prove-ownership", did,
// nonce}) — keys in that order, compact, JavaScript string escaping.
func RegistrationChallengeMessage(did, nonce string) []byte {
	// The three keys are already in sorted order, and JCS escapes strings as
	// JSON.stringify does, so JCS of this map is byte-identical.
	b, _ := jcs.Canonicalize(map[string]any{"action": "prove-ownership", "did": did, "nonce": nonce})
	return b
}

// RegistrationNeedsProof reports whether registering did needs a challenge
// proof: every DID except a rotatable did:aroha:E….
func RegistrationNeedsProof(did string) bool { return !identity.IsInceptionDID(did) }

// AgentRecord is a registry record as GET /v1/agents returns it.
type AgentRecord struct {
	DID         string `json:"did"`
	DIDHash     string `json:"didHash"`
	PublishedBy string `json:"publishedBy,omitempty"`
	// OwnerAddress is a placeholder until staking is live.
	OwnerAddress string `json:"ownerAddress"`
	ManifestCID  string `json:"manifestCID"`
	// PublicKeyB64 is the base64url Ed25519 key the registry holds.
	PublicKeyB64     string      `json:"publicKeyB64"`
	StakedWei        json.Number `json:"stakedWei"`
	ReputationScore  float64     `json:"reputationScore"`
	Active           bool        `json:"active"`
	RegisteredAt     int64       `json:"registeredAt"`
	LastUpdatedAt    int64       `json:"lastUpdatedAt"`
	CapabilityIDs    []string    `json:"capabilityIds,omitempty"`
	EndpointURL      string      `json:"endpointUrl,omitempty"`
	KeyVersion       int         `json:"keyVersion,omitempty"`
	KeyRotatedAt     *int64      `json:"keyRotatedAt,omitempty"`
	Verified         bool        `json:"verified,omitempty"`
	VerificationTier string      `json:"verificationTier,omitempty"`
	Domain           string      `json:"domain,omitempty"`
	OrgSigned        bool        `json:"orgSigned,omitempty"`
	Visibility       string      `json:"visibility,omitempty"`
}

// PublicKey decodes PublicKeyB64 (base64url, or standard base64).
func (r *AgentRecord) PublicKey() (ed25519.PublicKey, error) {
	s := strings.TrimRight(r.PublicKeyB64, "=")
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		b, err = base64.RawStdEncoding.DecodeString(s)
	}
	if err != nil || len(b) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("record for %s has no valid 32-byte Ed25519 key", r.DID)
	}
	return b, nil
}

// HTTPError is a non-2xx registry answer.
type HTTPError struct {
	StatusCode int
	Body       string
}

func (e *HTTPError) Error() string {
	return fmt.Sprintf("Aroha Registry HTTP %d: %s", e.StatusCode, e.Body)
}

func isClientError(err error) bool {
	var he *HTTPError
	return errors.As(err, &he) && he.StatusCode >= 400 && he.StatusCode < 500
}

// Options configures a Client.
type Options struct {
	// BaseURL defaults to ResolveRegistryURL("").
	BaseURL string
	// FallbackURLs are tried in order when a registry is unreachable or
	// answers 5xx. A 4xx is a caller error and is never retried elsewhere.
	FallbackURLs []string
	// APIKey is sent as a Bearer token.
	APIKey string
	// AllowInsecureHTTP permits http:// to non-loopback hosts. Development only.
	AllowInsecureHTTP bool
	// HTTPClient defaults to a client with DefaultTimeout.
	HTTPClient *http.Client
}

// Client talks to one registry and its fallbacks.
type Client struct {
	urls   []string
	apiKey string
	http   *http.Client
}

// New validates the registry URLs and returns a Client.
func New(opts Options) (*Client, error) {
	urls := []string{ResolveRegistryURL(opts.BaseURL)}
	for _, u := range opts.FallbackURLs {
		urls = append(urls, strings.TrimRight(u, "/"))
	}
	for _, u := range urls {
		if err := transport.CheckEndpoint(u, opts.AllowInsecureHTTP); err != nil {
			return nil, fmt.Errorf("registry URL: %w", err)
		}
	}
	hc := opts.HTTPClient
	if hc == nil {
		hc = &http.Client{Timeout: DefaultTimeout}
	}
	return &Client{urls: urls, apiKey: opts.APIKey, http: hc}, nil
}

// Signer signs a message with the agent key (for HSM- or KMS-held keys). It
// must return a 64-byte Ed25519 signature.
type Signer func(message []byte) ([]byte, error)

// RegisterOptions configures Register.
type RegisterOptions struct {
	// PrivateKey or Sign proves possession of the agent key. One of them is
	// required for every DID except did:aroha:E….
	PrivateKey ed25519.PrivateKey
	Sign       Signer
	// EndpointURL is where the agent is reachable (http or https).
	EndpointURL string
	// KEL and ControllerKEL (did:aroha:E… only) carry the agent's Key Event
	// Log, and its controller's, if they were not posted to /v1/kel first.
	KEL           []identity.KelEvent
	ControllerKEL []identity.KelEvent
	// Visibility is "public" (default), "unlisted" or "private".
	Visibility string
}

// Register registers did with the manifest at manifestCID and returns the
// registry's didHash. publicKey is the agent key; for a did:aroha:E… it may
// be nil (the registry takes the key from the KEL) and, if given, must be the
// KEL's current key. The challenge is redeemable only at the registry that
// issued it, so each fallback attempt runs the whole exchange.
func (c *Client) Register(ctx context.Context, did, manifestCID string, publicKey ed25519.PublicKey, opts RegisterOptions) (string, error) {
	needsProof := RegistrationNeedsProof(did)
	if needsProof && opts.PrivateKey == nil && opts.Sign == nil {
		return "", fmt.Errorf("registry.Register(%s): a PrivateKey or Sign is required — the registry only registers a DID "+
			"whose key the caller proves it holds (POST /v1/agents/challenge)", did)
	}
	if err := checkRegistrationKey(did, publicKey, opts.PrivateKey, needsProof); err != nil {
		return "", err
	}
	var didHash string
	err := c.withFallback(func(base string) error {
		body := map[string]any{"did": did, "manifestCID": manifestCID}
		if publicKey != nil {
			body["publicKeyB64"] = base64.RawURLEncoding.EncodeToString(publicKey)
		}
		if opts.EndpointURL != "" {
			body["endpointUrl"] = opts.EndpointURL
		}
		if opts.Visibility != "" {
			body["visibility"] = opts.Visibility
		}
		if opts.KEL != nil {
			body["kel"] = opts.KEL
		}
		if opts.ControllerKEL != nil {
			body["controllerKel"] = opts.ControllerKEL
		}
		if needsProof {
			var ch struct {
				Nonce string `json:"nonce"`
			}
			if err := c.do(ctx, http.MethodPost, base, "/v1/agents/challenge", map[string]any{"did": did}, &ch); err != nil {
				return err
			}
			if ch.Nonce == "" {
				return &HTTPError{StatusCode: 502, Body: "registry returned no challenge nonce"}
			}
			sig, err := signChallenge(opts, did, ch.Nonce)
			if err != nil {
				return err
			}
			body["challengeNonce"] = ch.Nonce
			body["challengeSignature"] = base64.RawURLEncoding.EncodeToString(sig)
		}
		var res struct {
			DIDHash string `json:"didHash"`
		}
		if err := c.do(ctx, http.MethodPost, base, "/v1/agents", body, &res); err != nil {
			return err
		}
		didHash = res.DIDHash
		return nil
	})
	if err != nil {
		return "", err
	}
	if didHash == "" {
		didHash = HashDID(did)
	}
	return didHash, nil
}

func signChallenge(opts RegisterOptions, did, nonce string) ([]byte, error) {
	msg := RegistrationChallengeMessage(did, nonce)
	var sig []byte
	if opts.PrivateKey != nil {
		sig = ed25519.Sign(opts.PrivateKey, msg)
	} else {
		var err error
		if sig, err = opts.Sign(msg); err != nil {
			return nil, fmt.Errorf("registration signer: %w", err)
		}
	}
	if len(sig) != ed25519.SignatureSize {
		return nil, errors.New("registration signer must return a 64-byte Ed25519 signature")
	}
	return sig, nil
}

// checkRegistrationKey runs the checks the server also makes, so the caller
// gets a precise error instead of a 400/403 after a round trip.
func checkRegistrationKey(did string, publicKey ed25519.PublicKey, priv ed25519.PrivateKey, needsProof bool) error {
	if publicKey == nil && !needsProof {
		return nil
	}
	if len(publicKey) != ed25519.PublicKeySize {
		return errors.New("publicKey must be a 32-byte Ed25519 public key")
	}
	if identity.IsContentAddressedDID(did) {
		if k := identity.ResolveContentAddressedKey(did); k == nil || !bytes.Equal(k, publicKey) {
			return fmt.Errorf("%s is content-addressed and can only be registered with the key it encodes", did)
		}
	}
	if priv != nil {
		if len(priv) != ed25519.PrivateKeySize || !bytes.Equal(priv.Public().(ed25519.PublicKey), publicKey) {
			return errors.New("registration private key does not match the publicKey being registered")
		}
	}
	return nil
}

// Resolve returns the record for did, or (nil, nil) when the registry has
// none (or will not show it to this caller).
func (c *Client) Resolve(ctx context.Context, did string) (*AgentRecord, error) {
	var rec *AgentRecord
	err := c.withFallback(func(base string) error {
		var r AgentRecord
		err := c.do(ctx, http.MethodGet, base, "/v1/agents/"+HashDID(did), nil, &r)
		var he *HTTPError
		if errors.As(err, &he) && he.StatusCode == http.StatusNotFound {
			rec = nil
			return nil
		}
		if err != nil {
			return err
		}
		rec = &r
		return nil
	})
	if err != nil {
		return nil, err
	}
	if rec != nil && rec.DID != "" && rec.DID != did {
		return nil, fmt.Errorf("registry answered for %s, not %s", rec.DID, did)
	}
	return rec, nil
}

// Discover returns the agents the registry lists for every one of the
// capability IDs (the server's capability index is built from each agent's
// CID-verified manifest, never from what the registrant claimed).
func (c *Client) Discover(ctx context.Context, capabilityIDs []string) ([]AgentRecord, error) {
	parts := make([]string, len(capabilityIDs))
	for i, id := range capabilityIDs {
		parts[i] = encodeURIComponent(id)
	}
	return c.list(ctx, "/v1/agents?capabilities="+strings.Join(parts, ","))
}

// List pages through the registry's public listing (and, with an API key,
// the caller's own and granted agents). limit 0 uses the server default.
func (c *Client) List(ctx context.Context, limit, offset int) ([]AgentRecord, error) {
	q := []string{}
	if limit > 0 {
		q = append(q, "limit="+strconv.Itoa(limit))
	}
	if offset > 0 {
		q = append(q, "offset="+strconv.Itoa(offset))
	}
	path := "/v1/agents"
	if len(q) > 0 {
		path += "?" + strings.Join(q, "&")
	}
	return c.list(ctx, path)
}

func (c *Client) list(ctx context.Context, path string) ([]AgentRecord, error) {
	var out []AgentRecord
	err := c.withFallback(func(base string) error {
		var raw json.RawMessage
		if err := c.do(ctx, http.MethodGet, base, path, nil, &raw); err != nil {
			return err
		}
		out = nil
		if err := json.Unmarshal(raw, &out); err == nil {
			return nil
		}
		// Some deployments wrap the list: {"agents": [...]}.
		var wrapped struct {
			Agents []AgentRecord `json:"agents"`
		}
		if err := json.Unmarshal(raw, &wrapped); err != nil {
			return fmt.Errorf("registry returned an unreadable agent list: %w", err)
		}
		out = wrapped.Agents
		return nil
	})
	return out, err
}

// UpdateManifest points did at a new manifest CID (owner API key only).
func (c *Client) UpdateManifest(ctx context.Context, did, manifestCID string) error {
	return c.withFallback(func(base string) error {
		return c.do(ctx, http.MethodPut, base, "/v1/agents/"+HashDID(did)+"/manifest", map[string]any{"manifestCID": manifestCID}, nil)
	})
}

// Deactivate deactivates did (owner API key only).
func (c *Client) Deactivate(ctx context.Context, did string) error {
	return c.withFallback(func(base string) error {
		return c.do(ctx, http.MethodDelete, base, "/v1/agents/"+HashDID(did), nil, nil)
	})
}

// withFallback tries each registry in order, moving on after a network
// error or a 5xx and stopping at the first success or 4xx.
func (c *Client) withFallback(fn func(base string) error) error {
	var last error
	for _, base := range c.urls {
		err := fn(base)
		if err == nil {
			return nil
		}
		if isClientError(err) || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return err
		}
		last = err
	}
	return last
}

func (c *Client) do(ctx context.Context, method, base, path string, body, out any) error {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, base+path, rd)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.apiKey)
	}
	res, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	data, err := io.ReadAll(io.LimitReader(res.Body, 16<<20))
	if err != nil {
		return err
	}
	if res.StatusCode < 200 || res.StatusCode > 299 {
		return &HTTPError{StatusCode: res.StatusCode, Body: string(data)}
	}
	if out == nil || len(bytes.TrimSpace(data)) == 0 {
		return nil
	}
	if err := json.Unmarshal(data, out); err != nil {
		return fmt.Errorf("registry returned malformed JSON for %s %s: %w", method, path, err)
	}
	return nil
}

// encodeURIComponent escapes s as JavaScript's encodeURIComponent does.
func encodeURIComponent(s string) string {
	const unreserved = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.!~*'()"
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		ch := s[i]
		if strings.IndexByte(unreserved, ch) >= 0 {
			b.WriteByte(ch)
		} else {
			fmt.Fprintf(&b, "%%%02X", ch)
		}
	}
	return b.String()
}

// ─── KEL source ───────────────────────────────────────────────────────────────

// KelSourceOptions configures HTTPKelSource.
type KelSourceOptions struct {
	// FallbackURLs are tried in order on a network error or 5xx (never on a 4xx).
	FallbackURLs []string
	// AllowInsecureHTTP permits http:// to non-loopback hosts. Development only.
	AllowInsecureHTTP bool
	// HTTPClient defaults to a client with Timeout.
	HTTPClient *http.Client
	// Timeout per request. Default 10 s.
	Timeout time.Duration
}

// HTTPKelSource is an identity.KelSource backed by a registry's
// GET /v1/kel/:did. The caller re-verifies what it returns (a registry can
// withhold a log, not forge one). 200 → the events; 404 → (nil, nil); 409 →
// an error, because the registry has recorded duplicity or knows its copy is
// stale, and acting on that log could hide a revocation; any other 4xx → an
// error; network error or 5xx → the next fallback, then an error.
func HTTPKelSource(registryURL string, opts KelSourceOptions) (identity.KelSource, error) {
	urls := []string{ResolveRegistryURL(registryURL)}
	for _, u := range opts.FallbackURLs {
		urls = append(urls, strings.TrimRight(u, "/"))
	}
	for _, u := range urls {
		if err := transport.CheckEndpoint(u, opts.AllowInsecureHTTP); err != nil {
			return nil, fmt.Errorf("registry URL: %w", err)
		}
	}
	hc := opts.HTTPClient
	if hc == nil {
		timeout := opts.Timeout
		if timeout == 0 {
			timeout = 10 * time.Second
		}
		hc = &http.Client{Timeout: timeout}
	}
	return func(did string) ([]identity.KelEvent, error) {
		var last error
		for _, base := range urls {
			req, err := http.NewRequest(http.MethodGet, base+"/v1/kel/"+encodeURIComponent(did), nil)
			if err != nil {
				return nil, err
			}
			req.Header.Set("Accept", "application/json")
			res, err := hc.Do(req)
			if err != nil {
				last = err
				continue
			}
			data, rerr := io.ReadAll(io.LimitReader(res.Body, 16<<20))
			res.Body.Close()
			switch {
			case rerr != nil:
				last = rerr
				continue
			case res.StatusCode == http.StatusNotFound:
				return nil, nil
			case res.StatusCode >= 500:
				last = &HTTPError{StatusCode: res.StatusCode, Body: string(data)}
				continue
			case res.StatusCode < 200 || res.StatusCode > 299:
				return nil, &HTTPError{StatusCode: res.StatusCode, Body: string(data)}
			}
			v, err := jcs.Parse(data)
			if err != nil {
				return nil, fmt.Errorf("registry returned malformed JSON for the KEL of %s: %w", did, err)
			}
			body, _ := v.(map[string]any)
			if d, present := body["did"]; present && d != did {
				return nil, fmt.Errorf("registry answered GET /v1/kel for %v, not %s", d, did)
			}
			arr, ok := body["events"].([]any)
			if !ok {
				return nil, fmt.Errorf("registry returned no events array for %s", did)
			}
			events := make([]identity.KelEvent, 0, len(arr))
			for i, e := range arr {
				ev, ok := e.(map[string]any)
				if !ok {
					return nil, fmt.Errorf("registry KEL for %s: event %d is not an object", did, i)
				}
				events = append(events, ev)
			}
			return events, nil
		}
		if last == nil {
			last = errors.New("HTTPKelSource: no registry URL")
		}
		return nil, last
	}, nil
}
