// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

// Package transport implements Aroha Layer 0 — Transport.
//
// ArohaClient sends signed envelopes to remote agents.
// ArohaServer serves the well-known DID Document and dispatches inbound messages.
package transport

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// ArohaClient sends Aroha envelopes to remote agents via HTTPS POST.
//
// Endpoints must be https, except loopback hosts (127.0.0.0/8, ::1,
// localhost). Set ClientOptions.AllowInsecureHTTP to permit plain http to
// other hosts on a network you control.
type ArohaClient struct {
	http              *http.Client
	timeout           time.Duration
	allowInsecureHTTP bool
}

// ClientOptions configures NewArohaClientWithOptions.
type ClientOptions struct {
	// Timeout per request. 0 = 30 s.
	Timeout time.Duration
	// AllowInsecureHTTP permits plain http to non-loopback hosts.
	AllowInsecureHTTP bool
}

// NewArohaClient creates a client with a 30-second default timeout.
func NewArohaClient() *ArohaClient {
	return NewArohaClientWithOptions(ClientOptions{})
}

// NewArohaClientWithOptions creates a client with explicit options.
func NewArohaClientWithOptions(opts ClientOptions) *ArohaClient {
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	return &ArohaClient{
		timeout:           timeout,
		http:              &http.Client{Timeout: timeout},
		allowInsecureHTTP: opts.AllowInsecureHTTP,
	}
}

// Send sends a Aroha envelope to the given endpoint.
//
// Returns the response envelope, or nil if the server responded 202 (async accepted).
// Returns an error for HTTP 4xx/5xx or network failures.
func (c *ArohaClient) Send(endpoint string, envelope map[string]any) (map[string]any, error) {
	return c.SendWithTimeout(endpoint, envelope, c.timeout)
}

// SendWithTimeout is like Send but with an explicit per-request timeout.
func (c *ArohaClient) SendWithTimeout(endpoint string, envelope map[string]any, timeout time.Duration) (map[string]any, error) {
	if err := CheckEndpoint(endpoint, c.allowInsecureHTTP); err != nil {
		return nil, err
	}
	body, err := json.Marshal(envelope)
	if err != nil {
		return nil, fmt.Errorf("marshal envelope: %w", err)
	}

	client := &http.Client{Timeout: timeout}
	resp, err := client.Post(endpoint, "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("POST %s: %w", endpoint, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusAccepted {
		return nil, nil // async — provider accepted, will stream result
	}
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("Aroha endpoint returned HTTP %d", resp.StatusCode)
	}

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	var result map[string]any
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("unmarshal response: %w", err)
	}
	return result, nil
}

// FetchDIDDocument fetches the DID Document from the well-known endpoint.
//
// baseURL is the agent's base URL, e.g. "https://agents.expedia.com".
func (c *ArohaClient) FetchDIDDocument(baseURL string) (map[string]any, error) {
	// Strip trailing slash then append well-known path
	for len(baseURL) > 0 && baseURL[len(baseURL)-1] == '/' {
		baseURL = baseURL[:len(baseURL)-1]
	}
	url := baseURL + "/.well-known/aroha-agent.json"
	if err := CheckEndpoint(url, c.allowInsecureHTTP); err != nil {
		return nil, err
	}

	resp, err := c.http.Get(url)
	if err != nil {
		return nil, fmt.Errorf("GET %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("could not fetch DID Document: HTTP %d", resp.StatusCode)
	}

	var doc map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return nil, fmt.Errorf("decode DID Document: %w", err)
	}
	return doc, nil
}
