// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

package transport

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"

	"github.com/ArohaLabs/aroha-protocol/sdks/go/aroha/messages"
)

// MessageHandler is the application callback for valid inbound Aroha messages.
//
//   - envelope:    the validated, fully-signed envelope
//   - respond:     call with a response envelope to reply synchronously
//   - streamEvent: call with stream events (for ArohaStream messages)
type MessageHandler func(
	envelope map[string]any,
	respond func(map[string]any),
	streamEvent func(map[string]any),
)

// PublicKeyResolver looks up the Ed25519 public key for a given DID.
// Return nil if the DID is unknown (message will be rejected with 403).
type PublicKeyResolver func(did string) ed25519.PublicKey

// DefaultMaxBodyBytes is the default request body cap (1 MiB). Larger
// bodies are rejected with 413 before parsing.
const DefaultMaxBodyBytes int64 = 1 << 20

// DefaultHost is the default bind address: loopback only.
const DefaultHost = "127.0.0.1"

// ServerConfig holds all ArohaServer parameters.
type ServerConfig struct {
	// Host is the interface to bind. Empty = DefaultHost (127.0.0.1, loopback
	// only). Set "0.0.0.0" (or "::", or an interface address) to accept
	// connections from other machines.
	Host             string
	Port             int
	DIDDocument      map[string]any
	MyDID            string
	ResolvePublicKey PublicKeyResolver
	NonceRegistry    *messages.NonceRegistry
	OnMessage        MessageHandler

	// DevMode skips ALL cryptographic validation (signature, nonce replay,
	// expiry). Intended for local development and hackathons — never set
	// in production. NewArohaServer refuses it (an error wrapping
	// messages.ErrDevModeNotPermitted) unless the environment sets
	// AROHA_DEV_MODE=1, and prints a warning to stderr once when on. Flip to
	// false and the full zero-trust pipeline re-engages with no handler code
	// changes required.
	DevMode bool

	// MaxBodyBytes caps the request body; larger bodies get 413.
	// 0 = DefaultMaxBodyBytes (1 MiB).
	MaxBodyBytes int64
}

// ArohaServer exposes two endpoints:
//
//	GET  /.well-known/aroha-agent.json  → DID Document
//	POST /aroha/v1                       → inbound Aroha envelopes
type ArohaServer struct {
	cfg        ServerConfig
	httpServer *http.Server
}

// NewArohaServer creates a server from the given config. It returns an error
// if DevMode is set without AROHA_DEV_MODE=1.
func NewArohaServer(cfg ServerConfig) (*ArohaServer, error) {
	if cfg.DevMode {
		if err := messages.RequireDevMode("transport.ServerConfig.DevMode"); err != nil {
			return nil, err
		}
	}
	if cfg.Host == "" {
		cfg.Host = DefaultHost
	}
	if cfg.MaxBodyBytes <= 0 {
		cfg.MaxBodyBytes = DefaultMaxBodyBytes
	}
	s := &ArohaServer{cfg: cfg}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/aroha-agent.json", s.handleWellKnown)
	mux.HandleFunc("POST /aroha/v1", s.handleAroha)
	s.httpServer = &http.Server{
		Addr:    net.JoinHostPort(cfg.Host, strconv.Itoa(cfg.Port)),
		Handler: mux,
	}
	return s, nil
}

// Handler returns the server's HTTP handler (for embedding or tests).
func (s *ArohaServer) Handler() http.Handler { return s.httpServer.Handler }

// Addr is the configured listen address (host:port).
func (s *ArohaServer) Addr() string { return s.httpServer.Addr }

// Start begins listening. Blocks until ctx is cancelled or an error occurs.
func (s *ArohaServer) Start(ctx context.Context) error {
	ln, err := net.Listen("tcp", s.httpServer.Addr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", s.httpServer.Addr, err)
	}
	errCh := make(chan error, 1)
	go func() { errCh <- s.httpServer.Serve(ln) }()

	select {
	case <-ctx.Done():
		return s.httpServer.Shutdown(context.Background())
	case err := <-errCh:
		return err
	}
}

// Stop gracefully shuts down the server.
func (s *ArohaServer) Stop(ctx context.Context) error {
	return s.httpServer.Shutdown(ctx)
}

// ── Handlers ──────────────────────────────────────────────────────────────────

func (s *ArohaServer) handleWellKnown(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(s.cfg.DIDDocument)
}

func (s *ArohaServer) handleAroha(w http.ResponseWriter, r *http.Request) {
	if r.ContentLength > s.cfg.MaxBodyBytes {
		http.Error(w, `{"error":"Payload too large"}`, http.StatusRequestEntityTooLarge)
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, s.cfg.MaxBodyBytes))
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			http.Error(w, `{"error":"Payload too large"}`, http.StatusRequestEntityTooLarge)
			return
		}
		http.Error(w, `{"error":"read error"}`, http.StatusBadRequest)
		return
	}

	var envelope map[string]any
	if err := json.Unmarshal(body, &envelope); err != nil {
		http.Error(w, `{"error":"invalid JSON"}`, http.StatusBadRequest)
		return
	}

	// ── Dev mode: skip all crypto — localhost / hackathon mode ────────────────
	if s.cfg.DevMode {
		s.dispatch(w, envelope)
		return
	}

	// Resolve sender public key
	fromDID, _ := envelope["from"].(string)
	senderKey := s.cfg.ResolvePublicKey(fromDID)
	if senderKey == nil {
		http.Error(w, fmt.Sprintf(`{"error":"unknown sender: %s"}`, fromDID), http.StatusForbidden)
		return
	}

	// Validate envelope
	if err := messages.Validate(envelope, senderKey, s.cfg.MyDID, s.cfg.NonceRegistry); err != nil {
		http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), http.StatusBadRequest)
		return
	}

	s.dispatch(w, envelope)
}

func (s *ArohaServer) dispatch(w http.ResponseWriter, envelope map[string]any) {
	var response map[string]any
	s.cfg.OnMessage(
		envelope,
		func(r map[string]any) { response = r },
		func(_ map[string]any) { /* WebSocket streaming: implement separately */ },
	)

	if response != nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	} else {
		w.WriteHeader(http.StatusAccepted)
	}
}
