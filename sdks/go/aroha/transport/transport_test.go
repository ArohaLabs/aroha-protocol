// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

package transport_test

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ArohaLabs/aroha-protocol/sdks/go/aroha/messages"
	"github.com/ArohaLabs/aroha-protocol/sdks/go/aroha/transport"
)

func cfg() transport.ServerConfig {
	return transport.ServerConfig{
		Port:             3001,
		MyDID:            "did:aroha:me",
		DIDDocument:      map[string]any{"id": "did:aroha:me"},
		ResolvePublicKey: func(string) ed25519.PublicKey { return nil },
		NonceRegistry:    messages.NewNonceRegistry(),
		OnMessage:        func(map[string]any, func(map[string]any), func(map[string]any)) {},
	}
}

func TestServer_DevModeNeedsEnv(t *testing.T) {
	c := cfg()
	c.DevMode = true
	t.Setenv(messages.DevModeEnv, "")
	if _, err := transport.NewArohaServer(c); !errors.Is(err, messages.ErrDevModeNotPermitted) ||
		!strings.Contains(err.Error(), "AROHA_DEV_MODE=1") {
		t.Fatalf("DevMode without AROHA_DEV_MODE=1 must be refused: %v", err)
	}
	t.Setenv(messages.DevModeEnv, "1")
	if _, err := transport.NewArohaServer(c); err != nil {
		t.Fatalf("AROHA_DEV_MODE=1 should permit DevMode: %v", err)
	}
	c.DevMode = false
	t.Setenv(messages.DevModeEnv, "")
	if _, err := transport.NewArohaServer(c); err != nil {
		t.Fatal(err)
	}
}

func TestServer_DefaultBindIsLoopback(t *testing.T) {
	s, err := transport.NewArohaServer(cfg())
	if err != nil {
		t.Fatal(err)
	}
	if s.Addr() != "127.0.0.1:3001" {
		t.Fatalf("default bind = %s", s.Addr())
	}
	c := cfg()
	c.Host = "0.0.0.0"
	s, _ = transport.NewArohaServer(c)
	if s.Addr() != "0.0.0.0:3001" {
		t.Fatalf("explicit host ignored: %s", s.Addr())
	}
}

func TestServer_BodyCap413(t *testing.T) {
	s, err := transport.NewArohaServer(cfg())
	if err != nil {
		t.Fatal(err)
	}
	big := bytes.Repeat([]byte(" "), int(transport.DefaultMaxBodyBytes)+1)

	// Declared Content-Length over the cap.
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/aroha/v1", bytes.NewReader(big)))
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("declared oversize: %d", rec.Code)
	}

	// No Content-Length (streamed): the reader cap still applies.
	req := httptest.NewRequest(http.MethodPost, "/aroha/v1", io.NopCloser(bytes.NewReader(big)))
	req.ContentLength = -1
	rec = httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("streamed oversize: %d", rec.Code)
	}

	// A small invalid body is a 400, not a 413.
	rec = httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/aroha/v1", strings.NewReader("{nope")))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("small invalid body: %d", rec.Code)
	}
}

func TestIsLoopbackHost(t *testing.T) {
	for host, want := range map[string]bool{
		"localhost": true, "api.localhost": true, "127.0.0.1": true, "127.9.9.9": true, "::1": true, "[::1]": true,
		"10.0.0.1": false, "example.com": false, "localhost.example.com": false, "128.0.0.1": false, "": false,
	} {
		if got := transport.IsLoopbackHost(host); got != want {
			t.Errorf("IsLoopbackHost(%q) = %v", host, got)
		}
	}
}

func TestCheckEndpoint(t *testing.T) {
	for _, ok := range []string{"https://agent.example.com/aroha/v1", "http://127.0.0.1:3001/aroha/v1", "http://[::1]:80/", "http://localhost:8080"} {
		if err := transport.CheckEndpoint(ok, false); err != nil {
			t.Errorf("%s: %v", ok, err)
		}
	}
	if err := transport.CheckEndpoint("http://agent.example.com", false); !errors.Is(err, transport.ErrInsecureEndpoint) ||
		!strings.Contains(err.Error(), "AllowInsecureHTTP") {
		t.Errorf("plain http accepted: %v", err)
	}
	if err := transport.CheckEndpoint("http://10.1.2.3/aroha/v1", true); err != nil {
		t.Errorf("explicit opt-in refused: %v", err)
	}
	for _, bad := range []string{"ftp://example.com", "file:///etc/hosts", "agent.example.com", "https://"} {
		if err := transport.CheckEndpoint(bad, true); err == nil {
			t.Errorf("%s accepted", bad)
		}
	}
}

func TestClient_RefusesPlainHTTPBeforeSending(t *testing.T) {
	c := transport.NewArohaClient()
	if _, err := c.Send("http://agent.example.com/aroha/v1", map[string]any{}); !errors.Is(err, transport.ErrInsecureEndpoint) {
		t.Fatalf("Send: %v", err)
	}
	if _, err := c.FetchDIDDocument("http://agent.example.com"); !errors.Is(err, transport.ErrInsecureEndpoint) {
		t.Fatalf("FetchDIDDocument: %v", err)
	}
	// Loopback (httptest) is allowed.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusAccepted) }))
	defer srv.Close()
	if r, err := c.Send(srv.URL+"/aroha/v1", map[string]any{}); err != nil || r != nil {
		t.Fatalf("loopback send: %v %v", r, err)
	}
}
