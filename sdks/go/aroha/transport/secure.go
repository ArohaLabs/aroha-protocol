// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

package transport

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
)

// ErrInsecureEndpoint is returned (wrapped) when an outbound endpoint is not
// https, is not a loopback host, and AllowInsecureHTTP is not set.
var ErrInsecureEndpoint = errors.New("insecure endpoint")

// IsLoopbackHost reports whether host is "localhost" (or a *.localhost
// name), in 127.0.0.0/8, or ::1. Brackets around an IPv6 literal are ignored.
func IsLoopbackHost(host string) bool {
	h := strings.ToLower(strings.TrimSuffix(strings.Trim(host, "[]"), "."))
	if h == "" {
		return false
	}
	if h == "localhost" || strings.HasSuffix(h, ".localhost") {
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}

// CheckEndpoint returns nil if rawURL is https, or http to a loopback host,
// or http to any host when allowInsecureHTTP is true. Any other scheme is
// always refused.
func CheckEndpoint(rawURL string, allowInsecureHTTP bool) error {
	u, err := url.Parse(rawURL)
	if err != nil || u.Hostname() == "" {
		return fmt.Errorf("[Aroha] unsupported endpoint URL %q: expected an https:// URL: %w", rawURL, ErrInsecureEndpoint)
	}
	switch strings.ToLower(u.Scheme) {
	case "https":
		return nil
	case "http":
		if allowInsecureHTTP || IsLoopbackHost(u.Hostname()) {
			return nil
		}
		return fmt.Errorf("[Aroha] refusing plain-http endpoint %q: messages would travel unencrypted; "+
			"use https, a loopback host, or set AllowInsecureHTTP for a network you control: %w", rawURL, ErrInsecureEndpoint)
	default:
		return fmt.Errorf("[Aroha] unsupported endpoint URL %q: expected an https:// URL: %w", rawURL, ErrInsecureEndpoint)
	}
}
