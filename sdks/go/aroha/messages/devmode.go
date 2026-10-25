// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

package messages

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
)

// DevModeEnv is the environment variable that must equal "1" before any
// switch that disables envelope verification (transport.ServerConfig.DevMode,
// ValidateOptions.SkipSignature without AcknowledgeUnauthenticated) is
// accepted. The TypeScript SDK gates the same switches on
// NODE_ENV=development; NODE_ENV means nothing outside Node, so the Go, Java
// and Python SDKs use AROHA_DEV_MODE instead.
const DevModeEnv = "AROHA_DEV_MODE"

// ErrDevModeNotPermitted is returned (wrapped) when a verification-disabling
// switch is requested without AROHA_DEV_MODE=1.
var ErrDevModeNotPermitted = errors.New("dev mode not permitted")

var (
	devWarnMu sync.Mutex
	devWarned = map[string]bool{}
)

// DevModePermitted reports whether the environment opts in to dev mode.
func DevModePermitted() bool {
	return strings.TrimSpace(os.Getenv(DevModeEnv)) == "1"
}

// RequireDevMode returns an error wrapping ErrDevModeNotPermitted unless
// AROHA_DEV_MODE=1. When permitted it prints a one-time warning per feature
// to stderr.
func RequireDevMode(feature string) error {
	if !DevModePermitted() {
		cur, set := os.LookupEnv(DevModeEnv)
		shown := "(unset)"
		if set {
			shown = fmt.Sprintf("%q", cur)
		}
		return fmt.Errorf("[Aroha] %s can only be enabled when %s=1 (current: %s); remove it before deploying: %w",
			feature, DevModeEnv, shown, ErrDevModeNotPermitted)
	}
	devWarnMu.Lock()
	first := !devWarned[feature]
	devWarned[feature] = true
	devWarnMu.Unlock()
	if first {
		fmt.Fprintf(os.Stderr,
			"[Aroha] WARNING: %s is ENABLED — cryptographic validation is bypassed. Never use dev mode in production.\n",
			feature)
	}
	return nil
}
