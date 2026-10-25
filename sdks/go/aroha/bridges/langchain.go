// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

// Package bridges provides adapters between Aroha and popular Go AI frameworks.
//
// LangChainGo bridge: wraps Aroha capabilities as tools.Tool objects
// for use with github.com/tmc/langchaingo.
package bridges

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"

	"github.com/ArohaLabs/aroha-protocol/sdks/go/aroha/messages"
	"github.com/ArohaLabs/aroha-protocol/sdks/go/aroha/transport"
)

// ArohaTool implements the langchaingo tools.Tool interface backed by a Aroha capability.
//
// It can be used with any LangChainGo agent:
//
//	import "github.com/tmc/langchaingo/agents"
//	import "github.com/tmc/langchaingo/tools"
//
//	arohaTools := bridges.ToolsForAgent(agents, capIDs, orch, keyID, privKey, client)
//	executor, _ := agents.Initialize(llm, arohaTools, agents.ZeroShotReactDescription)
type ArohaTool struct {
	name              string
	description       string
	agentDID          string
	agentEndpoint     string
	capabilityID      string
	orchestratorDID   string
	orchestratorKeyID string
	correlationID     string
	privateKey        ed25519.PrivateKey
	client            *transport.ArohaClient
}

// Name returns the tool's name (e.g. "aroha_search_flights").
func (t *ArohaTool) Name() string { return t.name }

// Description returns the tool's human-readable description.
func (t *ArohaTool) Description() string { return t.description }

// Call invokes the Aroha capability with the given JSON input string.
// Input is expected to be a JSON object whose fields are passed as params.
func (t *ArohaTool) Call(ctx context.Context, input string) (string, error) {
	var params map[string]any
	if err := json.Unmarshal([]byte(input), &params); err != nil {
		// If input is not JSON, wrap it as a plain query param
		params = map[string]any{"query": input}
	}

	body := map[string]any{
		"capability": t.capabilityID,
		"params":     params,
	}

	env, err := messages.BuildDefault(
		messages.TypeRequest, t.orchestratorDID, t.agentDID,
		body, t.correlationID, t.privateKey, t.orchestratorKeyID)
	if err != nil {
		return "", fmt.Errorf("build envelope: %w", err)
	}

	resp, err := t.client.Send(t.agentEndpoint, env)
	if err != nil {
		return "", err
	}
	if resp == nil {
		return "Request accepted (async)", nil
	}
	if msgType, _ := resp["type"].(string); msgType == messages.TypeError {
		b, _ := resp["body"].(map[string]any)
		msg, _ := b["message"].(string)
		return "", fmt.Errorf("Aroha error: %s", msg)
	}

	respBody, _ := resp["body"].(map[string]any)
	result := respBody["result"]
	if result == nil {
		result = respBody
	}
	out, _ := json.MarshalIndent(result, "", "  ")
	return string(out), nil
}

// ToolsForAgent converts discovered Aroha agents into ArohaTool slices.
//
//	agents:           list of discovered agents, each with "did", "endpoint", "manifest"
//	capabilityIDs:    which capability IDs to expose as tools
//	orchestratorDID:  DID of the orchestrator
//	orchestratorKeyID: key ID (e.g. "did:aroha:orch#key-1")
//	privateKey:       orchestrator's Ed25519 private key
//	client:           ArohaClient instance
func ToolsForAgent(
	agents []map[string]any,
	capabilityIDs []string,
	orchestratorDID, orchestratorKeyID string,
	privateKey ed25519.PrivateKey,
	client *transport.ArohaClient,
) []*ArohaTool {
	capSet := make(map[string]bool, len(capabilityIDs))
	for _, id := range capabilityIDs {
		capSet[id] = true
	}

	correlationID := messages.NewCorrelationID()
	var tools []*ArohaTool

	for _, agent := range agents {
		manifest, _ := agent["manifest"].(map[string]any)
		capabilities, _ := manifest["capabilities"].([]any)
		agentDID, _ := agent["did"].(string)
		agentEndpoint, _ := agent["endpoint"].(string)

		for _, capRaw := range capabilities {
			cap, _ := capRaw.(map[string]any)
			capID, _ := cap["id"].(string)
			if !capSet[capID] {
				continue
			}
			desc, _ := cap["description"].(string)
			if desc == "" {
				desc = "Aroha capability: " + capID
			}
			// Tool name: aroha_search_flights
			name := "aroha_"
			for _, c := range capID {
				if c == '-' {
					name += "_"
				} else {
					name += string(c)
				}
			}

			tools = append(tools, &ArohaTool{
				name:              name,
				description:       desc,
				agentDID:          agentDID,
				agentEndpoint:     agentEndpoint,
				capabilityID:      capID,
				orchestratorDID:   orchestratorDID,
				orchestratorKeyID: orchestratorKeyID,
				correlationID:     correlationID,
				privateKey:        privateKey,
				client:            client,
			})
		}
	}
	return tools
}
