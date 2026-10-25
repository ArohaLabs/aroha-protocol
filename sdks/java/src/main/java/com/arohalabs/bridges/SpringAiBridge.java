// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

package com.arohalabs.bridges;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.arohalabs.messages.ArohaEnvelope;
import com.arohalabs.transport.ArohaClient;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.springframework.ai.tool.ToolCallback;
import org.springframework.ai.tool.definition.ToolDefinition;

import java.util.*;

/**
 * Aroha ↔ Spring AI Bridge
 *
 * Wraps Aroha capabilities as Spring AI {@link ToolCallback} objects so any
 * Spring AI chat model or agent can call them transparently.
 *
 * Requires Spring AI 1.0.x on the classpath (the SDK declares it optional):
 *   {@code <dependency>
 *       <groupId>org.springframework.ai</groupId>
 *       <artifactId>spring-ai-model</artifactId>
 *   </dependency>}
 * ({@code spring-ai-core} was split into {@code spring-ai-model} and others
 * before 1.0.0 GA; there is no {@code spring-ai-core:1.0.0}.)
 *
 * Usage:
 * <pre>{@code
 *   var tools = SpringAiBridge.toolsForAgent(
 *       agents,              // discovered Aroha agents
 *       List.of("search-flights", "book-flight"),
 *       identity.did(),
 *       identity.keyId(),
 *       identity.privateKey(),
 *       new ArohaClient()
 *   );
 *
 *   ChatClient.builder(chatModel)
 *       .defaultTools(tools.toArray(new ToolCallback[0]))
 *       .build()
 *       .prompt("Book me the cheapest flight to Tokyo next Friday")
 *       .call().content();
 * }</pre>
 */
public final class SpringAiBridge {

    private SpringAiBridge() {}

    private static final ObjectMapper MAPPER = new ObjectMapper();

    // ── Factory ───────────────────────────────────────────────────────────────

    /**
     * Converts discovered Aroha agents into Spring AI ToolCallback instances.
     *
     * @param agents           list of discovered agents, each with "did", "endpoint",
     *                         and "manifest" (containing "capabilities" list)
     * @param capabilityIds    which capability IDs to expose as tools
     * @param orchestratorDid  DID of the orchestrating agent
     * @param orchestratorKeyId  key ID (e.g. "did:aroha:orch#key-1")
     * @param privateKey       orchestrator's Ed25519 private key
     * @param client           ArohaClient instance
     * @return list of ToolCallback objects ready for Spring AI
     */
    @SuppressWarnings("unchecked")
    public static List<ToolCallback> toolsForAgent(
            List<Map<String, Object>> agents,
            List<String> capabilityIds,
            String orchestratorDid,
            String orchestratorKeyId,
            Ed25519PrivateKeyParameters privateKey,
            ArohaClient client) {

        List<ToolCallback> tools = new ArrayList<>();
        String correlationId = ArohaEnvelope.newCorrelationId();

        for (Map<String, Object> agent : agents) {
            Map<String, Object> manifest = (Map<String, Object>) agent.getOrDefault("manifest", Map.of());
            List<Map<String, Object>> capabilities =
                (List<Map<String, Object>>) manifest.getOrDefault("capabilities", List.of());

            for (Map<String, Object> cap : capabilities) {
                String capId = (String) cap.get("id");
                if (!capabilityIds.contains(capId)) continue;

                String agentDid      = (String) agent.get("did");
                String agentEndpoint = (String) agent.get("endpoint");
                String description   = (String) cap.getOrDefault("description", capId);

                tools.add(new ArohaToolCallback(
                    capId, description, agentDid, agentEndpoint,
                    orchestratorDid, orchestratorKeyId, correlationId,
                    privateKey, client));
            }
        }
        return tools;
    }

    // ── ToolCallback Implementation ───────────────────────────────────────────

    static final class ArohaToolCallback implements ToolCallback {

        private final String capabilityId;
        private final String agentDid;
        private final String agentEndpoint;
        private final String orchestratorDid;
        private final String orchestratorKeyId;
        private final String correlationId;
        private final Ed25519PrivateKeyParameters privateKey;
        private final ArohaClient client;
        private final ToolDefinition definition;

        ArohaToolCallback(
                String capabilityId, String description,
                String agentDid, String agentEndpoint,
                String orchestratorDid, String orchestratorKeyId,
                String correlationId,
                Ed25519PrivateKeyParameters privateKey,
                ArohaClient client) {
            this.capabilityId      = capabilityId;
            this.agentDid          = agentDid;
            this.agentEndpoint     = agentEndpoint;
            this.orchestratorDid   = orchestratorDid;
            this.orchestratorKeyId = orchestratorKeyId;
            this.correlationId     = correlationId;
            this.privateKey        = privateKey;
            this.client            = client;

            // Tool name: aroha_search_flights, aroha_book_flight, etc.
            String toolName = "aroha_" + capabilityId.replace("-", "_");
            this.definition = ToolDefinition.builder()
                .name(toolName)
                .description(description)
                // Spring AI will pass the LLM-generated arguments as a JSON string
                .inputSchema("""
                    {"type":"object","properties":{"params":{"type":"object"}},"required":[]}
                    """)
                .build();
        }

        @Override
        public ToolDefinition getToolDefinition() {
            return definition;
        }

        @Override
        @SuppressWarnings("unchecked")
        public String call(String toolInput) {
            try {
                // toolInput is the JSON string the LLM produced for the tool arguments
                Map<String, Object> args = MAPPER.readValue(toolInput, Map.class);
                Map<String, Object> params = (Map<String, Object>) args.getOrDefault("params", args);

                Map<String, Object> body = new LinkedHashMap<>();
                body.put("capability", capabilityId);
                body.put("params",     params);

                Map<String, Object> envelope = ArohaEnvelope.build(
                    "ArohaRequest", orchestratorDid, agentDid,
                    body, correlationId, privateKey, orchestratorKeyId);

                Map<String, Object> response = client.send(agentEndpoint, envelope);

                if (response == null) return "Request accepted (async)";
                if ("ArohaError".equals(response.get("type"))) {
                    Map<String, Object> b = (Map<String, Object>) response.get("body");
                    return "Error: " + b.getOrDefault("message", "unknown error");
                }

                Map<String, Object> respBody = (Map<String, Object>) response.get("body");
                Object result = respBody.getOrDefault("result", respBody);
                return MAPPER.writerWithDefaultPrettyPrinter().writeValueAsString(result);

            } catch (Exception e) {
                return "Error: " + e.getMessage();
            }
        }
    }
}
