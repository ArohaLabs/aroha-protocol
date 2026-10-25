// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Core bridge logic: discovers an Aroha agent's capabilities and registers
 * each one as an MCP tool served over stdio.
 *
 * The MCP protocol speaks JSON-RPC 2.0 over stdin/stdout. Hermes Agent and
 * ZeroClaw both fork this process and pipe messages through it — no port
 * binding required.
 */

import { ArohaClient, type ArohaEnvelope } from "@aroha-sdk/core";
import { arohaAgentToMcpTools, type McpToolDefinition } from "@aroha-sdk/mcp-bridge";
import { type DiscoveredAgent } from "@aroha-sdk/registry";

export interface HermesMcpServerOptions {
  /** Aroha HTTP endpoint of the remote agent to expose. */
  endpoint: string;
  /** DID of the remote agent. */
  agentDID: string;
  /**
   * Ed25519 private key for this bridge's ephemeral identity.
   * If omitted, an ephemeral key pair is generated at startup.
   */
  privateKey?: Uint8Array;
  /** DID for this bridge instance. Generated if omitted. */
  bridgeDID?: string;
}

export interface HermesMcpServer {
  /** All MCP tool definitions registered from the Aroha agent. */
  tools: McpToolDefinition[];
  /** Handle an incoming MCP tool call and return the result. */
  handleToolCall(name: string, args: Record<string, unknown>): Promise<{
    content: Array<{ type: "text"; text: string }>;
    isError?: boolean;
  }>;
  /** Write MCP protocol messages to a writable stream (e.g. process.stdout). */
  serve(input: NodeJS.ReadableStream, output: NodeJS.WritableStream): Promise<void>;
}

/**
 * Build an MCP server that fronts a single Aroha agent.
 *
 * Steps:
 *  1. Fetch the agent's DID document from /.well-known/aroha-agent.json
 *  2. Convert each capability to an MCP tool definition
 *  3. Return a server that handles MCP JSON-RPC over any stream pair
 */
export async function createHermesMcpServer(
  opts: HermesMcpServerOptions
): Promise<HermesMcpServer> {
  // Always derive bridgeDID and privKey from the SAME keypair so the DID
  // document's verificationMethod matches the key used to sign outbound envelopes.
  // If opts.privateKey + opts.bridgeDID are both supplied the caller is
  // responsible for their consistency; if neither is supplied we generate a
  // fresh, self-consistent keypair via generateDID.
  let privKey: Uint8Array;
  let bridgeDID: string;

  if (opts.privateKey && opts.bridgeDID) {
    privKey = opts.privateKey;
    bridgeDID = opts.bridgeDID;
  } else {
    const { generateDID } = await import("@aroha-sdk/core");
    const kp = await generateDID("hermes-bridge", opts.endpoint);
    bridgeDID = opts.bridgeDID ?? kp.did;
    privKey = kp.privateKey;
  }

  // Fetch the agent manifest
  const manifestUrl = `${opts.endpoint.replace(/\/$/, "")}/.well-known/aroha-agent.json`;
  const manifestRes = await fetch(manifestUrl);
  if (!manifestRes.ok) {
    throw new Error(`Failed to fetch agent manifest from ${manifestUrl}: ${manifestRes.status}`);
  }
  const manifest = await manifestRes.json() as {
    id: string;
    capabilities?: Array<{
      id: string;
      description?: string;
      inputSchema?: Record<string, unknown>;
      outputSchema?: Record<string, unknown>;
      async?: boolean;
      maxResponseMs?: number;
      requiredTrustLevel?: 0 | 1 | 2 | 3 | 4;
      pricing?: { model: "free" | "per-transaction" | "subscription"; fee?: string; currency?: string };
      sagaRole?: "none" | "participant";
    }>;
  };

  const now = new Date().toISOString();
  // arohaAgentToMcpTools only reads manifest.did and manifest.capabilities —
  // stub the rest of DiscoveredAgent with empty/zero sentinels.
  const discoveredAgent = {
    endpoint: opts.endpoint,
    publicKey: new Uint8Array(0),
    record: {} as DiscoveredAgent["record"],
    manifest: {
      aroha: "1.0" as const,
      did: opts.agentDID,
      name: opts.agentDID,
      version: "1.0.0",
      endpoint: opts.endpoint,
      protocols: ["aroha/1.0"],
      createdAt: now,
      signature: "",
      capabilities: (manifest.capabilities ?? []).map((c) => ({
        id: c.id,
        version: "1.0.0",
        description: c.description ?? c.id,
        inputSchema: c.inputSchema ?? { type: "object", properties: {} },
        outputSchema: c.outputSchema ?? { type: "object" },
        async: c.async ?? false,
        maxResponseMs: c.maxResponseMs ?? 30_000,
        requiredTrustLevel: c.requiredTrustLevel ?? 1,
        pricing: c.pricing ?? { model: "free" as const },
        sagaRole: c.sagaRole ?? "none",
      })),
    },
  } satisfies DiscoveredAgent;

  const client = new ArohaClient();
  const correlationId = `hermes-bridge-${Date.now()}`;
  const { tools, handleToolCall } = arohaAgentToMcpTools(
    discoveredAgent,
    bridgeDID,
    privKey,
    client,
    correlationId
  );

  return {
    tools,
    handleToolCall,
    async serve(input, output) {
      await serveStdioMcp(tools, handleToolCall, input, output);
    },
  };
}

// ─── Minimal MCP stdio server (JSON-RPC 2.0) ─────────────────────────────────

type JsonRpcRequest = {
  jsonrpc: "2.0";
  id: number | string | null;
  method: string;
  params?: unknown;
};

type JsonRpcResponse = {
  jsonrpc: "2.0";
  id: number | string | null;
  result?: unknown;
  error?: { code: number; message: string };
};

async function serveStdioMcp(
  tools: McpToolDefinition[],
  handleToolCall: (name: string, args: Record<string, unknown>) => Promise<{ content: Array<{ type: "text"; text: string }>; isError?: boolean }>,
  input: NodeJS.ReadableStream,
  output: NodeJS.WritableStream
): Promise<void> {
  const send = (msg: JsonRpcResponse) => {
    const line = JSON.stringify(msg) + "\n";
    output.write(line);
  };

  let buffer = "";
  input.setEncoding("utf8");

  await new Promise<void>((resolve, reject) => {
    input.on("data", async (chunk: string) => {
      buffer += chunk;
      const lines = buffer.split("\n");
      buffer = lines.pop() ?? "";

      for (const line of lines) {
        const trimmed = line.trim();
        if (!trimmed) continue;

        let req: JsonRpcRequest;
        try {
          req = JSON.parse(trimmed) as JsonRpcRequest;
        } catch {
          send({ jsonrpc: "2.0", id: null, error: { code: -32700, message: "Parse error" } });
          continue;
        }

        await handleRequest(req, tools, handleToolCall, send);
      }
    });

    input.on("end", resolve);
    input.on("error", reject);
  });
}

async function handleRequest(
  req: JsonRpcRequest,
  tools: McpToolDefinition[],
  handleToolCall: (name: string, args: Record<string, unknown>) => Promise<{ content: Array<{ type: "text"; text: string }>; isError?: boolean }>,
  send: (msg: JsonRpcResponse) => void
): Promise<void> {
  switch (req.method) {
    case "initialize":
      send({
        jsonrpc: "2.0",
        id: req.id,
        result: {
          protocolVersion: "2024-11-05",
          capabilities: { tools: {} },
          serverInfo: { name: "aroha-hermes-bridge", version: "1.0.0" },
        },
      });
      break;

    case "notifications/initialized":
      // No response needed for notifications
      break;

    case "tools/list":
      send({
        jsonrpc: "2.0",
        id: req.id,
        result: {
          tools: tools.map((t) => ({
            name: t.name,
            description: t.description,
            inputSchema: t.inputSchema,
          })),
        },
      });
      break;

    case "tools/call": {
      const params = req.params as { name: string; arguments?: Record<string, unknown> };
      const result = await handleToolCall(params.name, params.arguments ?? {});
      send({
        jsonrpc: "2.0",
        id: req.id,
        result,
      });
      break;
    }

    default:
      send({
        jsonrpc: "2.0",
        id: req.id,
        error: { code: -32601, message: `Method not found: ${req.method}` },
      });
  }
}
