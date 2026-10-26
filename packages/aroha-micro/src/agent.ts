// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * @aroha-sdk/micro — Express-like Aroha agent API.
 *
 * The full Aroha protocol (Ed25519 DIDs, saga state machine, policy middleware)
 * is designed for zero-trust production networks. @aroha-sdk/micro makes the same
 * protocol accessible in 5 lines for local development and hackathons.
 *
 * Production mode (default, devMode: false):
 *   - Full signature verification on every inbound message
 *
 * Dev mode (devMode: true — opt-in, and core refuses it unless
 * NODE_ENV=development):
 *   - Ed25519 signing is performed but VERIFICATION is skipped on inbound msgs
 *   - ArohaReserve → auto-commits (single-call instead of two-phase saga)
 *   - Agent self-registers with the local `aroha dev` sandbox if it is running
 *
 * devMode used to default to TRUE, so an agent started with the 5-line
 * example accepted unsigned messages from anyone who could reach its port.
 */

import { resolveRegistryUrl } from "@aroha-sdk/core/endpoints";
import {
  ArohaServer,
  generateDID,
  buildEnvelope,
  ArohaErrorCode,
  type ArohaEnvelope,
  type ArohaRequestBody,
  type ArohaReserveBody,
  type ArohaResponseBody,
  type ArohaCommitAckBody,
  type PublicKeyResolver,
} from "@aroha-sdk/core";

// ─── Types ────────────────────────────────────────────────────────────────────

/** Handler for a single capability. Return any JSON-serialisable value. */
export type CapabilityHandler = (
  params: Record<string, unknown>
) => Promise<unknown> | unknown;

export interface MicroAgentOptions {
  /** Agent display name — used for console output and registry display. */
  name: string;
  /** Port to listen on. */
  port: number;
  /**
   * Dev mode: skip inbound crypto verification and auto-commit sagas.
   * Default: FALSE (it was true). Opt in for local development only; the
   * server refuses to start with it unless NODE_ENV=development.
   */
  devMode?: boolean;
  /**
   * Registry URL. Default: the Aroha-managed registry (AROHA_REGISTRY_URL
   * overrides). In devMode the default is instead the local `aroha dev`
   * sandbox at http://localhost:3000, which the agent auto-registers with
   * on startup (silently ignored if it is offline). Auto-registration only
   * ever happens in devMode.
   */
  registryUrl?: string;
  /**
   * Public base URL of this agent (what peers and the registry should call).
   * Default: AGENT_ENDPOINT env var, else http://localhost:{port}.
   */
  endpoint?: string;
  /**
   * Interface to bind. Default "127.0.0.1" (core's default). Pass "0.0.0.0"
   * to accept connections from other machines.
   */
  host?: string;
  /**
   * How peers' public keys are resolved when verifying inbound envelopes
   * (same signature as ArohaServer's `resolvePublicKey`). Return null for an
   * unknown sender; it is rejected with 401. The agent's own DID always
   * resolves. Default: only the agent's own DID resolves, so every peer is
   * rejected. Not consulted in devMode.
   */
  resolvePublicKey?: PublicKeyResolver;
}

// ─── MicroAgent ───────────────────────────────────────────────────────────────

export class MicroAgent {
  private readonly handlers = new Map<string, CapabilityHandler>();
  private server: ArohaServer | null = null;
  private _did = "";
  private _privateKey: Uint8Array = new Uint8Array(32);
  private readonly opts: Required<Omit<MicroAgentOptions, "host" | "resolvePublicKey">> &
    Pick<MicroAgentOptions, "host" | "resolvePublicKey">;

  constructor(opts: MicroAgentOptions) {
    const devMode = opts.devMode ?? false;
    const fromEnv = process.env.AGENT_ENDPOINT?.trim();
    this.opts = {
      ...opts,
      devMode,
      registryUrl: opts.registryUrl ?? (devMode ? "http://localhost:3000" : resolveRegistryUrl()),
      endpoint: (opts.endpoint ?? (fromEnv && fromEnv.length > 0 ? fromEnv : `http://localhost:${opts.port}`)).replace(/\/+$/, ""),
    };
  }

  get did(): string { return this._did; }
  get endpoint(): string { return this.opts.endpoint; }

  /**
   * Register a capability handler. Chainable.
   *
   * @example
   * agent
   *   .on("get-weather", async ({ city }) => ({ temp: 22, condition: "sunny" }))
   *   .on("book-hotel",  async ({ city, nights }) => ({ ref: "HT-123" }));
   */
  on(capability: string, handler: CapabilityHandler): this {
    this.handlers.set(capability, handler);
    return this;
  }

  /** Start listening. Generates an ephemeral Ed25519 DID on each run. */
  async start(): Promise<void> {
    const endpoint = `${this.endpoint}/aroha/v1`;
    const identity = await generateDID(this.opts.name, endpoint);
    this._did = identity.did;
    this._privateKey = identity.privateKey;

    const knownPublicKeys = new Map<string, Uint8Array>();
    knownPublicKeys.set(this._did, identity.publicKey);

    this.server = new ArohaServer({
      agentDID: this._did,
      didDocument: identity.document,
      port: this.opts.port,
      ...(this.opts.host ? { host: this.opts.host } : {}),
      devMode: this.opts.devMode,
      resolvePublicKey: async (senderDID, verificationMethodId) => {
        // In dev mode the ArohaServer short-circuits before verifying the key,
        // so this is only reached in production mode.
        const own = knownPublicKeys.get(senderDID);
        if (own) return own;
        return this.opts.resolvePublicKey ? this.opts.resolvePublicKey(senderDID, verificationMethodId) : null;
      },
      onMessage: async (envelope, respond) => this.dispatch(envelope, respond),
    });

    await this.server.start();

    if (this.opts.devMode) {
      await this.tryRegister();
      this.printBanner();
    }
  }

  /** Gracefully stop the server. */
  async stop(): Promise<void> {
    await this.server?.stop();
  }

  // ─── Internal dispatch ────────────────────────────────────────────────────

  private async dispatch(
    envelope: ArohaEnvelope,
    respond: (r: ArohaEnvelope) => void
  ): Promise<void> {
    const { type, body, from, correlationId } = envelope;

    if (type === "ArohaRequest") {
      const { capability, params = {} } = body as ArohaRequestBody;
      await this.invokeAndReply(capability, params, from, correlationId, respond, "ArohaResponse");
      return;
    }

    if (type === "ArohaReserve") {
      if (this.opts.devMode) {
        // Dev mode: skip two-phase saga, execute immediately and return CommitAck
        const { capability, params = {} } = body as ArohaReserveBody;
        await this.invokeAndReply(capability, params, from, correlationId, respond, "ArohaCommitAck");
      } else {
        // Production: caller must implement full saga handlers via ArohaServer directly
        const err = await buildEnvelope(
          "ArohaError", this._did, from,
          { code: ArohaErrorCode.ReservationFailed, message: "Saga not implemented — use ArohaServer directly for production sagas", retryable: false },
          correlationId, this._privateKey
        );
        respond(err);
      }
      return;
    }

    // Silently ignore other message types (ArohaCancel, ArohaSatisfactionSignal, etc.)
  }

  private async invokeAndReply(
    capability: string,
    params: Record<string, unknown>,
    from: string,
    correlationId: string,
    respond: (r: ArohaEnvelope) => void,
    successType: "ArohaResponse" | "ArohaCommitAck"
  ): Promise<void> {
    const handler = this.handlers.get(capability);

    if (!handler) {
      respond(await buildEnvelope(
        "ArohaError", this._did, from,
        { code: ArohaErrorCode.UnknownCapability, message: `Unknown capability: ${capability}`, retryable: false },
        correlationId, this._privateKey
      ));
      return;
    }

    try {
      const raw = await handler(params);
      const result = (raw !== null && typeof raw === "object" ? raw : { value: raw }) as Record<string, unknown>;

      if (successType === "ArohaResponse") {
        const responseBody: ArohaResponseBody = { capability, result };
        respond(await buildEnvelope("ArohaResponse", this._did, from, responseBody, correlationId, this._privateKey));
      } else {
        const ackBody: ArohaCommitAckBody = { reservationToken: `dev-${Date.now()}`, result };
        respond(await buildEnvelope("ArohaCommitAck", this._did, from, ackBody, correlationId, this._privateKey));
      }
    } catch (err) {
      respond(await buildEnvelope(
        "ArohaError", this._did, from,
        { code: ArohaErrorCode.InternalError, message: String(err), retryable: true },
        correlationId, this._privateKey
      ));
    }
  }

  // ─── Dev sandbox integration ──────────────────────────────────────────────

  private async tryRegister(): Promise<void> {
    try {
      await fetch(`${this.opts.registryUrl}/registry/register`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          did: this._did,
          endpoint: this.endpoint,
          capabilities: [...this.handlers.keys()],
          name: this.opts.name,
          registeredAt: new Date().toISOString(),
        }),
        signal: AbortSignal.timeout(600),
      });
    } catch {
      // `aroha dev` may not be running — that's fine, agents work standalone
    }
  }

  private printBanner(): void {
    const caps = [...this.handlers.keys()].join(", ") || "(none yet)";
    const W = "\x1b[33m";  // yellow
    const G = "\x1b[32m";  // green
    const C = "\x1b[36m";  // cyan
    const R = "\x1b[0m";

    console.log(`${G}✓${R} ${C}${this.opts.name}${R} ready`);
    console.log(`  endpoint     ${this.endpoint}/aroha/v1`);
    console.log(`  DID          ${this._did}`);
    console.log(`  capabilities ${caps}`);
    console.log(`  mode         ${W}dev${R} — flip devMode: false for production\n`);
  }
}

// ─── Factory ──────────────────────────────────────────────────────────────────

/**
 * Create a Aroha micro-agent.
 *
 * @example
 * import { createAgent } from '@aroha-sdk/micro';
 *
 * const agent = createAgent({ name: 'weather', port: 3001 });
 * agent.on('get-weather', async ({ city }) => ({ temp: 22, condition: 'sunny' }));
 * await agent.start();
 */
export function createAgent(opts: MicroAgentOptions): MicroAgent {
  return new MicroAgent(opts);
}
