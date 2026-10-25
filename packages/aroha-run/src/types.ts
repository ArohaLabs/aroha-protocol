// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

// ── Message / memory primitives ───────────────────────────────────────────────

export interface Message {
  role:    string;
  content: string;
}

/**
 * Pluggable session store. Implement this interface to back session memory
 * with Redis, Postgres, or any other store.
 * The default (when memory is "session") uses InMemorySessionStore.
 */
export interface SessionStore {
  load(sessionId: string): Promise<Message[]>;
  append(sessionId: string, messages: Message[]): Promise<void>;
  clear(sessionId: string): Promise<void>;
}

// ── Wire types ────────────────────────────────────────────────────────────────

export interface RunRequest {
  message:    string;
  sessionId?: string;
  history?:   Message[];
  context?:   Record<string, unknown>;
  stream?:    boolean;
  /**
   * Content provenance — callers should set "untrusted" when relaying content
   * from an external source (user input, another agent) so handlers can apply
   * appropriate scrutiny. Defaults to "trusted" for direct programmatic callers.
   */
  trust?:     "trusted" | "untrusted";
}

/**
 * Who is speaking to the agent.
 *
 * NOT part of the wire format, and deliberately absent from RunRequest: a
 * caller that could name itself in its own request body could name anyone.
 * The serve layer sets this from something it can actually stand behind —
 * a verified `aroha-sig` signature, or the embedding host's own out-of-band
 * knowledge via `ServeOptions.resolveCaller` — and falls back to
 * `unattributed` rather than guessing.
 *
 * Handlers that key anything per-person (durable memory, per-user quota,
 * per-user audit) must branch on `kind`. Treating an `unattributed` caller
 * as a person is how one user's data leaks to the next.
 */
export interface Caller {
  /**
   * "person"       — a human, identified by the host (session, SSO subject)
   * "agent"        — another agent, identified by a VERIFIED signature
   * "unattributed" — nobody could be identified; the honest default
   */
  kind: "person" | "agent" | "unattributed";
  /** Person DID or host user id, agent DID, or UNATTRIBUTED_CALLER. */
  id: string;
  /** For display only. Never use as an identity key — names are not unique. */
  displayName?: string;
}

/** The id every `unattributed` caller carries, so it is never an empty string. */
export const UNATTRIBUTED_CALLER = "unattributed";

/** The caller used when nobody could be identified. */
export const ANONYMOUS_CALLER: Caller = { kind: "unattributed", id: UNATTRIBUTED_CALLER };

export interface RunResponse {
  message:    string;
  sessionId:  string;
  artifacts?: unknown[];
  usage?:     Record<string, number>;
}

// ── Typed event stream ────────────────────────────────────────────────────────
//
// SSE responses from /v1/run emit newline-delimited JSON where each line is
// one of these event shapes.  Consumers branch on the `type` field.
// The `final` event always comes last and carries the complete message.

export type RunEvent =
  | { type: "token";             delta: string }
  | { type: "thinking";          delta: string }
  | { type: "tool_call";         id: string; name: string; args: unknown }
  | { type: "tool_result";       id: string; result: unknown }
  | { type: "approval_required"; id: string; action: unknown }
  | { type: "final";             message: string; sessionId: string; artifacts?: unknown[]; usage?: Record<string, number> }
  | { type: "error";             requestId: string; message?: string }
  /**
   * Something about HOW this turn was run, addressed to the person watching —
   * not model output and not a failure. History trimmed to fit the context
   * window is the first use: an operator asking "why did it forget?" needs to
   * be able to see that it did, and silent trimming is silent truncation with
   * a delay. Consumers that do not know this type ignore it.
   */
  | { type: "trace";             message: string }
  /**
   * A unit of work the agent did on the way to its answer, addressed to the
   * person watching: a retrieval, a skill being loaded, a memory recall, a
   * consult with another agent.
   *
   * Tool calls already have their own events. This covers everything else the
   * agent does that a user would otherwise experience as an unexplained pause
   * — which, before this existed, was all of it.
   *
   * `status` moves running -> done | failed for the same id, so a consumer can
   * show work in flight rather than only after the fact.
   */
  | {
      type: "step";
      id: string;
      kind: "retrieval" | "skill" | "memory" | "consult" | "context" | "figures";
      label: string;
      detail?: string;
      status: "running" | "done" | "failed";
      /**
       * The passages retrieval actually used, on `kind: "retrieval"` steps.
       *
       * Same reasoning as `table` below: carried on the event because it is
       * for a UI, not for the model. The model gets the passages themselves,
       * inside its prompt; a reader wants to know which documents were read
       * and how well each one matched.
       *
       * `score` is the engine's post-rerank relevance, 0..1. It is the most
       * informative number in the pipeline and it was being computed, used as
       * a cutoff, and then discarded one step before the component built to
       * display it.
       */
      sources?: Array<{
        docId: string;
        docName: string;
        /** 1-based, and absent when the engine could not determine one. */
        page?: number;
        /** Absent for built-in retrieval, which has ranks but no comparable score. */
        score?: number;
      }>;
      /**
       * A computed table, on `kind: "figures"` steps only.
       *
       * Carried on the event rather than left in the tool result because the
       * tool result is written for the MODEL — prose it reads and answers
       * from — while this is for a UI to render as rows and columns. The
       * same numbers, addressed to two different readers.
       *
       * `rows` are figures read from a source verbatim; `derivedRows` were
       * computed from them. A consumer that renders them identically loses
       * the distinction that makes the table checkable, so the two arrive
       * separately rather than pre-merged.
       */
      table?: {
        title: string;
        columns: string[];
        rows: string[][];
        derivedRows: string[][];
        /** The `name = expression` lines behind derivedRows, for showing the working. */
        program: string;
        check: { claim: string; test: string; passed: boolean } | null;
        note: string;
      };
    };

export interface ApprovalDecision {
  sessionId:  string;
  approvalId: string;
  decision:   "approve" | "edit" | "reject" | "respond";
  payload?:   unknown;
}

// ── Handler types ─────────────────────────────────────────────────────────────

/**
 * Context passed to every handler call. Extends RunRequest with server-side
 * helpers that are not part of the wire format.
 *
 * In async-generator handlers, yielding `{ type: "approval_required", id, action }`
 * and then awaiting the yield's return value is equivalent to calling
 * requestApproval() — the serve layer drives gen.next(decision) after the
 * caller POSTs to /v1/resume.
 */
export interface HandlerContext extends RunRequest {
  /** Request a human approval gate. Suspends the SSE stream until /v1/resume is called. */
  requestApproval(action: unknown): Promise<ApprovalDecision>;
  /**
   * Who is speaking. Always present — `{ kind: "unattributed" }` when nobody
   * could be identified, so a handler that forgets to check gets an id that
   * belongs to no one rather than `undefined` silently pooling every caller
   * into one bucket. Set by the serve layer; see the Caller docs for what it
   * is derived from and why it is not on the wire.
   */
  caller: Caller;
}

export type Handler =
  | ((ctx: HandlerContext) => string | Promise<string>)
  | ((ctx: HandlerContext) => AsyncGenerator<string | RunEvent, void, ApprovalDecision | undefined>);

// ── MCP tool definition (subset of MCP spec) ─────────────────────────────────

export interface McpInputSchema {
  type:        "object";
  properties:  Record<string, { type: string; description?: string; enum?: unknown[] }>;
  required?:   string[];
}

export interface McpToolDefinition {
  name:        string;
  description: string;
  inputSchema: McpInputSchema;
}

// ── serve() options ───────────────────────────────────────────────────────────

export interface ServeOptions {
  description?:   string;
  provider?:      string;
  model?:         string;
  systemPrompt?:  string;
  memory?:        "none" | "session" | "persistent";
  /** Supply a custom session store. Defaults to InMemorySessionStore when memory !== "none". */
  sessionStore?:  SessionStore;
  /**
   * Where suspended HITL approvals wait for `/v1/resume`, keyed by approvalId.
   *
   * Defaults to a fresh map per `serve()` call, which is right for a
   * standalone agent that is served once and never replaced. It is wrong for
   * a host that re-serves the same agent while it is running: the new
   * instance starts with an empty map, so a `/v1/resume` for an approval the
   * OLD instance raised finds nothing, answers 404, and the old instance's
   * generator stays suspended until its timeout — the human's decision is
   * lost with no way to give it again.
   *
   * Such a host passes a map it owns, keyed to the agent's identity rather
   * than to one instance, so a pending approval survives being re-served.
   * Keep one map per agent: approvalIds are unique, but a single shared map
   * would let a resume addressed to one agent settle an approval another
   * agent raised.
   */
  pendingApprovals?: Map<string, (d: ApprovalDecision) => void>;
  /**
   * "aroha-sig" — per-caller identity (DEFAULT): requests must be
   *               Ed25519-signed by the calling agent's DID key. Use with
   *               `allowedCallers` for a private agent only specific agents
   *               may call.
   * "bearer"    — shared secret; every holder is indistinguishable
   * "none"      — open; anyone who can reach the listener may run the
   *               handler. Opt-in only (it was the default before).
   */
  auth?:          "none" | "bearer" | "aroha-sig";
  /**
   * CORS policy. Default: no CORS headers at all (browsers on other origins
   * cannot call the agent). `{ origins: ["https://app.example"] }` allows
   * those origins; `{ origins: "*" }` allows any (public, read-only agents).
   * `false` is the same as omitting it — use it to make "the gateway in front
   * owns CORS" explicit.
   */
  cors?:          false | { origins: "*" | string[] };
  /** Request-body cap in bytes; larger requests get 413. Default 1 MiB. */
  maxBodyBytes?:  number;
  /**
   * Interface `start()` binds when called without a host. Default
   * "127.0.0.1" (was "0.0.0.0"). Pass "0.0.0.0" to serve other machines.
   */
  host?:          string;
  bearerTokens?:  Set<string> | string[];
  verifyBearer?:  (token: string) => boolean | Promise<boolean>;
  /**
   * DIDs permitted to call this agent (auth: "aroha-sig"). Omit to accept any
   * caller whose signature verifies — useful when you only need attribution.
   * A caller outside the list is rejected before any key resolution happens.
   */
  allowedCallers?: string[];
  /**
   * Resolves a caller DID to its raw Ed25519 public key. Defaults to the Aroha
   * registry. Return null for unknown DIDs — those requests are rejected.
   */
  resolveCallerKey?: (did: string) => Promise<Uint8Array | null> | Uint8Array | null;
  /** Reject replayed (did, nonce) pairs. Defaults to an in-process guard. */
  consumeNonce?:  (did: string, nonce: string) => Promise<boolean> | boolean;
  /** Accepted clock skew for signed requests. Default 5 minutes. */
  maxSkewMs?:     number;
  /**
   * Identify the human behind a request from the host's own knowledge — a
   * session cookie it issued, an SSO subject it verified. Called for every
   * run; return undefined when nobody is identified.
   *
   * This exists because the host often knows something the wire cannot carry
   * safely. It is only ever consulted for requests the host itself admitted,
   * so whatever it reads (a header the host sets, a lookup it performs) must
   * be something the host sets unconditionally — overwriting, never merging,
   * any value an outside caller supplied.
   *
   * A VERIFIED aroha-sig signature outranks this: a signature is proof, and
   * this is an assertion.
   */
  resolveCaller?: (request: Request) => Caller | undefined | Promise<Caller | undefined>;
  version?:       string;
  /**
   * When true, mounts a /mcp endpoint exposing the agent as an MCP server.
   * Compatible with Claude Desktop and any MCP client.
   */
  exposeMcp?:     boolean;
  /**
   * Additional MCP tools to expose alongside the built-in "run" tool.
   * Each tool's handler receives the parsed args and must return a string.
   */
  mcpTools?:      Array<McpToolDefinition & { handler: (args: Record<string, unknown>) => string | Promise<string> }>;
  /**
   * Content guard — called before the handler for every /v1/run request.
   * Return { blocked: true, reason } to reject the request with 400.
   * Use with ContentScreener from @aroha-sdk/policy for injection defence:
   *
   *   const screener = createContentScreener();
   *   serve("agent", handler, {
   *     contentGuard: (req) => screener.screen(req.message, req.trust ?? "untrusted"),
   *   });
   */
  contentGuard?:  (req: RunRequest) => { blocked: boolean; reason?: string } | Promise<{ blocked: boolean; reason?: string }>;
  /**
   * How long (ms) to wait for a /v1/resume call before auto-rejecting a
   * pending HITL approval. Default: 300_000 (5 minutes).
   */
  approvalTimeoutMs?: number;
}

export interface RegisterOptions {
  apiKey?:       string;
  registryUrl?:  string;
  /** The agent's DID. Required. */
  did?:          string;
  /** IPFS CID of the agent's capability manifest. Required by the registry. */
  manifestCID?:  string;
  /**
   * Proof of key possession (required for every DID except did:aroha:E…):
   * the registry issues a nonce (POST /v1/agents/challenge) that must be
   * signed with the agent key. Pass the 32-byte Ed25519 seed here, or
   * `sign` + `publicKey` for a key held elsewhere (HSM/KMS).
   */
  privateKey?:   Uint8Array;
  sign?:         (message: Uint8Array) => Promise<Uint8Array> | Uint8Array;
  /** Raw 32-byte public key. Required with `sign`; derived from `privateKey` otherwise. */
  publicKey?:    Uint8Array;
}

export interface ArohaAgent {
  /** Start a Node.js HTTP server on the given port. */
  start(port?: number, host?: string): void;
  /**
   * Returns a fetch-style handler `(req: Request) => Promise<Response>`.
   * Use for Cloudflare Workers, Vercel Edge, Bun.serve(), etc.
   */
  readonly fetch: (request: Request) => Promise<Response>;
  /** Register this agent on the Aroha Hub. */
  register(endpointUrl: string, options?: RegisterOptions): Promise<Record<string, unknown>>;
}
