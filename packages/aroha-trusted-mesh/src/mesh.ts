// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Aroha Trusted Mesh Mode
 *
 * When agents communicate within a VPC, Kubernetes pod network, or mTLS
 * service mesh, the network itself provides transport-level trust. Ed25519
 * signature verification adds latency with no additional security benefit.
 *
 * This module provides:
 *   - createTrustedMeshOptions(): ArohaServerOptions fragment that bypasses
 *     signature verification for known peer DIDs.
 *   - TrustedMeshClient: ArohaClient wrapper that sends unsigned envelopes
 *     to eliminate the per-message signing overhead.
 *
 * Security model:
 *   - Only use this within a network boundary you control (VPC, mTLS mesh).
 *   - A signature is skipped only when BOTH hold: the request arrived from a
 *     trusted network (or passes your own transport check, e.g. an mTLS
 *     peer certificate), AND the claimed DID is on the allowlist.
 *   - The DID allowlist alone is NOT a control. With signatures skipped,
 *     `envelope.from` is unauthenticated — anything that reaches the
 *     listener can write an allow-listed DID into it. This module used to
 *     decide on the DID alone; that let any client that could reach the
 *     port impersonate a mesh peer. The transport check is what makes the
 *     DID mean something.
 *   - Nonce and expiry checks are always enforced regardless of mesh mode.
 */

import { BlockList, isIP } from "node:net";
import type { IncomingMessage } from "node:http";
import {
  ArohaClient,
  buildUnsignedEnvelope,
  type ArohaEnvelope,
  type ArohaMessageType,
  type ArohaBodyByType,
  type SendOptions,
  newCorrelationId,
} from "@aroha-sdk/core";

// ─── Server-side: bypass signature for trusted peers ─────────────────────────

export interface TrustedMeshServerOptions {
  /**
   * DID allowlist — signature verification is skipped for these senders.
   * All other senders still require valid Ed25519 signatures.
   */
  trustedDIDs: string[];
  /**
   * Optional prefix match — trust any DID starting with this prefix.
   * Example: "did:aroha:internal:" trusts all internal agents.
   */
  trustedPrefixes?: string[];
  /**
   * Networks a request must arrive from, as CIDR ranges or single addresses
   * ("10.0.0.0/8", "fd00::/8", "192.168.1.20"). Defaults to loopback only
   * (127.0.0.0/8 and ::1) — the one network that is trusted on every host.
   * A VPC deployment names its own ranges here.
   */
  trustedNetworks?: string[];
  /**
   * Your own transport check, run in addition to `trustedNetworks` — for
   * example, that the TLS socket carries an authorised mesh peer
   * certificate. Return false to require a signature.
   */
  isTrustedTransport?: (req: IncomingMessage) => boolean;
}

const LOOPBACK = ["127.0.0.0/8", "::1"];

function buildNetworkList(networks: string[]): BlockList {
  const list = new BlockList();
  for (const entry of networks) {
    const [addr, bits] = entry.split("/");
    const family = isIP(addr);
    if (family === 0) throw new Error(`trustedNetworks: "${entry}" is not an IP address or CIDR range`);
    const type = family === 6 ? "ipv6" : "ipv4";
    if (bits === undefined) list.addAddress(addr, type);
    else list.addSubnet(addr, Number(bits), type);
  }
  return list;
}

function remoteAddressOf(req: IncomingMessage): { addr: string; type: "ipv4" | "ipv6" } | null {
  let addr = req.socket?.remoteAddress;
  if (!addr) return null;
  // An IPv4 client on a dual-stack socket arrives as ::ffff:a.b.c.d.
  if (addr.startsWith("::ffff:") && isIP(addr.slice(7)) === 4) addr = addr.slice(7);
  const family = isIP(addr);
  if (family === 0) return null;
  return { addr, type: family === 6 ? "ipv6" : "ipv4" };
}

/**
 * Returns a partial ArohaServerOptions object to merge into your server config.
 *
 * Provides `bypassSignatureForRequest`, which skips signature verification
 * only for a request that arrived over a trusted transport AND claims an
 * allow-listed DID. It deliberately does NOT provide the deprecated
 * DID-only `bypassSignatureFor` — see the security model above.
 *
 * Usage:
 *   const server = new ArohaServer({
 *     ...myOpts,
 *     ...createTrustedMeshOptions({
 *       trustedDIDs: [...],
 *       trustedNetworks: ["10.0.0.0/8"],
 *     }),
 *   });
 */
export function createTrustedMeshOptions(opts: TrustedMeshServerOptions): {
  bypassSignatureForRequest: (req: IncomingMessage, senderDID: string) => boolean;
} {
  const allowlist = new Set(opts.trustedDIDs);
  const prefixes = opts.trustedPrefixes ?? [];
  const networks = buildNetworkList(opts.trustedNetworks ?? LOOPBACK);

  const didAllowed = (did: string): boolean =>
    allowlist.has(did) || prefixes.some((prefix) => did.startsWith(prefix));

  return {
    bypassSignatureForRequest(req: IncomingMessage, senderDID: string): boolean {
      // Transport first: the DID means nothing until we know the request
      // came from somewhere only mesh peers can reach.
      const remote = remoteAddressOf(req);
      if (!remote || !networks.check(remote.addr, remote.type)) return false;
      if (opts.isTrustedTransport && !opts.isTrustedTransport(req)) return false;
      return didAllowed(senderDID);
    },
  };
}

// ─── Client-side: send unsigned envelopes ────────────────────────────────────

/**
 * ArohaClient variant that sends unsigned envelopes.
 * Use within a trusted mesh where the receiving server is configured with
 * createTrustedMeshOptions(), and this client's traffic arrives from one of
 * its trusted networks.
 *
 * All standard ArohaClient methods are available — only send() is overridden
 * to inject the unsigned envelope builder.
 */
export class TrustedMeshClient extends ArohaClient {
  constructor(
    private readonly senderDID: string,
    private readonly recipientDID: string
  ) {
    super();
  }

  /**
   * Build and send an unsigned Aroha envelope.
   * The receiving server must trust both this DID and the network it arrives from.
   */
  async sendUnsigned<T extends ArohaMessageType>(
    endpoint: string,
    type: T,
    body: T extends keyof ArohaBodyByType ? ArohaBodyByType[T] : Record<string, unknown>,
    correlationId?: string,
    opts?: SendOptions
  ): Promise<ArohaEnvelope | null> {
    const cid = correlationId ?? newCorrelationId();
    const envelope = await buildUnsignedEnvelope(
      type,
      this.senderDID,
      this.recipientDID,
      body,
      cid
    );
    return this.send(endpoint, envelope, opts);
  }
}

// ─── Zone helper ─────────────────────────────────────────────────────────────

/**
 * Create a named trust zone — a group of DIDs that trust each other.
 * Returns server options and a pre-configured TrustedMeshClient factory.
 *
 * Usage:
 *   const zone = createTrustedZone(["did:aroha:agent-a", "did:aroha:agent-b"]);
 *   const serverOpts = zone.serverOptions;
 *   const client = zone.createClient("did:aroha:agent-a", "did:aroha:agent-b");
 */
export function createTrustedZone(
  trustedDIDs: string[],
  prefixes?: string[],
  network?: Pick<TrustedMeshServerOptions, "trustedNetworks" | "isTrustedTransport">,
) {
  const serverOptions = createTrustedMeshOptions({
    trustedDIDs,
    trustedPrefixes: prefixes,
    ...network,
  });

  return {
    serverOptions,
    createClient(senderDID: string, recipientDID: string): TrustedMeshClient {
      return new TrustedMeshClient(senderDID, recipientDID);
    },
  };
}
