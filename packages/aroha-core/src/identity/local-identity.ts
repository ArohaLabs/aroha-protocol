// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Structural separation between a locally-minted identity and one that's
 * ready to publish.
 *
 * generateDID() returns an AgentKeyPair carrying the private key — correct
 * for that function, since something has to mint the key. But nothing about
 * AgentKeyPair itself stops it from being handed to a registry-publish call
 * by mistake; an app that mints identities it means to keep local (the
 * common case — most agents/mcps/skills a studio app creates are never
 * meant to be published) has to defensively remember to strip the private
 * key and stamp visibility/published fields by hand at every call site, with
 * no help from the type system if a call site forgets.
 *
 * mintLocalIdentity() + preparePublish() make that a structural guarantee
 * instead of a remembered convention: PublishableIdentity has no privateKey
 * field at all, so there is no object shape a publish function could accept
 * that also happens to carry the secret forward.
 */

import { generateDID, generateContentAddressedDID, type AgentKeyPair, type DIDDocument, type GenerateDIDOptions } from "./did.js";

/** A freshly minted identity that hasn't been prepared for publishing. Carries the private key. */
export interface LocalIdentity {
  readonly kind: "local";
  did: string;
  privateKey: Uint8Array;
  publicKey: Uint8Array;
  document: DIDDocument;
}

/**
 * The subset of a LocalIdentity safe to hand to a registry client —
 * structurally has no privateKey field, not just a convention of leaving it
 * out. Only produced by `preparePublish`, never by `mintLocalIdentity`.
 */
export interface PublishableIdentity {
  readonly kind: "publishable";
  did: string;
  publicKey: Uint8Array;
  document: DIDDocument;
}

export interface MintLocalIdentityOptions extends GenerateDIDOptions {
  /**
   * Mint a content-addressed did:aroha:<pubkey> instead of the default
   * did:aroha:<agentId> (or did:aroha:<namespace>.<agentId>). Needed by any
   * caller that wants the identity to later be eligible for a self-signed
   * SAR or a key-derived personal name (see generateContentAddressedDID's
   * doc comment) — a namespaced DID cannot do either, since neither can
   * recover a public key from the DID string alone. `agentId` is accepted
   * but unused in this mode: a content-addressed DID has no room for one.
   */
  contentAddressed?: boolean;
}

/** Mint a new identity, explicitly tagged as local. Same generation as generateDID(). */
export async function mintLocalIdentity(
  agentId: string,
  endpoint: string,
  options: MintLocalIdentityOptions = {},
): Promise<LocalIdentity> {
  const { contentAddressed, ...didOptions } = options;
  const identity: AgentKeyPair = contentAddressed
    ? await generateContentAddressedDID(endpoint)
    : await generateDID(agentId, endpoint, didOptions);
  return {
    kind: "local",
    did: identity.did,
    privateKey: identity.privateKey,
    publicKey: identity.publicKey,
    document: identity.document,
  };
}

/**
 * The only way to get a PublishableIdentity — an explicit call an app makes
 * at the one point it actually decides to publish, rather than every
 * call site needing to remember not to leak the private key by default.
 */
export function preparePublish(identity: LocalIdentity): PublishableIdentity {
  return {
    kind: "publishable",
    did: identity.did,
    publicKey: identity.publicKey,
    document: identity.document,
  };
}
