// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Off-TLS envelope sealing (design spec §6.1, M9).
 *
 * The gap this closes: `buildEnvelope`/`validateEnvelope` sign the envelope
 * body but never encrypt it — fine on TLS, where the transport itself
 * provides confidentiality, but "amend Layer 0 to: any bidirectional byte
 * transport; security is provided by Layer 2, not the transport" means a
 * LAN socket or an untrusted relay hop now carries the same envelope with
 * no TLS underneath it at all. The spec's rule: **encryption becomes
 * mandatory off-TLS** — "full-body encryption REQUIRED," not the existing
 * SHOULD.
 *
 * Deliberately NOT implemented by changing buildEnvelope/validateEnvelope
 * themselves — that would mean every existing caller (HTTP/TLS transport,
 * where this protection is redundant with TLS and unnecessary CPU cost)
 * has to start threading a recipient key through message construction.
 * Instead this is sign-then-seal / unseal-then-verify, applied only by
 * transports that need it:
 *
 *   buildEnvelope(...)            // unchanged — signs the real plaintext body
 *   sealEnvelope(envelope, pk)    // wire-only: swaps body for ciphertext
 *   ---- LAN/relay socket ----
 *   unsealEnvelope(sealed, sk)    // wire-only: swaps ciphertext back for plaintext
 *   validateEnvelope(...)         // unchanged — verifies against the restored plaintext
 *
 * unsealEnvelope's output is byte-for-byte the envelope buildEnvelope
 * produced (sealEnvelope/unsealEnvelope only ever touch `body` and the
 * `sealed` marker field), so the existing signature verification path needs
 * no awareness that sealing ever happened.
 */

import { encryptBody, decryptBody, type EncryptedBody } from "../crypto/encryption.js";
import type { ArohaEnvelope, ArohaMessageType } from "../messages/index.js";

/** An envelope whose `body` has been replaced by ciphertext for wire transport. */
export type SealedEnvelope<T extends ArohaMessageType = ArohaMessageType> =
  Omit<ArohaEnvelope<T>, "body"> & { body: EncryptedBody; sealed: true };

/**
 * Wrap an already-built, already-signed envelope's body in ciphertext for
 * transmission over a non-TLS transport. Call this immediately before
 * handing the envelope to a LAN or relay socket — never before signing,
 * since the signature must cover the real plaintext body.
 */
export async function sealEnvelope<T extends ArohaMessageType>(
  envelope: ArohaEnvelope<T>,
  recipientPubKey: Uint8Array,
): Promise<SealedEnvelope<T>> {
  const encrypted = await encryptBody(envelope.body as unknown as Record<string, unknown>, recipientPubKey);
  return { ...envelope, body: encrypted, sealed: true };
}

/**
 * Reverse of sealEnvelope: decrypt `body` back to plaintext so the result
 * can be passed to the ordinary `validateEnvelope`. Throws if `sealed` is
 * not `true` — call sites should not silently treat an unsealed envelope
 * arriving on a supposedly-sealed channel as fine, since that would mean
 * this message crossed the untrusted hop in cleartext.
 */
export async function unsealEnvelope<T extends ArohaMessageType>(
  sealed: SealedEnvelope<T>,
  recipientPrivateKey: Uint8Array,
): Promise<ArohaEnvelope<T>> {
  if (!sealed.sealed) {
    throw new Error("unsealEnvelope: envelope is not marked sealed — refusing to treat cleartext as sealed transport");
  }
  const { body: encrypted, sealed: _sealedFlag, ...rest } = sealed;
  const plaintext = await decryptBody(encrypted, recipientPrivateKey);
  return { ...rest, body: plaintext } as ArohaEnvelope<T>;
}

/** True if a value looks like a SealedEnvelope — use to branch before calling unsealEnvelope. */
export function isSealedEnvelope(value: unknown): value is SealedEnvelope {
  return (
    typeof value === "object" &&
    value !== null &&
    (value as { sealed?: unknown }).sealed === true &&
    typeof (value as { body?: unknown }).body === "object"
  );
}
