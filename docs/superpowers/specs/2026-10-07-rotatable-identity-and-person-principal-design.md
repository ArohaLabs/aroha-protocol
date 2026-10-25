<!-- Copyright (c) 2026 Aroha Labs
     SPDX-License-Identifier: Apache-2.0 -->

# Rotatable Identity and the Person Principal — Design

**Date:** 2026-10-07
**Status:** Implemented in the SDK (`@aroha-sdk/core`, `@aroha-sdk/credentials`, `@aroha-sdk/registry`); runtime and registry-server adoption pending (§8).
**Normative text:** [DID method → Rotatable identifiers (E-form) and Key Event Logs](../../spec/did-method.md#rotatable-identifiers-e-form-and-key-event-logs).
**Builds on:** [local runtime design §7.10](./2026-08-14-aroha-local-runtime-design.md) (key-derived personal names), [human identity design](./2026-08-18-human-identity-design.md) (Phase 3 per-user keys).

---

## 1. The problems

**1. Self-certifying DIDs cannot rotate.** `did:aroha:z<base58btc(pubkey)>` is the DID the runtime mints for every agent, because it is the only form a peer can verify with no registry: the key is the DID. That same property makes rotation impossible. A verifier deriving the key from the string ignores any rotation record, so:

- a **lost** device takes the identity with it — and with it the personal name (§7.10 derives it from the key), reputation, access grants, contacts, and anything that pinned the DID;
- a **stolen** device is worse: the thief *is* the identity, forever, and there is nothing the owner can publish that a verifier will believe over the DID itself.

The named form rotates, but only because a registry says which key is current — exactly the trust the z-form was introduced to remove.

**2. There is no person principal.** Every agent DID is self-controlled. Nothing says "these agents act for this person, and the person can revoke one". A mandate's root is just whichever DID signed first, which may be an agent minting its own authority. The human-identity design's Phase 3 gave users keys, but the receiver still had to trust the agent's attestation that a key belongs to a person.

## 2. What we built

**A. Inception-based, self-certifying identifiers with pre-rotation (KERI-style).**

```
did:aroha:E<base58btc(sha256(JCS(inception event without sig)))>
```

The identifier commits to a signed *inception event*, not to a key. The inception names the current key **and a digest of the next key**. Every later change is an event in an append-only Key Event Log (KEL), hash-chained by `prior` digest and `seq`, and authorised by something the previous state committed to:

| Event | Authorised by | Thief with only the current key… |
|---|---|---|
| `inception` | its own key (proof of possession) | — |
| `rotate` | the pre-committed next key, revealed and signing | cannot rotate |
| `recover` (agents) | the controller person, by sealing it in the person's KEL | cannot recover |
| `revoke` | the controller (sealed), or the identity's own next key | cannot revoke |
| `anchor` (persons) | the person's current key | (person keys: see §5) |

`verifyKel` replays the log offline: DID = inception digest, every signature, sequence, chaining, pre-rotation reveal = commitment, controller seals. A registry or peer can withhold events or serve a stale prefix; it cannot forge one. An inception-only DID verifies with the inception alone, so the z-form's zero-network property survives as long as the inception travels with first contact.

**B. Person principal.** A person is an E-DID of kind `person`. An agent's inception may name `controller: <person DID>`, fixed for life (it is inside the digest). `verifyAgentControlledBy` answers "does this person control this agent, right now". `verifyMandateChain` gains `kelSource`, `requirePersonRoot` and `expectedRootPerson`: the root must be an unrevoked person signing with their current key, and every E-DID grantor/grantee in the chain is checked against its KEL — a revoked agent (or an agent whose person revoked itself) kills the chain.

**C. Migration.** `migrateLegacyIdentity(zDid, zPrivateKey, opts)` creates an E-DID and a linkage `{from, to, toSeq, at}` signed by both the old key and the new identity's key at `toSeq`. Anyone who trusted the old DID can verify the new one belongs to the same holder.

**D. Personal names** for E-DIDs derive from the 32-byte inception digest through the same wordlist + scrypt pipeline (salt `aroha:personal-name:v1:inception`). **Names now survive rotation and recovery** — the payoff for naming. z-DID names are unchanged byte for byte.

**E. Signed Agent Records** for E-DIDs carry (or the verifier fetches) the KEL; the signature is checked against the KEL's current key, never a key in the record.

**F. Spec** section added; z-form marked legacy (non-rotatable), named form registry-trusted.

**G. JCS** moved from credentials to core (credentials re-exports it) so mandates and KEL events share one canonicaliser; core must not depend on credentials.

## 3. Decisions and the alternatives we rejected

**Anchors, not controller signatures.** The obvious design is "a recover event signed by the controller's current key". Rejected: a signature carries no ordering. If a person's key K1 leaked and they rotated to K2, a thief holding K1 can still sign a recover naming K1 "as the key of the time", and a verifier holding the person's complete, honest KEL cannot tell it came after the rotation. Anchoring puts the authorisation *inside* the person's hash-chained log at a sequence number; after the rotation K1 cannot append to the honest log, only fork it — and forks are what duplicity detection catches. Anchors also give **freshness for free**: a seal `{did, seq, digest}` tells any verifier holding the person's KEL that agent X has an event at seq N, so an agent log served without its revocation is detectably stale. Cost: recovery/revocation writes two logs (agent and person). Accepted.

**Separate prefix inside the existing method, not a new method.** `did:aroha:E…` keeps every `did:aroha:` code path (envelope `from`, registry keys, mandate fields) working, and the three forms are mutually exclusive by syntax: z-form starts with `z`; named DIDs are lowercase per the spec grammar, and `generateDID` now refuses any name that parses as a z- or E-form identifier. The parser is strict (exactly 32 bytes, canonical re-encoding), so `did:aroha:Echo` is a name, not an identifier.

**Keys current at verification time.** Mandates, envelopes and SARs from an E-DID verify against the key current *when verified*. After a rotation, outstanding mandates signed by the old key fail and must be re-issued. That is precisely right after a theft, and an acceptable cost after a routine rotation because mandates are short-lived. The alternative (verify against "the key current at issuance") needs a trusted issuance time, which nothing in a mandate provides — the timestamp is written by the possibly-stolen key.

**Single key per event in v1.** `keys` is an array so weighted multisig (KERI thresholds) can arrive in a later version without a wire-format break; v1 verifiers reject anything but exactly one key.

**The SAR `kel` field is outside the signature.** The log authenticates itself. Leaving it unsigned lets an index attach a newer log — and if that log has rotated away from the record's signing key, the record correctly stops verifying.

**Separate salt for inception-digest names.** Not load-bearing against any known attack (colliding a digest with a key is a 2^256 problem); it is hygiene so a future change to either derivation cannot alias the other.

**Person recovery is pre-rotation only.** There is no one above a person to vouch for a new key. The recovery story is the next key, kept away from the current one (§5). Losing both is unrecoverable by design; migration with a linkage is the fallback, and relationships must re-trust the link.

## 4. Public API (what the runtime/registry stream adopts)

All from `@aroha-sdk/core` unless noted. Types: `KelEvent` (= `InceptionEvent | RotateEvent | RecoverEvent | RevokeEvent | AnchorEvent`), `KelSeal`, `KelState`, `KelIdentity`, `KelSource = (did) => Promise<KelEvent[] | null | undefined>`, `KelStore`, `KelError` (`code: "invalid" | "stale" | "duplicity" | "controller-unavailable"`).

Creating and extending:
- `incept({ kind, controller?, privateKey?, nextPrivateKey?, now? }): Promise<KelIdentity>`
- `rotateKel(identity, { nextPrivateKey?, now? }?): Promise<KelIdentity>`
- `revokeKelSelf(identity, { reason?, now? }?): Promise<KelEvent[]>`
- `generateKelKeyMaterial(): Promise<KelKeyMaterial>` — for the replacement device
- `recoverAgent(person, agentKel, { publicKey, nextKeyDigest }, { now? }?): Promise<{ person: KelIdentity; agentKel: KelEvent[] }>`
- `revokeAgent(person, agentKel, { reason?, now? }?): Promise<{ person; agentKel }>`
- `anchorInKel(person, seals, { now? }?): Promise<KelIdentity>`

Verifying and resolving:
- `verifyKel(did, events, { resolveControllerKel?, requireController? }?): Promise<KelState>` (throws `KelError`)
- `acceptKel(did, events, store, { …VerifyKelOptions, onStale?: "reject" | "use-stored" }?): Promise<KelState>`
- `resolveKelState(did, source, { store?, requireController? }?): Promise<KelState | null>`
- `kelKeyResolver(source, { store?, requireController? }?): PublicKeyResolver`
- `verifyAgentControlledBy(agentDid, agentKel, personDid, personKel)`
- `InMemoryKelStore`, `kelSourceFromLogs(...logs)`, `keysAtSequence(state, seq)`
- `isInceptionDid`, `inceptionDigestFromDid`, `didFromInception`, `eventDigest`, `keyDigest`, `sha256Digest`, `KEL_VERSION`
- `canonicalizeJcs` (moved here; still exported by credentials)

Migration: `migrateLegacyIdentity(oldDid, oldPrivateKey, inceptOpts)`, `signIdentityLinkage(fromDid, fromPrivateKey, to, now?)`, `verifyLinkage(linkage, toKel, { resolveFromKey?, resolveControllerKel? }?)`.

`@aroha-sdk/credentials`: `VerifyMandateChainOptions` += `kelSource`, `kelStore`, `requirePersonRoot`, `expectedRootPerson`; `createMandateKeyResolver({ kelSource?, kelStore?, fallback? })`.

`@aroha-sdk/registry`: `derivePersonalLabelFromInception(digest)`, `derivePersonalLabelForDid(did)`, `verifyPersonalLabelForDid(label, did)`; `SignedAgentRecord.kel?`, `BuildSarInput.kel?`, `verifySar(candidate, now?, { kelSource?, kelStore? }?)`, new failure reasons `kel_unavailable | kel_invalid | revoked`.

## 5. Where keys live

| Secret | Should live | Why |
|---|---|---|
| Agent current key | Runtime OS keystore (§9.7), usable by the agent process | It signs every message |
| Agent next key | NOT in the agent process: the runtime keystore under a separate entry/policy, or the controller's device | A stolen agent host must not yield the rotation key; if it does, controller recovery is still available |
| Person current key | Passkey / secure-enclave-backed store on the person's primary device | It anchors recoveries and revocations of every agent the person controls |
| Person next key | Offline: printed recovery code / QR, or a second device's passkey store | It is the person's only recovery path |

A person's *current* key is the high-value secret: whoever holds it can anchor recoveries of that person's agents until the person rotates with their next key. After rotating, the person should re-check (and re-recover if necessary) their agents' logs.

## 6. Stale logs and duplicity — the honest limitation

A KEL proves authenticity, not completeness. Mitigations shipped: `KelStore` keeps the longest verified log per DID; a shorter log is stale (rejected, or answered from the stored log); a verified log that differs at any common sequence is a recorded duplicity alarm and the DID is refused from then on; verification happens *before* comparison so junk cannot raise false alarms; controller seals bound agent-log freshness. **Not solved:** a first-contact verifier fed only a forked or stale log, with nothing else to compare, will accept it. KERI's answer is witnesses/watchers; the near-term mitigation is registry plus peers as independent log mirrors and durable verifier stores.

Also stated plainly for migration: a z-DID is its key, so a thief holding it can produce a linkage to an E-DID of their own. Migrate while the key is yours alone; verifiers keep the first linkage per `from` and surface a conflicting second one to a human.

## 7. Testing

- core `identity/kel.test.ts` (33): inception-only verify; tampering of any inception field; rotate with the committed key; rotate signed by the stolen current key rejected; chaining (seq/prior/did); self-revoke closes the log; stolen key cannot self-revoke; controller recover works and is verified against anchors; recover needs the controller's KEL; non-controller recover rejected; anchored-digest mismatch is duplicity; controller revoke reported; withheld revocation detected via seals (stale); controller self-revocation propagates; superseded person key cannot extend the honest log; KelStore duplicity, stale, no false alarms, longest-wins; `kelKeyResolver` survives a lagging source; envelope validation via `kelKeyResolver` across rotation; migration linkage verifies (also after rotation), one-sided linkages fail, revoked successor fails.
- core `conformance/l0-kel-identity.conformance.test.ts` (6) with a **pinned vector** (fixed seeds → exact canonical inception, signature, DID, rotation digest) for other SDKs.
- credentials `mandate-kel.test.ts` (15): person-rooted chain verifies; agent / z-DID / wrong-person roots rejected; `requirePersonRoot` without `kelSource` fails closed; revoked root person; mandate signed by a later-revoked agent fails; mandate granted to a revoked agent fails; withheld revocation caught; missing controller KEL fails closed; old-key mandates fail after rotation, re-issued ones pass; thief's key fails after recovery; KelStore stops a rolled-back registry; `createMandateKeyResolver` never lets a registry answer for E or z.
- registry: E-DID personal name stable across rotation and recovery, z vector unchanged, named DIDs → null; SAR for E-DID verifies (attached or fetched log), follows rotation, ignores in-record keys, reports `kel_unavailable` / `kel_invalid` / `revoked`, recovered agent verifies against the new key only, KelStore defeats a rolled-back index.
- All pre-existing tests unchanged and green.

## 8. Adoption (follow-up stream: runtime + registry server)

**Runtime (`apps/aroha-runtime`).**
1. Mint new agents with `incept({ kind: "agent", controller: personDid })` instead of `generateContentAddressedDID`; persist `KelIdentity` (keys to the keystore per §5, `kel` as JSON next to the identity record).
2. Give each local user (human-identity Phase 3) a person identity: `incept({ kind: "person" })`; export the next key as a recovery code at creation and do not keep it on disk unencrypted.
3. A durable `KelStore` (SQLite: `kel_logs(did PRIMARY KEY, events_json, seq)`, `kel_duplicity(did, seq, digests_json, detected_at)`); wrap with `resolveKelState`/`kelKeyResolver` and compose it ahead of the existing z-DID resolver wherever a `PublicKeyResolver` is built (LAN server, gateway, `aroha-sig` verification). Note `DidResolutionCache` gives E-DIDs the default TTL, never permanent.
4. Ship the KEL with first contact (SAR `kel`, and a KEL attachment on whatever hello/handshake carries the DID) so peers keep the zero-network path.
5. Pass `kelSource` (+ `kelStore`) to `verifyMandateChain`; set `requirePersonRoot: true` at any gate that moves money.
6. UI: "Recover this agent" (person device runs `recoverAgent` with a public key + next digest generated on the new device), "Revoke agent", "Rotate keys"; show duplicity alarms prominently.
7. Migration: for each existing z-DID agent, `migrateLegacyIdentity(did, privateKey, { kind: "agent", controller, privateKey })` (keeps the device key, adds a next-key commitment); publish the linkage; keep the old personal name as a redirecting alias. `apps/aroha-runtime/src/hub/personal-name.ts` uses `publicKeyFromDid` + `derivePersonalLabel` — switch to `derivePersonalLabelForDid`.

**Registry server (`apps/registry-server`).**
1. `GET /v1/kel/:did` → events JSON; `POST /v1/kel/:did` → accepts a log only via `acceptKel` (verify, then reject stale/forked; record duplicity). Logs self-authenticate, so no API key is needed to submit, but rate-limit and cap log length. Require the controller's log to be present (and accepted) before accepting controller-authorised agent events.
2. Serve seals: a person's KEL is what proves an agent's revocation; never serve an agent's log shorter than the controller's seals imply.
3. `apps/registry-server/src/sar-verify.ts` and `src/personal-name.ts` are **copies** of the package code and do not know the E-form; replace them with the package functions (`verifySar(…, { kelSource, kelStore })`, `derivePersonalLabelForDid`). The personal-names route currently derives from `publicKey`; for E-DIDs it must derive from the DID.
4. Store linkages (`from` unique; a second, different `to` is flagged, not followed) and expose `GET /v1/linkage/:from`.

**Docs.** `docs/conformance/test-matrix.md` needs rows L0-KEL-01..06; the ReSpec HTML (`did-aroha-method-1.0.html`, `aroha-1.0.html`) has not been regenerated from the updated markdown.

## 9. Not in scope / future

Witnesses and watchers (first-contact duplicity), weighted multisig keys, person-to-person controller delegation (organisations), delegated agent creation anchored at inception, post-quantum keys in KEL events (the `keys` array and `v` field leave room).
