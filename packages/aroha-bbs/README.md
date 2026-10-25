# @aroha-sdk/bbs

BBS signatures over BLS12-381, following
[draft-irtf-cfrg-bbs-signatures](https://datatracker.ietf.org/doc/draft-irtf-cfrg-bbs-signatures/),
ciphersuite `BLS12381-SHA-256`.

BBS produces one short signature over many messages, which is the property
selective disclosure is built on: a holder can later prove they hold a valid
signature over *all* the messages while revealing only some of them. This is
the primitive the consult design's §11.2 named as missing.

## Read this before using it

**This is a from-scratch implementation and it has not been audited.** It is
correct against every published reference vector — which is a real bar, and
not the same bar as an audit. Nothing in Aroha makes a trust decision on it
today, and it should not be the only thing standing between an attacker and
something that matters until that changes.

Two specific limitations, stated rather than implied:

- **Not constant-time.** It inherits whatever `@noble/curves` guarantees for
  scalar multiplication and adds no protection of its own. Assume a local
  attacker who can time operations learns something.
- **A proof says nothing about who is presenting it.** It proves an issuer
  signed a message set containing the revealed values — not that the party
  showing it is the party it was issued to. Without separate holder binding, a
  proof that leaks is a bearer token. BBS has no opinion on this and neither
  does this package.
- **Randomness is the whole security of a proof.** `prove` draws its blinding
  scalars from `@noble/hashes`' CSPRNG, always. Fixed scalars (needed only to
  reproduce the published fixtures byte for byte) are confined to an internal
  test entry point that the package does not export; `prove` refuses the old
  `unsafeRandomScalars` option, because supplying it destroys zero-knowledge
  and unlinkability.

## Why implement it rather than depend on one

The runtime ships as a single compiled binary via `bun build --compile`, which
cannot load native addons. The maintained BBS libraries are WASM or native
bindings. A pure-JavaScript implementation over `@noble/curves` — already a
dependency of `@aroha-sdk/trust` — is the only option that survives the build,
so the choice was to implement it against the published vectors or not to have
it.

## Verification

The test suite runs the
[DIF/IETF reference fixtures](https://github.com/decentralized-identity/bbs-signature)
committed under `vectors/`:

- Every generator in `generators.json` is re-derived and compared, so the
  ciphersuite id, all five domain separation tags, `expand_len` and
  hash-to-curve are pinned to the standard rather than to our reading of it.
- Every `valid` signature fixture is reproduced **byte for byte** — signing is
  deterministic, so anything short of an exact match is a divergence.
- Every `invalid` fixture is rejected: modified, missing, extra, reordered and
  shuffled messages, a wrong public key, and a changed header.
- Every valid **proof** fixture is reproduced byte for byte by replaying the
  blinding scalars the fixture publishes — including partial disclosure, where
  4 of 10 messages are revealed — and both invalid proof fixtures are
  rejected. This matters more than it does for signing: a zero-knowledge proof
  has no observable output to eyeball, so a self-consistent wrong
  implementation would produce proofs only its own verifier accepts.
- `expand_message_xmd` is cross-checked against `@noble/curves`' independent
  implementation of the same RFC, rather than against constants typed in by
  hand.

```bash
npm test --workspace @aroha-sdk/bbs
```

## Usage

```ts
import { sign, verify, skToPk, utf8 } from "@aroha-sdk/bbs";

const sk = 0x60e55110f76883a13d030b2f6bd11883422d5abde717569fc0731f51237169fcn;
const pk = skToPk(sk);

const messages = [utf8("name=Dana"), utf8("dob=1990-04-12"), utf8("member=true")];
const signature = sign(sk, pk, messages, { header: utf8("credential-v1") });

verify(pk, signature, messages, { header: utf8("credential-v1") }); // true
```

`header` is bound into the signature but is not a message: use it for context
that must not be swappable, such as a credential type or issuance epoch.

`verify` returns `false` for every rejection, including malformed input, so
"invalid" and "unparseable" are not two different call sites for the same
security answer.

### Selective disclosure

```ts
import { prove, verifyProof, utf8 } from "@aroha-sdk/bbs";

// The holder reveals only message 2 ("over_18=true"), proving the issuer
// signed a set containing it — and revealing nothing about name, date of
// birth, or national id.
const proof = prove(pk, signature, messages, [2], {
  header: utf8("credential-v1"),
  presentationHeader: verifierNonce,
});

verifyProof(pk, proof, [messages[2]], [2], {
  header: utf8("credential-v1"),
  presentationHeader: verifierNonce,
}); // true
```

`disclosedIndexes` are the positions in the **original signed set**. The
verifier must know which attribute it is being shown, or a value proven at one
position could be presented as a different attribute — which is why the index
is bound into the challenge alongside the value.

`presentationHeader` is where a verifier's nonce goes. Without one, a proof
that verifier has seen once can be replayed to them forever.
