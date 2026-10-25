# Instructions for coding agents

This file is for AI coding agents (and people) working in this repository. The
full contributor guide is [CONTRIBUTING.md](CONTRIBUTING.md).

## Layout

- `spec-public/` and `docs/spec/`: the Aroha protocol specification. The
  Markdown and ReSpec HTML copies must stay in sync (CI checks this).
- `packages/`: the TypeScript reference implementation (`@aroha-sdk/*` on npm).
- `sdks/aroha-py`, `sdks/go`, `sdks/java`: the Python, Go and Java SDKs.
- `packages/aroha-credentials/test-vectors/` and `spec-public/vectors/`: shared
  test vectors every SDK is tested against. Keys and tokens in them are
  intentionally fake.

## Build and test

Node 22.12 or later.

```bash
npm ci
npm run build          # all packages, in dependency order
npm test               # vitest across all workspaces
npm run lint
npx tsc --noEmit -p tsconfig.json
npx vitest run --config vitest.conformance.config.ts   # conformance suite
```

One package: `npm run test --workspace=packages/aroha-core`.

Python SDK (Python 3.11 or later):

```bash
cd sdks/aroha-py
pip install -e ".[dev]" -c requirements-ci.txt
python -m pytest -q
```

Run the build, tests and lint before proposing a change. Do not mark work done
while any of them fail.

## Rules

- **Do not change protocol semantics without a spec PR.** Anything that changes
  what goes on the wire or how a verifier decides (envelope fields, signature
  rules, mandate token format, error codes, DID resolution) needs a change to
  the specification first, reviewed on its own. Implementation PRs follow it.
- **Keep the SDKs in step.** If a change touches a shared test vector, every SDK
  that reads that vector must still pass.
- **Sign off every commit (DCO).** Use `git commit -s`. The sign-off email must
  match the commit author. See CONTRIBUTING.md.
- **No secrets.** Never commit real keys, tokens or `.env` files.
- **Say what is true.** Docs and status pages describe what is built and tested
  today. Do not claim audits, certifications, standards status or production
  users that do not exist.
- **Security issues go to SECURITY.md**, not to public issues or pull requests.
