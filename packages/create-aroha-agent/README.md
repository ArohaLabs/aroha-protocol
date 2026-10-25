# create-aroha-agent

Zero-config scaffolder for Aroha agents. It runs `aroha init --yes` from `@aroha-sdk/cli`.

## Usage

No install needed:

```bash
npx create-aroha-agent my-agent
cd my-agent && npm install && npm run dev
```

## Flags

- `--type <provider|orchestrator>` — agent type (default: `provider`).
- `--port <n>` — Aroha port (default: `3001` for a provider, `3000` for an orchestrator).

To wrap an existing MCP server instead, use `npx @aroha-sdk/cli convert --from mcp --endpoint <url>`.

## What a provider scaffold contains

- **A persistent identity.** The first run generates an Ed25519 key and writes it to `.env` as `AROHA_PRIVATE_KEY` (git-ignored). Later runs reuse it, so the agent keeps the same key and DID.
- **Mandate chain verification** in `src/mandate.ts`. Set `AROHA_MANDATE_ROOT_DID` to the DID of the human you accept spending authority from, and every `ArohaRequest` / `ArohaReserve` must carry a mandate in `body.credentialToken` whose signed chain verifies link by link back to exactly that root, granted to the DID that signed the envelope:

```typescript
const result = await verifyMandateChain(token, resolveContentAddressedKey, {
  expectedRoot: ROOT_DID,
  expectedGrantee: envelope.from,
});
if (!result.valid || result.chainVerified !== true) {
  reject(403, "Aroha_FORBIDDEN", `Mandate rejected: ${result.reason ?? "chain not verified"}`);
}
```

If `AROHA_MANDATE_ROOT_DID` is unset, mandates are **not** enforced, and the agent prints a warning at startup. The older `AROHA_MANDATE_ISSUER_PUBLIC_KEY` setting is rejected at startup: a single issuer key cannot prove a delegated chain.

## License

Apache-2.0 — see [LICENSE](../../LICENSE).