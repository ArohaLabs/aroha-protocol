# @aroha-sdk/mcp-guard

![Beta](https://img.shields.io/badge/status-beta-blue) ![npm](https://img.shields.io/npm/v/@aroha-sdk/mcp-guard) ![Zero deps](https://img.shields.io/badge/dependencies-0-green)

**A firewall for your AI agent's tools.** Wrap any MCP server with action limits, always-deny rules, human approval gates, and a full audit log — zero code, one config change.

Your assistant's GitHub MCP server can delete repos. Your database server can drop tables. The model is polite, but politeness is not a security boundary. `mcp-guard` puts a hard boundary between the model and every tool it can reach.

## Quick start

Take any MCP server in your client config and wrap it:

**Before:**
```json
{
  "mcpServers": {
    "github": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-github"]
    }
  }
}
```

**After:**
```json
{
  "mcpServers": {
    "github": {
      "command": "npx",
      "args": ["-y", "@aroha-sdk/mcp-guard",
               "--block", "delete_*",
               "--gate",  "merge_*,create_repository",
               "--limit", "create_*:10",
               "--",
               "npx", "-y", "@modelcontextprotocol/server-github"]
    }
  }
}
```

That's it. Works with Claude Desktop, Cursor, Windsurf, Cline, Zed — anything that speaks MCP over stdio. The wrapped server needs no changes and never knows the guard is there.

## What each rule does

| Rule | Behaviour |
|------|-----------|
| `--block <globs>` | Matching tools are **always denied**. The model gets a clear refusal, the server never sees the call. |
| `--limit <glob>:<n>` | At most *n* calls per session across all tools matching the glob. The n+1th call is denied with a "do not retry" message. |
| `--gate <globs>` | Each call **pauses for human approval** — your client shows an approve/deny prompt with the tool name and arguments. MCP 2026-07-28 clients get a Multi Round-Trip Request (`input_required` with an embedded form, retried with `inputResponses`); older clients get a server-initiated elicitation, where no response within the timeout (default 120s) means deny. Clients without elicitation support fail closed: the call is denied at once, and the refusal says the client could not ask — it never claims you declined. |
| *(always on)* | Every decision is appended to `~/.aroha/mcp-guard.jsonl` — tool, timestamp, allow/deny — plus a session receipt on exit. Disable with `--no-log`. |

**Check that your client can ask.** A gate is only an "ask me" if your MCP client can show approval prompts (MCP elicitation, or the 2026-07-28 multi round-trip). If it cannot, every gated tool is refused — safe, but you are never asked. Each refusal says which it was: you declined, you dismissed the prompt, nobody answered within `--gate-timeout`, or the client could not show it. Support differs by client and version (public reports disagree for Claude Desktop), so gate one harmless tool first and confirm you see the prompt.

**List the real tool names before writing rules.** Globs match names, and servers name things their own way: the GitHub server pushes with `push_files` and comments with `add_issue_comment`, which a `send_*,create_*` rule misses. Rules are deny-lists, so a tool with a verb you did not list is allowed.

Globs are simple: `*` matches anything, `?` one character, matching is case-insensitive. Rules also accept env vars (`AROHA_GUARD_BLOCK`, `AROHA_GUARD_LIMIT`, `AROHA_GUARD_GATE`) so config args stay short.

### Approvals across protocol revisions

The guard picks the gate mechanism per request. A `tools/call` whose `_meta`
names protocol revision `2026-07-28` (or later) gets the stateless
Multi Round-Trip Request pattern: the guard answers
`resultType: "input_required"` with an `aroha_guard_approval` form and an
HMAC-protected `requestState` holding the approval id, the tool name and a
hash of the arguments. The retry is forwarded only when that state verifies
(unexpired, signed by this guard) and names the same tool and arguments, and
the form answer is an explicit approve. The guard strips its own fields
before forwarding; when the wrapped server asks for input itself, the guard
wraps that server's `requestState` so the next retry is still recognised as
approved. Set `AROHA_GUARD_STATE_KEY` (64+ hex characters) when approvals
must survive a proxy restart; the default key is random per process.

Requests without the 2026-07-28 `_meta` envelope (clients that opened with
`initialize`) keep the elicitation behaviour.

### Re-approval when a tool's definition changes

The guard fingerprints every tool in each `tools/list` result it sees
(name, title, description, input/output schema, annotations). If a later
list shows a different definition for a tool, the next call to that tool
needs a human approval even when no rule gates it; the approved definition is
then pinned. When a list carried a `ttlMs` freshness hint (2026-07-28) and
it has expired, the guard fetches a fresh list from the wrapped server before
deciding a call, so an expired client cache cannot hide a changed definition.

## Why fail closed?

Every ambiguous situation resolves to *deny*: unknown elicitation support, approval timeout, malformed rules at startup. A guard that fails open is decoration.

## Recipes

**Read-only database access:**
```
--block "insert_*,update_*,delete_*,drop_*,execute_*"
```

**Filesystem with a write budget:**
```
--limit "write_file:20" --block "delete_*" --gate "move_*"
```

**Anything irreversible needs a human:**
```
--gate "send_*,delete_*,merge_*,deploy_*,publish_*"
```

**Audit only (observe before you restrict):**
```
--name "github" --log ./github-audit.jsonl
```

## Library use

The rule engine and proxy are exported for embedding:

```typescript
import { GuardEngine, parseRules } from "@aroha-sdk/mcp-guard";

const engine = new GuardEngine(parseRules({
  block: ["delete_*"],
  limit: ["create_*:5"],
  gate:  ["merge_*"],
}));

engine.decide("delete_repo");  // { action: "block", reason: "..." }
```

## Part of the Aroha Protocol

`mcp-guard` is the zero-config entry point to [Aroha](https://www.aroha-labs.com) — cryptographically bounded authority for AI agents. When you outgrow session-scoped globs and need signed, verifiable, delegable authority (spending mandates, task mandates, receipts), the same rules become [Ed25519-signed mandates](https://www.aroha-labs.com/docs/mandates) that survive across agents and organisations.

MCP calls the tools. **mcp-guard bounds what they're allowed to do.**

## License

Apache-2.0 — see [LICENSE](../../LICENSE).