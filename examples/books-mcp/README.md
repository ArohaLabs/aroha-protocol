<!-- Copyright (c) 2026 Aroha Labs
     SPDX-License-Identifier: Apache-2.0 -->

# books-mcp — read-only SQL over MCP stdio (demo)

A small demonstration MCP server used in the document-intelligence demos: it exposes a
practice's "books" (a SQLite file) to an agent as two read-only tools, so budget questions are
answered by querying figures rather than by a model adding up numbers from prose.

This is **example code**, not a published package (it moved here from `packages/aroha-books-mcp`,
which was never an npm package).

## Files

| File | Purpose |
|------|---------|
| `index.mjs` | The MCP stdio server: `books_schema` (introspects the tables) and `books_query` (one `SELECT`, capped at 200 rows) |
| `seed.mjs` | Builds a sample retainer-billing practice database |
| `seed-audit.mjs` | Builds a second, differently shaped audit-practice database |

## Run

Requires Node.js ≥ 22.5 (uses the built-in `node:sqlite`).

```bash
node seed.mjs ./data/books.db          # or: node seed-audit.mjs ./data/audit.db
BOOKS_DB=./data/books.db node index.mjs # speaks MCP JSON-RPC on stdin/stdout
```

Point any MCP host at it as a stdio server:

```json
{ "mcpServers": { "books": { "command": "node", "args": ["examples/books-mcp/index.mjs"], "env": { "BOOKS_DB": "./data/books.db" } } } }
```

## Read-only, enforced twice

The database is opened with `readOnly: true`, and every statement is checked before it runs
(a single `SELECT`; no second statement, write verb, `PRAGMA` or `ATTACH`). The open flag is the
real protection; the statement check lets the agent be told *why* a query was refused.

The seed data is fictional.
