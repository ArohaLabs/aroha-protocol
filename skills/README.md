# Aroha Agent Skills

Agent Skills (`SKILL.md` with YAML front matter `name` and `description`) for working with the Aroha SDKs. Any host that loads the Agent Skills format can use them.

| Skill | Use it for |
|---|---|
| [aroha-integrate](aroha-integrate/SKILL.md) | **Start here.** Adding Aroha to an existing agent, tool server or API: pick the smallest path (wrap an MCP server, verify in a handler, present a mandate, or run the runtime) and prove it refuses what it should |
| [aroha-mandates](aroha-mandates/SKILL.md) | Issuing and verifying spending and task mandates, the governed verifier profile, guest grants and `actingFor` |
| [aroha-receipts](aroha-receipts/SKILL.md) | Signing and verifying action receipts v2: executed and denied actions, `presentedHash`, trace links |
| [aroha-python-sdk](aroha-python-sdk/SKILL.md) | Verifying mandate chains and Conversation and Memory Profile objects from Python |

Validation: each directory passes `agentskills validate <dir>` from the `skills-ref` reference library (PyPI `skills-ref` 0.1.1). Last run on 2026-10-19 (all four valid). To re-run:

```sh
python -m venv .venv && .venv/bin/pip install skills-ref
for d in skills/*/; do .venv/bin/agentskills validate "$d"; done
```
