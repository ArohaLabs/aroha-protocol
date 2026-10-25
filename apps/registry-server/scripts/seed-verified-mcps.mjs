#!/usr/bin/env node
// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0
//
// Registers a curated set of REAL, officially-published, vendor-hosted MCP
// servers on the Aroha registry, so an agent builder browsing the Aroha
// marketplace finds working endpoints on day one instead of an empty list.
//
// Every entry below was verified against the vendor's own documentation
// (not a blog, not an aggregator) before being added here — see SOURCE on
// each. None of these are Aroha-operated: each description says so
// explicitly and credits @aroha-sdk/mcp-bridge as the thing that makes them
// callable the Aroha way (DID auth, mandates) rather than raw MCP.
//
// Deliberately excluded:
//   - Playwright: Microsoft ships no official hosted endpoint (self-host only).
//     Registering someone's personal deployment under the Aroha marketplace
//     would misrepresent an unverified third party as "Playwright."
//   - Sentry: domain (mcp.sentry.dev) is confirmed via a first-party redirect
//     from docs.sentry.io, but the exact sub-path wasn't independently
//     confirmed — left out rather than guessed.
//
// Usage:
//   REGISTRY_ADMIN_SECRET=... node scripts/seed-verified-mcps.mjs [--dry-run]
//
// Target registry: REGISTRY_URL_OVERRIDE (legacy name), else AROHA_REGISTRY_URL,
// else the managed registry (AROHA_MANAGED_REGISTRY_URL).

import { resolveRegistryUrl } from "@aroha-sdk/core/endpoints";

const REGISTRY_URL = resolveRegistryUrl(process.env.REGISTRY_URL_OVERRIDE || undefined);
const ADMIN_SECRET = process.env.REGISTRY_ADMIN_SECRET;
const DRY_RUN = process.argv.includes("--dry-run");
const ORG_NAME = "Aroha Marketplace";
const OWNER_ID = "system:marketplace-seed";

if (!ADMIN_SECRET && !DRY_RUN) {
  console.error("REGISTRY_ADMIN_SECRET is required (or pass --dry-run to preview without it).");
  process.exit(1);
}

function wrap(vendor, sourceUrl) {
  return (
    `Official ${vendor} MCP server. Not operated by Aroha Labs. ` +
    `Wrapped for Aroha agents via @aroha-sdk/mcp-bridge, so it can be called ` +
    `with DID auth and mandates like any other Aroha resource. ` +
    `Source: ${sourceUrl}`
  );
}

/** did:aroha:marketplace:<slug> — a distinct namespace from user-registered agents. */
function did(slug) {
  return `did:aroha:marketplace:${slug}`;
}

const MCPS = [
  {
    slug: "gmail", name: "Gmail", endpointUrl: "https://gmailmcp.googleapis.com/mcp/v1",
    toolIds: ["search_messages", "get_message", "get_thread", "list_labels", "create_draft", "modify_labels"],
    description: wrap("Gmail", "developers.google.com/workspace/gmail/api/reference/mcp"),
  },
  {
    slug: "google-calendar", name: "Google Calendar", endpointUrl: "https://calendarmcp.googleapis.com/mcp/v1",
    toolIds: ["list_events", "get_event", "list_calendars", "suggest_time", "create_event", "update_event", "delete_event", "respond_to_event", "search_events"],
    description: wrap("Google Calendar", "developers.google.com/workspace/calendar/api/v3/reference/mcp"),
  },
  {
    slug: "google-drive", name: "Google Drive", endpointUrl: "https://drivemcp.googleapis.com/mcp/v1",
    toolIds: ["copy_file", "create_file", "download_file_content", "get_file_metadata", "get_file_permissions", "list_recent_files", "read_file_content", "search_files"],
    description: wrap("Google Drive", "developers.google.com/workspace/drive/api/reference/mcp"),
  },
  {
    slug: "linear", name: "Linear", endpointUrl: "https://mcp.linear.app/mcp",
    toolIds: [], // Linear's docs describe capabilities in prose, not an enumerated tool list
    description: wrap("Linear", "linear.app/docs/mcp"),
  },
  {
    slug: "notion", name: "Notion", endpointUrl: "https://mcp.notion.com/mcp",
    toolIds: [],
    description: wrap("Notion", "developers.notion.com/guides/mcp/get-started-with-mcp"),
  },
  {
    slug: "github", name: "GitHub", endpointUrl: "https://api.githubcopilot.com/mcp/",
    toolIds: [],
    description: wrap("GitHub", "docs.github.com/en/copilot/how-tos/provide-context/use-mcp-in-your-ide/set-up-the-github-mcp-server"),
  },
  {
    slug: "figma", name: "Figma", endpointUrl: "https://mcp.figma.com/mcp",
    toolIds: [],
    description: wrap("Figma (Dev Mode MCP Server)", "help.figma.com/hc/en-us/articles/32132100833559"),
  },
  {
    slug: "stripe", name: "Stripe", endpointUrl: "https://mcp.stripe.com",
    toolIds: [],
    description: wrap("Stripe", "docs.stripe.com/mcp"),
  },
  {
    slug: "cloudflare-api", name: "Cloudflare API", endpointUrl: "https://mcp.cloudflare.com/mcp",
    toolIds: [],
    description: wrap("Cloudflare API (2,500+ endpoints)", "developers.cloudflare.com/agents/model-context-protocol/mcp-servers-for-cloudflare/"),
  },
  {
    slug: "cloudflare-docs", name: "Cloudflare Docs", endpointUrl: "https://docs.mcp.cloudflare.com/mcp",
    toolIds: [],
    description: wrap("Cloudflare Documentation search", "developers.cloudflare.com/agents/model-context-protocol/mcp-servers-for-cloudflare/"),
  },
  {
    slug: "cloudflare-workers-bindings", name: "Cloudflare Workers Bindings", endpointUrl: "https://bindings.mcp.cloudflare.com/mcp",
    toolIds: [],
    description: wrap("Cloudflare Workers Bindings (storage, AI, compute)", "developers.cloudflare.com/agents/model-context-protocol/mcp-servers-for-cloudflare/"),
  },
  {
    slug: "cloudflare-browser", name: "Cloudflare Browser Rendering", endpointUrl: "https://browser.mcp.cloudflare.com/mcp",
    toolIds: [],
    description: wrap("Cloudflare Browser Rendering (fetch pages, screenshots, markdown)", "developers.cloudflare.com/agents/model-context-protocol/mcp-servers-for-cloudflare/"),
  },
  {
    slug: "cloudflare-radar", name: "Cloudflare Radar", endpointUrl: "https://radar.mcp.cloudflare.com/mcp",
    toolIds: [],
    description: wrap("Cloudflare Radar (global Internet traffic insights, URL scans)", "developers.cloudflare.com/agents/model-context-protocol/mcp-servers-for-cloudflare/"),
  },
  {
    slug: "cloudflare-ai-gateway", name: "Cloudflare AI Gateway", endpointUrl: "https://ai-gateway.mcp.cloudflare.com/mcp",
    toolIds: [],
    description: wrap("Cloudflare AI Gateway (LLM request logs, prompt/response inspection)", "developers.cloudflare.com/agents/model-context-protocol/mcp-servers-for-cloudflare/"),
  },
  {
    slug: "cloudflare-ai-search", name: "Cloudflare AI Search", endpointUrl: "https://autorag.mcp.cloudflare.com/mcp",
    toolIds: [],
    description: wrap("Cloudflare AI Search / AutoRAG (list and search documents)", "developers.cloudflare.com/agents/model-context-protocol/mcp-servers-for-cloudflare/"),
  },
];

async function req(path, opts) {
  const res = await fetch(`${REGISTRY_URL}${path}`, {
    ...opts,
    headers: { "Content-Type": "application/json", Authorization: `Bearer ${ADMIN_SECRET}`, ...opts?.headers },
  });
  const body = await res.json().catch(() => ({}));
  return { status: res.status, body };
}

async function main() {
  console.log(`Target: ${REGISTRY_URL}${DRY_RUN ? " (dry run)" : ""}`);
  console.log(`Entries to register: ${MCPS.length}\n`);

  if (DRY_RUN) {
    for (const m of MCPS) console.log(`  [dry-run] ${m.name} -> ${m.endpointUrl}`);
    return;
  }

  // Mint a dedicated org key rather than reusing an existing one, so these
  // entries are attributable and revocable as a single unit if ever needed.
  const keyRes = await req("/v1/auth/keys", {
    method: "POST",
    body: JSON.stringify({ orgName: ORG_NAME, ownerId: OWNER_ID }),
  });
  if (keyRes.status !== 201) {
    console.error("Failed to mint marketplace API key:", keyRes.status, keyRes.body);
    process.exit(1);
  }
  const apiKey = keyRes.body.key;
  console.log(`Minted API key for org "${ORG_NAME}" (not printed).\n`);

  let created = 0, skipped = 0, failed = 0;
  for (const m of MCPS) {
    const payload = {
      did: did(m.slug),
      name: m.name,
      description: m.description,
      endpointUrl: m.endpointUrl,
      toolIds: m.toolIds,
    };
    const res = await fetch(`${REGISTRY_URL}/v1/mcps`, {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${apiKey}` },
      body: JSON.stringify(payload),
    });
    const body = await res.json().catch(() => ({}));

    if (res.status === 201) {
      console.log(`  ✓ ${m.name.padEnd(28)} ${payload.did} -> ${body.didHash}`);
      created++;
    } else if (res.status === 409) {
      console.log(`  = ${m.name.padEnd(28)} already registered, skipping`);
      skipped++;
    } else {
      console.error(`  ✗ ${m.name.padEnd(28)} ${res.status} ${JSON.stringify(body)}`);
      failed++;
    }
  }

  console.log(`\n${created} created, ${skipped} already present, ${failed} failed.`);
  if (failed > 0) process.exit(1);
}

main();
