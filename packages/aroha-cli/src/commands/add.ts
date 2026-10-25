// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

import { readFile, writeFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import { ask, confirm, closePrompts } from "../utils/prompt.js";
import { banner, success, fatal, log } from "../utils/scaffold.js";

export interface AddCapabilityFlags {
  saga?: boolean;
  port?: number;
}

/** Append a new capability skeleton to an existing agent's handlers.ts */
export async function runAddCapability(capabilityId: string | undefined, flags: AddCapabilityFlags): Promise<void> {
  banner("aroha add capability — extend an existing agent");

  if (!capabilityId) {
    capabilityId = await ask("Capability ID", "my-new-capability");
  }

  const isSaga = flags.saga ?? await confirm("Does this capability need saga support (reserve/commit/cancel)?", false);
  const handlersPath = resolve(process.cwd(), "src/handlers.ts");
  const manifestPath = resolve(process.cwd(), "src/manifest.ts");

  let handlersSource: string;
  try {
    handlersSource = await readFile(handlersPath, "utf8");
  } catch {
    fatal(`Could not read ${handlersPath}. Run this command from the root of a aroha-generated agent.`);
  }

  // ── Inject into switch (capability) in handleRequest ──────────────────────
  const requestPatch = `
        case "${capabilityId}": {
          // TODO: implement ${capabilityId} business logic
          const result = { message: "Not implemented yet" };
          return buildEnvelope("ArohaResponse", agentDID, from,
            { capability, result },
            correlationId, privateKey);
        }`;

  const reservePatch = !isSaga ? "" : `
      case "${capabilityId}": {
        // TODO: check inventory, hold resources, issue token
        const token = \`RES-\${crypto.randomUUID()}\`;
        const expiresAt = new Date(Date.now() + holdDurationMs);
        reservations.set(token, { capability, params, expiresAt, committed: false });
        return buildEnvelope("ArohaReserveAck", agentDID, from,
          { reservationToken: token, expiresAt: expiresAt.toISOString() },
          correlationId, privateKey);
      }`;

  // Insert into ArohaRequest switch before the `default:` case in handleRequest
  let patched = handlersSource.replace(
    /(\/\/ TODO: add your capabilities here\n)?(\s+default:\n\s+return buildEnvelope\("ArohaError"[^}]+code: ArohaErrorCode\.UnknownCapability[^}]+Unknown capability)/,
    `${requestPatch}\n$2`
  );

  if (patched === handlersSource) {
    // Fallback: append before the last `default:` in handleRequest
    log("info", "Could not auto-patch handleRequest — appending stub at end of file");
    patched = handlersSource + `\n// Stub for ${capabilityId} — wire into handleRequest switch:\n${requestPatch}\n`;
  }

  if (isSaga && reservePatch) {
    patched = patched.replace(
      /(\/\/ TODO: add transactional capabilities here\n)?(\s+default:\n\s+return buildEnvelope\("ArohaError"[^}]+code: ArohaErrorCode\.UnknownCapability[^}]+Cannot reserve)/,
      `${reservePatch}\n$2`
    );
  }

  await writeFile(handlersPath, patched, "utf8");
  log("create", `src/handlers.ts — added ${capabilityId} stub`);

  // ── Inject into manifest capabilities array ────────────────────────────────
  try {
    let manifestSource = await readFile(manifestPath, "utf8");
    const capEntry = `    {
      id: "${capabilityId}",
      version: "1.0.0",
      description: "TODO: describe ${capabilityId}",
      inputSchema: { type: "object" as const, properties: {}, required: [] },
      outputSchema: { type: "object" as const },
      async: false,
      maxResponseMs: ${isSaga ? 30000 : 5000},
      requiredTrustLevel: ${isSaga ? 2 : 1} as 0 | 1 | 2 | 3 | 4,
      pricing: { model: "${isSaga ? "per-transaction" : "free"}" as const },
      sagaRole: "${isSaga ? "participant" : "none"}" as const,
      ${isSaga ? `reserveCapabilityId: "${capabilityId}",\n      cancelCapabilityId: "${capabilityId}",` : ""}
    },`;

    // Insert before the closing `]` of capabilities array
    manifestSource = manifestSource.replace(/(\s+\],\s*\n\s+signature)/, `\n${capEntry}\n$1`);
    await writeFile(manifestPath, manifestSource, "utf8");
    log("create", `src/manifest.ts — registered ${capabilityId} capability`);
  } catch {
    log("skip", "src/manifest.ts not found — skipping manifest update");
  }

  closePrompts();
  success(`Capability "${capabilityId}" added${isSaga ? " (saga: reserve/commit/cancel)" : ""}`);
  console.log(`  Open src/handlers.ts and replace the TODO stub with your business logic.\n`);
}
