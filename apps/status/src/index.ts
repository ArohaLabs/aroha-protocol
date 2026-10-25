// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

import express from "express";

const app = express();
const PORT = process.env.STATUS_PORT ?? 4000;

interface ServiceStatus {
  name: string;
  url: string;
  status: "operational" | "degraded" | "down";
  latencyMs?: number;
  checkedAt: string;
}

async function checkService(name: string, url: string): Promise<ServiceStatus> {
  const start = Date.now();
  try {
    const res = await fetch(url, { signal: AbortSignal.timeout(5_000) });
    const latencyMs = Date.now() - start;
    return {
      name, url,
      status: res.ok ? "operational" : "degraded",
      latencyMs,
      checkedAt: new Date().toISOString(),
    };
  } catch {
    return { name, url, status: "down", checkedAt: new Date().toISOString() };
  }
}

// The deployed Aroha services. Same hosts as AROHA_MANAGED_REGISTRY_URL and
// AROHA_DEFAULT_IPFS_GATEWAY in @aroha-sdk/core/endpoints (inlined: this app
// does not depend on the SDK). No custom domains are attached to either
// Worker, so the workers.dev hosts are what resolves.
const MANAGED_REGISTRY_URL = "https://aroha-registry.aroha-labs.workers.dev";
const IPFS_GATEWAY_ORIGIN = "https://aroha-ipfs-gateway.aroha-labs.workers.dev";

function trimSlash(u: string): string {
  return u.trim().replace(/\/+$/, "");
}

// Full probe URLs: REGISTRY_URL / IPFS_URL (legacy names). Otherwise derived
// from AROHA_REGISTRY_URL / AROHA_IPFS_GATEWAY (the SDK's override variables)
// or the managed defaults.
const REGISTRY_PROBE = process.env.REGISTRY_URL
  ?? `${trimSlash(process.env.AROHA_REGISTRY_URL || MANAGED_REGISTRY_URL)}/health`;
const IPFS_PROBE = process.env.IPFS_URL
  ?? `${process.env.AROHA_IPFS_GATEWAY ? new URL(process.env.AROHA_IPFS_GATEWAY).origin : IPFS_GATEWAY_ORIGIN}/api/v0/version`;

app.get("/api/status", async (_req, res) => {
  const services = await Promise.all([
    checkService("Registry API", REGISTRY_PROBE),
    checkService("IPFS Gateway", IPFS_PROBE),
  ]);

  const overall = services.every(s => s.status === "operational") ? "operational" : "degraded";
  res.json({ overall, services, generatedAt: new Date().toISOString() });
});

app.get("/", (_req, res) => {
  res.send(`<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><title>Aroha Status</title>
<style>body{font-family:sans-serif;max-width:700px;margin:2rem auto}
.operational{color:#16a34a}.degraded{color:#d97706}.down{color:#dc2626}</style>
</head>
<body>
<h1>Aroha Protocol Status</h1>
<p>Live status: <a href="/api/status">/api/status</a></p>
<div id="status">Loading...</div>
<script>
fetch("/api/status").then(r=>r.json()).then(d=>{
  document.getElementById("status").innerHTML =
    "<h2 class='"+d.overall+"'>Overall: "+d.overall+"</h2>"
    + d.services.map(s=>"<p class='"+s.status+"'>"+s.name+": "+s.status+(s.latencyMs?" ("+s.latencyMs+"ms)":"")+"</p>").join("")
    + "<p><small>Updated: "+d.generatedAt+"</small></p>";
});
</script></body></html>`);
});

app.listen(PORT, () => console.log(`[Aroha Status] listening on port ${PORT}`));
