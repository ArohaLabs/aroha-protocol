// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

// THE AGENT'S SIDE. Runs wherever the agent runs. It holds its OWN key only —
// never the customer's. The flow:
//
//   1. node agent.mjs did                    → print the agent's DID; send it to the customer
//                                               ("please authorise this agent")
//   2. the customer runs `customer.mjs authorise <agentDid> …` on their device
//      and sends back the token (in a product: your app's consent screen
//      delivers it, e.g. over your API or an OAuth-style redirect)
//   3. node agent.mjs invoice <serviceUrl> <customerId> <amountUsd> <token>
//
// Every call carries the token PLUS a proof signed with the agent's key over
// this exact request, so a copied token is useless to anyone else.

import { presentMandateHttp } from "@aroha-sdk/credentials";
import { pathToFileURL } from "node:url";
import { loadOrCreateKey } from "./lib/keystore.mjs";

/** Send one invoice under the customer's authorisation. Returns { status, body }. */
export async function sendInvoice({ serviceUrl, audience, key, token, customerId, amountUsd, presentAt }) {
  const url = `${serviceUrl}/tools/send_invoice`;
  const body = JSON.stringify({ customerId, amountUsd });
  const headers = await presentMandateHttp({
    token, holderDid: key.did, holderPrivateKey: key.privateKey,
    audience: audience ?? serviceUrl, method: "POST", url, body,
    ...(presentAt !== undefined ? { now: presentAt } : {}),
  });
  const res = await fetch(url, { method: "POST", headers: { ...headers, "content-type": "application/json" }, body });
  return { status: res.status, body: await res.json().catch(() => null) };
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const key = await loadOrCreateKey(process.env.AGENT_KEY ?? ".keys/agent.json");
  const [cmd, ...args] = process.argv.slice(2);
  if (cmd === "did") {
    console.log(key.did);
  } else if (cmd === "invoice") {
    const [serviceUrl, customerId, amountUsd, token] = args;
    console.log(await sendInvoice({ serviceUrl, key, token, customerId, amountUsd: Number(amountUsd) }));
  } else {
    console.error("usage: node agent.mjs did | invoice <serviceUrl> <customerId> <amountUsd> <token>");
    process.exitCode = 2;
  }
}
