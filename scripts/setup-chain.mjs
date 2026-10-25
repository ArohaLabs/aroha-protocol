#!/usr/bin/env node
// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0
/**
 * setup-chain.mjs — Aroha local Anvil deploy + agent registration
 *
 * Deploys the three Aroha contracts to a local Anvil instance and writes
 * chain-addresses.json that chat-demo.mjs reads at startup.
 *
 * Prerequisites (run from WSL/bash):
 *   1. forge build                    # compile contracts → out/
 *   2. anvil                          # leave running in another terminal
 *   3. node scripts/setup-chain.mjs  # this script
 *
 * Then start the demo:
 *   VLLM_URL=http://localhost:8000/v1 node scripts/chat-demo.mjs
 */

import { ethers } from "ethers";
import { readFileSync, writeFileSync, existsSync } from "fs";
import { fileURLToPath } from "url";
import { dirname, join } from "path";

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT      = join(__dirname, "..");

// ── Config ────────────────────────────────────────────────────────────────────

const ANVIL_URL = process.env.ANVIL_URL ?? "http://127.0.0.1:8545";

// Anvil deterministic account #0 — deployer / orchestrator
const DEPLOYER_KEY = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";

// Anvil accounts #1-3 — agent recipient wallets (well-known Foundry test keys)
const AGENT_WALLETS = {
  flight:  "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
  hotel:   "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC",
  payment: "0x90F79bf6EB2c4f870365E785982E1f101E93b906",
};

// ── Helpers ───────────────────────────────────────────────────────────────────

function loadArtifact(contractName) {
  const path = join(ROOT, "out", `${contractName}.sol`, `${contractName}.json`);
  if (!existsSync(path)) {
    console.error(`\n[chain] ERROR: artifact not found at ${path}`);
    console.error("        Please run:  forge build\n");
    process.exit(1);
  }
  const artifact = JSON.parse(readFileSync(path, "utf8"));
  return { abi: artifact.abi, bytecode: artifact.bytecode.object };
}

// ── Main ──────────────────────────────────────────────────────────────────────

async function main() {
  console.log("[chain] Aroha — local Anvil setup");
  console.log("[chain] Connecting to", ANVIL_URL);

  const provider = new ethers.JsonRpcProvider(ANVIL_URL);
  try {
    const block = await provider.getBlockNumber();
    console.log(`[chain] ✓ Anvil running · block #${block}`);
  } catch {
    console.error("[chain] ✗ Cannot connect to Anvil at", ANVIL_URL);
    console.error("         Start Anvil first:  anvil");
    process.exit(1);
  }

  // Reset Anvil to a clean state (wipes all deployed contracts + nonces)
  process.stdout.write("[chain] Resetting Anvil state … ");
  await provider.send("anvil_reset", []);
  // Explicitly set deployer nonce to 0 in case Anvil's reset is async
  await provider.send("anvil_setNonce", [
    new ethers.Wallet(DEPLOYER_KEY).address,
    "0x0",
  ]);
  console.log("✓");

  // Re-create provider + signer after reset — avoid any cached nonce state
  const provider2 = new ethers.JsonRpcProvider(ANVIL_URL);
  const deployer  = new ethers.Wallet(DEPLOYER_KEY, provider2);
  const balance   = await provider2.getBalance(deployer.address);
  console.log("[chain] Deployer  :", deployer.address);
  console.log("[chain] Balance   :", ethers.formatEther(balance), "ETH");

  // ── Load forge artifacts ─────────────────────────────────────────────────────

  console.log("\n[chain] Loading artifacts from out/ …");
  const regArt = loadArtifact("ArohaRegistry");
  const escArt = loadArtifact("ArohaEscrow");
  const repArt = loadArtifact("ArohaReputation");
  console.log("[chain] ✓ Artifacts loaded");

  // ── Deploy with explicit nonces to avoid ethers nonce-caching races ───────────

  let nonce = await provider2.getTransactionCount(deployer.address, "latest");
  console.log("[chain] Starting nonce:", nonce);

  // 1. ArohaRegistry
  process.stdout.write("[chain] Deploying ArohaRegistry …");
  const regFactory = new ethers.ContractFactory(regArt.abi, regArt.bytecode, deployer);
  const regTx      = await regFactory.getDeployTransaction(ethers.ZeroAddress, ethers.ZeroAddress);
  const regSent    = await deployer.sendTransaction({ ...regTx, nonce: nonce++ });
  const regReceipt = await regSent.wait();
  const registryAddress = regReceipt.contractAddress;
  console.log(" ✓", registryAddress);

  // 2. ArohaEscrow
  process.stdout.write("[chain] Deploying ArohaEscrow …");
  const escFactory = new ethers.ContractFactory(escArt.abi, escArt.bytecode, deployer);
  const escTx      = await escFactory.getDeployTransaction(deployer.address);
  const escSent    = await deployer.sendTransaction({ ...escTx, nonce: nonce++ });
  const escReceipt = await escSent.wait();
  const escrowAddress = escReceipt.contractAddress;
  console.log(" ✓", escrowAddress);

  // 3. ArohaReputation
  process.stdout.write("[chain] Deploying ArohaReputation …");
  const repFactory = new ethers.ContractFactory(repArt.abi, repArt.bytecode, deployer);
  const repTx      = await repFactory.getDeployTransaction(registryAddress);
  const repSent    = await deployer.sendTransaction({ ...repTx, nonce: nonce++ });
  const repReceipt = await repSent.wait();
  const reputationAddress = repReceipt.contractAddress;
  console.log(" ✓", reputationAddress);

  // 4. Wire: set reputation oracle
  process.stdout.write("[chain] Wiring reputation oracle …");
  const registry   = new ethers.Contract(registryAddress, regArt.abi, deployer);
  const wireTx     = await registry.setReputationOracle(reputationAddress, { nonce: nonce++ });
  await wireTx.wait();
  console.log(" ✓");

  // ── Write addresses ──────────────────────────────────────────────────────────

  const addresses = {
    registry:     registryAddress,
    escrow:       escrowAddress,
    reputation:   reputationAddress,
    deployer:     deployer.address,
    agentWallets: AGENT_WALLETS,
    anvilUrl:     ANVIL_URL,
    deployedAt:   new Date().toISOString(),
  };

  const outPath = join(ROOT, "chain-addresses.json");
  writeFileSync(outPath, JSON.stringify(addresses, null, 2));

  console.log("\n[chain] ✓ chain-addresses.json written");
  console.log("[chain] ✓ Contracts deployed and wired");
  console.log("\n[chain] Agent wallets (Anvil accounts 1-3):");
  for (const [name, addr] of Object.entries(AGENT_WALLETS)) {
    const bal = ethers.formatEther(await provider2.getBalance(addr));
    console.log(`         ${name.padEnd(10)} ${addr}  (${bal} ETH)`);
  }
  console.log("\n[chain] Ready! Start the demo:");
  console.log("         VLLM_URL=http://localhost:8000/v1 node scripts/chat-demo.mjs\n");
}

main().catch(e => {
  console.error("[chain] Fatal:", e.message);
  process.exit(1);
});
