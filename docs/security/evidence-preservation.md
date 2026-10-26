<!-- Copyright (c) 2026 Aroha Labs
     SPDX-License-Identifier: Apache-2.0 -->

# Evidence Preservation Runbook

**Objective (defensive):** when an agent may have taken an unauthorized action, stop further actions, keep every record needed to reconstruct what happened, and show later that the records were not altered.
**Owner:** @projectmed99 (sole named maintainer, per `MAINTAINERS.md`). **Last reviewed:** 2026-10-15.
**Scope:** the Aroha runtime (the `aroha` binary; its source is not in this repository) and agents that issue signed action receipts with `@aroha-sdk/core`. This is a manual process. No step below is automated unless it says so.

Use it together with the [Incident Response Playbook](incident-response.md). That playbook covers triage, fixes and disclosure. This runbook covers the records.

## What the records are

| Record | Where | Integrity control (what is enforced) |
|---|---|---|
| Audit trail | `<workspace>/logs/audit.jsonl` plus rotated archives | Hash chain. The install key signs the head into `logs/audit-checkpoints.jsonl` every 100 entries, every 5 minutes and at shutdown. The chain is verified at startup and on every audit-health read. |
| Witnessed anchors | `<workspace>/logs/audit-anchors.jsonl` | Only when `auditAnchorUrl` is set (default off). A registry witness countersigns each head, so later truncation or rewriting is detectable. |
| CLI audit journal | `<workspace>/logs/audit-pending.jsonl` | Each line is signed with the install key and folded into the chain. |
| Action receipts | Hash in the audit trail; the receipt travels with outbound actions | Ed25519 by the acting agent. v2 receipts can also record refusals (`outcome: "denied"`). As of 2026-10-15 the runtime does not emit denied receipts yet (see `docs/trust.md`). |
| Kill-switch state | `<workspace>/kill-switch.json` | Persisted, reported in `/v1/admin/status` with who set it and when. |
| Key Event Logs | `<workspace>/kel/` | Hash-chained and signed per identity. |
| Conversations, memory | Workspace files (thread and memory stores) | No signature at rest. Copy them as they are and hash the copy (see step 3). |

## Steps

1. **Stop new actions (contain).** As an admin, set the kill switch with `POST /v1/admin/kill-switch` to the narrowest mode that contains the incident: `throttled` (a rolling-minute budget across all gated traffic), `paused` (every action refused in both directions; consults and chat still answer) or `stopped` (everything refused). The mode persists across restarts, applies to inbound consults, actions, chat and invites over LAN and relay, to outbound peer actions and to consequential MCP tool calls, and every refusal it causes produces a signed denied-action receipt. If a mandate is involved, revoke it at the registry (`POST /v1/mandates/:id/revoke`), so every verifier that consults revocation refuses it.
2. **Record the current state.** Save the output of `GET /v1/admin/status`, including `audit.intact`, `entriesSinceLastCheckpoint`, `auditAnchors.lastAnchoredSeq`, `killSwitch`, `killSwitchMode` and `keystore`. Then take a signed evidence bundle with `POST /v1/admin/evidence`: it contains the audit trail and its verification result, the SHA-256 of every file in `logs/`, the witnessed anchors, the kill-switch state and an index of receipt hashes, is signed with the install key (`aroha.evidence-bundle/v1`), and a copy is written to `<workspace>/evidence/`. Check it with `verifyEvidenceBundle()`. Note the UTC time and who ran the step.
3. **Copy, then hash.** Stop the runtime, so that a shutdown checkpoint signs the final head. Then copy `<workspace>/logs/`, `<workspace>/kel/`, `<workspace>/kill-switch.json` and the conversation and memory stores to write-once or offline storage. Compute SHA-256 of every copied file and store the list beside the copy and in the incident ticket. Do not copy `credentials/`, the keystore or `config.toml` secrets into evidence storage.
4. **Verify the copy.** Start a runtime against a copy of the workspace (never the original) and confirm `audit.intact: true`. If anchors were enabled, confirm the last anchored sequence is at or below the log head and its hash matches. A failure here is itself evidence: record it and do not repair the log.
5. **Collect receipts.** For each action under review, find its receipt hash in the audit trail. Verify the receipt with `verifyActionReceipt` against a key you resolved yourself, and check `receiptMatches` against the recorded arguments. For v2 receipts, read `requesterDid`, `principalDid`, `approval` and `presentedHash`. Where the approval surface kept what it showed, check it with `verifyPresentedHash`.
6. **Hold.** Keep the evidence set unchanged until the post-incident review closes. Record every later access (who, when, why) in the incident ticket.

## Known gaps (stated so that nobody relies on them)

- Witnessed anchoring is off by default. Without it, someone who holds the install key could rewrite the log and re-sign the checkpoints.
- Conversation and memory files are not signed at rest. Their integrity rests on the step-3 hashes taken after the incident.
- The evidence bundle is signed with the install key, so it proves the bundle came from this install, not that the install was uncompromised; pair it with witnessed anchors.
- Receipts prove what the agent claimed, not that the claim is true.

## Verification (how to confirm this runbook works)

Run steps 1 to 5 against a test workspace at least once per quarter. Pass criteria: the kill switch survives a restart; the copied trail verifies; one executed receipt and one denied receipt verify; an evidence bundle verifies and a tampered copy fails; and the hash list matches on a second read. Record the date and result in the weekly report.
