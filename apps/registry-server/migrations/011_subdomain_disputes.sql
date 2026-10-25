-- Migration 011: subdomain dispute path (design spec §9.6)
--
-- Run against production D1:
--   node scripts/migrate.mjs --remote
--
-- Adds the two columns POST /v1/provision-subdomain/dispute writes to.
-- A brand-domain owner who proves control of the matching real domain
-- (.well-known/aroha-firm-claim.json, same single-channel HTTPS proof
-- pattern brand-adjacent provisioning itself requires — see
-- routes/provision.ts's verifyBrandDomainProof()) can flag an already-
-- provisioned subdomain as disputed. Never cleared automatically:
-- resolution (re-allocate, or confirm no real conflict) stays an operator
-- decision — this migration only adds the place to record that a dispute
-- was raised and by what proof, not an automated takedown mechanism.

ALTER TABLE subdomain_claims ADD COLUMN disputed_at INTEGER;
ALTER TABLE subdomain_claims ADD COLUMN dispute_reason TEXT;
