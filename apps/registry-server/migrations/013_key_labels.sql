-- Copyright (c) 2026 Aroha Labs
-- SPDX-License-Identifier: Apache-2.0
--
-- What a key is FOR, so somebody can revoke the right one.
--
-- A person who connects Aroha on a laptop, a desktop and a work machine ends
-- up with three live keys, listed as three identical rows differing only by a
-- hash and a timestamp. Revoking the laptop after losing it then means
-- guessing, and guessing wrong revokes the machine they are sitting at.
--
-- The label is supplied by whatever asked for the key — the desktop app sends
-- its computer's name — and is display only. Nothing is authorised by it, and
-- it is never used for scoping: owner_id remains the only thing that decides
-- whose key this is. So a label somebody sets to a lie is a cosmetic problem
-- rather than a security one.

ALTER TABLE api_keys ADD COLUMN label TEXT;
