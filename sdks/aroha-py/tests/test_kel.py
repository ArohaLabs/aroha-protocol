# Copyright (c) 2026 Aroha Labs
# SPDX-License-Identifier: Apache-2.0

"""E-DIDs and Key Event Logs (aroha.kel).

The L0-KEL-01 expected values are copied verbatim from the TypeScript
conformance suite:
  packages/aroha-core/src/conformance/l0-kel-identity.conformance.test.ts
(seed(b) = 32 bytes all equal to b, NOW = 2026-10-07T00:00:00.000Z).
"""

from datetime import datetime, timezone

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from aroha.jcs import canonicalize_jcs
from aroha.kel import (
    InMemoryKelStore,
    KelError,
    accept_kel,
    anchor_in_kel,
    event_digest,
    incept,
    inception_digest_from_did,
    is_inception_did,
    kel_key_resolver,
    kel_source_from_logs,
    keys_at_sequence,
    recover_agent,
    generate_kel_key_material,
    revoke_agent,
    revoke_kel_self,
    rotate_kel,
    verify_agent_controlled_by,
    verify_kel,
    _b64url,
)

NOW = datetime(2026, 10, 7, tzinfo=timezone.utc)


def seed(b: int) -> bytes:
    return bytes([b]) * 32


class TestL0Kel01PinnedVector:
    def test_inception_body_did_and_signature(self):
        ident = incept("person", private_key=seed(1), next_private_key=seed(2), now=NOW)
        body = {k: v for k, v in ident.kel[0].items() if k != "sig"}
        assert canonicalize_jcs(body) == (
            '{"createdAt":"2026-10-07T00:00:00.000Z","keys":["zAKnL4NNf3DGWZJS6cPknBuEGnVsV4A4m5tgebLHaRSZ9"],'
            '"kind":"person","nextKeyDigest":"E89dkqqjMw9HTi1pqHbANSNwioHuMhmpTCXapTmfUr1EW","type":"inception","v":1}'
        )
        assert ident.did == "did:aroha:EFLYfS6RfFTTMNdhSybB52jJ4KCTLsNXC4ZuBECvceFKZ"
        assert ident.kel[0]["sig"] == (
            "a-jO6pXYXMBFY3nEhbzzz20MlJ81pxy17L42BgphDMw8ogNyKOeLD_Rg5yMhtv22Rf6kt8d4kpW0VWrdt3TjCw"
        )

    def test_rotation_digest(self):
        ident = incept("person", private_key=seed(1), next_private_key=seed(2), now=NOW)
        rotated = rotate_kel(ident, next_private_key=seed(3), now=NOW)
        assert event_digest(rotated.kel[1]) == "ED3cVEYDPescYcT6jaD4swqCa3PyGvTDUxhhahnYVFTrr"
        state = verify_kel(ident.did, rotated.kel)
        assert state.sequence == 1
        assert state.current_key == rotated.public_key


def test_pinned_vector_verifies_from_wire_json():
    # The same inception as a plain dict, as it would arrive from a TS peer.
    inception = {
        "v": 1, "type": "inception", "kind": "person",
        "keys": ["zAKnL4NNf3DGWZJS6cPknBuEGnVsV4A4m5tgebLHaRSZ9"],
        "nextKeyDigest": "E89dkqqjMw9HTi1pqHbANSNwioHuMhmpTCXapTmfUr1EW",
        "createdAt": "2026-10-07T00:00:00.000Z",
        "sig": "a-jO6pXYXMBFY3nEhbzzz20MlJ81pxy17L42BgphDMw8ogNyKOeLD_Rg5yMhtv22Rf6kt8d4kpW0VWrdt3TjCw",
    }
    state = verify_kel("did:aroha:EFLYfS6RfFTTMNdhSybB52jJ4KCTLsNXC4ZuBECvceFKZ", [inception])
    assert state.kind == "person" and not state.revoked


def test_did_forms():
    ident = incept("agent")
    assert is_inception_did(ident.did)
    assert len(inception_digest_from_did(ident.did)) == 32
    assert not is_inception_did("did:aroha:Echo")
    assert not is_inception_did("did:aroha:zFVen3X669xLzsi6N2V91DoiyzHzg1uAgqiT8jZ9nS96Z")
    assert not is_inception_did("did:aroha:" + ident.did[len("did:aroha:"):] + ".x")


def test_l0_kel_02_inception_only_log_verifies():
    ident = incept("agent")
    assert verify_kel(ident.did, ident.kel).current_key == ident.public_key


def test_l0_kel_03_rotation_signed_by_current_key_is_rejected():
    ident = incept("agent", private_key=seed(4), next_private_key=seed(5), now=NOW)
    honest = rotate_kel(ident, now=NOW).kel[1]
    body = {k: v for k, v in honest.items() if k != "sig"}
    thief_sig = Ed25519PrivateKey.from_private_bytes(seed(4)).sign(canonicalize_jcs(body).encode())
    forged = {**body, "sig": _b64url(thief_sig)}
    with pytest.raises(KelError):
        verify_kel(ident.did, [ident.kel[0], forged])
    assert verify_kel(ident.did, [ident.kel[0], honest])


def test_l0_kel_04_controller_events_need_the_controllers_log():
    person = incept("person")
    agent = incept("agent", controller=person.did)
    person2, agent_kel = revoke_agent(person, agent.kel)
    assert verify_kel(agent.did, agent_kel, kel_source_from_logs(person2.kel)).revoked
    with pytest.raises(KelError) as ei:
        verify_kel(agent.did, agent_kel)
    assert ei.value.code == "controller-unavailable"


def test_unanchored_recover_is_invalid_not_duplicity():
    person = incept("person")
    agent = incept("agent", controller=person.did)
    mat = generate_kel_key_material()
    _, agent_kel = recover_agent(person, agent.kel, mat["public_key"], mat["next_key_digest"])
    with pytest.raises(KelError) as ei:
        verify_kel(agent.did, agent_kel, kel_source_from_logs(person.kel))  # person log WITHOUT the anchor
    assert ei.value.code == "invalid"


def test_recover_installs_new_key_and_stale_agent_log_is_detected():
    person = incept("person")
    agent = incept("agent", controller=person.did)
    mat = generate_kel_key_material()
    person2, agent_kel = recover_agent(person, agent.kel, mat["public_key"], mat["next_key_digest"])
    state = verify_kel(agent.did, agent_kel, kel_source_from_logs(person2.kel))
    assert state.current_key == mat["public_key"]
    assert keys_at_sequence(state, 0) == agent.kel[0]["keys"]
    # Serving the agent's OLD log next to the person's NEW log: the seal proves it stale.
    with pytest.raises(KelError) as ei:
        verify_kel(agent.did, agent.kel, kel_source_from_logs(person2.kel))
    assert ei.value.code == "stale"


def test_l0_kel_05_duplicity():
    ident = incept("person")
    store = InMemoryKelStore()
    accept_kel(ident.did, rotate_kel(ident).kel, store)
    with pytest.raises(KelError) as ei:
        accept_kel(ident.did, rotate_kel(ident).kel, store)
    assert ei.value.code == "duplicity"
    with pytest.raises(KelError):
        accept_kel(ident.did, ident.kel, store)  # alarm is sticky


def test_l0_kel_06_stale():
    ident = incept("person")
    store = InMemoryKelStore()
    accept_kel(ident.did, rotate_kel(ident).kel, store)
    with pytest.raises(KelError) as ei:
        accept_kel(ident.did, ident.kel, store)
    assert ei.value.code == "stale"


def test_self_revocation_and_key_resolver():
    ident = incept("person")
    src_live = kel_source_from_logs(ident.kel)
    assert kel_key_resolver(src_live)(ident.did) == ident.public_key
    revoked = revoke_kel_self(ident, reason="lost")
    assert verify_kel(ident.did, revoked).revoked
    assert kel_key_resolver(kel_source_from_logs(revoked))(ident.did) is None
    assert kel_key_resolver(src_live)("did:aroha:zFVen3X669xLzsi6N2V91DoiyzHzg1uAgqiT8jZ9nS96Z") is None


def test_tampered_inception_is_rejected():
    ident = incept("person")
    tampered = {**ident.kel[0], "kind": "agent"}
    with pytest.raises(KelError):
        verify_kel(ident.did, [tampered])


def test_controlled_by():
    person = incept("person")
    agent = incept("agent", controller=person.did)
    ok, reason = verify_agent_controlled_by(agent.did, agent.kel, person.did, person.kel)
    assert ok, reason
    person = anchor_in_kel(person, [])
    other = incept("person")
    ok, _ = verify_agent_controlled_by(agent.did, agent.kel, other.did, other.kel)
    assert not ok
