---
name: aroha-python-sdk
description: Use the Aroha Python SDK (package "aroha") to verify Aroha spending-mandate chains, issue/verify/enforce task mandates, Key Event Logs, and Conversation and Memory Profile objects (signed rooms, consent records, turns, action receipts v1/v2). Use when Python code must check Aroha authority or attribution produced by a TypeScript or other Aroha implementation.
license: Apache-2.0
compatibility: Python 3.11+, package aroha 2.x (pip install aroha), depends on cryptography.
metadata:
  project: Aroha (https://github.com/ArohaLabs/aroha-protocol)
  spec: aroha-1.0 §6.5, §12
---

# Aroha Python SDK

The Python SDK produces the same canonical bytes (RFC 8785 JCS) as the TypeScript reference, so signatures cross languages. This skill covers verification. Issuing rooms, consent and receipts is done by the runtime that holds the keys.

## Verify a spending-mandate chain

```python
from aroha import verify_mandate_chain

result = verify_mandate_chain(token, expected_root=person_did, is_revoked=is_revoked, expected_grantee=my_did)
if not result.valid:
    raise PermissionError(result.reason)
```

For a person root, pass `kel_source=` and `require_person_root=True` (or `expected_root_person=`). A chain that drops or flips a parent's `actingFor` (payer or payee) is refused.

## Gate an action on a task mandate

```python
from aroha.task_mandate import enforce_task_constraints, TaskActionRequest, TaskConstraintViolation

try:
    mandate = enforce_task_constraints(token, grantor_public_key, TaskActionRequest(
        "send-email", room_id=room_id_from_runtime, on_behalf_of=member_did_from_runtime,
        human_approved=approved, current_action_counts=counts, data_access={"email": "write"},
    ), expected_grantee=my_did)
except TaskConstraintViolation as e:
    refuse(e.code, str(e))   # CONTEXT_MISMATCH, ACTION_LIMIT_EXCEEDED, HUMAN_GATE_REQUIRED, ...
```

Task tokens are single links (v2: JCS over `{mandate, purpose: "aroha.task-mandate/v2", v: 2}`). `issue_task_mandate` / `attenuate_task_mandate` issue them; when you hold the parent too, run `check_task_narrowing(parent, child)` yourself — a child that widens its parent still has a valid signature. Take `room_id` and `on_behalf_of` from your own room record, never from the request body.

## Verify conversation objects

```python
from aroha.conversation import (
    kel_resolver, verify_room, verify_consent, verify_turn, effective_consent,
    verify_action_receipt, verify_presented_hash, content_addressed_key,
)

resolve = kel_resolver(kels)            # {did: [KEL events]}; z-form DIDs resolve as agents
room = verify_room(room_record, resolve)                    # owner must be a person
consent = verify_consent(consent_record, resolve, room_record)  # every event signed by its actor
turn = verify_turn(turn_obj, resolve, room_record)          # turn.kind == "person" | "agent", from the KEL
receipt = verify_action_receipt(receipt_obj, content_addressed_key)
assert room.ok and consent.ok and turn.ok and receipt.ok
assert verify_presented_hash(receipt_obj, presented_content) is None
granted = effective_consent(consent_record)   # e.g. {"transcript_retention", "agent_use_of_messages"}
```

## Rules

- Take a signer's kind (person or agent) only from `Verification.kind`, which comes from the Key Event Log. Never take it from the object.
- A consent record with a withdrawal by someone other than the subject needs the room record. Without it, verification fails by design.
- Each function returns `Verification(ok, reason, kind)` and never raises on bad input. Treat `ok == False` as "do not act".
- Check your build against the vectors: `pytest sdks/aroha-py/tests/test_conversation_vectors.py tests/test_mandate_vectors.py tests/test_task_mandate_vectors.py`.
