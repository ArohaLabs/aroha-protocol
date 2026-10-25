# Phase 1 — Consult Hardening in aroha-doc-intel (studio-backend)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add the four missing safety properties — loop prevention, question composition, outbound question screening, and a consult audit log — to the cross-firm agent consult that already ships in aroha-doc-intel.

**Architecture:** The consult flow already exists end to end: `POST /remote-agents/{did}/run` signs a firm-to-firm envelope out via `aroha_client.call_remote`, and `POST /agents/run/shared` answers inbound calls with `redact_pii` applied to the answer. This plan adds a `consult/` layer around both ends without changing either route's contract with the UI.

**Tech Stack:** Python 3, FastAPI, Pydantic, pytest. Node SDK bridge (`aroha/aroha_call.mjs`) for signing — untouched by this work.

**Spec:** [../specs/2026-08-18-internal-consult-design.md](../specs/2026-08-18-internal-consult-design.md)

> **Why here and not aroha-runtime.** The runtime cannot be downloaded by anyone today — the repo is private, `aroha.sh` does not resolve, and no `runtime-v*` tag has ever been created, so no binary has ever been built. dust-ux ships this feature to a real client now. Hardening a consult that has users beats building a second one that has none.

## Global Constraints

- **Do not change the UI contract.** `POST /remote-agents/{did}/run` keeps taking `{message}` and returning `{answer, envelope, remoteDid, remoteName}`. New fields may be *added* to the response; nothing existing may be removed or renamed. The dust frontend is shipping to a client and must not need a coordinated change.
- **Consult only.** No action requests, no signed approvals, no side effects on the remote side. Phase 2.
- **Existing behaviour is preserved.** `redact_pii` on the answer path stays exactly as it is — this plan adds screening on the *question* path, it does not move or replace the answer-side redaction.
- **Audit stores redaction categories, never redacted values** (spec §6.2/§7).
- **Follow the repo's existing style**: module docstring explaining *why*, `from __future__ import annotations`, type hints, deterministic regex over LLM calls, honest docstrings about limitations.
- **Tests use the existing `temp_store` autouse fixture** (`tests/conftest.py`) — never touch the developer's real JSON stores.
- Run tests with `pytest` from `studio-backend/`.

---

## File Structure

| File | Responsibility |
|---|---|
| `studio-backend/consult_guard.py` | Hop count + consult chain checks. Pure functions |
| `studio-backend/consult_compose.py` | Conversation → self-contained question |
| `studio-backend/consult_audit.py` | JSONL audit append + read |
| `studio-backend/pii_redact.py` | *Modify* — add `redact_with_categories` |
| `studio-backend/app.py` | *Modify* — wire both consult ends, add audit route |
| `studio-backend/store.py` | *Modify* — audit file path |
| `studio-backend/tests/test_consult_guard.py` | New |
| `studio-backend/tests/test_consult_compose.py` | New |
| `studio-backend/tests/test_consult_audit.py` | New |
| `studio-backend/tests/test_consult_api.py` | New — end-to-end route behaviour |

---

## Task 1: Consult loop guard

**Files:**
- Create: `studio-backend/consult_guard.py`
- Test: `studio-backend/tests/test_consult_guard.py`

**Interfaces:**
- Consumes: nothing
- Produces: `check_loop_limits(hop_count: int, consult_chain: list[str], own_did: str, max_hops: int = 3) -> LoopCheck`; `next_hop(hop_count: int, consult_chain: list[str], own_did: str) -> tuple[int, list[str]]`; `LoopCheck` is a dataclass with `ok: bool` and `reason: str | None`

- [ ] **Step 1: Write the failing test**

```python
"""consult_guard.py — two independent limits, per the consult design spec §3.2.

A hop count alone cannot stop a 2-cycle under a generous depth limit, and a
chain check alone cannot stop unbounded linear depth. Both are tested here
because both are load-bearing.
"""

from consult_guard import check_loop_limits, next_hop


def test_allows_hops_one_through_three_with_max_three():
    for hop in (1, 2, 3):
        assert check_loop_limits(hop, ["did:aroha:zA"], "did:aroha:zB", max_hops=3).ok


def test_refuses_the_fourth_hop():
    result = check_loop_limits(4, ["a", "b", "c", "d"], "did:aroha:zB", max_hops=3)
    assert not result.ok
    assert "hop" in result.reason.lower()


def test_refuses_a_cycle_even_inside_the_hop_limit():
    result = check_loop_limits(2, ["did:aroha:zA", "did:aroha:zB"], "did:aroha:zA", max_hops=3)
    assert not result.ok
    assert "cycle" in result.reason.lower() or "chain" in result.reason.lower()


def test_refuses_a_non_positive_hop_count_as_malformed():
    assert not check_loop_limits(0, [], "did:aroha:zB", max_hops=3).ok
    assert not check_loop_limits(-1, [], "did:aroha:zB", max_hops=3).ok


def test_next_hop_increments_and_appends_own_did():
    hop, chain = next_hop(1, ["did:aroha:zA"], "did:aroha:zB")
    assert hop == 2
    assert chain == ["did:aroha:zA", "did:aroha:zB"]


def test_next_hop_does_not_mutate_the_input_chain():
    original = ["did:aroha:zA"]
    next_hop(1, original, "did:aroha:zB")
    assert original == ["did:aroha:zA"]


def test_first_hop_from_empty_state():
    hop, chain = next_hop(0, [], "did:aroha:zSELF")
    assert hop == 1
    assert chain == ["did:aroha:zSELF"]
```

- [ ] **Step 2: Run it to verify it fails**

Run: `cd studio-backend && pytest tests/test_consult_guard.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'consult_guard'`

- [ ] **Step 3: Write the implementation**

```python
"""consult_guard.py — loop prevention for cross-firm agent consults.

Agent A asks B, B asks A, and real money burns in a cycle nobody notices
until the bill arrives. Two independent limits, because they fail
differently:

  hop_count     bounds runaway depth   (A -> B -> C -> D -> ...)
  consult_chain catches cycles         (A -> B -> A)

A count alone does not stop a 2-cycle under a generous depth limit; a chain
check alone does not stop unbounded linear depth. Both are required.

Checked before any model call — this gate is free, so it runs first.
"""

from __future__ import annotations

from dataclasses import dataclass

DEFAULT_MAX_HOPS = 3


@dataclass(frozen=True)
class LoopCheck:
    ok: bool
    reason: str | None = None


def check_loop_limits(
    hop_count: int,
    consult_chain: list[str],
    own_did: str,
    max_hops: int = DEFAULT_MAX_HOPS,
) -> LoopCheck:
    """Whether a consult arriving with this hop state may be answered."""
    if not isinstance(hop_count, int) or hop_count < 1:
        return LoopCheck(False, f"Malformed hop count: {hop_count!r}")
    if hop_count > max_hops:
        return LoopCheck(
            False,
            f"Consult hop limit exceeded ({hop_count} > {max_hops}).",
        )
    if own_did in consult_chain:
        return LoopCheck(
            False,
            "Consult cycle detected — this firm is already in the chain "
            f"[{' -> '.join(consult_chain)}].",
        )
    return LoopCheck(True)


def next_hop(
    hop_count: int,
    consult_chain: list[str],
    own_did: str,
) -> tuple[int, list[str]]:
    """Hop state to put on an outgoing consult. Never mutates its input.

    A first-hop consult passes hop_count=0 and an empty chain, and gets back
    (1, [own_did]).
    """
    return hop_count + 1, [*consult_chain, own_did]
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd studio-backend && pytest tests/test_consult_guard.py -v`
Expected: PASS, 7 tests.

- [ ] **Step 5: Commit**

```bash
cd "<doc-intel checkout>"
git add studio-backend/consult_guard.py studio-backend/tests/test_consult_guard.py
git commit -m "feat(consult): hop count and cycle detection

Two independent limits — a count alone cannot stop a 2-cycle under a
generous depth limit, and a chain check alone cannot stop unbounded
linear depth. Neither existed before: A -> B -> A would loop until
something else broke."
```

---

## Task 2: Redaction categories

**Files:**
- Modify: `studio-backend/pii_redact.py`
- Test: `studio-backend/tests/test_pii_redact.py`

**Interfaces:**
- Consumes: existing `redact_pii`
- Produces: `redact_with_categories(text: str) -> RedactionResult` where `RedactionResult` is a dataclass with `text: str`, `categories: list[str]`, `gutted: bool`

The existing `redact_pii(text) -> str` keeps working unchanged — the answer path depends on it.

- [ ] **Step 1: Write the failing test**

Append to `studio-backend/tests/test_pii_redact.py`:

```python
from pii_redact import redact_with_categories


def test_reports_the_category_of_what_it_redacted():
    result = redact_with_categories("Reach jane@example.com about it.")
    assert "jane@example.com" not in result.text
    assert "email" in result.categories


def test_never_returns_the_redacted_value_in_categories():
    result = redact_with_categories("Reach jane@example.com about it.")
    assert "jane@example.com" not in "".join(result.categories)


def test_deduplicates_repeated_categories():
    result = redact_with_categories("mail a@b.com and c@d.com")
    assert result.categories.count("email") == 1


def test_clean_text_reports_no_categories_and_is_unchanged():
    text = "What is the standard payment term for vendors?"
    result = redact_with_categories(text)
    assert result.text == text
    assert result.categories == []
    assert result.gutted is False


def test_flags_a_question_as_gutted_when_redaction_removes_most_of_it():
    result = redact_with_categories("a@b.com c@d.com e@f.com g@h.com")
    assert result.gutted is True


def test_a_normal_question_with_one_email_is_not_gutted():
    result = redact_with_categories(
        "Can you confirm the payment terms we agreed for jane@example.com's account?"
    )
    assert result.gutted is False
```

- [ ] **Step 2: Run it to verify it fails**

Run: `cd studio-backend && pytest tests/test_pii_redact.py -v`
Expected: FAIL — `ImportError: cannot import name 'redact_with_categories'`

- [ ] **Step 3: Read the existing module before changing it**

Run: `cd studio-backend && cat pii_redact.py`

Note the exact placeholder strings (`[email address]`, `[phone number]`, …) and the compiled pattern names. Step 4 reuses them rather than introducing a second set.

- [ ] **Step 4: Add the categorised variant**

Append to `studio-backend/pii_redact.py`:

```python
@dataclass(frozen=True)
class RedactionResult:
    """What redaction did, without saying what it removed.

    `categories` names the KINDS of data stripped, never the values. An audit
    log that records the PII it redacted defeats its own purpose.
    """

    text: str
    categories: list[str]
    gutted: bool


# Minimum fraction of a question's alphanumeric content that must survive
# redaction before the question is judged too hollowed-out to be worth asking.
_MIN_SURVIVING_RATIO = 0.5


def redact_with_categories(text: str) -> RedactionResult:
    """redact_pii, plus which categories fired and whether the result is hollow.

    Used on the OUTBOUND question path (app.py's /remote-agents/{did}/run).
    The inbound answer path keeps using plain redact_pii — its caller wants
    the scrubbed string and nothing else.
    """
    categories: list[str] = []
    for name, pattern in _CATEGORISED_PATTERNS:
        if pattern.search(text) and name not in categories:
            categories.append(name)

    redacted = redact_pii(text)

    def alnum(s: str) -> int:
        return sum(1 for ch in s if ch.isalnum())

    without_placeholders = re.sub(r"\[[a-z ]+\]", "", redacted)
    original = alnum(text)
    surviving = alnum(without_placeholders)
    gutted = original > 0 and (surviving / original) < _MIN_SURVIVING_RATIO

    return RedactionResult(text=redacted, categories=categories, gutted=gutted)
```

Add `from dataclasses import dataclass` to the imports, and define `_CATEGORISED_PATTERNS` next to the existing patterns, reusing the module's already-compiled regexes:

```python
# (category name, pattern) for reporting WHAT kind of data was found. Reuses
# the same compiled patterns redact_pii applies, so the two can never disagree
# about whether something matched.
_CATEGORISED_PATTERNS = [
    ("email", _EMAIL_RE),
    ("phone", _PHONE_RE),
    ("ssn", _SSN_RE),
    ("account", _ACCOUNT_RE),
    ("name", _NAME_RE),
]
```

Match the actual constant names in the file — if a pattern is named differently, use its real name rather than renaming it.

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd studio-backend && pytest tests/test_pii_redact.py -v`
Expected: PASS — the 6 new tests plus every pre-existing one. The pre-existing tests passing unchanged is the signal that the answer path is untouched.

- [ ] **Step 6: Commit**

```bash
cd "<doc-intel checkout>"
git add studio-backend/pii_redact.py studio-backend/tests/test_pii_redact.py
git commit -m "feat(consult): redact_with_categories for the outbound question path

redact_pii is unchanged and the answer path keeps using it — the existing
tests passing untouched is the proof. The new variant additionally reports
WHICH categories fired (never the values) so an audit record can show what
was withheld, and flags a question that redaction has hollowed out."
```

---

## Task 3: Consult audit log

**Files:**
- Create: `studio-backend/consult_audit.py`
- Modify: `studio-backend/store.py`
- Test: `studio-backend/tests/test_consult_audit.py`

**Interfaces:**
- Consumes: `store._CONSULT_AUDIT_PATH`
- Produces: `append_consult(record: ConsultRecord) -> None`; `read_consults(limit: int = 100, offset: int = 0) -> list[dict]`; `ConsultRecord` dataclass

- [ ] **Step 1: Add the audit path to store.py**

Next to the other `_*_PATH` constants in `studio-backend/store.py`:

```python
_CONSULT_AUDIT_PATH = Path(__file__).parent / "consult_audit.jsonl"
```

Add it to `tests/conftest.py`'s `temp_store` fixture, alongside the other monkeypatched paths:

```python
    monkeypatch.setattr(store, "_CONSULT_AUDIT_PATH", tmp_path / "consult_audit.jsonl")
```

- [ ] **Step 2: Write the failing test**

```python
"""consult_audit.py — one record per consult, written on every outcome
including refusals. A refused consult must be as visible as an answered one.
"""

import json

from consult_audit import ConsultRecord, append_consult, read_consults


def record(**over) -> ConsultRecord:
    base = dict(
        correlation_id="corr-1",
        direction="outbound",
        peer_did="did:aroha:zPEER",
        peer_name="Partner Firm",
        question="What is the standard payment term?",
        redactions=[],
        answer="Net 30.",
        hop_count=1,
        outcome="answered",
    )
    base.update(over)
    return ConsultRecord(**base)


def test_returns_empty_before_anything_is_written():
    assert read_consults() == []


def test_round_trips_one_record():
    append_consult(record())
    out = read_consults()
    assert len(out) == 1
    assert out[0]["correlationId"] == "corr-1"
    assert out[0]["outcome"] == "answered"


def test_returns_newest_first():
    append_consult(record(correlation_id="older"))
    append_consult(record(correlation_id="newer"))
    assert [r["correlationId"] for r in read_consults()] == ["newer", "older"]


def test_honours_limit_and_offset():
    for i in range(5):
        append_consult(record(correlation_id=f"c{i}"))
    assert len(read_consults(limit=2)) == 2
    assert read_consults(limit=2, offset=2)[0]["correlationId"] == "c2"


def test_stores_redaction_categories_never_values():
    append_consult(record(redactions=["email"], question="mail [email address]"))
    raw = json.dumps(read_consults()[0])
    assert "email" in raw
    assert "@" not in raw


def test_skips_a_corrupt_line_rather_than_losing_the_whole_log():
    import store
    append_consult(record(correlation_id="good"))
    with open(store._CONSULT_AUDIT_PATH, "a", encoding="utf-8") as fh:
        fh.write("{not json\n")
    append_consult(record(correlation_id="alsogood"))
    assert {r["correlationId"] for r in read_consults()} == {"good", "alsogood"}


def test_records_a_refusal_outcome():
    append_consult(record(outcome="loop", answer=None))
    assert read_consults()[0]["outcome"] == "loop"
    assert read_consults()[0]["answer"] is None
```

- [ ] **Step 3: Run it to verify it fails**

Run: `cd studio-backend && pytest tests/test_consult_audit.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'consult_audit'`

- [ ] **Step 4: Write the implementation**

```python
"""consult_audit.py — the record of every cross-firm consult.

JSONL rather than a row in one of the JSON stores: this file only ever grows
by appending, and an append-only line format survives a partial write without
taking the rest of the log with it. It is also the artifact an operator hands
to a compliance reviewer, so it stays readable without the studio running.

PRIVACY RULE: `redactions` holds the CATEGORIES that were stripped, never the
values. An audit log that records the personal data it removed is the leak it
was built to prevent.

Written on EVERY outcome, including refusals. A consult refused for looping
is as interesting to an operator as one that was answered — arguably more.
"""

from __future__ import annotations

import json
import logging
import time
import uuid
from dataclasses import dataclass, field

import store

logger = logging.getLogger("consult_audit")


@dataclass
class ConsultRecord:
    correlation_id: str
    direction: str          # "outbound" (we asked) | "inbound" (we were asked)
    peer_did: str
    question: str
    hop_count: int
    outcome: str            # answered | declined | loop | error
    peer_name: str = ""
    redactions: list[str] = field(default_factory=list)
    answer: str | None = None


def append_consult(record: ConsultRecord) -> None:
    """Append one record. Never raises — a failed audit write must not take
    down the consult it was recording, but it must be loud in the logs."""
    payload = {
        "id": str(uuid.uuid4()),
        "timestamp": int(time.time() * 1000),
        "correlationId": record.correlation_id,
        "direction": record.direction,
        "peerDid": record.peer_did,
        "peerName": record.peer_name,
        "question": record.question,
        "redactions": record.redactions,
        "answer": record.answer,
        "hopCount": record.hop_count,
        "outcome": record.outcome,
    }
    try:
        with open(store._CONSULT_AUDIT_PATH, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(payload) + "\n")
    except OSError:
        logger.exception("consult_audit_write_failed")


def read_consults(limit: int = 100, offset: int = 0) -> list[dict]:
    """Newest first. A corrupt line is skipped, not fatal — one truncated
    write must not blind the operator to the rest of the log."""
    path = store._CONSULT_AUDIT_PATH
    if not path.exists():
        return []

    records: list[dict] = []
    try:
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    records.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    except OSError:
        logger.exception("consult_audit_read_failed")
        return []

    records.sort(key=lambda r: r.get("timestamp", 0), reverse=True)
    return records[offset : offset + limit]
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd studio-backend && pytest tests/test_consult_audit.py -v`
Expected: PASS, 7 tests.

If `test_returns_newest_first` is flaky, two appends landed in the same millisecond — make it deterministic by having the test pass explicit timestamps rather than by adding a sleep.

- [ ] **Step 6: Commit**

```bash
cd "<doc-intel checkout>"
git add studio-backend/consult_audit.py studio-backend/store.py studio-backend/tests/test_consult_audit.py studio-backend/tests/conftest.py
git commit -m "feat(consult): JSONL audit log for cross-firm consults

Written on every outcome including refusals — a consult refused for
looping matters as much to an operator as one that was answered. Stores
redaction categories, never values. A failed audit write is logged loudly
but never takes down the consult it was recording."
```

---

## Task 4: Question composer

**Files:**
- Create: `studio-backend/consult_compose.py`
- Test: `studio-backend/tests/test_consult_compose.py`

**Interfaces:**
- Consumes: `model_client` (the studio's existing model caller)
- Produces: `COMPOSER_SYSTEM_PROMPT: str`; `compose_question(conversation: list[dict], domain_hint: str | None = None, *, call_model) -> str`

- [ ] **Step 1: Read how the studio calls a model**

Run: `cd studio-backend && grep -n "def " model_client.py | head -20`

Note the function that takes messages and returns text. Step 4 injects it as `call_model` rather than importing it directly, so the tests need no model.

- [ ] **Step 2: Write the failing test**

```python
"""consult_compose.py — the question that crosses the firm boundary is
CONSTRUCTED, never the raw conversation. That is the data-minimisation
boundary, and a self-contained question is also more answerable than a
transcript fragment.
"""

from consult_compose import COMPOSER_SYSTEM_PROMPT, compose_question


def fake_model(captured: dict):
    def call(messages, **kwargs):
        captured["messages"] = messages
        captured["kwargs"] = kwargs
        return "What is the standard vendor payment term?"
    return call


def test_returns_the_composed_question():
    out = compose_question(
        [{"role": "user", "content": "what do we normally pay vendors on"}],
        call_model=fake_model({}),
    )
    assert out == "What is the standard vendor payment term?"


def test_runs_in_an_isolated_context_with_its_own_system_prompt():
    captured: dict = {}
    compose_question(
        [{"role": "user", "content": "internal chatter"}],
        call_model=fake_model(captured),
    )
    assert captured["messages"][0]["content"] == COMPOSER_SYSTEM_PROMPT


def test_includes_the_domain_hint_when_given():
    captured: dict = {}
    compose_question(
        [{"role": "user", "content": "x"}],
        domain_hint="finance",
        call_model=fake_model(captured),
    )
    assert "finance" in str(captured["messages"])


def test_drops_system_messages_from_the_transcript_it_composes_from():
    captured: dict = {}
    compose_question(
        [
            {"role": "system", "content": "INTERNAL SYSTEM PROMPT"},
            {"role": "user", "content": "a question"},
        ],
        call_model=fake_model(captured),
    )
    assert "INTERNAL SYSTEM PROMPT" not in str(captured["messages"])


def test_trims_whitespace_from_the_models_answer():
    def call(messages, **kwargs):
        return "  Q?  \n"
    assert compose_question([{"role": "user", "content": "x"}], call_model=call) == "Q?"


def test_falls_back_to_the_last_user_message_when_the_model_returns_nothing():
    def call(messages, **kwargs):
        return "   "
    out = compose_question(
        [{"role": "user", "content": "what are the payment terms"}],
        call_model=call,
    )
    assert out == "what are the payment terms"
```

- [ ] **Step 3: Run it to verify it fails**

Run: `cd studio-backend && pytest tests/test_consult_compose.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'consult_compose'`

- [ ] **Step 4: Write the implementation**

```python
"""consult_compose.py — turn a conversation into one question worth asking
another firm.

Before this, /remote-agents/{did}/run forwarded whatever the user typed. That
works, but it means whatever context happened to be in the message crosses a
firm boundary verbatim. Composing instead does two things at once: it is the
data-minimisation boundary (the other firm sees a question, not our
conversation), and a self-contained question is materially more answerable
than a fragment that assumed context the reader does not have.

The model call is injected rather than imported so the tests exercise the
composition logic without a model, and so a caller can pick which model does
this cheap job.

EXCLUDED from what crosses: system prompts, conversation history, internal
identifiers, and anything else not needed to answer the question.
"""

from __future__ import annotations

from typing import Callable, Protocol


class _CallModel(Protocol):
    def __call__(self, messages: list[dict], **kwargs) -> str: ...


COMPOSER_SYSTEM_PROMPT = (
    "You turn a conversation into ONE self-contained question to ask another "
    "firm's assistant. Output only the question — no preamble, no explanation, "
    "no quotation marks. The other firm has no access to this conversation, so "
    "the question must stand entirely on its own. Include only what is needed "
    "to answer it. Never include personal data, names, contact details, "
    "account numbers, or internal identifiers unless they are essential to the "
    "question itself."
)


def compose_question(
    conversation: list[dict],
    domain_hint: str | None = None,
    *,
    call_model: _CallModel,
) -> str:
    """Compose the question to send. Falls back to the last user message if
    the model returns nothing usable — a consult that silently sends an empty
    question is worse than one that sends the user's own words."""
    usable = [
        m for m in conversation
        if m.get("role") in ("user", "assistant") and m.get("content")
    ]
    transcript = "\n".join(f"{m['role']}: {m['content']}" for m in usable)

    prefix = f"Subject area: {domain_hint}\n\n" if domain_hint else ""
    messages = [
        {"role": "system", "content": COMPOSER_SYSTEM_PROMPT},
        {
            "role": "user",
            "content": f"{prefix}Conversation:\n{transcript}\n\nThe question to ask:",
        },
    ]

    composed = (call_model(messages) or "").strip()
    if composed:
        return composed

    for message in reversed(usable):
        if message["role"] == "user":
            return str(message["content"]).strip()
    return ""
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd studio-backend && pytest tests/test_consult_compose.py -v`
Expected: PASS, 6 tests.

- [ ] **Step 6: Commit**

```bash
cd "<doc-intel checkout>"
git add studio-backend/consult_compose.py studio-backend/tests/test_consult_compose.py
git commit -m "feat(consult): compose a self-contained question

The outbound path forwarded the user's raw message, so whatever context
was in it crossed a firm boundary verbatim. Composing is both the
data-minimisation boundary and a quality win. Falls back to the last user
message rather than sending an empty question if the model returns nothing."
```

---

## Task 5: Wire the outbound consult path

**Files:**
- Modify: `studio-backend/app.py` (`RemoteRunBody`, `run_remote_agent` at ~line 760–840)
- Test: `studio-backend/tests/test_consult_api.py`

**Interfaces:**
- Consumes: `check_loop_limits`, `next_hop`, `compose_question`, `redact_with_categories`, `append_consult`
- Produces: unchanged response keys plus `question`, `redactions`

- [ ] **Step 1: Write the failing test**

```python
"""The outbound consult route keeps its contract with the dust UI while
gaining composition, screening, loop state, and an audit record.
"""

import pytest
from fastapi.testclient import TestClient

import app as app_module
import store
from consult_audit import read_consults

client = TestClient(app_module.app)


@pytest.fixture
def a_remote_agent():
    store.add_remote_agent({
        "did": "did:aroha:zPEER",
        "name": "Partner Firm",
        "description": "",
        "endpoint": "http://127.0.0.1:9/aroha",
        "didDocument": {},
    })
    return "did:aroha:zPEER"


@pytest.fixture
def stub_remote_call(monkeypatch):
    """Replace the Node bridge — this test is about our logic, not theirs."""
    sent: dict = {}

    class Reply:
        answer = "Net 30."
        envelope = {"correlationId": "corr-x"}

    def fake_call_remote(**kwargs):
        sent.update(kwargs)
        return Reply()

    monkeypatch.setattr(app_module.aroha_client, "call_remote", fake_call_remote)
    monkeypatch.setattr(store, "firm_identity", lambda: {
        "did": "did:aroha:zSELF", "privateKey": "aa" * 32,
    })
    return sent


@pytest.fixture
def stub_composer(monkeypatch):
    monkeypatch.setattr(
        app_module, "compose_question",
        lambda conversation, domain_hint=None, **kw: "Composed question?",
    )


def test_keeps_the_existing_response_contract(a_remote_agent, stub_remote_call, stub_composer):
    res = client.post(f"/remote-agents/{a_remote_agent}/run", json={"message": "hi"})
    assert res.status_code == 200
    body = res.json()
    for key in ("answer", "envelope", "remoteDid", "remoteName"):
        assert key in body, f"the dust UI depends on {key}"
    assert body["answer"] == "Net 30."


def test_sends_the_composed_question_not_the_raw_message(
    a_remote_agent, stub_remote_call, stub_composer,
):
    client.post(f"/remote-agents/{a_remote_agent}/run", json={"message": "raw user text"})
    assert stub_remote_call["message"] == "Composed question?"
    assert "raw user text" not in stub_remote_call["message"]


def test_redacts_pii_from_the_question_before_sending(
    a_remote_agent, stub_remote_call, monkeypatch,
):
    monkeypatch.setattr(
        app_module, "compose_question",
        lambda conversation, domain_hint=None, **kw: "Chase the invoice for jane@example.com",
    )
    res = client.post(f"/remote-agents/{a_remote_agent}/run", json={"message": "x"})
    assert res.status_code == 200
    assert "jane@example.com" not in stub_remote_call["message"]
    assert "email" in res.json()["redactions"]


def test_refuses_a_consult_that_would_exceed_the_hop_limit(
    a_remote_agent, stub_remote_call, stub_composer,
):
    res = client.post(
        f"/remote-agents/{a_remote_agent}/run",
        json={"message": "hi", "hopCount": 3, "consultChain": ["a", "b", "c"]},
    )
    assert res.status_code == 403
    assert read_consults()[0]["outcome"] == "loop"


def test_refuses_a_cycle_back_to_this_firm(
    a_remote_agent, stub_remote_call, stub_composer,
):
    res = client.post(
        f"/remote-agents/{a_remote_agent}/run",
        json={"message": "hi", "hopCount": 1, "consultChain": ["did:aroha:zSELF"]},
    )
    assert res.status_code == 403
    assert read_consults()[0]["outcome"] == "loop"


def test_writes_exactly_one_audit_record_on_success(
    a_remote_agent, stub_remote_call, stub_composer,
):
    client.post(f"/remote-agents/{a_remote_agent}/run", json={"message": "hi"})
    records = read_consults()
    assert len(records) == 1
    assert records[0]["direction"] == "outbound"
    assert records[0]["outcome"] == "answered"
    assert records[0]["hopCount"] == 1


def test_audits_an_error_when_the_remote_call_fails(
    a_remote_agent, stub_composer, monkeypatch,
):
    monkeypatch.setattr(store, "firm_identity", lambda: {
        "did": "did:aroha:zSELF", "privateKey": "aa" * 32,
    })

    def boom(**kwargs):
        raise app_module.aroha_client.RemoteAgentError("unreachable")

    monkeypatch.setattr(app_module.aroha_client, "call_remote", boom)
    res = client.post(f"/remote-agents/{a_remote_agent}/run", json={"message": "hi"})
    assert res.status_code == 502
    assert read_consults()[0]["outcome"] == "error"
```

- [ ] **Step 2: Run it to verify it fails**

Run: `cd studio-backend && pytest tests/test_consult_api.py -v`
Expected: FAIL — the route sends the raw message and writes no audit record.

- [ ] **Step 3: Extend RemoteRunBody**

In `app.py`, replace the `RemoteRunBody` class:

```python
class RemoteRunBody(BaseModel):
    """One message to send to a remote agent.

    hopCount/consultChain carry loop state when this studio is relaying a
    consult it was itself asked (design spec §3.2). Both default to a
    first-hop consult, so the dust UI keeps posting just {"message": ...}
    and needs no change.
    """
    message: str
    hopCount: int = 0
    consultChain: list[str] = Field(default_factory=list)
    domainHint: str | None = None
```

- [ ] **Step 4: Rewrite the route body**

Add imports at the top of `app.py`:

```python
from consult_audit import ConsultRecord, append_consult, read_consults
from consult_compose import compose_question
from consult_guard import check_loop_limits, next_hop
from pii_redact import redact_pii, redact_with_categories
```

(replacing the existing `from pii_redact import redact_pii`)

Replace the body of `run_remote_agent` after the `remote is None` check:

```python
    firm = store.firm_identity()
    if firm is None or not firm.get("privateKey"):
        raise HTTPException(status_code=503,
            detail="This studio's Aroha identity could not be created. "
                   "Check that Node.js is installed and try again.")

    own_did = firm["did"]
    correlation_id = str(uuid.uuid4())

    def audit(question: str, redactions: list[str], outcome: str, answer: str | None,
              hop: int) -> None:
        append_consult(ConsultRecord(
            correlation_id=correlation_id, direction="outbound",
            peer_did=remote.did, peer_name=remote.name, question=question,
            redactions=redactions, answer=answer, hop_count=hop, outcome=outcome,
        ))

    # Free gate first: a loop check costs nothing, a model call does not.
    hop_count, consult_chain = next_hop(data.hopCount, data.consultChain, own_did)
    loop = check_loop_limits(hop_count, data.consultChain, own_did)
    if not loop.ok:
        audit(data.message, [], "loop", None, hop_count)
        raise HTTPException(status_code=403, detail=loop.reason)

    composed = compose_question(
        [{"role": "user", "content": data.message}],
        data.domainHint,
        call_model=_consult_model_call,
    )
    screened = redact_with_categories(composed)

    if screened.gutted:
        audit(screened.text, screened.categories, "declined", None, hop_count)
        raise HTTPException(
            status_code=422,
            detail="That question could not be sent — removing personal data "
                   "from it left too little to ask.",
        )

    try:
        reply = aroha_client.call_remote(
            endpoint=remote.endpoint,
            caller_did=own_did,
            caller_private_key_hex=firm["privateKey"],
            remote_did=remote.did,
            message=screened.text,
            remote_did_document=remote.didDocument,
        )
    except aroha_client.RemoteAgentError as e:
        audit(screened.text, screened.categories, "error", None, hop_count)
        raise HTTPException(status_code=502, detail=str(e))

    audit(screened.text, screened.categories, "answered", reply.answer, hop_count)

    return {"answer": reply.answer, "envelope": reply.envelope,
            "remoteDid": remote.did, "remoteName": remote.name,
            "question": screened.text, "redactions": screened.categories}
```

Add `import uuid` at the top if absent, and define the model adapter near the other helpers:

```python
def _consult_model_call(messages: list[dict], **kwargs) -> str:
    """Compose with the studio's configured model. Isolated from any agent —
    the composer has no tools and no agent identity, by design."""
    return model_client.complete(messages)
```

Use whatever `model_client` function `grep -n "def " model_client.py` showed in Task 4 Step 1 — match its real name and signature rather than assuming `complete`.

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd studio-backend && pytest tests/test_consult_api.py -v`
Expected: PASS, 7 tests.

- [ ] **Step 6: Run the whole backend suite**

Run: `cd studio-backend && pytest -v`
Expected: every pre-existing test still passes. `test_api.py` passing untouched is the signal the UI contract held.

- [ ] **Step 7: Commit**

```bash
cd "<doc-intel checkout>"
git add studio-backend/app.py studio-backend/tests/test_consult_api.py
git commit -m "feat(consult): compose, screen, loop-check and audit outbound consults

The route kept its contract with the dust UI — same request shape, same
four response keys, two added. hopCount/consultChain default to a
first-hop consult so the frontend needs no coordinated change.

Order is deliberate: the loop check is free and runs before the model
call that is not. Every path writes exactly one audit record, refusals
included."
```

---

## Task 6: Guard the inbound answering path

**Files:**
- Modify: `studio-backend/app.py` (`SharedRunRequest`, `run_agent_for_remote_caller` at ~line 587–617)
- Test: `studio-backend/tests/test_consult_api.py` (append)

**Interfaces:**
- Consumes: `check_loop_limits`, `append_consult`
- Produces: unchanged response shape; refuses looping inbound consults

- [ ] **Step 1: Write the failing test**

Append to `studio-backend/tests/test_consult_api.py`:

```python
def test_inbound_shared_run_refuses_a_looping_consult(monkeypatch):
    monkeypatch.setattr(store, "firm_identity", lambda: {
        "did": "did:aroha:zSELF", "privateKey": "aa" * 32,
    })
    agent = store.add_agent({"name": "Finance", "instructions": "be terse"})

    res = client.post("/agents/run/shared", json={
        "agentId": agent.id,
        "message": "q",
        "hopCount": 1,
        "consultChain": ["did:aroha:zSELF"],
    })
    assert res.status_code == 403
    assert read_consults()[0]["outcome"] == "loop"


def test_inbound_shared_run_still_answers_a_normal_consult(monkeypatch):
    monkeypatch.setattr(store, "firm_identity", lambda: {
        "did": "did:aroha:zSELF", "privateKey": "aa" * 32,
    })
    agent = store.add_agent({"name": "Finance", "instructions": "be terse"})

    class Result:
        answer = "Net 30, contact jane@example.com"
        sources: list = []

    monkeypatch.setattr(app_module, "run_agent", lambda req: Result())

    res = client.post("/agents/run/shared", json={
        "agentId": agent.id, "message": "payment terms?",
    })
    assert res.status_code == 200
    # The answer-side redaction that already existed must still apply.
    assert "jane@example.com" not in res.json()["answer"]
    assert read_consults()[0]["direction"] == "inbound"
```

Adjust `store.add_agent(...)` to the real creation helper — check with `grep -n "def add_agent\|def create_agent" store.py`.

- [ ] **Step 2: Run it to verify it fails**

Run: `cd studio-backend && pytest tests/test_consult_api.py -v -k inbound`
Expected: FAIL — `SharedRunRequest` rejects the extra fields, and no audit record is written.

- [ ] **Step 3: Extend SharedRunRequest and guard the route**

```python
class SharedRunRequest(BaseModel):
    agentId: str
    message: str = Field(max_length=MAX_MESSAGE_CHARS)
    # Loop state from the calling firm (design spec §3.2). Absent from an
    # older caller, which is treated as a first-hop consult.
    hopCount: int = 1
    consultChain: list[str] = Field(default_factory=list)
```

In `run_agent_for_remote_caller`, after the `get_agent is None` check:

```python
    firm = store.firm_identity()
    own_did = firm["did"] if firm else ""
    correlation_id = str(uuid.uuid4())

    loop = check_loop_limits(req.hopCount, req.consultChain, own_did)
    if not loop.ok:
        append_consult(ConsultRecord(
            correlation_id=correlation_id, direction="inbound",
            peer_did=req.consultChain[-1] if req.consultChain else "unknown",
            question=req.message, hop_count=req.hopCount,
            outcome="loop", answer=None,
        ))
        raise HTTPException(status_code=403, detail=loop.reason)
```

and after computing `result`, before returning:

```python
    redacted_answer = redact_pii(result.answer)
    append_consult(ConsultRecord(
        correlation_id=correlation_id, direction="inbound",
        peer_did=req.consultChain[-1] if req.consultChain else "unknown",
        question=req.message, hop_count=req.hopCount,
        outcome="answered", answer=redacted_answer,
    ))
```

then return `redacted_answer` in place of the inline `redact_pii(result.answer)` so the audited text and the sent text are provably the same string.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd studio-backend && pytest tests/test_consult_api.py -v`
Expected: PASS, 9 tests.

- [ ] **Step 5: Commit**

```bash
cd "<doc-intel checkout>"
git add studio-backend/app.py studio-backend/tests/test_consult_api.py
git commit -m "feat(consult): loop-check and audit inbound consults

The answering side now refuses a consult that loops back to this firm,
and records every inbound consult. The answer-side redaction that already
existed is unchanged — the audited string and the sent string are now the
same variable, so they cannot drift."
```

---

## Task 7: Audit route and UI panel

**Files:**
- Modify: `studio-backend/app.py`
- Modify: `frontend/src/api/studio.ts`
- Modify: `frontend/src/screens/dust/DustApp.tsx`
- Test: `studio-backend/tests/test_consult_api.py` (append)

- [ ] **Step 1: Write the failing test**

```python
def test_consult_audit_route_returns_records(monkeypatch):
    from consult_audit import ConsultRecord, append_consult as write
    write(ConsultRecord(
        correlation_id="c1", direction="outbound", peer_did="did:aroha:zP",
        question="q", hop_count=1, outcome="answered", answer="a",
    ))
    res = client.get("/consult-audit")
    assert res.status_code == 200
    assert res.json()[0]["correlationId"] == "c1"


def test_consult_audit_route_caps_the_limit():
    res = client.get("/consult-audit?limit=100000")
    assert res.status_code == 200
    assert len(res.json()) <= 500
```

- [ ] **Step 2: Run it to verify it fails**

Run: `cd studio-backend && pytest tests/test_consult_api.py -v -k audit_route`
Expected: FAIL — 404.

- [ ] **Step 3: Add the route**

Next to the other `/remote-agents` routes in `app.py`:

```python
@app.get("/consult-audit")
def list_consult_audit(limit: int = 100, offset: int = 0) -> list[dict]:
    """Every cross-firm consult this studio has made or answered.

    The artifact an operator hands a compliance reviewer. Capped so a caller
    cannot ask the studio to read an unbounded log into memory.
    """
    return read_consults(limit=max(1, min(limit, 500)), offset=max(0, offset))
```

- [ ] **Step 4: Add the frontend API binding**

In `frontend/src/api/studio.ts`, next to `listRemoteAgents`:

```ts
export interface ConsultAuditRecord {
  id:            string;
  timestamp:     number;
  correlationId: string;
  direction:     'outbound' | 'inbound';
  peerDid:       string;
  peerName:      string;
  question:      string;
  redactions:    string[];
  answer:        string | null;
  hopCount:      number;
  outcome:       string;
}
```

and in the `studio` object:

```ts
  listConsultAudit: () =>
    fetch(`${BASE}/consult-audit`).then(json<ConsultAuditRecord[]>),
```

- [ ] **Step 5: Surface it in the Remote agents screen**

In `DustApp.tsx`, the `remote-agents` place already renders a `Collection`. Add a second section below it listing recent consults — reuse the existing `Collection`/`Row` shapes rather than inventing a table, so it inherits the screen's styling:

```tsx
rows={consultAudit.map((r): Row => ({
  id: r.id,
  values: {
    when:      text(new Date(r.timestamp).toLocaleString()),
    direction: text(r.direction),
    peer:      text(r.peerName || r.peerDid),
    outcome:   text(r.outcome),
    withheld:  text(r.redactions.length ? r.redactions.join(', ') : '—'),
  },
}))}
```

Load it with the other reloads: `const [consultAudit, setConsultAudit] = useState<ConsultAuditRecord[]>([])` and a `reload.consultAudit` entry calling `studio.listConsultAudit()`.

Render the peer DID in monospace, matching how the screen already presents DIDs — the DID is the verifiable identity, the display name is not.

- [ ] **Step 6: Run tests and typecheck**

Run: `cd studio-backend && pytest -v`
Expected: all pass.

Run: `cd frontend && npx tsc --noEmit`
Expected: clean.

- [ ] **Step 7: Commit**

```bash
cd "<doc-intel checkout>"
git add studio-backend/app.py studio-backend/tests/test_consult_api.py frontend/src/api/studio.ts frontend/src/screens/dust/DustApp.tsx
git commit -m "feat(consult): audit route and panel on the Remote agents screen

An operator can now see every consult made or answered, what was withheld
from each, and which were refused. Reuses the existing Collection shapes
so it inherits the screen's styling rather than introducing a second
table idiom."
```

---

## Task 8: Full regression and manual verification

**Files:** none — verification only

- [ ] **Step 1: Full backend suite**

Run: `cd studio-backend && pytest -v`
Expected: every test passes, including all pre-existing ones.

- [ ] **Step 2: Frontend typecheck and build**

Run: `cd frontend && npx tsc --noEmit && npm run build`
Expected: clean.

- [ ] **Step 3: Manual — a real consult still works**

Start the studio. On the Remote agents screen, add a remote agent and `@mention` it in a thread. Confirm:
- the answer still arrives (the UI contract held)
- the audit panel shows the consult, with any redactions listed
- the question recorded is the *composed* one, not the raw message

- [ ] **Step 4: Manual — a loop is refused**

Add this studio's own firm DID as a remote agent, then consult it. Expect a 403 and a `loop` record in the audit panel, not a hang or a recursive call.

- [ ] **Step 5: Commit any fixes and push**

```bash
cd "<doc-intel checkout>"
git status
git push
```

Do not treat the work as done until the full suite passes and both manual checks behave as described.
