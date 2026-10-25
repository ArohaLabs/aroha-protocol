# Copyright (c) 2026 Aroha Labs
# SPDX-License-Identifier: Apache-2.0

"""Framework bridges, exercised WITHOUT any framework installed.

Each bridge's framework import is satisfied by a minimal stand-in module, so
the mapping logic — which capabilities become tools, what schema and name
they get, what envelope is signed and sent, how a framework's reply becomes
the /v1/run message — runs in every CI job. The same paths run against the
real frameworks in tests/test_bridges_<framework>.py when those are installed.
"""

from __future__ import annotations

import asyncio
import contextlib
import importlib
import sys
import types
from typing import Any, Iterator

import pytest
from pydantic import BaseModel, ConfigDict

import aroha.bridges as bridges_pkg
from aroha.bridges import _common
from tests._bridge_helpers import (
    PROVIDER_DID,
    PROVIDER_ENDPOINT,
    SEARCH_SCHEMA,
    Caller,
    Orchestrator,
    RecordingClient,
    discovered_agents,
    run,
    signed_post,
    trust_callers,
)


@contextlib.contextmanager
def stub_framework(bridge: str, modules: dict[str, types.ModuleType]) -> Iterator[Any]:
    """Import ``aroha.bridges.<bridge>`` with ``modules`` standing in for the framework.

    Restores sys.modules (and the package attribute) afterwards, so a real
    framework import in another test file is unaffected.
    """
    full = f"aroha.bridges.{bridge}"
    saved = {name: sys.modules.get(name) for name in [*modules, full]}
    saved_attr = getattr(bridges_pkg, bridge, None)
    try:
        sys.modules.pop(full, None)
        sys.modules.update(modules)
        yield importlib.import_module(full)
    finally:
        for name, mod in saved.items():
            if mod is None:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = mod
        if saved_attr is None:
            if hasattr(bridges_pkg, bridge):
                delattr(bridges_pkg, bridge)
        else:
            setattr(bridges_pkg, bridge, saved_attr)


def module(name: str, **attrs: Any) -> types.ModuleType:
    m = types.ModuleType(name)
    m.__dict__.update(attrs)
    return m


@pytest.fixture
def orch() -> Orchestrator:
    return Orchestrator()


# ── _common: framework-free plumbing ──────────────────────────────────────────

def test_tool_name_is_a_valid_function_name():
    assert _common.tool_name("search-flights") == "aroha_search_flights"
    assert _common.tool_name("ns:flights.search v2") == "aroha_ns_flights_search_v2"
    assert len(_common.tool_name("x" * 200)) == 64


def test_input_schema_defaults_and_rejects_non_object():
    assert _common.input_schema({}) == {"type": "object", "properties": {}}
    assert _common.input_schema({"inputSchema": {"type": "string"}}) == {"type": "object", "properties": {}}
    assert _common.input_schema({"inputSchema": SEARCH_SCHEMA}) == SEARCH_SCHEMA


def test_iter_capabilities_picks_only_requested():
    got = [cap["id"] for _, cap in _common.iter_capabilities(discovered_agents(), ["book-flight", "search-flights"])]
    assert got == ["search-flights", "book-flight"]
    assert list(_common.iter_capabilities([{"did": "x", "endpoint": "y"}], ["a"])) == []


def test_format_response_shapes():
    assert "accepted" in _common.format_response(None).lower()
    assert _common.format_response({"type": "ArohaError", "body": {"message": "nope"}}) == "Error: nope"
    assert _common.format_response({"type": "ArohaResponse", "body": {"result": {"a": 1}}}) == '{\n  "a": 1\n}'


async def test_call_capability_sends_a_signed_request(orch):
    client = RecordingClient(orch)
    out = await _common.call_capability(
        client, orchestrator_did=orch.did, agent_did=PROVIDER_DID, endpoint=PROVIDER_ENDPOINT,
        capability_id="search-flights", params={"origin": "SFO"}, correlation_id="saga-1",
        private_key=orch.private_key,
    )
    endpoint, env = client.sent[0]
    assert endpoint == PROVIDER_ENDPOINT
    assert env["type"] == "ArohaRequest" and env["from"] == orch.did and env["to"] == PROVIDER_DID
    assert env["correlationId"] == "saga-1"
    assert env["body"] == {"capability": "search-flights", "params": {"origin": "SFO"}}
    assert '"origin": "SFO"' in out


async def test_run_sync_works_inside_a_running_loop():
    async def answer():
        await asyncio.sleep(0)
        return 42
    # asyncio.run() would raise "cannot be called from a running event loop".
    assert _common.run_sync(answer()) == 42


def test_run_sync_without_a_loop():
    async def answer():
        return "ok"
    assert _common.run_sync(answer()) == "ok"


def test_model_from_schema_types_required_and_extra():
    M = _common.model_from_schema("aroha_search_flights_params", SEARCH_SCHEMA)
    assert M.model_json_schema()["required"] == ["origin"]
    m = M.model_validate({"origin": "SFO", "cabin": "economy"})
    assert _common.params_from_model(m) == {"origin": "SFO", "cabin": "economy"}
    with pytest.raises(Exception):
        M.model_validate({"passengers": 2})


# ── langchain_bridge ──────────────────────────────────────────────────────────

class _StubLangChainTool(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)
    name: str
    description: str
    args_schema: Any = None


async def test_langchain_bridge_with_stub(orch):
    lc_tools = module("langchain_core.tools", BaseTool=_StubLangChainTool)
    with stub_framework("langchain_bridge", {"langchain_core": module("langchain_core"), "langchain_core.tools": lc_tools}) as lb:
        client = RecordingClient(orch)
        tools = await lb.aroha_tools_for_agent(
            discovered_agents(), ["search-flights", "book-flight"], orch.did, orch.private_key, client
        )
        assert [t.name for t in tools] == ["aroha_search_flights", "aroha_book_flight"]
        assert tools[0].args_schema == SEARCH_SCHEMA
        assert tools[1].args_schema == {"type": "object", "properties": {}}
        assert tools[0].correlation_id == tools[1].correlation_id

        await tools[0]._arun(origin="SFO")
        # The sync entry point is called from inside this running loop.
        tools[1]._run(flight="UA1")
        assert [e["body"] for _, e in client.sent] == [
            {"capability": "search-flights", "params": {"origin": "SFO"}},
            {"capability": "book-flight", "params": {"flight": "UA1"}},
        ]


# ── langchain_v1 ──────────────────────────────────────────────────────────────

class _Msg:
    def __init__(self, content: Any) -> None:
        self.content = content


def _lc_stubs() -> dict[str, types.ModuleType]:
    return {
        "langchain_core": module("langchain_core"),
        "langchain_core.runnables": module("langchain_core.runnables", Runnable=object),
        "langchain_core.messages": module(
            "langchain_core.messages",
            HumanMessage=type("HumanMessage", (_Msg,), {}),
            AIMessage=type("AIMessage", (_Msg,), {}),
        ),
    }


@contextlib.contextmanager
def lc_stubbed():
    saved = {n: sys.modules.get(n) for n in _lc_stubs()}
    sys.modules.update(_lc_stubs())
    try:
        yield
    finally:
        for n, m in saved.items():
            if m is None:
                sys.modules.pop(n, None)
            else:
                sys.modules[n] = m


async def test_langchain_v1_from_chain_output_extraction():
    from aroha.bridges.langchain_v1 import from_chain

    class AgentExecutorLike:
        def __init__(self) -> None:
            self.inputs: list[dict] = []

        async def ainvoke(self, inputs):
            self.inputs.append(inputs)
            return {"input": inputs["message"], "output": "the answer"}

    chain = AgentExecutorLike()
    with lc_stubbed():
        agent = from_chain(chain, memory="session", auth="none")
    out = await run(agent, "question", "s1")
    assert out["message"] == "the answer"          # not the echoed "input"
    await run(agent, "again", "s1")
    assert chain.inputs[1]["history"] == [
        {"role": "user", "content": "question"}, {"role": "assistant", "content": "the answer"},
    ]

    class BlocksChain:
        async def ainvoke(self, inputs):
            return _Msg([{"type": "text", "text": "Hel"}, {"type": "tool_use"}, {"type": "text", "text": "lo"}])

    with lc_stubbed():
        agent = from_chain(BlocksChain(), auth="none")
    assert (await run(agent, "x"))["message"] == "Hello"


async def test_langchain_v1_from_graph_history_vs_checkpointer():
    from aroha.bridges.langchain_v1 import from_graph

    class Graph:
        def __init__(self, checkpointer) -> None:
            self.checkpointer = checkpointer
            self.calls: list[tuple[list, dict]] = []

        async def ainvoke(self, state, config=None):
            self.calls.append((state["messages"], config))
            return {"messages": [*state["messages"], _Msg(f"reply {len(self.calls)}")]}

    plain, saved = Graph(None), Graph(object())
    with lc_stubbed():  # the handler imports message classes per request
        a, b = from_graph(plain, auth="none"), from_graph(saved, auth="none")
        for agent in (a, b):
            await run(agent, "one", "thread-1")
            out = await run(agent, "two", "thread-1")
            assert out["message"] == "reply 2"
    assert [m.content for m in plain.calls[1][0]] == ["one", "reply 1", "two"]
    assert [m.content for m in saved.calls[1][0]] == ["two"]   # checkpointer holds the rest
    assert saved.calls[1][1] == {"configurable": {"thread_id": "thread-1"}}


# ── crewai_bridge ─────────────────────────────────────────────────────────────

class _StubCrewTool(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)
    name: str
    description: str
    args_schema: Any = None


async def test_crewai_bridge_with_stub(orch):
    stubs = {"crewai": module("crewai"), "crewai.tools": module("crewai.tools", BaseTool=_StubCrewTool)}
    with stub_framework("crewai_bridge", stubs) as cb:
        client = RecordingClient(orch)
        # Constructing the tool used to fail: fields were assigned after
        # super().__init__() had already rejected them as missing.
        tool = cb.ArohaCrewTool(
            capability_id="search-flights", agent_did=PROVIDER_DID, agent_endpoint=PROVIDER_ENDPOINT,
            orchestrator_did=orch.did, private_key=orch.private_key, input_schema=SEARCH_SCHEMA, client=client,
        )
        assert tool.name == "aroha_search_flights"
        assert tool.args_schema.model_json_schema()["required"] == ["origin"]
        tool._run(origin="SFO", passengers=None)
        assert client.sent[0][1]["body"]["params"] == {"origin": "SFO"}

        tools = cb.aroha_tools_for_crew(discovered_agents(), ["book-flight"], orch.did, orch.private_key, client)
        assert [t.name for t in tools] == ["aroha_book_flight"]
        assert "Error: sold out" == await _with_reply(client, {"type": "ArohaError", "body": {"message": "sold out"}},
                                                     tools[0]._execute({}))


async def _with_reply(client: RecordingClient, reply: Any, coro) -> Any:
    client.reply = reply
    return await coro


# ── crewai_v1 ─────────────────────────────────────────────────────────────────

class _FakeCrewOutput:
    def __init__(self, raw: str) -> None:
        self.raw = raw


class _FakeCrew:
    def __init__(self, description: str = "Answer: {message}") -> None:
        self.description = description
        self.kickoffs: list[Any] = []
        self.copies: list["_FakeCrew"] = []

    def copy(self) -> "_FakeCrew":
        c = _FakeCrew(self.description)
        self.copies.append(c)
        return c

    def kickoff(self, inputs=None):
        self.kickoffs.append(inputs)
        text = self.description.format(**inputs) if inputs else self.description
        return _FakeCrewOutput(f"done: {text}")


async def test_crewai_v1_factory_and_instance(monkeypatch):
    monkeypatch.setitem(sys.modules, "crewai", module("crewai"))
    from aroha.bridges.crewai_v1 import from_crew

    made: list[_FakeCrew] = []

    def factory(message: str) -> _FakeCrew:
        made.append(_FakeCrew(description=message))
        return made[-1]

    out = await run(from_crew(factory, auth="none"), "find {braces} literally")
    assert out["message"] == "done: find {braces} literally"
    assert made[0].kickoffs == [None]          # no interpolation of user text

    shared = _FakeCrew()
    agent = from_crew(shared, memory="session", auth="none")
    assert (await run(agent, "hi", "s"))["message"] == "done: Answer: hi"
    await run(agent, "and again", "s")
    assert shared.kickoffs == []               # never mutated; copied per request
    assert shared.copies[1].kickoffs[0]["history"] == "user: hi\nassistant: done: Answer: hi"


# ── autogen_bridge ────────────────────────────────────────────────────────────

class _StubAutoGenBaseTool:
    def __class_getitem__(cls, item):
        return cls

    def __init__(self, args_type, return_type, name, description, strict=False):
        self._args_type, self._name, self._description = args_type, name, description

    @property
    def name(self):
        return self._name

    @property
    def description(self):
        return self._description

    async def run_json(self, args, cancellation_token, call_id=None):
        return await self.run(self._args_type.model_validate(args), cancellation_token)


async def test_autogen_bridge_with_stub(orch):
    stubs = {
        "autogen_core": module("autogen_core", CancellationToken=object),
        "autogen_core.tools": module("autogen_core.tools", BaseTool=_StubAutoGenBaseTool, ToolSchema=dict),
    }
    with stub_framework("autogen_bridge", stubs) as ab:
        client = RecordingClient(orch)
        tools = ab.aroha_tools_for_autogen(discovered_agents(), ["search-flights"], orch.did, orch.private_key, client)
        (tool,) = tools
        assert tool.name == "aroha_search_flights"
        assert tool.schema["parameters"]["properties"] == SEARCH_SCHEMA["properties"]
        assert tool.schema["parameters"]["required"] == ["origin"]
        out = await tool.run_json({"origin": "SFO", "passengers": 2}, object())
        assert client.sent[0][1]["body"]["params"] == {"origin": "SFO", "passengers": 2}
        assert '"capability": "search-flights"' in out


# ── google_adk ────────────────────────────────────────────────────────────────

class _Part:
    def __init__(self, text=None, thought=False):
        self.text, self.thought = text, thought


class _Content:
    def __init__(self, role=None, parts=None):
        self.role, self.parts = role, parts or []


class _Event:
    def __init__(self, final: bool, content: _Content | None):
        self._final, self.content = final, content

    def is_final_response(self):
        return self._final


class _SessionService:
    def __init__(self):
        self.sessions: dict[tuple, dict] = {}

    async def get_session(self, *, app_name, user_id, session_id, config=None):
        return self.sessions.get((app_name, user_id, session_id))

    async def create_session(self, *, app_name, user_id, state=None, session_id=None):
        key = (app_name, user_id, session_id)
        if key in self.sessions:
            raise ValueError("exists")
        self.sessions[key] = {"turns": []}
        return self.sessions[key]


class _Runner:
    """Mimics google.adk.runners.Runner: unknown session ids are an error."""

    def __init__(self):
        self.app_name = "app"
        self.session_service = _SessionService()

    async def run_async(self, *, user_id, session_id, new_message):
        session = await self.session_service.get_session(app_name=self.app_name, user_id=user_id, session_id=session_id)
        if session is None:
            raise ValueError(f"Session not found: {session_id}")
        session["turns"].append(new_message.parts[0].text)
        yield _Event(False, _Content("model", [_Part("partial")]))
        yield _Event(True, _Content("model", [_Part("thinking...", thought=True),
                                              _Part(f"turn {len(session['turns'])}: {new_message.parts[0].text}")]))


async def test_google_adk_creates_session_and_reuses_it(monkeypatch):
    genai_types = module("google.genai.types", Content=_Content, Part=_Part)
    monkeypatch.setitem(sys.modules, "google", module("google"))
    monkeypatch.setitem(sys.modules, "google.genai", module("google.genai", types=genai_types))
    monkeypatch.setitem(sys.modules, "google.genai.types", genai_types)
    from aroha.bridges.google_adk import from_runner

    runner = _Runner()
    agent = from_runner(runner, user_id="u1", auth="none")
    assert (await run(agent, "hello", "sess-9"))["message"] == "turn 1: hello"
    assert (await run(agent, "again", "sess-9"))["message"] == "turn 2: again"
    assert list(runner.session_service.sessions) == [("app", "u1", "sess-9")]


# ── openai_v1 ─────────────────────────────────────────────────────────────────

def _completion(text: str):
    msg = types.SimpleNamespace(content=text)
    return types.SimpleNamespace(choices=[types.SimpleNamespace(message=msg)])


class _SyncCompletions:
    def __init__(self):
        self.calls: list[dict] = []

    def create(self, *, model, messages):
        self.calls.append({"model": model, "messages": messages})
        return _completion(f"sync:{messages[-1]['content']}")


class _AsyncCompletions:
    def __init__(self):
        self.calls: list[dict] = []

    async def create(self, *, model, messages):
        self.calls.append({"model": model, "messages": messages})
        return _completion(f"async:{messages[-1]['content']}")


def _client(completions):
    return types.SimpleNamespace(chat=types.SimpleNamespace(completions=completions))


async def test_openai_client_sync_and_async():
    from aroha.bridges.openai_v1 import from_openai_client

    sync, asyn = _SyncCompletions(), _AsyncCompletions()
    a = from_openai_client(_client(sync), model="m1", system_prompt="sys", auth="none")
    b = from_openai_client(_client(asyn), model="m2", auth="none")
    assert (await run(a, "hi", "s"))["message"] == "sync:hi"
    # An async client used to be run in a thread and fail on an un-awaited coroutine.
    assert (await run(b, "hi"))["message"] == "async:hi"
    await run(a, "more", "s")
    assert sync.calls[1]["messages"] == [
        {"role": "system", "content": "sys"},
        {"role": "user", "content": "hi"},
        {"role": "assistant", "content": "sync:hi"},
        {"role": "user", "content": "more"},
    ]
    assert asyn.calls[0]["model"] == "m2"


async def test_openai_agent_passes_history(monkeypatch):
    seen: list[Any] = []

    class Runner:
        @staticmethod
        async def run(agent, run_input):
            seen.append(run_input)
            return types.SimpleNamespace(final_output=f"agent:{len(seen)}")

    monkeypatch.setitem(sys.modules, "agents", module("agents", Runner=Runner))
    from aroha.bridges.openai_v1 import from_openai_agent

    agent = from_openai_agent(object(), memory="session", auth="none")
    assert (await run(agent, "first", "s"))["message"] == "agent:1"
    await run(agent, "second", "s")
    assert seen[0] == "first"
    assert seen[1] == [
        {"role": "user", "content": "first"},
        {"role": "assistant", "content": "agent:1"},
        {"role": "user", "content": "second"},
    ]


# ── auth: every /v1/run bridge is authenticated by default ────────────────────

class _EchoChain:
    async def ainvoke(self, inputs):
        return "ok"


class _EchoGraph:
    checkpointer = None

    async def ainvoke(self, state, config=None):
        return {"messages": [_Msg("ok")]}


def _default_auth_agents(monkeypatch) -> list:
    """One agent per v1/run factory, every one built WITHOUT an auth argument."""
    monkeypatch.setitem(sys.modules, "crewai", module("crewai"))
    for name, mod in _lc_stubs().items():
        monkeypatch.setitem(sys.modules, name, mod)
    from aroha.bridges.crewai_v1 import from_crew
    from aroha.bridges.google_adk import from_runner
    from aroha.bridges.langchain_v1 import from_chain, from_graph
    from aroha.bridges.openai_v1 import from_openai_agent, from_openai_client

    return [
        from_chain(_EchoChain()),
        from_graph(_EchoGraph()),
        from_crew(_FakeCrew()),
        from_runner(_Runner()),
        from_openai_client(_client(_SyncCompletions())),
        from_openai_agent(object()),
    ]


async def test_v1_run_bridges_default_to_signed_requests(monkeypatch):
    agents = _default_auth_agents(monkeypatch)
    assert [a.auth for a in agents] == ["aroha-sig"] * len(agents)
    for agent in agents:
        resp = await signed_post(agent, None, "unsigned")
        assert resp.status_code == 401, (agent.name, resp.text)


async def test_signed_request_reaches_the_bridge(monkeypatch):
    caller = Caller()
    agent = _default_auth_agents(monkeypatch)[0]
    trust_callers(agent, caller)
    resp = await signed_post(agent, caller, "hello")
    assert resp.status_code == 200 and resp.json()["message"] == "ok"


async def test_caller_did_in_context_is_set_by_the_server_only():
    from aroha.agent import CALLER_CONTEXT_KEY, ArohaAgent

    seen: list[dict] = []

    async def handler(message, session_id, history, context, **kw):
        seen.append(context)
        return "ok"

    caller = Caller()
    signed = ArohaAgent(name="t", handler=handler)
    trust_callers(signed, caller)
    forged = {CALLER_CONTEXT_KEY: "did:aroha:someone-else", "x": 1}
    assert (await signed_post(signed, caller, "hi", context=forged)).status_code == 200
    assert seen[-1] == {CALLER_CONTEXT_KEY: caller.did, "x": 1}

    open_agent = ArohaAgent(name="t", handler=handler, auth="none")
    assert (await signed_post(open_agent, None, "hi", context=forged)).status_code == 200
    assert seen[-1] == {"x": 1}   # no verified caller: a client-supplied value is dropped


async def test_google_adk_user_is_the_verified_caller(monkeypatch):
    genai_types = module("google.genai.types", Content=_Content, Part=_Part)
    monkeypatch.setitem(sys.modules, "google", module("google"))
    monkeypatch.setitem(sys.modules, "google.genai", module("google.genai", types=genai_types))
    monkeypatch.setitem(sys.modules, "google.genai.types", genai_types)
    from aroha.bridges.google_adk import from_runner

    alice, bob = Caller(), Caller()
    runner = _Runner()
    agent = from_runner(runner)
    trust_callers(agent, alice, bob)
    assert (await signed_post(agent, alice, "a1", "shared")).json()["message"] == "turn 1: a1"
    # Bob names Alice's session id but lands in his own ADK session.
    assert (await signed_post(agent, bob, "b1", "shared")).json()["message"] == "turn 1: b1"
    assert (await signed_post(agent, alice, "a2", "shared")).json()["message"] == "turn 2: a2"
    assert sorted(k[1] for k in runner.session_service.sessions) == sorted([alice.did, bob.did])
