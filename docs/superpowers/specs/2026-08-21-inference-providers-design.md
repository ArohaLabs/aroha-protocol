# Inference Providers: local models and hosted APIs, per agent

**Status:** design, awaiting review
**Date:** 2026-08-21

## 1. What this is for

Let a person run some agents on a local model and others against a hosted
API, choosing per agent, and set up the hosted credential without editing a
file by hand. Where a provider supports OAuth, let them sign in instead of
pasting a key.

## 2. Where this starts — corrected against the code

The plumbing is further along than it looks, and in one respect worse.

**Already built and tested:**

- `EngineManager` (`src/engine/manager.ts`) abstracts local vs hosted, so
  callers do not know which answered.
- `src/engine/hosted.ts` implements **three providers** —
  `anthropic | openai | google` — including both wire formats: the OpenAI
  `/v1/chat/completions` streaming shape, and Anthropic's Messages API SSE,
  which is genuinely different and gets its own streamer.
- Local detection covers Ollama, vLLM and LM Studio.
- `gateway/oidc.ts` and `gateway/auth-api.ts` already implement
  **Authorization Code + PKCE** for human login, including the constraint
  that matters here, already written into `config.ts`: *"There is no client
  secret: a distributed binary cannot hold one."*

**Not built:**

- **Nothing supplies a hosted config.** `main.ts:217` constructs
  `new EngineManager(undefined, preferredEngine)` — the hosted argument is
  explicitly `undefined`, and there is no `config.toml` key for it. Hosted
  inference is unreachable today.
- No per-agent provider choice. `AgentRecord.model` is a bare string with no
  provider beside it.
- No credential storage. No UI.

**A shipped false instruction.** When no engine is found, `resolve()` tells
the user to *"set a hosted provider key in ~/.aroha/config.toml"*. That key
does not exist. Whatever else this design does, that message stops being a
lie.

## 3. The trap this design has to avoid

`resolve()` today tries local first and falls back to hosted **silently**,
with nothing in the API or the interface reporting which one answered.

That cannot fire right now, because no hosted config can be supplied. **It
fires the moment this feature wires one up** — which is precisely what we
are about to do.

It matters because of what the product says about itself. The sidebar reads
*"Running on your hardware."* The website promises *"not a single byte
leaving your walls."* The knowledge screens say documents never leave the
machine. For a firm that bought local-first for confidentiality reasons, an
invisible fallback that sends a contract to a third party — while the
interface still claims otherwise — is the single failure that loses the
customer and cannot be walked back.

**So: hosted inference is never a fallback.** It is a per-agent choice, made
deliberately, and visible wherever that agent appears.

## 4. Design

### 4.1 The provider lives on the agent

`AgentRecord` gains an inference target:

```ts
export type InferenceTarget =
  | { kind: "local"; model: string }
  | { kind: "hosted"; provider: HostedProvider; model: string };
```

Absent on existing records, which reads as `{ kind: "local", model }` — the
behaviour every current agent already has, so no install changes meaning on
upgrade.

`EngineManager.resolve()` keeps its local-detection role but stops choosing
policy. The agent's target decides; `resolve()` answers *"is the local
engine present"*, not *"what should I use"*.

**A hosted agent with no credential is an error, not a downgrade.** It
reports that the provider is not connected and refuses the turn. Silently
answering from a different model than the one the agent says it uses is the
same class of lie as the fallback.

*Decided 2026-08-21, and this one is contestable.* Degrading to the local
model would produce fewer support tickets in the short run and is what some
products do. It is rejected because the failure it creates is undetectable:
the answer arrives, looks plausible, and is worse than the one the agent was
configured to give — with nothing on screen to say so. A refusal is a
support ticket; a silent downgrade is a wrong answer nobody knows to
question. If this proves too strict in practice, the fix is a per-agent
opt-in to fall back, never a default.

### 4.2 It is visible, everywhere the agent is

- The agent card carries the provider, not just the model.
- The chat header shows it for the answering agent — a thread can involve
  several agents, so this is per turn, not per thread.
- **A cloud turn from an agent with documents attached warns once**, names
  what leaves the machine, and remembers the answer **per agent**. This is
  the one interruption worth its cost: it is the moment the product's
  promise changes for that agent.

  *Decided 2026-08-21.* Warning on every turn was rejected — people learn to
  dismiss a repeated dialog without reading it, which is worse than not
  warning at all, because it manufactures consent. Warning only when
  documents are attached was rejected because it misses the agent that was
  already on a hosted provider before anyone gave it documents. Once per
  agent, at the moment the two facts first meet, is the smallest
  interruption that still lands.

- The workspace footer's *"Running on your hardware"* becomes conditional,
  and **reflects a mixed workspace rather than vanishing from it**:

  | Workspace | Footer |
  |---|---|
  | every agent local | "Running on your hardware" |
  | any agent hosted | "Some agents use hosted models" |

  *Decided 2026-08-21.* In a mixed workspace the original sentence is
  neither true nor false, and simply removing it is the worst option: the
  line disappearing is invisible, so the person who most needs to know their
  setup changed is the one least likely to notice. Saying the weaker true
  thing is better than saying nothing.

### 4.3 Credentials

Provider credentials go in a store, not `config.toml`:

```
~/.aroha/credentials/<provider>.json      mode 0600
```

- **Never returned to the browser.** The UI learns *connected / not
  connected*, a masked hint (last four characters) and, for OAuth, an
  expiry. It never receives the secret. This mirrors how `/v1/settings`
  already returns a resolved value rather than the licence body.
- **Fails closed.** Unreadable or malformed reads as absent, the same rule
  `readLicence()` already applies.
- One file per provider, so revoking one cannot corrupt another.

Storing a bearer token on disk at 0600 is the same protection the workspace
already gives Ed25519 agent keys. Anything stronger — OS keychain — is a
later change behind the same interface, and is noted in §6.

### 4.4 Two credential kinds behind one interface

```ts
export type Credential =
  | { kind: "api_key"; key: string }
  | { kind: "oauth"; accessToken: string; refreshToken?: string; expiresAt: string };
```

Everything above the store reads a resolved bearer value and does not care
which kind produced it. This is what keeps OAuth from being a bolt-on: it is
a second kind of credential, added per provider, not a parallel code path.

## 5. OAuth, honestly, provider by provider

"OAuth for any provider" is not reachable. The support is uneven:

| Provider | Auth available |
|---|---|
| Anthropic | **OAuth** — `Authorization: Bearer` plus header `anthropic-beta: oauth-2025-04-20` |
| Google | API key (AI Studio), **or** OAuth/ADC via Vertex |
| Azure Foundry | **OAuth** (Entra ID) |
| OpenRouter | **OAuth** (PKCE) |
| OpenAI | API keys only — no OAuth for API access |
| AWS Bedrock | IAM SigV4 — not OAuth |

**Why it is worth doing anyway, for this product specifically.** The
argument is not security — both an API key and an OAuth token end as a
bearer value on disk, so the gain there is second-order. The argument is
onboarding. *"Sign in with Google"* is something an accountant does without
help. *"Create an API key in the developer console and paste it here"* is a
support call. This product sells to firms, not to developers, and that
difference is the whole case.

**Why it is not first.** Each provider needs its own registered client id and
its own flow, and the most likely bring-your-own-key provider — OpenAI —
cannot do it at all. API keys work everywhere on day one; OAuth is added
provider by provider behind §4.4's interface.

**The mechanism, when we do it.** Authorization Code + PKCE with a loopback
redirect, which suits a desktop app and needs no client secret — the
constraint `config.ts` already records for OIDC. The runtime already runs a
loopback HTTP server and `gateway/oidc.ts` already implements PKCE, so this
reuses proven code rather than introducing a second flow.

## 6. Out of scope

- **OS keychain storage.** Behind the §4.3 interface, so it is a later swap.
- **Per-turn provider override.** The agent decides; a caller does not get to
  redirect one turn elsewhere.
- **Bedrock and Vertex.** Both need signing schemes rather than a bearer
  token, and neither is on the path to the first customer.
- **Cost accounting.** Hosted inference costs money per token; showing spend
  is a real feature and a separate one.
- **Changing what the free tier includes.** Bringing your own key is not a
  licensing change.

## 7. What has to be true before this is done

1. `resolve()`'s "no engine" message names something that exists.
2. No configuration causes a hosted provider to answer for an agent whose
   target is local.
3. A hosted agent with no credential refuses, and says why.
4. No credential value is ever returned by an API or reaches the browser.
5. An agent with documents attached warns before its first cloud turn.
6. *"Running on your hardware"* appears only when it is true.
7. Existing agents keep answering exactly as they do now, with no edit.
