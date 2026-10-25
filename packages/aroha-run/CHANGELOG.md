# Changelog

## 1.4.0

Three additive changes. Nothing removed, nothing renamed — an existing
consumer upgrades without edits.

### `HandlerContext.caller` — who is speaking

`serve()` built the handler context from the request body alone, and the
`callerDid` it already derived from a verified `aroha-sig` signature was
computed and discarded. A handler could not know who it was talking to,
which meant nothing could be keyed per person: not durable memory, not a
per-user quota, not a per-user audit trail.

```ts
interface Caller {
  kind: "person" | "agent" | "unattributed";
  id: string;
  displayName?: string;
}
```

Three properties carry the weight:

- **Not on the wire.** `RunRequest` has no `caller`. One that could name
  itself in its own request body could name anyone, so the field is set
  after the body is parsed and an invented one is ignored.
- **Required, not optional.** A handler keying per person gets an id
  belonging to nobody rather than `undefined` quietly pooling every caller
  into one bucket.
- **Proof beats assertion.** A verified signature outranks the host's
  `resolveCaller` hook, so a host bug cannot relabel a cryptographically
  identified agent as any person it likes.

**Migration:** none for handlers, which only read it. Code that constructs a
`HandlerContext` by hand — server-side only — must now supply `caller`;
`ANONYMOUS_CALLER` is exported for when nobody is identified.

### `ServeOptions.resolveCaller` — naming the human

Lets the embedding host identify the person behind a request from its own
knowledge: a session cookie it issued, an SSO subject it verified. Called
per run; return `undefined` when nobody is identified.

Whatever it reads must be something the host sets **unconditionally** —
overwriting, never merging, any value an outside caller supplied. Otherwise
it is an impersonation primitive.

### `RunEvent` gains `trace`

```ts
| { type: "trace"; message: string }
```

Something about *how* a turn ran, addressed to the person watching — neither
model output nor a failure. The first use is history trimmed to fit a
context window: silent trimming is silent truncation with a delay, and
someone asking "why did it forget?" has to be able to see that it did.

Consumers that do not know the type ignore it.

### Also

`registerSkill`, `resolveSkill`, `listSkills` and `SKILL_TYPES` are now
marked `@deprecated`. They publish and resolve a **registry listing** — a
name, a description, an endpoint — which is a directory entry, not
procedural knowledge. An Agent Skill is a `SKILL.md` folder in the open
format around forty agent products read. The functions still work and the
registry still serves them; the tag exists so the collision is visible at
the call site.
