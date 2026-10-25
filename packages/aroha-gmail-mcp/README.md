# @aroha-sdk/gmail-mcp

An MCP server for Gmail — search, read, label and draft — built against the
**ordinary Gmail API**.

---

## Why this exists

Google publishes its own Gmail MCP server at `gmailmcp.googleapis.com`. It is
part of the [Google Workspace Developer Preview Program][preview], and a
project that is not enrolled in that programme cannot use it. Every call is
answered:

```
The caller does not have permission
```

regardless of the scopes on the token, regardless of the API being enabled in
the project, and with nothing in the message to say which of those is wrong.

That was established by measurement rather than inference. With one account,
one OAuth client and one token carrying every scope that service lists:

| Request | Result |
|---|---|
| `list_labels` via `gmailmcp.googleapis.com` | refused |
| `users/me/labels` via `gmail.googleapis.com` | 22 labels |
| `users/me/messages?q=…` via `gmail.googleapis.com` | 201 matches |
| the same `list_labels`, through a client enrolled in the preview | worked |

So the capability was never out of reach — only that one endpoint was. This
server talks to the API that is open to everybody.

[preview]: https://developers.google.com/workspace/gmail/api/guides/configure-mcp-server

---

## Setup

**1. Create an OAuth client** in the Google Cloud console
(APIs & Services → Credentials → Create credentials → OAuth client ID).

- **Desktop app** if the option is offered — it needs no client secret and
  accepts any loopback port.
- **Web application** works too, and then you need its client secret *and*
  must register the redirect URI that `login` prints.

Enable the **Gmail API** for the project. (Not the Gmail *MCP* API — that is
the preview-gated one this server exists to avoid.)

**2. Sign in once** to obtain a refresh token:

```bash
GOOGLE_CLIENT_ID=…apps.googleusercontent.com \
GOOGLE_CLIENT_SECRET=GOCSPX-…            \
npx aroha-gmail-mcp login
```

Your browser opens; consent; the refresh token is printed to stdout. Nothing
is written to disk — where that token belongs is your decision.

Override the scopes with `GOOGLE_SCOPES` if you want less than the default
(`gmail.readonly` and `gmail.compose`).

**3. Add the server.**

In **Aroha** — Tools → Add manually:

| Field | Value |
|---|---|
| Name | `gmail` |
| Command | `npx` |
| Arguments | `-y @aroha-sdk/gmail-mcp` |

with `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET` and `GOOGLE_REFRESH_TOKEN` in
the environment.

In **Claude Desktop** — `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "gmail": {
      "command": "npx",
      "args": ["-y", "@aroha-sdk/gmail-mcp"],
      "env": {
        "GOOGLE_CLIENT_ID": "…apps.googleusercontent.com",
        "GOOGLE_CLIENT_SECRET": "GOCSPX-…",
        "GOOGLE_REFRESH_TOKEN": "1//…"
      }
    }
  }
}
```

---

## Tools

| Tool | What it does |
|---|---|
| `gmail_search_messages` | Search with Gmail's own query syntax (`from:alice newer_than:7d`, `subject:invoice has:attachment`, `is:unread`). Returns sender, subject, date and snippet. Capped at 25 results. |
| `gmail_get_message` | Read one message in full, including its body. |
| `gmail_list_labels` | Labels, with message and unread counts. |
| `gmail_create_draft` | Compose a draft. **Never sends** — the draft appears in Gmail for a person to review and send. |

There is deliberately **no send tool**. A draft is reviewable and reversible;
sending is neither, and "draft it and let me look" is what people actually
ask for. Under Aroha every call additionally passes through `mcp-guard`, so a
draft is gated like any other tool.

---

## Notes on the implementation

**Access tokens are minted, not configured.** Google's last an hour, so a
server configured with one would work through a demo and stop before anybody
used it in earnest — with an error indistinguishable from a broken setup. The
configured secret is the *refresh* token; access tokens are cached and renewed
a minute before they expire.

**Header injection is prevented at the MIME layer.** The subject of a drafted
email is very often model output, and a newline in a header value would let
anything upstream inject a `Bcc` into a message a person is about to read and
trust. Header values are stripped of CR and LF; the body is left alone,
because newlines there are just text.

**An empty search result is an answer, not an error.** It returns
"No messages matched …" rather than `[]`, because a model handed an empty
array will often retry or apologise instead of reporting the finding.
