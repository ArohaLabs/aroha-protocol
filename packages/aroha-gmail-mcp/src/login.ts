// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * One-time sign-in, to obtain the refresh token this server runs on.
 *
 * Authorization Code + PKCE with a loopback redirect — the same shape the
 * runtime uses, and for the same reason: it suits software installed on
 * somebody's machine and needs no client secret of its own (though it will
 * send one, because a Web-application OAuth client requires it even with
 * PKCE, and not everybody can create a Desktop client).
 *
 * Run once:
 *
 *   GOOGLE_CLIENT_ID=... GOOGLE_CLIENT_SECRET=... npx aroha-gmail-mcp login
 *
 * It prints the refresh token and exits. Nothing is written to disk: where
 * that token belongs — an env var, a secret store, an MCP host's config — is
 * the operator's decision, and guessing it would be this server inventing a
 * home for somebody else's credential.
 */

import { createServer } from "node:http";
import { createHash, randomBytes } from "node:crypto";
import { spawn } from "node:child_process";

const AUTHORIZE = "https://accounts.google.com/o/oauth2/v2/auth";
const TOKEN = "https://oauth2.googleapis.com/token";

/**
 * What this server can actually use.
 *
 * `gmail.readonly` for search and reading, `gmail.compose` for drafts. Both
 * are what the Gmail API documents for those operations — this is not the
 * preview MCP endpoint's scope list, which is a different service.
 */
export const DEFAULT_SCOPES = [
  "https://www.googleapis.com/auth/gmail.readonly",
  "https://www.googleapis.com/auth/gmail.compose",
];

function base64Url(buf: Buffer): string {
  return buf.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function pkcePair(): { verifier: string; challenge: string } {
  const verifier = base64Url(randomBytes(32));
  const challenge = base64Url(createHash("sha256").update(verifier).digest());
  return { verifier, challenge };
}

export function authorizeUrl(opts: {
  clientId: string; redirectUri: string; challenge: string; state: string; scopes: string[];
}): string {
  const url = new URL(AUTHORIZE);
  url.searchParams.set("response_type", "code");
  url.searchParams.set("client_id", opts.clientId);
  url.searchParams.set("redirect_uri", opts.redirectUri);
  url.searchParams.set("scope", opts.scopes.join(" "));
  url.searchParams.set("code_challenge", opts.challenge);
  url.searchParams.set("code_challenge_method", "S256");
  url.searchParams.set("state", opts.state);
  // Without BOTH of these Google returns no refresh token on a repeat
  // authorization — and a refresh token is the entire point of this command.
  url.searchParams.set("access_type", "offline");
  url.searchParams.set("prompt", "consent");
  return url.toString();
}

function openBrowser(url: string): void {
  const [cmd, args] =
    process.platform === "win32" ? ["rundll32.exe", ["url.dll,FileProtocolHandler", url]] :
    process.platform === "darwin" ? ["open", [url]] :
    ["xdg-open", [url]];
  try {
    spawn(cmd, args as string[], { detached: true, stdio: "ignore" }).unref();
  } catch {
    // Printed below regardless, so a machine with no opener is not stuck.
  }
}

/** Runs the flow and resolves with the refresh token. */
export async function login(opts: {
  clientId: string;
  clientSecret?: string;
  scopes?: string[];
  port?: number;
  /**
   * Bind and redirect to exactly this URI, rather than choosing a free port.
   *
   * A Desktop OAuth client accepts any loopback port, so the default is to
   * take whatever is free. A WEB client does not: it matches the redirect
   * byte for byte against what was registered, and the error for getting it
   * wrong names the URI it received and never the one it wanted. Passing the
   * registered URI here is what lets somebody with a Web client sign in
   * without adding a second entry in the console.
   */
  redirectUri?: string;
}): Promise<string> {
  const { verifier, challenge } = pkcePair();
  const state = base64Url(randomBytes(24));
  const scopes = opts.scopes ?? DEFAULT_SCOPES;

  return new Promise((resolve, reject) => {
    // When a redirect URI is supplied, its port and path are what the server
    // must bind and serve — anything else produces a mismatch at Google.
    const fixed = opts.redirectUri ? new URL(opts.redirectUri) : null;
    const callbackPath = fixed ? fixed.pathname : "/callback";

    const server = createServer(async (req, res) => {
      const url = new URL(req.url ?? "/", "http://127.0.0.1");
      if (url.pathname !== callbackPath) { res.writeHead(404).end(); return; }

      const finish = (title: string, detail: string) => {
        res.writeHead(200, { "content-type": "text/html; charset=utf-8" });
        res.end(
          `<!doctype html><meta charset="utf-8"><title>${title}</title>` +
          `<body style="font:14px system-ui;margin:3rem auto;max-width:32rem;padding:0 1rem">` +
          `<h1 style="font-size:20px">${title}</h1><p>${detail}</p>`,
        );
      };

      // The state check is what makes this endpoint safe to expose at all:
      // it is entered by a cross-site redirect carrying no credential.
      if (url.searchParams.get("state") !== state) {
        finish("That sign-in could not be matched", "Start it again.");
        return;
      }
      const err = url.searchParams.get("error");
      const code = url.searchParams.get("code");
      if (err || !code) {
        finish("Sign-in was not completed", err ? `Google reported: ${err}` : "No code came back.");
        server.close();
        reject(new Error(err ?? "no authorization code"));
        return;
      }

      try {
        const body = new URLSearchParams({
          grant_type: "authorization_code",
          code,
          redirect_uri: opts.redirectUri ??
            `http://127.0.0.1:${(server.address() as { port: number }).port}/callback`,
          client_id: opts.clientId,
          code_verifier: verifier,
          ...(opts.clientSecret ? { client_secret: opts.clientSecret } : {}),
        });
        const tokenRes = await fetch(TOKEN, {
          method: "POST",
          headers: { "content-type": "application/x-www-form-urlencoded" },
          body: body.toString(),
        });
        const json = (await tokenRes.json()) as {
          refresh_token?: string; error?: string; error_description?: string;
        };
        if (!tokenRes.ok || !json.refresh_token) {
          const detail = json.error_description ?? json.error ?? `HTTP ${tokenRes.status}`;
          finish("Sign-in was not completed", detail);
          server.close();
          reject(new Error(detail));
          return;
        }
        finish("Signed in", "You can close this tab. The refresh token was printed in your terminal.");
        server.close();
        resolve(json.refresh_token);
      } catch (e) {
        finish("Sign-in was not completed", (e as Error).message);
        server.close();
        reject(e as Error);
      }
    });

    const bindPort = fixed ? Number(fixed.port || 80) : (opts.port ?? 0);
    server.on("error", (e) => reject(new Error(
      `Could not listen on ${bindPort}: ${(e as Error).message}. ` +
      "If another process holds that port, stop it and try again.",
    )));
    server.listen(bindPort, "127.0.0.1", () => {
      const { port } = server.address() as { port: number };
      const redirectUri = opts.redirectUri ?? `http://127.0.0.1:${port}/callback`;
      const url = authorizeUrl({ clientId: opts.clientId, redirectUri, challenge, state, scopes });
      // Printed as well as opened: a Web-application OAuth client needs this
      // exact redirect registered, and the port is chosen at runtime — so the
      // one string somebody may have to paste into the console is shown.
      process.stderr.write(`\nRedirect URI in use: ${redirectUri}\n`);
      process.stderr.write("(register that exactly if your OAuth client is a Web application)\n\n");
      process.stderr.write(`Opening: ${url}\n\n`);
      openBrowser(url);
    });
  });
}
