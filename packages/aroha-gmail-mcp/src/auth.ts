// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Google credentials for the Gmail MCP server.
 *
 * ── Why this server exists at all ────────────────────────────────────────
 *
 * Google ships its own Gmail MCP server at `gmailmcp.googleapis.com`, and it
 * is unusable by a third-party runtime: it is part of the Google Workspace
 * Developer Preview Program, so a project that has enabled the API and holds
 * a token with every scope the service lists is STILL answered
 * "The caller does not have permission". Measured, not assumed — the same
 * token, same account, same call succeeded through a client admitted to the
 * preview and failed through one that was not.
 *
 * The ordinary Gmail API — `gmail.googleapis.com` — is generally available
 * and answers that same token perfectly: profile, labels, and a real search
 * all returned. So this server does the obvious thing and talks to the API
 * that is actually open, exposing it over MCP itself.
 *
 * ── Credentials, and why a refresh token rather than an access token ─────
 *
 * Google's access tokens last an hour. A server configured with one would
 * work through a demo and stop before anybody used it in earnest, with an
 * error indistinguishable from a broken setup. So the configured secret is
 * the REFRESH token, and access tokens are minted from it on demand and
 * cached until shortly before they expire.
 *
 * Nothing here writes a credential to disk. The refresh token arrives in the
 * environment, from whatever provisioned it, and stays in memory — this
 * process has no workspace of its own to protect.
 */

export interface GoogleAuthConfig {
  clientId: string;
  /** Required for a Web-application OAuth client; absent for a Desktop one. */
  clientSecret?: string;
  refreshToken: string;
  /** Injected in tests. */
  fetchImpl?: typeof fetch;
  now?: () => number;
}

const TOKEN_URL = "https://oauth2.googleapis.com/token";

/**
 * How long before expiry a cached token is considered spent.
 *
 * A token that expires while a request is in flight fails with a 401 that
 * reads exactly like a bad credential, so the cache gives itself a minute of
 * headroom rather than using the token until the last second.
 */
const EXPIRY_MARGIN_MS = 60_000;

export class GoogleAuth {
  private accessToken: string | null = null;
  private expiresAtMs = 0;

  constructor(private readonly cfg: GoogleAuthConfig) {}

  /**
   * A usable access token, minting one when the cached one is spent.
   *
   * Throws rather than returning null: every caller needs a token to do
   * anything at all, and an empty Authorization header produces a refusal
   * that says nothing about the real cause.
   */
  async accessTokenNow(): Promise<string> {
    const now = (this.cfg.now ?? Date.now)();
    if (this.accessToken && now < this.expiresAtMs - EXPIRY_MARGIN_MS) {
      return this.accessToken;
    }

    const doFetch = this.cfg.fetchImpl ?? fetch;
    let res: Response;
    try {
      res = await doFetch(TOKEN_URL, {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded", accept: "application/json" },
        body: new URLSearchParams({
          grant_type: "refresh_token",
          refresh_token: this.cfg.refreshToken,
          client_id: this.cfg.clientId,
          // Omitted entirely when absent: sending an empty client_secret is
          // not the same as sending none, and Google rejects the blank value.
          ...(this.cfg.clientSecret ? { client_secret: this.cfg.clientSecret } : {}),
        }).toString(),
      });
    } catch (e) {
      throw new Error(`Could not reach Google to renew the sign-in: ${(e as Error).message}`);
    }

    const body = (await res.json().catch(() => ({}))) as {
      access_token?: string; expires_in?: number; error?: string; error_description?: string;
    };
    if (!res.ok || !body.access_token) {
      const detail = body.error_description ?? body.error ?? `HTTP ${res.status}`;
      throw new Error(
        `Google would not renew the sign-in: ${detail}. ` +
        "The refresh token may have been revoked, or the client id and secret may not match it.",
      );
    }

    const lifetimeSec = typeof body.expires_in === "number" && body.expires_in > 0 ? body.expires_in : 3600;
    this.accessToken = body.access_token;
    this.expiresAtMs = now + lifetimeSec * 1000;
    return this.accessToken;
  }
}

/**
 * Read the configuration from the environment, saying precisely what is
 * missing rather than failing later at the first call.
 *
 * A server that starts happily and then refuses every tool is the failure
 * this whole area kept producing; refusing to start, with the variable
 * names in the message, is the honest alternative.
 */
export function configFromEnv(env: NodeJS.ProcessEnv = process.env): GoogleAuthConfig {
  const clientId = env.GOOGLE_CLIENT_ID?.trim();
  const refreshToken = env.GOOGLE_REFRESH_TOKEN?.trim();
  const clientSecret = env.GOOGLE_CLIENT_SECRET?.trim();

  const missing = [
    !clientId && "GOOGLE_CLIENT_ID",
    !refreshToken && "GOOGLE_REFRESH_TOKEN",
  ].filter(Boolean);

  if (missing.length > 0) {
    throw new Error(
      `aroha-gmail-mcp is missing ${missing.join(" and ")}. ` +
      "Run `aroha-gmail-mcp login` to obtain a refresh token, then set it in this server's env.",
    );
  }

  return {
    clientId: clientId as string,
    refreshToken: refreshToken as string,
    ...(clientSecret ? { clientSecret } : {}),
  };
}
