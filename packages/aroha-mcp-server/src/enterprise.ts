// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Enterprise-Managed Authorization (ID-JAG), resource-server side.
 *
 * Specs followed:
 *   - MCP extension `io.modelcontextprotocol/enterprise-managed-authorization`
 *     (modelcontextprotocol/ext-auth, specification/stable, status Stable)
 *   - draft-ietf-oauth-identity-assertion-authz-grant-04 (2026-05-21)
 *
 * Who does what (the specs put almost everything on the authorization server):
 *   - The enterprise IdP evaluates policy and issues the ID-JAG
 *     (`typ: oauth-id-jag+jwt`) in an RFC 8693 token exchange.
 *   - The MCP server's authorization server (the "Resource Authorization
 *     Server") validates the ID-JAG (draft §4.4.1: typ, `aud` = its own issuer,
 *     `client_id` = the authenticated client, signature against the IdP's
 *     keys, expiry, replay) and issues an access token audience-restricted to
 *     this server (EMA §5.1).
 *   - This server (the resource server) has no trust relationship with the
 *     IdP (draft §6) and never sees an ID-JAG. It validates its own
 *     authorization server's access tokens as for any OAuth client, then reads
 *     the enterprise identity the authorization server copied into the token.
 *
 * ASSUMPTION: neither spec defines how an access token says it was issued
 * from an ID-JAG, or which IdP subject it carries. This server reads one
 * object claim (default `id_jag`) that the authorization server must add:
 *
 *   "id_jag": { "iss": <IdP issuer>, "sub": <IdP subject>, "jti": <ID-JAG jti>,
 *               "tenant"?: <IdP tenant>, "email"?: …, "aroha_mandate_id"?: … }
 *
 * The claim name is configurable. Re-check against the specs when they define
 * a transcription. Owner: @projectmed99. Due: 2027-01-21.
 *
 * The enterprise identity (IdP issuer, tenant, subject) — not the
 * authorization server's own `sub` — selects the user's signing key, so the
 * grantor DID of every mandate the user issues is rooted in the enterprise
 * subject (docs/integrations/id-jag-profile.md).
 */

/** The MCP extension identifier. */
export const ENTERPRISE_MANAGED_AUTHORIZATION_EXTENSION = "io.modelcontextprotocol/enterprise-managed-authorization";
/** JWT `typ` of an ID-JAG (draft §3.1). An ID-JAG is a grant, never an access token. */
export const ID_JAG_TYP = "oauth-id-jag+jwt";
/** RFC 8693 token type the client requests from the IdP (draft §4.3). */
export const ID_JAG_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:id-jag";
/** Authorization-server metadata value advertising ID-JAG support (draft §7). */
export const ID_JAG_GRANT_PROFILE = "urn:ietf:params:oauth:grant-profile:id-jag";
/** The JWT bearer grant the client uses at the authorization server (RFC 7523). */
export const JWT_BEARER_GRANT = "urn:ietf:params:oauth:grant-type:jwt-bearer";

/** Default access-token claim carrying the ID-JAG provenance. */
export const DEFAULT_ENTERPRISE_CLAIM = "id_jag";

/**
 * Guest-grant claims from the Aroha profile. This server cannot enforce
 * them, and the profile says such a resource server should refuse the token.
 */
const UNENFORCEABLE_PROFILE_CLAIMS = ["aroha_on_behalf_of", "aroha_room_id"] as const;

export interface TrustedIdp {
  /** The IdP's issuer identifier, exact string (the ID-JAG `iss`). */
  issuer: string;
  /** When set, only these tenants (the ID-JAG `tenant` claim) are accepted. */
  tenants?: string[];
}

export interface EnterpriseAuthOptions {
  /** IdPs whose subjects this server accepts as enterprise users. Empty = none. */
  trustedIdps: TrustedIdp[];
  /** Refuse access tokens that were not issued from an ID-JAG. */
  required: boolean;
  /** Access-token claim the authorization server writes the provenance into. */
  claim: string;
}

/** The enterprise identity behind an access token issued from an ID-JAG. */
export interface EnterpriseIdentity {
  /** IdP issuer (ID-JAG `iss`). */
  idpIssuer: string;
  /** IdP subject (ID-JAG `sub`), in the IdP's namespace. */
  subject: string;
  /** IdP tenant, for multi-tenant issuers (draft §6). */
  tenant?: string;
  /** The ID-JAG's `jti`: joins this session to the IdP's audit log. */
  idJagId: string;
  /** The authorization server that exchanged the ID-JAG (access token `iss`). */
  authorizationServer: string;
  /** The OAuth client the ID-JAG was issued to. */
  clientId: string;
  /** Leaf mandate id when the ID-JAG was minted from an Aroha mandate (profile claim `aroha_mandate_id`). */
  mandateId?: string;
}

/** Outcome of reading the enterprise claim: absent, present and valid, or refused. */
export type EnterpriseClaimOutcome =
  | { kind: "absent" }
  | { kind: "enterprise"; identity: EnterpriseIdentity }
  | { kind: "refused"; reason: string };

function nonEmptyString(v: unknown): v is string {
  return typeof v === "string" && v.length > 0 && v.length <= 1024;
}

/**
 * Read and check the enterprise provenance of a verified access-token payload
 * (signature, `iss`, `aud`, `exp` already checked). Fails closed: a claim that
 * is present but malformed, names an untrusted IdP or tenant, or carries
 * constraints this server cannot enforce is a refusal, never "absent".
 */
export function readEnterpriseIdentity(
  payload: Record<string, unknown>,
  ctx: { authorizationServer: string; clientId: string },
  opts: EnterpriseAuthOptions,
): EnterpriseClaimOutcome {
  for (const c of UNENFORCEABLE_PROFILE_CLAIMS) {
    if (c in payload) return { kind: "refused", reason: `token carries ${c}, which this server cannot enforce` };
  }
  const raw = payload[opts.claim];
  if (raw === undefined) return { kind: "absent" };
  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) {
    return { kind: "refused", reason: `${opts.claim} claim is not an object` };
  }
  const claim = raw as Record<string, unknown>;
  for (const c of UNENFORCEABLE_PROFILE_CLAIMS) {
    if (c in claim) return { kind: "refused", reason: `${opts.claim}.${c} cannot be enforced by this server` };
  }
  if (!nonEmptyString(claim.iss)) return { kind: "refused", reason: `${opts.claim}.iss is missing` };
  if (!nonEmptyString(claim.sub)) return { kind: "refused", reason: `${opts.claim}.sub is missing` };
  if (!nonEmptyString(claim.jti)) return { kind: "refused", reason: `${opts.claim}.jti is missing` };
  if (claim.tenant !== undefined && !nonEmptyString(claim.tenant)) return { kind: "refused", reason: `${opts.claim}.tenant is malformed` };

  const idp = opts.trustedIdps.find((t) => t.issuer === claim.iss);
  if (!idp) return { kind: "refused", reason: "identity provider is not trusted by this server" };
  if (idp.tenants && !(typeof claim.tenant === "string" && idp.tenants.includes(claim.tenant))) {
    return { kind: "refused", reason: "identity provider tenant is not trusted by this server" };
  }
  // draft §3.1: an ID-JAG always names its client. The authorization server
  // must carry that binding into the access token.
  if (!nonEmptyString(ctx.clientId)) return { kind: "refused", reason: "enterprise token does not name its client" };

  const mandateId = claim.aroha_mandate_id;
  if (mandateId !== undefined && !nonEmptyString(mandateId)) return { kind: "refused", reason: `${opts.claim}.aroha_mandate_id is malformed` };

  return {
    kind: "enterprise",
    identity: {
      idpIssuer: claim.iss,
      subject: claim.sub,
      ...(typeof claim.tenant === "string" ? { tenant: claim.tenant } : {}),
      idJagId: claim.jti,
      authorizationServer: ctx.authorizationServer,
      clientId: ctx.clientId,
      ...(typeof mandateId === "string" ? { mandateId } : {}),
    },
  };
}

/**
 * The key-store principal for an enterprise user: IdP issuer, tenant and
 * subject, in an encoding that cannot collide with an ordinary OAuth
 * principal (`<issuer>|<sub>`, see principalFromToken). The authorization
 * server's own `sub` is not part of it: the enterprise subject is the root.
 */
export function enterprisePrincipal(identity: Pick<EnterpriseIdentity, "idpIssuer" | "tenant" | "subject">): string {
  return `id-jag:${JSON.stringify([identity.idpIssuer, identity.tenant ?? null, identity.subject])}`;
}

/** Whether a value is an EnterpriseIdentity this module produced (AuthInfo.extra is untyped). */
export function isEnterpriseIdentity(v: unknown): v is EnterpriseIdentity {
  if (typeof v !== "object" || v === null) return false;
  const o = v as Record<string, unknown>;
  return nonEmptyString(o.idpIssuer) && nonEmptyString(o.subject) && nonEmptyString(o.idJagId)
    && nonEmptyString(o.authorizationServer) && nonEmptyString(o.clientId);
}

/**
 * What a mandate issued by an enterprise user reports about its root: the
 * grantor DID is the key this server holds for exactly this enterprise
 * subject. The binding is asserted by this server, not signed by the IdP.
 */
export function enterpriseRoot(identity: EnterpriseIdentity, grantorDid: string): Record<string, unknown> {
  return {
    kind: "enterprise",
    grantorDid,
    idpIssuer: identity.idpIssuer,
    subject: identity.subject,
    ...(identity.tenant ? { tenant: identity.tenant } : {}),
    idJagId: identity.idJagId,
    authorizationServer: identity.authorizationServer,
    clientId: identity.clientId,
    ...(identity.mandateId ? { idJagMandateId: identity.mandateId } : {}),
    binding: "asserted by this server: grantorDid is the signing key it holds for this enterprise subject",
  };
}
