// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

package com.arohalabs.mandate;

import com.arohalabs.crypto.Jcs;
import com.arohalabs.crypto.Signing;
import com.arohalabs.identity.DID;
import com.arohalabs.identity.Kel;
import com.arohalabs.util.IsoTime;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.*;

/**
 * ArohaMandateCredential — issues, attenuates, and verifies ArohaSpendingMandate
 * tokens, wire-compatible with {@code @aroha-sdk/credentials} (mandate.ts).
 *
 * <p>The mandate chain enforces:
 * <ol>
 *   <li><b>Provenance</b> — every mandate traces back, link by link, to a root
 *       intent mandate. {@link #verifyMandateChain} proves it: each link is
 *       signed by its grantor, each grantor is the previous link's grantee, and
 *       each parentMandateId names the previous link. A v2 token CARRIES its
 *       ancestors so a verifier can check this offline.</li>
 *   <li><b>Monotonic narrowing</b> ({@link #checkNarrowing}) — a child's
 *       constraints are a subset of its parent's. Checked at attenuation time
 *       (an early error for honest callers) and AGAIN by the verifier on every
 *       link; only the verifier-side check is a security property, because a
 *       dishonest delegating agent simply skips its own check.</li>
 * </ol>
 *
 * <p>Token versions:
 * <ul>
 *   <li>v1 (legacy, read-only here) — {@code {mandate, signature}} signed over
 *       sorted-key JSON of the body. Accepted by {@link #verify} for backward
 *       compatibility, and by {@link #verifyMandateChain} only as a root.</li>
 *   <li>v2 — {@code {v: 2, mandate, signature, chain}}, chain root-first and
 *       excluding the leaf. Each signature covers RFC 8785 JCS of
 *       {@code {"mandate": <body>, "v": 2}} ({@link #mandateSigningPayloadV2}).</li>
 * </ul>
 *
 * <p>Verification works on the token's RAW decoded JSON, never on a re-encoded
 * Java object, so the bytes checked are the bytes the issuer signed (a body
 * from another SDK may carry e.g. {@code "allowedMerchants": null}).
 *
 * <p>References: AP2 Intent/Cart/Payment Mandates; IETF
 * draft-niyikiza-oauth-attenuating-agent-tokens; RFC 8785.
 */
public class ArohaMandateCredential {

    /** Current token version produced by every issuing method. */
    public static final int MANDATE_TOKEN_VERSION = 2;

    static final long DEFAULT_CLOCK_TOLERANCE_MS = 30_000L;
    static final int DEFAULT_MAX_DEPTH = 8;
    static final Duration DEFAULT_INTENT_TTL = Duration.ofHours(1);

    /**
     * Reads tolerate fields this SDK does not model (a newer issuer may add
     * some); writes omit absent optional fields rather than emitting null,
     * which would change the signed bytes.
     */
    static final ObjectMapper MAPPER = new ObjectMapper()
            .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false)
            .configure(DeserializationFeature.FAIL_ON_TRAILING_TOKENS, true)
            .setSerializationInclusion(JsonInclude.Include.NON_NULL);

    private static final Map<String, Integer> TIER_RANK = Map.of("intent", 0, "cart", 1, "payment", 2);

    // ── Types ─────────────────────────────────────────────────────────────────

    /**
     * Spending constraints. A null component means the field is absent from the
     * JSON; {@code currency} absent means USD.
     */
    @JsonPropertyOrder({"spendLimitUsd", "sessionLimitUsd", "currency", "merchantCategory",
        "requireHumanApprovalAboveUsd", "allowedMerchants", "validFrom", "validUntil"})
    public record SpendingConstraints(
        double spendLimitUsd,
        Double sessionLimitUsd,
        String currency,
        String merchantCategory,
        Double requireHumanApprovalAboveUsd,
        List<String> allowedMerchants,
        String validFrom,
        String validUntil
    ) {
        public static Builder builder(double spendLimitUsd) { return new Builder(spendLimitUsd); }

        public static class Builder {
            private final double spendLimitUsd;
            private Double sessionLimitUsd, requireHumanApprovalAboveUsd;
            private String currency, merchantCategory, validFrom, validUntil;
            private List<String> allowedMerchants;
            Builder(double spendLimitUsd) { this.spendLimitUsd = spendLimitUsd; }
            public Builder sessionLimit(double v)      { sessionLimitUsd = v; return this; }
            /** ISO 4217; omit for USD. */
            public Builder currency(String v)          { currency = v; return this; }
            public Builder category(String v)          { merchantCategory = v; return this; }
            public Builder approvalAbove(double v)     { requireHumanApprovalAboveUsd = v; return this; }
            public Builder merchants(List<String> v)   { allowedMerchants = v == null ? null : List.copyOf(v); return this; }
            /** Not-before, ISO 8601. */
            public Builder validFrom(String v)         { validFrom = v; return this; }
            public Builder validFrom(Instant v)        { validFrom = IsoTime.format(v); return this; }
            /** Not-after, ISO 8601. */
            public Builder validUntil(String v)        { validUntil = v; return this; }
            public Builder validUntil(Instant v)       { validUntil = IsoTime.format(v); return this; }
            public SpendingConstraints build() {
                return new SpendingConstraints(spendLimitUsd, sessionLimitUsd, currency,
                    merchantCategory, requireHumanApprovalAboveUsd, allowedMerchants, validFrom, validUntil);
            }
        }
    }

    /** A mandate body (TS {@code ArohaSpendingMandateBody}). {@code parentMandateId} is null for a root. */
    @JsonPropertyOrder({"mandateTier", "constraints", "grantee", "grantor", "issuedAt", "expiresAt",
        "parentMandateId", "mandateId"})
    public record SpendingMandate(
        String mandateTier,
        SpendingConstraints constraints,
        String grantee,
        String grantor,
        String issuedAt,
        String expiresAt,
        @JsonInclude(JsonInclude.Include.ALWAYS) String parentMandateId,
        String mandateId
    ) {}

    /**
     * One signed link of a chain. {@code v} is the signing rule of THIS link
     * (1 legacy, 2 JCS); {@code mandate} is the raw JSON body as signed.
     */
    public record ChainLink(int v, Map<String, Object> mandate, String signature) {
        public SpendingMandate typed() { return toTyped(mandate); }
    }

    /**
     * An issued or decoded mandate. {@code v} and {@code chain} are null on
     * objects built by hand with the 3-argument constructor; the token is then
     * decoded to recover them when attenuating.
     */
    public record SignedMandate(SpendingMandate mandate, String signature, String token,
                                Integer v, List<ChainLink> chain) {
        public SignedMandate(SpendingMandate mandate, String signature, String token) {
            this(mandate, signature, token, null, null);
        }
    }

    /**
     * Verification verdict. {@code chainVerified} is true only when every link
     * from a root intent mandate down to this one verified; a legacy v1 child
     * proves only that its immediate grantor signed it.
     */
    public record VerificationResult(boolean valid, SpendingMandate mandate, String reason,
                                     boolean chainVerified, List<SpendingMandate> chain, String rootGrantor) {
        public VerificationResult(boolean valid, SpendingMandate mandate, String reason) {
            this(valid, mandate, reason, false, null, null);
        }

        static VerificationResult fail(String reason) {
            return new VerificationResult(false, null, reason);
        }
    }

    /**
     * Resolves the Ed25519 public key (32 raw bytes) a DID signs with, or null.
     * Must not trust anything inside the token being verified.
     */
    @FunctionalInterface
    public interface MandateKeyResolver {
        byte[] resolve(String did) throws Exception;
    }

    /**
     * Revocation hook: true if the mandate {@code mandateId} issued by
     * {@code grantor} has been revoked. A throw fails closed.
     *
     * <p>A mandateId is chosen by whoever mints the mandate, so on its own it
     * names nothing: anyone can mint a valid mandate of their own that reuses
     * someone else's id. The grantor is what the signature binds, so
     * (grantor, mandateId) is the identity a shared revocation list must be
     * keyed by.
     */
    @FunctionalInterface
    public interface MandateRevocationCheck {
        boolean isRevoked(String mandateId, String grantor) throws Exception;
    }

    /** Options for {@link #verify} and {@link #verifyMandateChain}. All optional. */
    public static final class VerifyOptions {
        MandateRevocationCheck isRevoked;
        long clockToleranceMs = DEFAULT_CLOCK_TOLERANCE_MS;
        Long nowMs;
        String expectedRoot;
        String expectedGrantee;
        int maxDepth = DEFAULT_MAX_DEPTH;
        Kel.KelSource kelSource;
        Kel.KelStore kelStore;
        boolean requirePersonRoot;
        String expectedRootPerson;
        Long keyRotatedAt;
        MandateKeyResolver resolveKey;

        /** Consulted for EVERY link: revoking the intent kills everything beneath it. */
        public VerifyOptions isRevoked(MandateRevocationCheck v) { isRevoked = v; return this; }
        /** Slack for NOT-BEFORE checks only (issuedAt, validFrom). Default 30 000. Never extends expiry. */
        public VerifyOptions clockToleranceMs(long v) { clockToleranceMs = v; return this; }
        /** Override "now" (epoch ms). */
        public VerifyOptions now(long epochMs) { nowMs = epochMs; return this; }
        public VerifyOptions now(Instant v) { nowMs = v.toEpochMilli(); return this; }
        /** The chain's root grantor must be exactly this DID. */
        public VerifyOptions expectedRoot(String v) { expectedRoot = v; return this; }
        /** The leaf's grantee must be exactly this DID (normally your own). */
        public VerifyOptions expectedGrantee(String v) { expectedGrantee = v; return this; }
        /** Maximum links accepted, root and leaf included. Default 8. */
        public VerifyOptions maxDepth(int v) { maxDepth = v; return this; }
        /**
         * KEL source for rotatable {@code did:aroha:E…} DIDs: each E-DID grantor's
         * key comes from its verified log, and a revoked grantor or grantee (or
         * controller) fails the link.
         */
        public VerifyOptions kelSource(Kel.KelSource v) { kelSource = v; return this; }
        public VerifyOptions kelStore(Kel.KelStore v) { kelStore = v; return this; }
        /** Root grantor must be a non-revoked person E-DID. Requires kelSource. */
        public VerifyOptions requirePersonRoot(boolean v) { requirePersonRoot = v; return this; }
        /** Implies requirePersonRoot; the root person must be exactly this DID. */
        public VerifyOptions expectedRootPerson(String v) { expectedRootPerson = v; return this; }
        /** {@link #verify} only: reject a leaf issued at or before this epoch ms (key since rotated). */
        public VerifyOptions keyRotatedAt(long v) { keyRotatedAt = v; return this; }
        /** {@link #verify} only: resolver for ANCESTOR keys of a v2 token. Default content-addressed DIDs. */
        public VerifyOptions resolveKey(MandateKeyResolver v) { resolveKey = v; return this; }

        VerifyOptions copy() {
            VerifyOptions o = new VerifyOptions();
            o.isRevoked = isRevoked; o.clockToleranceMs = clockToleranceMs; o.nowMs = nowMs;
            o.expectedRoot = expectedRoot; o.expectedGrantee = expectedGrantee; o.maxDepth = maxDepth;
            o.kelSource = kelSource; o.kelStore = kelStore; o.requirePersonRoot = requirePersonRoot;
            o.expectedRootPerson = expectedRootPerson; o.keyRotatedAt = keyRotatedAt; o.resolveKey = resolveKey;
            return o;
        }
    }

    // ── Issue ─────────────────────────────────────────────────────────────────

    /**
     * Issue a root intent mandate from a user (or their personal agent) to an
     * agent. {@code ttl} null means one hour.
     */
    public static SignedMandate issueIntent(
        String grantorDID, String granteeDID,
        SpendingConstraints constraints,
        Ed25519PrivateKeyParameters privateKey,
        Duration ttl
    ) {
        Duration t = ttl != null ? ttl : DEFAULT_INTENT_TTL;
        return issue("intent", grantorDID, granteeDID, constraints, null, privateKey,
            System.currentTimeMillis() + t.toMillis(), List.of());
    }

    /** Attenuate to a cart mandate. See {@link #attenuateToPayment}. */
    public static SignedMandate attenuateToCart(
        SignedMandate parent, String granteeDID,
        SpendingConstraints narrowed,
        Ed25519PrivateKeyParameters grantorKey,
        Duration ttl
    ) {
        return attenuate("cart", parent, granteeDID, narrowed, grantorKey, ttl);
    }

    /**
     * Attenuate to a payment mandate. In order: inherit the optional limits the
     * caller omitted (sessionLimitUsd, requireHumanApprovalAboveUsd, validFrom,
     * validUntil, currency), {@link #checkNarrowing} (throws on any widening),
     * then sign with the parent's grantee as grantor. The child never outlives
     * the parent; the returned token embeds the parent's chain plus the parent.
     */
    public static SignedMandate attenuateToPayment(
        SignedMandate parent, String granteeDID,
        SpendingConstraints narrowed,
        Ed25519PrivateKeyParameters grantorKey,
        Duration ttl
    ) {
        return attenuate("payment", parent, granteeDID, narrowed, grantorKey, ttl);
    }

    private static SignedMandate attenuate(
        String tier, SignedMandate parent, String granteeDID,
        SpendingConstraints narrowed, Ed25519PrivateKeyParameters grantorKey, Duration ttl
    ) {
        String parentTier = parent.mandate().mandateTier();
        if (TIER_RANK.get(tier) < TIER_RANK.getOrDefault(parentTier, 0)) {
            throw new IllegalArgumentException("Cannot attenuate " + parentTier + " → " + tier
                + ": a child cannot be a broader tier than its parent");
        }
        SpendingConstraints child = inheritOmitted(parent.mandate().constraints(), narrowed);
        String reason = checkNarrowing(parent.mandate().constraints(), child, parentTier, tier);
        if (reason != null) throw new IllegalArgumentException(reason);

        List<ChainLink> chain = ancestryIncludingParent(parent);

        // A child may never outlive its parent; pass an ABSOLUTE expiry so a
        // second clock read cannot land it one tick past the parent.
        long parentExpiry = IsoTime.parseMillis(parent.mandate().expiresAt());
        long expiry = ttl != null ? Math.min(parentExpiry, System.currentTimeMillis() + ttl.toMillis()) : parentExpiry;

        return issue(tier, parent.mandate().grantee(), granteeDID, child,
            parent.mandate().mandateId(), grantorKey, expiry, chain);
    }

    /**
     * The chain a child of {@code parent} must carry: the parent's ancestry
     * followed by the parent itself. Uses the structured chain when present,
     * else decodes {@code parent.token()}; a legacy v1 parent is accepted only
     * if it is a root.
     */
    private static List<ChainLink> ancestryIncludingParent(SignedMandate parent) {
        Integer version = parent.v();
        List<ChainLink> ancestors = parent.chain();
        Map<String, Object> rawParent = null;
        if (parent.token() != null) {
            Object decoded = parseToken(parent.token());
            if (decoded instanceof ParsedToken pt
                    && Objects.equals(pt.leaf().mandate().get("mandateId"), parent.mandate().mandateId())) {
                rawParent = pt.leaf().mandate();
                if (version == null) version = pt.leaf().v();
                if (ancestors == null && pt.leaf().v() == 2) ancestors = pt.ancestors();
            }
        }
        int v = version != null && version == 2 ? 2 : 1;
        if (ancestors == null) {
            if (parent.mandate().parentMandateId() != null) {
                throw new IllegalArgumentException(
                    "Cannot attenuate a legacy v1 mandate that is not a root: its ancestry was never embedded, "
                        + "so the child could not be verified back to the human. Re-issue the chain from the root.");
            }
            ancestors = List.of();
        }
        if (rawParent == null) rawParent = toRaw(parent.mandate());
        List<ChainLink> out = new ArrayList<>(ancestors);
        out.add(new ChainLink(v, rawParent, parent.signature()));
        return out;
    }

    private static SignedMandate issue(
        String tier, String grantorDID, String granteeDID,
        SpendingConstraints constraints, String parentId,
        Ed25519PrivateKeyParameters privateKey, long expiresAtMs, List<ChainLink> chain
    ) {
        Map<String, Object> constraintsRaw = toRaw(constraints);
        String shape = checkConstraintsShape(constraintsRaw);
        if (shape != null) throw new IllegalArgumentException("Invalid spending constraints: " + shape);

        Map<String, Object> body = new LinkedHashMap<>();
        body.put("mandateTier", tier);
        body.put("constraints", constraintsRaw);
        body.put("grantee", granteeDID);
        body.put("grantor", grantorDID);
        body.put("issuedAt", IsoTime.now());
        body.put("expiresAt", IsoTime.formatMillis(expiresAtMs));
        body.put("parentMandateId", parentId);
        body.put("mandateId", UUID.randomUUID().toString());

        byte[] sig = Signing.signBytes(signingBytes(2, body), privateKey);
        String signature = Base64.getUrlEncoder().withoutPadding().encodeToString(sig);

        Map<String, Object> token = new LinkedHashMap<>();
        token.put("v", MANDATE_TOKEN_VERSION);
        token.put("mandate", body);
        token.put("signature", signature);
        token.put("chain", chain.stream().map(ArohaMandateCredential::linkToJson).toList());
        String tokenStr = Base64.getUrlEncoder().withoutPadding()
            .encodeToString(Jcs.stringify(token).getBytes(StandardCharsets.UTF_8));

        return new SignedMandate(toTyped(body), signature, tokenStr, 2, List.copyOf(chain));
    }

    private static Map<String, Object> linkToJson(ChainLink l) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("v", l.v());
        m.put("mandate", l.mandate());
        m.put("signature", l.signature());
        return m;
    }

    /**
     * Decode a token into a SignedMandate without verifying it — for an agent
     * that received a token and wants to attenuate it further.
     */
    public static SignedMandate decodeMandateToken(String token) {
        Object parsed = parseToken(token);
        if (parsed instanceof String reason) throw new IllegalArgumentException(reason);
        ParsedToken pt = (ParsedToken) parsed;
        return new SignedMandate(pt.leaf().typed(), pt.leaf().signature(), token,
            pt.leaf().v(), pt.leaf().v() == 2 ? pt.ancestors() : null);
    }

    // ── Verify ────────────────────────────────────────────────────────────────

    /** {@link #verify(String, Ed25519PublicKeyParameters, String, VerifyOptions)} with defaults. */
    public static VerificationResult verify(
        String token, Ed25519PublicKeyParameters publicKey, String expectedGrantee
    ) {
        return verify(token, publicKey, expectedGrantee, new VerifyOptions());
    }

    /**
     * Verify a token against ONE caller-supplied key: the leaf grantor's.
     *
     * <p>Proves the leaf was signed by that key, is in its time window, is not
     * revoked and (optionally) names {@code expectedGrantee}. For a v2 token it
     * also verifies the embedded chain back to a root (ancestor keys via
     * {@code options.resolveKey}, default content-addressed DIDs). A legacy v1
     * child cannot prove human authorisation and gets {@code chainVerified=false}.
     * Gate money on {@link #verifyMandateChain}, or on chainVerified plus expectedRoot.
     */
    public static VerificationResult verify(
        String token, Ed25519PublicKeyParameters publicKey, String expectedGrantee, VerifyOptions options
    ) {
        VerifyOptions opts = options != null ? options : new VerifyOptions();
        Object parsed = parseToken(token);
        if (parsed instanceof String reason) return VerificationResult.fail(reason);
        ParsedToken pt = (ParsedToken) parsed;
        ChainLink leaf = pt.leaf();
        Map<String, Object> m = leaf.mandate();
        long now = opts.nowMs != null ? opts.nowMs : System.currentTimeMillis();

        String timeProblem = checkTimeWindow(m, now, opts.clockToleranceMs);
        if (timeProblem != null) return VerificationResult.fail(timeProblem);

        if (expectedGrantee != null && !expectedGrantee.isEmpty() && !expectedGrantee.equals(m.get("grantee"))) {
            return VerificationResult.fail("Mandate grantee mismatch: expected " + expectedGrantee);
        }

        if (opts.keyRotatedAt != null) {
            Long issuedAtMs = IsoTime.parseMillis(m.get("issuedAt"));
            if ((issuedAtMs == null ? 0 : issuedAtMs) <= opts.keyRotatedAt) {
                return VerificationResult.fail("Mandate was signed with a since-rotated key");
            }
        }

        byte[] leafKey = publicKey.getEncoded();
        String sigProblem = checkLinkSignature(leaf, leafKey);
        if (sigProblem != null) return VerificationResult.fail(sigProblem);

        String revoked = checkRevocation(m, opts.isRevoked);
        if (revoked != null) return VerificationResult.fail(revoked);

        if (leaf.v() == 1) {
            boolean isRoot = m.get("parentMandateId") == null;
            if (opts.expectedRoot != null) {
                if (!isRoot) {
                    return VerificationResult.fail("Legacy v1 token carries no ancestry; cannot prove the expected root");
                }
                if (!opts.expectedRoot.equals(m.get("grantor"))) {
                    return VerificationResult.fail("Chain root mismatch: expected " + opts.expectedRoot
                        + ", got " + m.get("grantor"));
                }
            }
            if (isRoot && !"intent".equals(m.get("mandateTier"))) {
                return VerificationResult.fail("A root mandate must be an intent mandate, got " + m.get("mandateTier"));
            }
            SpendingMandate typed = toTyped(m);
            return isRoot
                ? new VerificationResult(true, typed, null, true, List.of(typed), typed.grantor())
                : new VerificationResult(true, typed, null, false, null, null);
        }

        // v2: the token claims a chain, so the chain must verify. The leaf's key
        // is the one the caller vouched for; every ancestor resolves independently.
        MandateKeyResolver ancestorResolver = opts.resolveKey != null
            ? opts.resolveKey : ArohaMandateCredential::resolveContentAddressedKey;
        //
        // The caller's key applies to the LEAF LINK ONLY, by position. Matching
        // it by DID (did.equals(leafGrantor) ? leafKey : ...) lent it to any
        // ANCESTOR naming the same grantor, so a forged root signed by the leaf
        // key verified as the real root. Same fix as @aroha-sdk/credentials.
        String leafGrantor = (String) m.get("grantor");
        byte[] derived;
        try {
            derived = resolveContentAddressedKey(leafGrantor);
        } catch (Exception e) {
            derived = null;
        }
        if (derived != null && !java.security.MessageDigest.isEqual(derived, leafKey)) {
            return VerificationResult.fail("Supplied key does not match the key derived from the grantor DID");
        }

        List<ChainLink> links = new ArrayList<>(pt.ancestors());
        links.add(leaf);
        VerifyOptions chainOpts = opts.copy();
        chainOpts.expectedGrantee = expectedGrantee;
        return verifyLinks(links, ancestorResolver, chainOpts, leafKey);
    }

    /**
     * Verify a token all the way back to its human root — the check a payee
     * must run before moving money. For every link, root first: signature
     * against {@code resolveKey(grantor)}; root has no parent, is an intent and
     * matches expectedRoot; each child's grantor is the parent's grantee, its
     * parentMandateId is the parent's id, its tier is not broader, its
     * constraints narrow the parent's (re-checked here) and it does not outlive
     * the parent; time windows; revocation. A legacy v1 token is accepted only
     * as a root.
     *
     * @param resolveKey DID → key; null means content-addressed DIDs only.
     */
    public static VerificationResult verifyMandateChain(
        String token, MandateKeyResolver resolveKey, VerifyOptions options
    ) {
        VerifyOptions opts = options != null ? options : new VerifyOptions();
        MandateKeyResolver resolver = resolveKey != null ? resolveKey : ArohaMandateCredential::resolveContentAddressedKey;
        Object parsed = parseToken(token);
        if (parsed instanceof String reason) return VerificationResult.fail(reason);
        ParsedToken pt = (ParsedToken) parsed;
        if (pt.leaf().v() == 1 && pt.leaf().mandate().get("parentMandateId") != null) {
            return VerificationResult.fail("Legacy v1 token carries no ancestry; it cannot be verified back to a root");
        }
        List<ChainLink> links = new ArrayList<>(pt.ancestors());
        links.add(pt.leaf());
        return verifyLinks(links, resolver, opts, null);
    }

    private record KelResult(Kel.KelState state, String error) {}

    /** {@code leafKey}, when non-null, verifies the final link only — never an ancestor. */
    private static VerificationResult verifyLinks(List<ChainLink> links, MandateKeyResolver resolveKey,
                                                  VerifyOptions opts, byte[] leafKey) {
        long now = opts.nowMs != null ? opts.nowMs : System.currentTimeMillis();
        long tolerance = opts.clockToleranceMs;

        if (links.isEmpty()) return VerificationResult.fail("Empty mandate chain");
        if (links.size() > opts.maxDepth) {
            return VerificationResult.fail("Mandate chain has " + links.size() + " links; maximum is " + opts.maxDepth);
        }
        boolean requirePerson = opts.requirePersonRoot || opts.expectedRootPerson != null;
        if (requirePerson && opts.kelSource == null) {
            return VerificationResult.fail("requirePersonRoot needs a kelSource to verify the root person's KEL");
        }
        Map<String, KelResult> kelCache = new HashMap<>();
        java.util.function.Function<String, KelResult> kelStateOf = opts.kelSource == null ? null
            : did -> kelCache.computeIfAbsent(did, d -> {
                try {
                    Kel.KelState st = Kel.resolveKelState(d, opts.kelSource, opts.kelStore, true);
                    if (st == null) return new KelResult(null, "no Key Event Log available");
                    if (st.revoked) return new KelResult(null, "identity has been revoked");
                    if (st.controllerRevoked) return new KelResult(null, "controller " + st.controller + " has been revoked");
                    return new KelResult(st, null);
                } catch (Kel.KelException e) {
                    return new KelResult(null, "Key Event Log rejected: " + e.getMessage());
                }
            });

        Set<Object> seen = new HashSet<>();
        for (int i = 0; i < links.size(); i++) {
            ChainLink link = links.get(i);
            Map<String, Object> m = link.mandate();
            String where = "chain link " + i + " (" + m.get("mandateTier") + " " + m.get("mandateId") + ")";

            if (!seen.add(m.get("mandateId"))) return VerificationResult.fail(where + ": mandateId repeats within the chain");

            String grantor = (String) m.get("grantor");
            String grantee = (String) m.get("grantee");

            // Signature first: nothing below means anything until we know who wrote it.
            byte[] key;
            Kel.KelState grantorKel = null;
            if (kelStateOf != null && Kel.isInceptionDid(grantor)) {
                KelResult r = kelStateOf.apply(grantor);
                if (r.error() != null) return VerificationResult.fail(where + ": grantor " + grantor + ": " + r.error());
                grantorKel = r.state();
                key = r.state().currentKey;
            } else if (leafKey != null && i == links.size() - 1) {
                key = leafKey;
            } else {
                try {
                    key = resolveKey.resolve(grantor);
                } catch (Exception e) {
                    return VerificationResult.fail(where + ": Key resolution failed for grantor " + grantor);
                }
            }
            if (key == null) return VerificationResult.fail(where + ": Cannot resolve public key for grantor " + grantor);
            String sigProblem = checkLinkSignature(link, key);
            if (sigProblem != null) return VerificationResult.fail(where + ": " + sigProblem);

            // The grantee holds this link's authority: if it was revoked, so was that.
            if (kelStateOf != null && Kel.isInceptionDid(grantee)) {
                KelResult r = kelStateOf.apply(grantee);
                if (r.error() != null) return VerificationResult.fail(where + ": grantee " + grantee + ": " + r.error());
            }

            if (i == 0) {
                if (m.get("parentMandateId") != null) {
                    return VerificationResult.fail(where
                        + ": first link has a parentMandateId — the token does not carry its full ancestry back to a root");
                }
                if (!"intent".equals(m.get("mandateTier"))) {
                    return VerificationResult.fail(where + ": a root mandate must be an intent mandate, got " + m.get("mandateTier"));
                }
                if (opts.expectedRoot != null && !opts.expectedRoot.equals(grantor)) {
                    return VerificationResult.fail(where + ": Chain root mismatch: expected " + opts.expectedRoot + ", got " + grantor);
                }
                if (requirePerson) {
                    if (grantorKel == null) {
                        return VerificationResult.fail(where + ": root grantor " + grantor + " is not a person identity (did:aroha:E…)");
                    }
                    if (!"person".equals(grantorKel.kind)) {
                        return VerificationResult.fail(where + ": root grantor " + grantor + " is an " + grantorKel.kind + ", not a person");
                    }
                    if (opts.expectedRootPerson != null && !opts.expectedRootPerson.equals(grantor)) {
                        return VerificationResult.fail(where + ": Chain root mismatch: expected person "
                            + opts.expectedRootPerson + ", got " + grantor);
                    }
                }
            } else {
                Map<String, Object> p = links.get(i - 1).mandate();
                if (!Objects.equals(grantor, p.get("grantee"))) {
                    return VerificationResult.fail(where + ": grantor " + grantor + " is not the parent's grantee " + p.get("grantee"));
                }
                if (!Objects.equals(m.get("parentMandateId"), p.get("mandateId"))) {
                    return VerificationResult.fail(where + ": parentMandateId " + m.get("parentMandateId")
                        + " does not match the parent's mandateId " + p.get("mandateId"));
                }
                if (TIER_RANK.get((String) m.get("mandateTier")) < TIER_RANK.get((String) p.get("mandateTier"))) {
                    return VerificationResult.fail(where + ": tier " + m.get("mandateTier")
                        + " is broader than the parent's " + p.get("mandateTier"));
                }
                String narrowing = checkNarrowing(toTyped(p).constraints(), toTyped(m).constraints(),
                    (String) p.get("mandateTier"), (String) m.get("mandateTier"));
                if (narrowing != null) return VerificationResult.fail(where + ": " + narrowing);
                if (IsoTime.parseMillis(m.get("expiresAt")) > IsoTime.parseMillis(p.get("expiresAt"))) {
                    return VerificationResult.fail(where + ": expiresAt " + m.get("expiresAt")
                        + " outlives the parent's " + p.get("expiresAt"));
                }
            }

            String timeProblem = checkTimeWindow(m, now, tolerance);
            if (timeProblem != null) return VerificationResult.fail(where + ": " + timeProblem);

            String revokedProblem = checkRevocation(m, opts.isRevoked);
            if (revokedProblem != null) return VerificationResult.fail(where + ": " + revokedProblem);
        }

        Map<String, Object> leaf = links.get(links.size() - 1).mandate();
        if (opts.expectedGrantee != null && !opts.expectedGrantee.isEmpty()
                && !opts.expectedGrantee.equals(leaf.get("grantee"))) {
            return VerificationResult.fail("Mandate grantee mismatch: expected " + opts.expectedGrantee);
        }
        List<SpendingMandate> chain = links.stream().map(ChainLink::typed).toList();
        return new VerificationResult(true, chain.get(chain.size() - 1), null, true, chain,
            (String) links.get(0).mandate().get("grantor"));
    }

    /**
     * Default resolver for content-addressed DIDs ({@code did:aroha:z<base58btc(pubkey)>}):
     * the DID commits to its own key. Null for every other form, including
     * named DIDs (not self-certifying) and {@code did:aroha:E…} (needs a KEL).
     * The round-trip check keeps {@code did:aroha:zoo} from decoding to garbage.
     */
    public static byte[] resolveContentAddressedKey(String did) {
        if (did == null || !did.startsWith("did:aroha:z")) return null;
        try {
            byte[] key = DID.fromMultibase(did.substring("did:aroha:".length()));
            if (key.length != 32) return null;
            return DID.generateDid(key).equals(did) ? key : null;
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Resolver covering all three {@code did:aroha:} forms (TS
     * {@code createMandateKeyResolver}): E-DIDs from their verified KEL (null
     * if revoked), z-DIDs from the DID itself, anything else via
     * {@code fallback}. Self-certifying forms never fall through to the fallback.
     */
    public static MandateKeyResolver createMandateKeyResolver(Kel.KelSource kelSource, Kel.KelStore kelStore,
                                                              MandateKeyResolver fallback) {
        return did -> {
            if (Kel.isInceptionDid(did)) {
                if (kelSource == null) return null;
                try {
                    Kel.KelState st = Kel.resolveKelState(did, kelSource, kelStore, false);
                    if (st == null || st.revoked || st.controllerRevoked || st.currentKey == null) return null;
                    return st.currentKey;
                } catch (Kel.KelException e) {
                    return null;
                }
            }
            byte[] derived = resolveContentAddressedKey(did);
            if (derived != null) return derived;
            return fallback != null ? fallback.resolve(did) : null;
        };
    }

    // ── Enforcement ──────────────────────────────────────────────────────────

    /** Why a spend was refused (TS {@code SpendingConstraintViolation}). */
    public static final class SpendingConstraintViolation extends Exception {
        private final String code;
        public SpendingConstraintViolation(String message, String code) {
            super(message);
            this.code = code;
        }
        /** MANDATE_INVALID, LIMIT_EXCEEDED, MERCHANT_NOT_ALLOWED or INVALID_AMOUNT. */
        public String code() { return code; }
    }

    /**
     * Verify a token AND check a proposed spend against it — call at the
     * payment gate. {@code requireChain} demands a chain verified to a root;
     * set it wherever real money moves. {@code merchantDID} is required when
     * the mandate restricts merchants.
     */
    public static SpendingMandate enforceSpendingConstraints(
        String token, Ed25519PublicKeyParameters grantorPublicKey, String expectedGrantee,
        String merchantDID, double proposedAmountUsd, boolean requireChain, VerifyOptions options
    ) throws SpendingConstraintViolation {
        VerificationResult r = verify(token, grantorPublicKey, expectedGrantee, options);
        if (!r.valid()) throw new SpendingConstraintViolation("Mandate invalid: " + r.reason(), "MANDATE_INVALID");
        if (requireChain && !r.chainVerified()) {
            throw new SpendingConstraintViolation(
                "Mandate invalid: token does not carry a chain verifiable back to a root mandate", "MANDATE_INVALID");
        }
        SpendingConstraints c = r.mandate().constraints();
        if (!Double.isFinite(proposedAmountUsd) || proposedAmountUsd < 0) {
            throw new SpendingConstraintViolation("Proposed amount " + proposedAmountUsd
                + " is not a finite, non-negative number", "INVALID_AMOUNT");
        }
        if (proposedAmountUsd > c.spendLimitUsd()) {
            throw new SpendingConstraintViolation("Proposed $" + Jcs.formatNumber(proposedAmountUsd)
                + " exceeds mandate limit $" + Jcs.formatNumber(c.spendLimitUsd()), "LIMIT_EXCEEDED");
        }
        if (c.allowedMerchants() != null) {
            if (merchantDID == null) {
                throw new SpendingConstraintViolation(
                    "merchantDID is required when the mandate restricts allowedMerchants", "MERCHANT_NOT_ALLOWED");
            }
            if (!c.allowedMerchants().contains(merchantDID)) {
                throw new SpendingConstraintViolation("Merchant " + merchantDID
                    + " is not in the mandate's allowed merchant list", "MERCHANT_NOT_ALLOWED");
            }
        }
        return r.mandate();
    }

    // ── Canonicalisation & signing ───────────────────────────────────────────

    /**
     * The exact string a v2 signature covers: JCS of {@code {"mandate": body, "v": 2}}.
     * {@code mandate} is the raw JSON body (a {@code Map}) or a {@link SpendingMandate}.
     */
    public static String mandateSigningPayloadV2(Object mandate) {
        Map<String, Object> raw = mandate instanceof SpendingMandate sm ? toRaw(sm) : asMap(mandate);
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("mandate", raw);
        payload.put("v", 2);
        return Jcs.canonicalize(payload);
    }

    private static byte[] signingBytes(int v, Map<String, Object> mandate) {
        // v1 was JSON.stringify(sortKeys(body)); for JSON values that is the
        // same byte string as JCS, so JCS reproduces it.
        String s = v == 2 ? mandateSigningPayloadV2(mandate) : Jcs.canonicalize(mandate);
        return s.getBytes(StandardCharsets.UTF_8);
    }

    private static String checkLinkSignature(ChainLink link, byte[] publicKey) {
        try {
            byte[] sig = Base64.getUrlDecoder().decode(link.signature());
            return Signing.verifyBytes(signingBytes(link.v(), link.mandate()), sig, publicKey) ? null : "Invalid signature";
        } catch (Exception e) {
            return "Signature verification error";
        }
    }

    private static String checkRevocation(Map<String, Object> m, MandateRevocationCheck isRevoked) {
        if (isRevoked == null) return null;
        Object id = m.get("mandateId");
        try {
            return isRevoked.isRevoked((String) id, (String) m.get("grantor")) ? "Mandate " + id + " has been revoked" : null;
        } catch (Exception e) {
            // An unreachable revocation service is not evidence of non-revocation.
            return "Revocation check failed for mandate " + id;
        }
    }

    /** Expiry-side checks are strict; not-before checks get {@code tolerance} ms. */
    @SuppressWarnings("unchecked")
    private static String checkTimeWindow(Map<String, Object> m, long now, long tolerance) {
        if (IsoTime.parseMillis(m.get("expiresAt")) < now) return "Mandate expired";
        if (IsoTime.parseMillis(m.get("issuedAt")) > now + tolerance) {
            return "Mandate issuedAt " + m.get("issuedAt") + " is in the future";
        }
        Map<String, Object> c = (Map<String, Object>) m.get("constraints");
        if (c.containsKey("validFrom") && IsoTime.parseMillis(c.get("validFrom")) > now + tolerance) {
            return "Mandate not yet valid (validFrom " + c.get("validFrom") + ")";
        }
        if (c.containsKey("validUntil") && IsoTime.parseMillis(c.get("validUntil")) < now) {
            return "Mandate validity window has ended (validUntil " + c.get("validUntil") + ")";
        }
        return null;
    }

    // ── Token parsing & shape validation ─────────────────────────────────────

    private record ParsedToken(ChainLink leaf, List<ChainLink> ancestors) {}

    /** ParsedToken, or a String with the reason the token was rejected. */
    private static Object parseToken(String token) {
        Object raw;
        try {
            byte[] bytes = Base64.getUrlDecoder().decode(token);
            raw = MAPPER.readValue(bytes, Object.class);
        } catch (Exception e) {
            return "Malformed token";
        }
        if (!(raw instanceof Map<?, ?> rawMap)) return "Malformed token";
        Map<String, Object> t = asMap(rawMap);

        Object vObj = t.containsKey("v") ? t.get("v") : Integer.valueOf(1);
        Integer v = versionOf(vObj);
        if (v == null) return "Unsupported mandate token version: " + vObj;
        if (v == 1 && t.containsKey("chain")) return "Malformed token: chain present without v: 2";

        Object leaf = toLink(v, t);
        if (leaf instanceof String reason) return "Malformed token: " + reason;

        List<ChainLink> ancestors = new ArrayList<>();
        if (v == 2) {
            if (!(t.get("chain") instanceof List<?> chain)) return "Malformed token: v2 token requires a chain array";
            for (int i = 0; i < chain.size(); i++) {
                Object entry = chain.get(i);
                Integer ev = entry instanceof Map<?, ?> em ? versionOf(em.get("v")) : null;
                if (ev == null) return "Malformed token: chain[" + i + "] is not a versioned link";
                Object link = toLink(ev, asMap(entry));
                if (link instanceof String reason) return "Malformed token: chain[" + i + "]: " + reason;
                ancestors.add((ChainLink) link);
            }
        }
        return new ParsedToken((ChainLink) leaf, List.copyOf(ancestors));
    }

    /** 1 or 2 when {@code v} is that JSON number, else null. */
    private static Integer versionOf(Object v) {
        if (v instanceof Number n) {
            double d = n.doubleValue();
            if (d == 1) return 1;
            if (d == 2) return 2;
        }
        return null;
    }

    private static Object toLink(int v, Map<String, Object> raw) {
        if (!(raw.get("signature") instanceof String sig)) return "signature missing";
        String shape = checkMandateShape(raw.get("mandate"));
        if (shape != null) return shape;
        return new ChainLink(v, asMap(raw.get("mandate")), sig);
    }

    private static boolean isAmount(Object x) {
        return x instanceof Number n && Double.isFinite(n.doubleValue()) && n.doubleValue() >= 0;
    }

    private static boolean isIsoDate(Object x) {
        return IsoTime.parseMillis(x) != null;
    }

    /**
     * Structural validation of a decoded mandate body (TS {@code checkMandateShape}).
     * Every comparison downstream reads these fields; a missing or mistyped one
     * must not turn into a silent pass.
     */
    static String checkMandateShape(Object mo) {
        if (!(mo instanceof Map<?, ?> m)) return "mandate is not an object";
        // A task mandate is not a spending mandate, whatever else it carries:
        // the tiers overlap and a v1 task signature covers the same sorted-JSON
        // bytes as a v1 spending one. Refuse the type marker outright (TS, Python, Go too).
        if (m.containsKey("mandateType")) return "mandateType present: this is a task mandate, not a spending mandate";
        Object tier = m.get("mandateTier");
        if (!"intent".equals(tier) && !"cart".equals(tier) && !"payment".equals(tier)) return "mandateTier is invalid";
        for (String f : List.of("grantor", "grantee", "mandateId")) {
            if (!(m.get(f) instanceof String s) || s.isEmpty()) return f + " is missing";
        }
        if (!isIsoDate(m.get("issuedAt"))) return "issuedAt is not a date";
        if (!isIsoDate(m.get("expiresAt"))) return "expiresAt is not a date";
        // JS: m.parentMandateId !== null && typeof !== "string" — absent (undefined) is invalid too.
        if (!m.containsKey("parentMandateId")) return "parentMandateId is invalid";
        Object pid = m.get("parentMandateId");
        if (pid != null && !(pid instanceof String)) return "parentMandateId is invalid";
        return checkConstraintsShape(m.get("constraints"));
    }

    static String checkConstraintsShape(Object co) {
        if (!(co instanceof Map<?, ?> c)) return "constraints is not an object";
        if (!isAmount(c.get("spendLimitUsd"))) return "constraints.spendLimitUsd must be a finite, non-negative number";
        for (String f : List.of("sessionLimitUsd", "requireHumanApprovalAboveUsd")) {
            if (c.containsKey(f) && !isAmount(c.get(f))) return "constraints." + f + " must be a finite, non-negative number";
        }
        if (c.containsKey("currency") && !(c.get("currency") instanceof String)) return "constraints.currency must be a string";
        if (c.containsKey("merchantCategory") && c.get("merchantCategory") != null
                && !(c.get("merchantCategory") instanceof String)) {
            return "constraints.merchantCategory must be a string or null";
        }
        if (c.containsKey("allowedMerchants") && c.get("allowedMerchants") != null) {
            if (!(c.get("allowedMerchants") instanceof List<?> l) || !l.stream().allMatch(x -> x instanceof String)) {
                return "constraints.allowedMerchants must be an array of DIDs or null";
            }
        }
        for (String f : List.of("validFrom", "validUntil")) {
            if (c.containsKey(f) && !isIsoDate(c.get(f))) return "constraints." + f + " must be an ISO 8601 date";
        }
        return null;
    }

    // ── Narrowing ────────────────────────────────────────────────────────────

    /**
     * A child that leaves out sessionLimitUsd, requireHumanApprovalAboveUsd,
     * validFrom, validUntil or currency inherits the parent's value. Omission
     * used to WIDEN (no approval threshold at all); the verifier now rejects
     * that, so honest callers get the parent's value filled in.
     * allowedMerchants and merchantCategory are NOT inherited — a merchant
     * restriction must be restated explicitly, as in the TypeScript SDK.
     */
    private static SpendingConstraints inheritOmitted(SpendingConstraints parent, SpendingConstraints child) {
        return new SpendingConstraints(
            child.spendLimitUsd(),
            child.sessionLimitUsd() != null ? child.sessionLimitUsd() : parent.sessionLimitUsd(),
            child.currency() != null ? child.currency() : parent.currency(),
            child.merchantCategory(),
            child.requireHumanApprovalAboveUsd() != null
                ? child.requireHumanApprovalAboveUsd() : parent.requireHumanApprovalAboveUsd(),
            child.allowedMerchants(),
            child.validFrom() != null ? child.validFrom() : parent.validFrom(),
            child.validUntil() != null ? child.validUntil() : parent.validUntil()
        );
    }

    /**
     * Null when {@code child} is a subset of {@code parent}; otherwise why not.
     * Identical rules and messages to TS {@code checkNarrowing}: where the PARENT
     * sets an optional limit, the child must set it too, to an equal or
     * narrower value (absence is widening, never "no opinion"). Used at
     * attenuation time and on every link by the verifier.
     */
    public static String checkNarrowing(SpendingConstraints parent, SpendingConstraints child,
                                        String parentTier, String childTier) {
        String prefix = "Cannot attenuate " + parentTier + " → " + childTier;
        if (!Double.isFinite(child.spendLimitUsd()) || child.spendLimitUsd() < 0) {
            return prefix + ": child spendLimitUsd must be a finite, non-negative number";
        }
        if (child.spendLimitUsd() > parent.spendLimitUsd()) {
            return prefix + ": child spendLimitUsd (" + num(child.spendLimitUsd()) + ") exceeds parent ("
                + num(parent.spendLimitUsd()) + ")";
        }
        if (parent.sessionLimitUsd() != null) {
            if (child.sessionLimitUsd() == null) {
                return prefix + ": parent sets sessionLimitUsd (" + num(parent.sessionLimitUsd()) + ") but child omits it";
            }
            if (!isAmount(child.sessionLimitUsd()) || child.sessionLimitUsd() > parent.sessionLimitUsd()) {
                return prefix + ": child sessionLimitUsd exceeds parent";
            }
        }
        if (parent.requireHumanApprovalAboveUsd() != null) {
            if (child.requireHumanApprovalAboveUsd() == null) {
                return prefix + ": parent sets an approval threshold (requireHumanApprovalAboveUsd "
                    + num(parent.requireHumanApprovalAboveUsd()) + ") but child omits it";
            }
            if (!isAmount(child.requireHumanApprovalAboveUsd())
                    || child.requireHumanApprovalAboveUsd() > parent.requireHumanApprovalAboveUsd()) {
                return prefix + ": child approval threshold exceeds parent";
            }
        }
        String pc = parent.currency() != null ? parent.currency() : "USD";
        String cc = child.currency() != null ? child.currency() : "USD";
        if (!cc.equals(pc)) {
            return prefix + ": child currency \"" + cc + "\" differs from parent \"" + pc + "\"";
        }
        if (parent.allowedMerchants() != null) {
            if (child.allowedMerchants() == null) {
                return prefix + ": parent restricts allowedMerchants but child sets none";
            }
            // Non-empty parent: child must name at least one. EMPTY parent
            // means "no merchant at all", so the child must stay empty.
            if (!parent.allowedMerchants().isEmpty() && child.allowedMerchants().isEmpty()) {
                return prefix + ": parent restricts allowedMerchants but child sets none";
            }
            Set<String> parentSet = new HashSet<>(parent.allowedMerchants());
            for (String m : child.allowedMerchants()) {
                if (!parentSet.contains(m)) return prefix + ": child allowedMerchants contains \"" + m + "\" not in parent";
            }
        }
        if (parent.merchantCategory() != null) {
            if (child.merchantCategory() == null) {
                return prefix + ": child merchantCategory must not widen parent's \"" + parent.merchantCategory() + "\" restriction";
            }
            if (!child.merchantCategory().equals(parent.merchantCategory())) {
                return prefix + ": child merchantCategory \"" + child.merchantCategory() + "\" does not match parent \""
                    + parent.merchantCategory() + "\"";
            }
        }
        if (parent.validUntil() != null) {
            if (child.validUntil() == null) {
                return prefix + ": parent sets validUntil (" + parent.validUntil() + ") but child omits it";
            }
            Long c = IsoTime.parseMillis(child.validUntil());
            Long p = IsoTime.parseMillis(parent.validUntil());
            if (c == null || (p != null && c > p)) {
                return prefix + ": child validUntil (" + child.validUntil() + ") extends beyond parent (" + parent.validUntil() + ")";
            }
        }
        if (parent.validFrom() != null) {
            if (child.validFrom() == null) {
                return prefix + ": parent sets validFrom (" + parent.validFrom() + ") but child omits it";
            }
            Long c = IsoTime.parseMillis(child.validFrom());
            Long p = IsoTime.parseMillis(parent.validFrom());
            if (c == null || (p != null && c < p)) {
                return prefix + ": child validFrom (" + child.validFrom() + ") precedes parent (" + parent.validFrom() + ")";
            }
        }
        return null;
    }

    private static String num(double d) {
        return Jcs.formatNumber(d);
    }

    // ── Conversions ──────────────────────────────────────────────────────────

    @SuppressWarnings("unchecked")
    private static Map<String, Object> asMap(Object o) {
        return (Map<String, Object>) o;
    }

    /** Record → JSON tree (absent optional fields omitted, parentMandateId kept). */
    static Map<String, Object> toRaw(Object record) {
        return MAPPER.convertValue(record, new TypeReference<LinkedHashMap<String, Object>>() {});
    }

    static SpendingMandate toTyped(Map<String, Object> raw) {
        return MAPPER.convertValue(raw, SpendingMandate.class);
    }
}
