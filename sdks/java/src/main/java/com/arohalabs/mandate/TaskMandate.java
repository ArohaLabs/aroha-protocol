// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

package com.arohalabs.mandate;

import com.arohalabs.crypto.Jcs;
import com.arohalabs.crypto.Signing;
import com.arohalabs.mandate.ArohaMandateCredential.MandateRevocationCheck;
import com.arohalabs.mandate.ArohaMandateCredential.SpendingConstraints;
import com.arohalabs.util.IsoTime;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;
import com.fasterxml.jackson.core.type.TypeReference;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.*;

/**
 * Task mandates — authority for NON-monetary delegation (research, drafting,
 * scheduling…), optionally combined with spending ("hybrid"). Wire-compatible
 * with {@code issueTaskMandate} / {@code attenuateTaskMandate} /
 * {@code verifyTaskMandate} / {@code checkTaskConstraints} /
 * {@code checkTaskNarrowing} in {@code @aroha-sdk/credentials} (mandate.ts).
 *
 * <p>Token formats:
 * <ul>
 *   <li>v2 (issued now) — base64url of {@code {"v":2,"mandate":…,"signature":…}};
 *       the signature covers RFC 8785 JCS of
 *       {@code {"mandate": <body>, "purpose": "aroha.task-mandate/v2", "v": 2}}
 *       ({@link #signingPayloadV2}). The purpose tag means a task-mandate
 *       signature verifies as nothing else — not a spending mandate, not v1.</li>
 *   <li>v1 (legacy, verify only) — {@code {mandate, signature}} over sorted-key
 *       JSON of the body.</li>
 * </ul>
 *
 * <p>A task-mandate token carries no embedded chain: multi-hop task chains
 * are verified by {@code @aroha-sdk/delegation} (not ported). Each link here
 * is verified on its own, and {@link #checkTaskNarrowing} is the per-link rule
 * a chain verifier applies.
 *
 * <p>Like {@link ArohaMandateCredential}, verification works on the token's
 * RAW decoded JSON, so the bytes checked are the bytes the issuer signed.
 */
public final class TaskMandate {

    private TaskMandate() {}

    /** Token version produced by {@link #issue} and {@link #attenuate}. */
    public static final int TASK_MANDATE_TOKEN_VERSION = 2;

    /** Domain-separation tag inside every v2 task-mandate signature. */
    public static final String TASK_MANDATE_PURPOSE = "aroha.task-mandate/v2";

    static final Duration DEFAULT_TTL = Duration.ofHours(1);

    // ── Types ─────────────────────────────────────────────────────────────────

    /** Compute ceiling; every component optional (null = absent = no limit). */
    @JsonPropertyOrder({"llmTokens", "webRequests", "executionTimeMs", "cpuSeconds"})
    @JsonIgnoreProperties(ignoreUnknown = true)
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record ComputeLimit(Double llmTokens, Double webRequests, Double executionTimeMs, Double cpuSeconds) {}

    /**
     * Non-monetary limits (TS {@code TaskConstraints}). Every field is
     * optional; absent means "no limit on this resource". Values of
     * {@code dataAccess}: "none", "read", "write" (write WITHOUT read),
     * "read-write". {@code outputHandling}: "internal-only", "user-only",
     * "shareable". {@code onBehalfOf} / {@code roomId} are the conversation
     * profile's guest-grant bindings.
     */
    @JsonPropertyOrder({"actionLimits", "computeLimit", "dataAccess", "outputHandling", "reversibleOnly",
        "humanGates", "checkpointIntervalMs", "requireSandbox", "maxDelegationDepth", "onBehalfOf", "roomId"})
    @JsonIgnoreProperties(ignoreUnknown = true)
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record TaskConstraints(
        Map<String, Double> actionLimits,
        ComputeLimit computeLimit,
        Map<String, String> dataAccess,
        String outputHandling,
        Boolean reversibleOnly,
        List<String> humanGates,
        Double checkpointIntervalMs,
        Boolean requireSandbox,
        Integer maxDelegationDepth,
        String onBehalfOf,
        String roomId
    ) {
        public static Builder builder() { return new Builder(); }

        /** No limits at all ({@code {}}). */
        public static TaskConstraints none() { return builder().build(); }

        public static final class Builder {
            private Map<String, Double> actionLimits;
            private ComputeLimit computeLimit;
            private Map<String, String> dataAccess;
            private String outputHandling, onBehalfOf, roomId;
            private Boolean reversibleOnly, requireSandbox;
            private List<String> humanGates;
            private Double checkpointIntervalMs;
            private Integer maxDelegationDepth;

            public Builder actionLimit(String capability, double max) {
                if (actionLimits == null) actionLimits = new LinkedHashMap<>();
                actionLimits.put(capability, max);
                return this;
            }
            public Builder actionLimits(Map<String, Double> v) { actionLimits = v == null ? null : new LinkedHashMap<>(v); return this; }
            public Builder computeLimit(ComputeLimit v) { computeLimit = v; return this; }
            public Builder dataAccess(String resource, String access) {
                if (dataAccess == null) dataAccess = new LinkedHashMap<>();
                dataAccess.put(resource, access);
                return this;
            }
            public Builder dataAccess(Map<String, String> v) { dataAccess = v == null ? null : new LinkedHashMap<>(v); return this; }
            public Builder outputHandling(String v) { outputHandling = v; return this; }
            public Builder reversibleOnly(boolean v) { reversibleOnly = v; return this; }
            public Builder humanGates(List<String> v) { humanGates = v == null ? null : List.copyOf(v); return this; }
            public Builder checkpointIntervalMs(double v) { checkpointIntervalMs = v; return this; }
            public Builder requireSandbox(boolean v) { requireSandbox = v; return this; }
            public Builder maxDelegationDepth(int v) { maxDelegationDepth = v; return this; }
            public Builder onBehalfOf(String v) { onBehalfOf = v; return this; }
            public Builder roomId(String v) { roomId = v; return this; }
            public TaskConstraints build() {
                return new TaskConstraints(
                    actionLimits == null ? null : Collections.unmodifiableMap(new LinkedHashMap<>(actionLimits)),
                    computeLimit,
                    dataAccess == null ? null : Collections.unmodifiableMap(new LinkedHashMap<>(dataAccess)),
                    outputHandling, reversibleOnly,
                    humanGates, checkpointIntervalMs, requireSandbox, maxDelegationDepth, onBehalfOf, roomId);
            }
        }
    }

    /** Instance binding for one transaction (TS {@code MandateInvariants}). */
    @JsonPropertyOrder({"payee", "parameters", "maxAmount", "expiry"})
    @JsonIgnoreProperties(ignoreUnknown = true)
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record MandateInvariants(List<String> payee, Map<String, Object> parameters, Amount maxAmount, String expiry) {}

    @JsonPropertyOrder({"amount", "currency"})
    public record Amount(double amount, String currency) {}

    /** Typed view of a task-mandate body (TS {@code ArohaTaskMandateBody}). */
    @JsonIgnoreProperties(ignoreUnknown = true)
    public record TaskMandateBody(
        String mandateType,
        String mandateTier,
        List<String> allowed,
        List<String> blocked,
        TaskConstraints taskConstraints,
        SpendingConstraints spendingConstraints,
        MandateInvariants invariants,
        String grantee,
        String grantor,
        String issuedAt,
        String expiresAt,
        String parentMandateId,
        String mandateId
    ) {}

    /**
     * An issued or decoded task mandate. {@code mandate} is the raw JSON body
     * exactly as signed; {@link #body()} is a typed view of it. {@code v} is
     * the signing rule (2 now, 1 legacy).
     */
    public record SignedTaskMandate(Map<String, Object> mandate, String signature, String token, int v) {
        public TaskMandateBody body() { return typed(mandate); }
    }

    /** Verdict of {@link #verify}. {@code mandate} is the raw body when valid. */
    public record VerificationResult(boolean valid, Map<String, Object> mandate, String reason) {
        static VerificationResult fail(String reason) { return new VerificationResult(false, null, reason); }
        public TaskMandateBody body() { return mandate == null ? null : typed(mandate); }
    }

    /** Optional issuance settings (TS {@code issueTaskMandate} options). */
    public static final class IssueOptions {
        List<String> blocked;
        SpendingConstraints spendingConstraints;
        String parentMandateId;
        String tier;
        MandateInvariants invariants;
        Long expiresAtMs;

        public IssueOptions blocked(List<String> v) { blocked = v == null ? null : List.copyOf(v); return this; }
        /** Makes the mandate "hybrid". */
        public IssueOptions spendingConstraints(SpendingConstraints v) { spendingConstraints = v; return this; }
        public IssueOptions parentMandateId(String v) { parentMandateId = v; return this; }
        /** "intent" (default), "cart" or "execution". */
        public IssueOptions tier(String v) { tier = v; return this; }
        public IssueOptions invariants(MandateInvariants v) { invariants = v; return this; }
        /** Absolute expiry (epoch ms), overriding the TTL. */
        public IssueOptions expiresAtMs(long v) { expiresAtMs = v; return this; }
    }

    /** Optional attenuation settings (TS {@code attenuateTaskMandate} options). */
    public static final class AttenuateOptions {
        List<String> blocked;
        SpendingConstraints spendingConstraints;
        MandateInvariants invariants;

        /** Merged with (never replacing) the parent's blocked list. */
        public AttenuateOptions blocked(List<String> v) { blocked = v == null ? null : List.copyOf(v); return this; }
        /** Default: inherited from the parent. */
        public AttenuateOptions spendingConstraints(SpendingConstraints v) { spendingConstraints = v; return this; }
        /** NOT inherited: a parent's invariants must be restated. */
        public AttenuateOptions invariants(MandateInvariants v) { invariants = v; return this; }
    }

    /** Options for {@link #verify}. */
    public static final class VerifyOptions {
        Long nowMs;
        long clockToleranceMs = ArohaMandateCredential.DEFAULT_CLOCK_TOLERANCE_MS;
        MandateRevocationCheck isRevoked;

        /** Override "now" (epoch ms). */
        public VerifyOptions now(long epochMs) { nowMs = epochMs; return this; }
        /** Slack on the issuedAt not-before check only. Default 30 000. Never extends expiry. */
        public VerifyOptions clockToleranceMs(long v) { clockToleranceMs = v; return this; }
        /** Revocation hook keyed by (mandateId, grantor); a throw fails closed. */
        public VerifyOptions isRevoked(MandateRevocationCheck v) { isRevoked = v; return this; }
    }

    /**
     * One requested action, checked against a VERIFIED mandate by
     * {@link #checkTaskConstraints}. {@code roomId} / {@code onBehalfOf} must
     * come from the runtime's own records, never from the request body.
     */
    public static final class TaskActionRequest {
        final String requestedCapability;
        Map<String, Number> currentActionCounts;
        Number currentLlmTokens, currentWebRequests, currentWallClockMs;
        boolean hasCompute;
        String capabilityReversibility;
        Map<String, String> dataAccess;
        boolean humanApproved;
        String roomId;
        String onBehalfOf;

        public TaskActionRequest(String requestedCapability) {
            this.requestedCapability = Objects.requireNonNull(requestedCapability, "requestedCapability");
        }
        public TaskActionRequest currentActionCounts(Map<String, ? extends Number> v) {
            currentActionCounts = v == null ? null : new HashMap<>(v);
            return this;
        }
        /** Consumption so far this session; any argument may be null. */
        public TaskActionRequest currentCompute(Number llmTokens, Number webRequests, Number wallClockMs) {
            hasCompute = true;
            currentLlmTokens = llmTokens; currentWebRequests = webRequests; currentWallClockMs = wallClockMs;
            return this;
        }
        /** "full", "semi" or "irreversible". Omitted = irreversible (fails closed under reversibleOnly). */
        public TaskActionRequest capabilityReversibility(String v) { capabilityReversibility = v; return this; }
        /** Resource → "read" | "write" | "read-write" the action touches. */
        public TaskActionRequest dataAccess(Map<String, String> v) { dataAccess = v == null ? null : new LinkedHashMap<>(v); return this; }
        /** Set ONLY after a human approved this action. */
        public TaskActionRequest humanApproved(boolean v) { humanApproved = v; return this; }
        public TaskActionRequest roomId(String v) { roomId = v; return this; }
        public TaskActionRequest onBehalfOf(String v) { onBehalfOf = v; return this; }
    }

    /** A constraint breach. {@code code} is one of the TS {@code TaskConstraintViolation} codes. */
    public static final class TaskConstraintViolation extends Exception {
        private final String code;
        public TaskConstraintViolation(String message, String code) {
            super(message);
            this.code = code;
        }
        /**
         * MANDATE_INVALID, CAPABILITY_NOT_PERMITTED, REVERSIBILITY_VIOLATION,
         * HUMAN_GATE_REQUIRED, ACTION_LIMIT_EXCEEDED, COMPUTE_LIMIT_EXCEEDED,
         * DATA_ACCESS_VIOLATION, SANDBOX_REQUIRED, DELEGATION_DEPTH_EXCEEDED or
         * CONTEXT_MISMATCH.
         */
        public String code() { return code; }
    }

    // ── Issue ─────────────────────────────────────────────────────────────────

    /** {@link #issue(String, String, List, TaskConstraints, Ed25519PrivateKeyParameters, Duration, IssueOptions)} without options. */
    public static SignedTaskMandate issue(String grantorDID, String granteeDID, List<String> allowed,
                                          TaskConstraints taskConstraints, Ed25519PrivateKeyParameters privateKey,
                                          Duration ttl) {
        return issue(grantorDID, granteeDID, allowed, taskConstraints, privateKey, ttl, null);
    }

    /**
     * Issue a root task mandate (TS {@code issueTaskMandate}). {@code ttl}
     * null means one hour. With {@code spendingConstraints} the mandate is
     * "hybrid", otherwise "task".
     */
    public static SignedTaskMandate issue(String grantorDID, String granteeDID, List<String> allowed,
                                          TaskConstraints taskConstraints, Ed25519PrivateKeyParameters privateKey,
                                          Duration ttl, IssueOptions options) {
        IssueOptions o = options != null ? options : new IssueOptions();
        Objects.requireNonNull(allowed, "allowed");
        TaskConstraints tc = taskConstraints != null ? taskConstraints : TaskConstraints.none();
        long expiresAtMs = o.expiresAtMs != null ? o.expiresAtMs
            : System.currentTimeMillis() + (ttl != null ? ttl : DEFAULT_TTL).toMillis();

        // Same key order as the TS draft object; absent optionals are omitted
        // (JSON.stringify drops undefined), parentMandateId is always present.
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("mandateType", o.spendingConstraints != null ? "hybrid" : "task");
        body.put("mandateTier", o.tier != null ? o.tier : "intent");
        body.put("allowed", new ArrayList<>(allowed));
        if (o.blocked != null) body.put("blocked", new ArrayList<>(o.blocked));
        body.put("taskConstraints", toRaw(tc));
        if (o.spendingConstraints != null) body.put("spendingConstraints", toRaw(o.spendingConstraints));
        if (o.invariants != null) body.put("invariants", toRaw(o.invariants));
        body.put("grantee", granteeDID);
        body.put("grantor", grantorDID);
        body.put("issuedAt", IsoTime.now());
        body.put("expiresAt", IsoTime.formatMillis(expiresAtMs));
        body.put("parentMandateId", o.parentMandateId);
        body.put("mandateId", UUID.randomUUID().toString());

        String shape = checkTaskMandateShape(body);
        if (shape != null) throw new IllegalArgumentException("Invalid task mandate: " + shape);

        byte[] sig = Signing.signBytes(signingBytes(2, body), privateKey);
        String signature = b64url(sig);
        Map<String, Object> token = new LinkedHashMap<>();
        token.put("v", TASK_MANDATE_TOKEN_VERSION);
        token.put("mandate", body);
        token.put("signature", signature);
        String tokenStr = b64url(Jcs.stringify(token).getBytes(StandardCharsets.UTF_8));
        return new SignedTaskMandate(body, signature, tokenStr, 2);
    }

    /**
     * Attenuate to a narrower child (TS {@code attenuateTaskMandate}), signed
     * by the parent's grantee. The parent's blocked list and
     * spendingConstraints are inherited when not given; its onBehalfOf /
     * roomId bindings are inherited when the child leaves them out. Throws
     * {@link IllegalArgumentException} on any widening ({@link #checkTaskNarrowing}).
     * The child never outlives the parent. {@code ttl} null = parent's expiry.
     */
    public static SignedTaskMandate attenuate(SignedTaskMandate parent, String granteeDID, List<String> narrowedAllowed,
                                              TaskConstraints narrowedConstraints, Ed25519PrivateKeyParameters grantorKey,
                                              Duration ttl, AttenuateOptions options) {
        AttenuateOptions o = options != null ? options : new AttenuateOptions();
        Map<String, Object> p = parent.mandate();

        List<String> blocked = mergeLists(stringList(p.get("blocked")), o.blocked);
        SpendingConstraints spending = o.spendingConstraints != null ? o.spendingConstraints
            : (p.get("spendingConstraints") != null
                ? ArohaMandateCredential.MAPPER.convertValue(p.get("spendingConstraints"), SpendingConstraints.class)
                : null);

        TaskConstraints nc = narrowedConstraints != null ? narrowedConstraints : TaskConstraints.none();
        Map<String, Object> ptc = asMap(p.get("taskConstraints"));
        if (ptc != null) {
            String pOnBehalf = ptc.get("onBehalfOf") instanceof String s ? s : null;
            String pRoom = ptc.get("roomId") instanceof String s ? s : null;
            nc = new TaskConstraints(nc.actionLimits(), nc.computeLimit(), nc.dataAccess(), nc.outputHandling(),
                nc.reversibleOnly(), nc.humanGates(), nc.checkpointIntervalMs(), nc.requireSandbox(),
                nc.maxDelegationDepth(),
                nc.onBehalfOf() == null ? pOnBehalf : nc.onBehalfOf(),
                nc.roomId() == null ? pRoom : nc.roomId());
        }

        Map<String, Object> child = new LinkedHashMap<>();
        child.put("allowed", new ArrayList<>(narrowedAllowed));
        if (blocked != null) child.put("blocked", blocked);
        child.put("taskConstraints", toRaw(nc));
        if (spending != null) child.put("spendingConstraints", toRaw(spending));
        if (o.invariants != null) child.put("invariants", toRaw(o.invariants));
        String reason = checkTaskNarrowing(p, child);
        if (reason != null) throw new IllegalArgumentException(reason);

        long parentExpiry = IsoTime.parseMillis(p.get("expiresAt"));
        long expiry = ttl != null ? Math.min(parentExpiry, System.currentTimeMillis() + ttl.toMillis()) : parentExpiry;

        IssueOptions io = new IssueOptions()
            .expiresAtMs(expiry)
            .blocked(blocked)
            .spendingConstraints(spending)
            .parentMandateId((String) p.get("mandateId"))
            .tier("intent".equals(p.get("mandateTier")) ? "cart" : "execution")
            .invariants(o.invariants);
        return issue((String) p.get("grantee"), granteeDID, narrowedAllowed, nc, grantorKey, null, io);
    }

    /** Union of two optional lists, order-preserving; null when both are. */
    private static List<String> mergeLists(List<String> a, List<String> b) {
        if (a == null && b == null) return null;
        LinkedHashSet<String> s = new LinkedHashSet<>();
        if (a != null) s.addAll(a);
        if (b != null) s.addAll(b);
        return new ArrayList<>(s);
    }

    /** Decode a token without verifying it — to attenuate a mandate you received. */
    public static SignedTaskMandate decode(String token) {
        Object raw = parseRaw(token);
        if (!(raw instanceof Map<?, ?> rm)) throw new IllegalArgumentException("Malformed token");
        Map<String, Object> t = asMap(rm);
        if (!(t.get("signature") instanceof String sig) || sig.isEmpty()) {
            throw new IllegalArgumentException("Malformed token: signature missing");
        }
        Integer v = tokenVersion(t);
        if (v == null) throw new IllegalArgumentException("Unsupported task mandate token version: " + t.get("v"));
        String shape = checkTaskMandateShape(t.get("mandate"));
        if (shape != null) throw new IllegalArgumentException("Malformed token: " + shape);
        return new SignedTaskMandate(asMap(t.get("mandate")), sig, token, v);
    }

    // ── Verify ────────────────────────────────────────────────────────────────

    /** {@link #verify(String, Ed25519PublicKeyParameters, String, VerifyOptions)} with defaults. */
    public static VerificationResult verify(String token, Ed25519PublicKeyParameters publicKey, String expectedGrantee) {
        return verify(token, publicKey, expectedGrantee, new VerifyOptions());
    }

    /**
     * Verify a task-mandate token (TS {@code verifyTaskMandate}): shape,
     * time window (expiry strict; issuedAt not-before with tolerance),
     * grantee, signature under the rule its version names, and revocation.
     * Never throws on attacker-supplied input; returns {@code valid=false}.
     */
    public static VerificationResult verify(String token, Ed25519PublicKeyParameters publicKey, String expectedGrantee,
                                            VerifyOptions options) {
        VerifyOptions opts = options != null ? options : new VerifyOptions();
        if (token == null || token.isEmpty()) return VerificationResult.fail("Malformed token");
        Object raw = parseRaw(token);
        if (!(raw instanceof Map<?, ?> rm)) return VerificationResult.fail("Malformed token");
        Map<String, Object> t = asMap(rm);
        if (!(t.get("signature") instanceof String signature) || signature.isEmpty()) {
            return VerificationResult.fail("Malformed token: signature missing");
        }
        Integer version = tokenVersion(t);
        if (version == null) return VerificationResult.fail("Unsupported task mandate token version: " + t.get("v"));
        String shape = checkTaskMandateShape(t.get("mandate"));
        if (shape != null) return VerificationResult.fail("Malformed token: " + shape);
        Map<String, Object> m = asMap(t.get("mandate"));

        long now = opts.nowMs != null ? opts.nowMs : System.currentTimeMillis();
        long expiresAt = IsoTime.parseMillis(m.get("expiresAt"));
        long issuedAt = IsoTime.parseMillis(m.get("issuedAt"));
        if (expiresAt < now) return VerificationResult.fail("Task mandate expired");
        if (issuedAt > now + opts.clockToleranceMs) {
            return VerificationResult.fail("Task mandate issuedAt " + m.get("issuedAt") + " is in the future");
        }
        if (expiresAt < issuedAt) return VerificationResult.fail("Task mandate expires before it was issued");

        if (expectedGrantee != null && !expectedGrantee.isEmpty() && !expectedGrantee.equals(m.get("grantee"))) {
            return VerificationResult.fail("Grantee mismatch: expected " + expectedGrantee);
        }

        if (publicKey == null || !verifySignature(m, signature, version, publicKey.getEncoded())) {
            return VerificationResult.fail("Invalid signature");
        }

        String revoked = checkRevocation(m, opts.isRevoked);
        if (revoked != null) return VerificationResult.fail(revoked);
        return new VerificationResult(true, m, null);
    }

    /** Verify one link's signature under rule {@code v} (1 or 2). Never throws. */
    public static boolean verifySignature(Map<String, Object> mandate, String signature, int v, byte[] publicKey) {
        try {
            byte[] sig = Base64.getUrlDecoder().decode(signature);
            return Signing.verifyBytes(signingBytes(v == 2 ? 2 : 1, mandate), sig, publicKey);
        } catch (Exception e) {
            return false;
        }
    }

    private static String checkRevocation(Map<String, Object> m, MandateRevocationCheck isRevoked) {
        if (isRevoked == null) return null;
        Object id = m.get("mandateId");
        try {
            return isRevoked.isRevoked((String) id, (String) m.get("grantor"))
                ? "Task mandate " + id + " has been revoked" : null;
        } catch (Exception e) {
            return "Revocation check failed for task mandate " + id;
        }
    }

    /**
     * Verify {@code token} and check {@code request} against it (TS
     * {@code enforceTaskConstraints}). Returns the verified raw body; throws
     * {@link TaskConstraintViolation} (code MANDATE_INVALID when the token
     * itself fails) on any breach.
     */
    public static Map<String, Object> enforce(String token, Ed25519PublicKeyParameters grantorPublicKey,
                                              String expectedGrantee, MandateRevocationCheck isRevoked,
                                              TaskActionRequest request) throws TaskConstraintViolation {
        VerificationResult r = verify(token, grantorPublicKey, expectedGrantee, new VerifyOptions().isRevoked(isRevoked));
        if (!r.valid()) throw new TaskConstraintViolation("Task mandate invalid: " + r.reason(), "MANDATE_INVALID");
        TaskConstraintViolation v = checkTaskConstraints(r.mandate(), request);
        if (v != null) throw v;
        return r.mandate();
    }

    // ── Canonicalisation ─────────────────────────────────────────────────────

    /**
     * The exact string a v2 signature covers: JCS of
     * {@code {"mandate": body, "purpose": "aroha.task-mandate/v2", "v": 2}}.
     */
    public static String signingPayloadV2(Map<String, Object> mandate) {
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("mandate", mandate);
        payload.put("purpose", TASK_MANDATE_PURPOSE);
        payload.put("v", 2);
        return Jcs.canonicalize(payload);
    }

    private static byte[] signingBytes(int v, Map<String, Object> mandate) {
        // v1 = JSON.stringify(sortKeys(body)), which equals JCS for JSON values.
        String s = v == 2 ? signingPayloadV2(mandate) : Jcs.canonicalize(mandate);
        return s.getBytes(StandardCharsets.UTF_8);
    }

    // ── Shape ────────────────────────────────────────────────────────────────

    private static Object parseRaw(String token) {
        try {
            return ArohaMandateCredential.MAPPER.readValue(Base64.getUrlDecoder().decode(token), Object.class);
        } catch (Exception e) {
            return null;
        }
    }

    /** 1 (absent or 1) or 2; null for anything else (never guessed). */
    private static Integer tokenVersion(Map<String, Object> raw) {
        if (!raw.containsKey("v")) return 1;
        if (raw.get("v") instanceof Number n) {
            double d = n.doubleValue();
            if (d == 1) return 1;
            if (d == 2) return 2;
        }
        return null;
    }

    private static boolean isCount(Object x) {
        return x instanceof Number n && Double.isFinite(n.doubleValue()) && n.doubleValue() >= 0;
    }

    private static boolean isStringList(Object x) {
        return x instanceof List<?> l && l.stream().allMatch(e -> e instanceof String);
    }

    private static boolean isIsoDate(Object x) {
        return IsoTime.parseMillis(x) != null;
    }

    /**
     * Structural validation of a decoded body (TS {@code checkTaskMandateShape}).
     * Null when well-formed. A missing or mistyped limit must never read as
     * "no limit exceeded".
     */
    public static String checkTaskMandateShape(Object mo) {
        if (!(mo instanceof Map<?, ?> m)) return "mandate is not an object";
        Object type = m.get("mandateType");
        if (!"task".equals(type) && !"hybrid".equals(type)) return "mandateType is invalid";
        Object tier = m.get("mandateTier");
        if (!"intent".equals(tier) && !"cart".equals(tier) && !"execution".equals(tier)) return "mandateTier is invalid";
        for (String f : List.of("grantor", "grantee", "mandateId")) {
            if (!(m.get(f) instanceof String s) || s.isEmpty()) return f + " is missing";
        }
        if (!isIsoDate(m.get("issuedAt"))) return "issuedAt is not a date";
        if (!isIsoDate(m.get("expiresAt"))) return "expiresAt is not a date";
        // JS: parentMandateId !== null && typeof !== "string" — absent is invalid too.
        if (!m.containsKey("parentMandateId")) return "parentMandateId is invalid";
        Object pid = m.get("parentMandateId");
        if (pid != null && !(pid instanceof String)) return "parentMandateId is invalid";
        if (!isStringList(m.get("allowed"))) return "allowed must be an array of capability ids";
        if (m.containsKey("blocked") && !isStringList(m.get("blocked"))) return "blocked must be an array of capability ids";

        if (!(m.get("taskConstraints") instanceof Map<?, ?> tc)) return "taskConstraints is not an object";
        if (tc.containsKey("actionLimits")) {
            if (!(tc.get("actionLimits") instanceof Map<?, ?> al)) return "taskConstraints.actionLimits must be an object";
            for (Map.Entry<?, ?> e : al.entrySet()) {
                if (!isCount(e.getValue())) {
                    return "taskConstraints.actionLimits[\"" + e.getKey() + "\"] must be a finite, non-negative number";
                }
            }
        }
        if (tc.containsKey("computeLimit")) {
            if (!(tc.get("computeLimit") instanceof Map<?, ?> cl)) return "taskConstraints.computeLimit must be an object";
            for (String f : COMPUTE_FIELDS) {
                if (cl.containsKey(f) && !isCount(cl.get(f))) {
                    return "taskConstraints.computeLimit." + f + " must be a finite, non-negative number";
                }
            }
        }
        if (tc.containsKey("dataAccess")) {
            if (!(tc.get("dataAccess") instanceof Map<?, ?> da)) return "taskConstraints.dataAccess must be an object";
            for (Map.Entry<?, ?> e : da.entrySet()) {
                if (!(e.getValue() instanceof String s) || !DATA_ACCESS_RIGHTS.containsKey(s)) {
                    return "taskConstraints.dataAccess[\"" + e.getKey() + "\"] is invalid";
                }
            }
        }
        if (tc.containsKey("reversibleOnly") && !(tc.get("reversibleOnly") instanceof Boolean)) {
            return "taskConstraints.reversibleOnly must be a boolean";
        }
        for (String f : List.of("onBehalfOf", "roomId")) {
            if (tc.containsKey(f) && (!(tc.get(f) instanceof String s) || s.isEmpty())) {
                return "taskConstraints." + f + " must be a non-empty string";
            }
        }
        if ("hybrid".equals(type) || m.containsKey("spendingConstraints")) {
            String sc = ArohaMandateCredential.checkConstraintsShape(m.get("spendingConstraints"));
            if (sc != null) return "spendingConstraints: " + sc;
        }
        if (m.containsKey("invariants") && !(m.get("invariants") instanceof Map)) return "invariants must be an object";
        return null;
    }

    // ── Constraint enforcement ───────────────────────────────────────────────

    private record Rights(boolean read, boolean write) {}

    /** "write" is write WITHOUT read: rights are sets, child ⊆ parent. */
    private static final Map<String, Rights> DATA_ACCESS_RIGHTS = Map.of(
        "none", new Rights(false, false),
        "read", new Rights(true, false),
        "write", new Rights(false, true),
        "read-write", new Rights(true, true));

    private static final Map<String, Integer> OUTPUT_HANDLING_RANK = Map.of("internal-only", 0, "user-only", 1, "shareable", 2);

    private static final List<String> COMPUTE_FIELDS = List.of("llmTokens", "webRequests", "executionTimeMs", "cpuSeconds");

    /** {@link #checkTaskConstraints(Map, TaskActionRequest)} on a typed body. */
    public static TaskConstraintViolation checkTaskConstraints(TaskMandateBody mandate, TaskActionRequest request) {
        return checkTaskConstraints(toRaw(mandate), request);
    }

    /**
     * Check one action against an ALREADY-VERIFIED mandate body (TS
     * {@code checkTaskConstraints}). Null when allowed, else the violation
     * (returned, not thrown). Order: room / on-behalf-of binding, allowed,
     * blocked, reversibleOnly, humanGates, actionLimits, computeLimit (when
     * consumption is reported), dataAccess.
     */
    public static TaskConstraintViolation checkTaskConstraints(Map<String, Object> mandate, TaskActionRequest request) {
        Map<String, Object> tc = asMap(mandate.get("taskConstraints"));
        if (tc == null) tc = Map.of();
        String cap = request.requestedCapability;

        // A grant bound to one room / member is refused for any other, and for
        // a request that names none at all.
        if (tc.containsKey("roomId") && !Objects.equals(request.roomId, tc.get("roomId"))) {
            return new TaskConstraintViolation("The mandate is bound to room " + tc.get("roomId") + "; the request is from "
                + (request.roomId != null ? request.roomId : "no room"), "CONTEXT_MISMATCH");
        }
        if (tc.containsKey("onBehalfOf") && !Objects.equals(request.onBehalfOf, tc.get("onBehalfOf"))) {
            return new TaskConstraintViolation("The mandate acts on behalf of " + tc.get("onBehalfOf") + "; the request is for "
                + (request.onBehalfOf != null ? request.onBehalfOf : "nobody named"), "CONTEXT_MISMATCH");
        }

        List<String> allowed = stringList(mandate.get("allowed"));
        if (allowed == null || !allowed.contains(cap)) {
            return new TaskConstraintViolation("Capability \"" + cap + "\" is not in the mandate's allowed list",
                "CAPABILITY_NOT_PERMITTED");
        }
        List<String> blocked = stringList(mandate.get("blocked"));
        if (blocked != null && blocked.contains(cap)) {
            return new TaskConstraintViolation("Capability \"" + cap + "\" is explicitly blocked by the mandate",
                "CAPABILITY_NOT_PERMITTED");
        }

        if (Boolean.TRUE.equals(tc.get("reversibleOnly"))) {
            String rev = request.capabilityReversibility != null ? request.capabilityReversibility : "irreversible";
            if (rev.equals("irreversible")) {
                return new TaskConstraintViolation("Capability \"" + cap + "\" is irreversible but mandate requires reversibleOnly",
                    "REVERSIBILITY_VIOLATION");
            }
        }

        List<String> gates = stringList(tc.get("humanGates"));
        if (gates != null && gates.contains(cap) && !request.humanApproved) {
            return new TaskConstraintViolation("Capability \"" + cap + "\" requires human approval (humanGate)",
                "HUMAN_GATE_REQUIRED");
        }

        Map<String, Object> limits = asMap(tc.get("actionLimits"));
        if (limits != null && limits.get(cap) instanceof Number limit) {
            Number cur = request.currentActionCounts != null ? request.currentActionCounts.get(cap) : null;
            double current = cur != null ? cur.doubleValue() : 0;
            if (current >= limit.doubleValue()) {
                return new TaskConstraintViolation("Action limit exceeded for \"" + cap + "\": " + num(current) + "/"
                    + num(limit.doubleValue()), "ACTION_LIMIT_EXCEEDED");
            }
        }

        Map<String, Object> cl = asMap(tc.get("computeLimit"));
        if (cl != null && request.hasCompute) {
            if (cl.get("llmTokens") instanceof Number n && val(request.currentLlmTokens) >= n.doubleValue()) {
                return new TaskConstraintViolation("LLM token budget exhausted (" + num(n.doubleValue()) + " max)",
                    "COMPUTE_LIMIT_EXCEEDED");
            }
            if (cl.get("webRequests") instanceof Number n && val(request.currentWebRequests) >= n.doubleValue()) {
                return new TaskConstraintViolation("Web request budget exhausted (" + num(n.doubleValue()) + " max)",
                    "COMPUTE_LIMIT_EXCEEDED");
            }
            if (cl.get("executionTimeMs") instanceof Number n && val(request.currentWallClockMs) >= n.doubleValue()) {
                return new TaskConstraintViolation("Execution time budget exhausted (" + num(n.doubleValue()) + "ms max)",
                    "COMPUTE_LIMIT_EXCEEDED");
            }
        }

        return checkTaskDataAccess(tc, request.dataAccess);
    }

    /**
     * The dataAccess rule on its own (TS {@code checkTaskDataAccess}). Null
     * when every requested resource is granted with the rights asked for, or
     * when the mandate sets no dataAccess map. A resource missing from the map
     * is "none"; an unknown requested level fails closed.
     */
    public static TaskConstraintViolation checkTaskDataAccess(Map<String, Object> taskConstraints, Map<String, String> requested) {
        Map<String, Object> grants = taskConstraints == null ? null : asMap(taskConstraints.get("dataAccess"));
        if (grants == null || requested == null) return null;
        for (Map.Entry<String, String> e : requested.entrySet()) {
            Object granted = grants.containsKey(e.getKey()) ? grants.get(e.getKey()) : "none";
            Rights g = granted instanceof String s ? DATA_ACCESS_RIGHTS.get(s) : null;
            Rights w = e.getValue() == null ? null : DATA_ACCESS_RIGHTS.get(e.getValue());
            if (g == null || w == null || (w.read() && !g.read()) || (w.write() && !g.write())) {
                return new TaskConstraintViolation("Data access \"" + e.getValue() + "\" on \"" + e.getKey()
                    + "\" exceeds the mandate's grant (" + granted + ")", "DATA_ACCESS_VIOLATION");
            }
        }
        return null;
    }

    // ── Narrowing ────────────────────────────────────────────────────────────

    /**
     * Null when {@code child} is equal to or narrower than {@code parent};
     * otherwise why not (TS {@code checkTaskNarrowing}, same rules and
     * messages). For every constraint the PARENT sets, the child must set it
     * too, equal or narrower — omission is widening.
     *
     * <p>{@code child} is a raw body or the subset of one: {@code allowed},
     * {@code blocked}, {@code taskConstraints}, {@code spendingConstraints},
     * {@code invariants} and optionally {@code expiresAt}. Not checked here:
     * maxDelegationDepth (owned by a chain verifier) and
     * grantor/grantee/parentMandateId linkage.
     */
    public static String checkTaskNarrowing(Map<String, Object> parent, Map<String, Object> child) {
        String prefix = "Cannot attenuate task mandate";
        Map<String, Object> ptc = orEmpty(asMap(parent.get("taskConstraints")));
        Map<String, Object> ctc = orEmpty(asMap(child.get("taskConstraints")));

        Set<String> parentAllowed = new HashSet<>(orEmpty(stringList(parent.get("allowed"))));
        List<String> childAllowedList = orEmpty(stringList(child.get("allowed")));
        for (String cap : childAllowedList) {
            if (!parentAllowed.contains(cap)) {
                return prefix + ": child allowed includes \"" + cap + "\" which is not in parent's allowed list";
            }
        }
        Set<String> childAllowed = new HashSet<>(childAllowedList);

        Set<String> childBlocked = new HashSet<>(orEmpty(stringList(child.get("blocked"))));
        for (String cap : orEmpty(stringList(parent.get("blocked")))) {
            if (!childBlocked.contains(cap)) return prefix + ": child drops parent's blocked capability \"" + cap + "\"";
        }

        // actionLimits — only capabilities the child can still invoke matter.
        Map<String, Object> pal = asMap(ptc.get("actionLimits"));
        if (pal != null) {
            Map<String, Object> cal = asMap(ctc.get("actionLimits"));
            for (Map.Entry<String, Object> e : pal.entrySet()) {
                String cap = e.getKey();
                if (!childAllowed.contains(cap)) continue;
                Object pl = e.getValue();
                Object cl = cal == null ? null : cal.get(cap);
                if (cl == null) {
                    return prefix + ": parent sets actionLimits[\"" + cap + "\"] (" + str(pl) + ") but child omits it";
                }
                if (!isCount(cl) || gt(cl, pl)) {
                    return prefix + ": child actionLimits[\"" + cap + "\"] (" + str(cl) + ") exceeds parent (" + str(pl) + ")";
                }
            }
        }

        Map<String, Object> pcl = asMap(ptc.get("computeLimit"));
        if (pcl != null) {
            Map<String, Object> ccl = asMap(ctc.get("computeLimit"));
            for (String f : COMPUTE_FIELDS) {
                Object p = pcl.get(f);
                if (p == null) continue;
                Object c = ccl == null ? null : ccl.get(f);
                if (c == null) return prefix + ": parent sets computeLimit." + f + " (" + str(p) + ") but child omits it";
                if (!isCount(c) || gt(c, p)) return prefix + ": child " + f + " (" + str(c) + ") exceeds parent (" + str(p) + ")";
            }
        }

        // dataAccess — a missing key inside the map is "none" (narrowing);
        // omitting the WHOLE map is "no limit" (widening).
        Map<String, Object> pda = asMap(ptc.get("dataAccess"));
        if (pda != null) {
            Map<String, Object> cda = asMap(ctc.get("dataAccess"));
            if (cda == null) return prefix + ": parent restricts dataAccess but child omits it";
            for (Map.Entry<String, Object> e : cda.entrySet()) {
                Object pa = pda.containsKey(e.getKey()) ? pda.get(e.getKey()) : "none";
                Rights c = e.getValue() instanceof String s ? DATA_ACCESS_RIGHTS.get(s) : null;
                Rights p = pa instanceof String s ? DATA_ACCESS_RIGHTS.get(s) : null;
                if (c == null || p == null || (c.read() && !p.read()) || (c.write() && !p.write())) {
                    return prefix + ": child dataAccess[\"" + e.getKey() + "\"] (" + e.getValue() + ") exceeds parent (" + pa + ")";
                }
            }
        }

        if (Boolean.TRUE.equals(ptc.get("reversibleOnly")) && !Boolean.TRUE.equals(ctc.get("reversibleOnly"))) {
            return prefix + ": parent requires reversibleOnly but child does not";
        }
        if (Boolean.TRUE.equals(ptc.get("requireSandbox")) && !Boolean.TRUE.equals(ctc.get("requireSandbox"))) {
            return prefix + ": parent requires requireSandbox but child does not";
        }

        // onBehalfOf / roomId — a parent's binding is kept verbatim.
        for (String f : List.of("onBehalfOf", "roomId")) {
            if (ptc.get(f) != null && !Objects.equals(ctc.get(f), ptc.get(f))) {
                return prefix + ": child " + f + " (" + (ctc.get(f) != null ? ctc.get(f) : "unset")
                    + ") does not keep the parent's " + f + " (" + ptc.get(f) + ")";
            }
        }

        List<String> pg = stringList(ptc.get("humanGates"));
        if (pg != null) {
            Set<String> cg = new HashSet<>(orEmpty(stringList(ctc.get("humanGates"))));
            for (String cap : pg) {
                if (childAllowed.contains(cap) && !cg.contains(cap)) {
                    return prefix + ": child drops parent's human gate on \"" + cap + "\"";
                }
            }
        }

        if (ptc.get("outputHandling") != null) {
            Integer p = OUTPUT_HANDLING_RANK.get(String.valueOf(ptc.get("outputHandling")));
            Object co = ctc.get("outputHandling");
            Integer c = co == null ? null : OUTPUT_HANDLING_RANK.get(String.valueOf(co));
            if (c == null || p == null || c > p) {
                return prefix + ": child outputHandling (" + (co != null ? co : "unset") + ") is wider than parent ("
                    + ptc.get("outputHandling") + ")";
            }
        }

        if (ptc.get("checkpointIntervalMs") != null) {
            Object p = ptc.get("checkpointIntervalMs");
            Object c = ctc.get("checkpointIntervalMs");
            if (c == null || !isCount(c) || gt(c, p)) {
                return prefix + ": child checkpointIntervalMs (" + (c != null ? str(c) : "unset")
                    + ") is longer than parent (" + str(p) + ")";
            }
        }

        if (parent.get("spendingConstraints") != null) {
            if (child.get("spendingConstraints") == null) return prefix + ": parent sets spendingConstraints but child omits them";
            SpendingConstraints ps = ArohaMandateCredential.MAPPER.convertValue(parent.get("spendingConstraints"), SpendingConstraints.class);
            SpendingConstraints cs = ArohaMandateCredential.MAPPER.convertValue(child.get("spendingConstraints"), SpendingConstraints.class);
            String reason = ArohaMandateCredential.checkNarrowing(ps, cs, "task", "task");
            if (reason != null) return prefix + ": spendingConstraints: " + reason;
        }

        String inv = checkInvariantsNarrowing(prefix, asMap(parent.get("invariants")), asMap(child.get("invariants")));
        if (inv != null) return inv;

        if (child.get("expiresAt") != null) {
            Long c = IsoTime.parseMillis(child.get("expiresAt"));
            Long p = IsoTime.parseMillis(parent.get("expiresAt"));
            if (c == null || p == null || c > p) {
                return prefix + ": child expiry (" + child.get("expiresAt") + ") extends beyond parent (" + parent.get("expiresAt") + ")";
            }
        }
        return null;
    }

    /** {@link #checkTaskNarrowing(Map, Map)} on typed bodies. */
    public static String checkTaskNarrowing(TaskMandateBody parent, TaskMandateBody child) {
        return checkTaskNarrowing(toRaw(parent), toRaw(child));
    }

    private static String checkInvariantsNarrowing(String prefix, Map<String, Object> pi, Map<String, Object> ci) {
        if (pi == null) return null;
        if (ci == null) return prefix + ": parent has invariants but child drops them entirely";

        List<String> pp = stringList(pi.get("payee"));
        if (pi.get("payee") != null) {
            List<String> cp = stringList(ci.get("payee"));
            if (ci.get("payee") == null) return prefix + ": parent restricts payee but child has no payee invariant";
            Set<String> parentPayees = new HashSet<>(orEmpty(pp));
            for (String p : orEmpty(cp)) {
                if (!parentPayees.contains(p)) return prefix + ": child payee \"" + p + "\" is not in parent's payee list";
            }
        }

        Map<String, Object> pm = asMap(pi.get("maxAmount"));
        if (pm != null) {
            Map<String, Object> cm = asMap(ci.get("maxAmount"));
            if (cm == null) return prefix + ": parent has maxAmount invariant but child has none";
            if (!Objects.equals(cm.get("currency"), pm.get("currency"))) {
                return prefix + ": child maxAmount currency (" + cm.get("currency") + ") differs from parent (" + pm.get("currency") + ")";
            }
            if (!isCount(cm.get("amount")) || gt(cm.get("amount"), pm.get("amount"))) {
                return prefix + ": child maxAmount (" + str(cm.get("amount")) + ") exceeds parent (" + str(pm.get("amount")) + ")";
            }
        }

        Map<String, Object> pParams = asMap(pi.get("parameters"));
        if (pParams != null) {
            Map<String, Object> cParams = orEmpty(asMap(ci.get("parameters")));
            for (Map.Entry<String, Object> e : pParams.entrySet()) {
                if (!cParams.containsKey(e.getKey()) || !strictEquals(cParams.get(e.getKey()), e.getValue())) {
                    return prefix + ": child parameter \"" + e.getKey() + "\" does not match parent's fixed value";
                }
            }
        }

        if (pi.get("expiry") != null) {
            if (ci.get("expiry") == null) return prefix + ": parent has expiry invariant but child has none";
            Long c = IsoTime.parseMillis(ci.get("expiry"));
            Long p = IsoTime.parseMillis(pi.get("expiry"));
            if (c == null || (p != null && c > p)) {
                return prefix + ": child expiry (" + ci.get("expiry") + ") exceeds parent (" + pi.get("expiry") + ")";
            }
        }
        return null;
    }

    // ── Helpers ──────────────────────────────────────────────────────────────

    /** JavaScript {@code a > b} for two JSON numbers; false if either is not a number. */
    private static boolean gt(Object a, Object b) {
        return a instanceof Number x && b instanceof Number y && x.doubleValue() > y.doubleValue();
    }

    /** JavaScript {@code ===} on JSON scalars (numbers by value). */
    private static boolean strictEquals(Object a, Object b) {
        if (a instanceof Number x && b instanceof Number y) return x.doubleValue() == y.doubleValue();
        return a != null && a.equals(b);
    }

    private static double val(Number n) {
        return n == null ? 0 : n.doubleValue();
    }

    private static String num(double d) {
        return Jcs.formatNumber(d);
    }

    private static String str(Object o) {
        return o instanceof Number n && Double.isFinite(n.doubleValue()) ? num(n.doubleValue()) : String.valueOf(o);
    }

    private static <K, V> Map<K, V> orEmpty(Map<K, V> m) {
        return m == null ? Map.of() : m;
    }

    private static <T> List<T> orEmpty(List<T> l) {
        return l == null ? List.of() : l;
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> asMap(Object o) {
        return o instanceof Map<?, ?> m ? (Map<String, Object>) m : null;
    }

    @SuppressWarnings("unchecked")
    private static List<String> stringList(Object o) {
        return isStringList(o) ? (List<String>) o : null;
    }

    private static String b64url(byte[] b) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(b);
    }

    /** Record → JSON tree with absent (null) optional fields omitted. */
    static Map<String, Object> toRaw(Object record) {
        return ArohaMandateCredential.MAPPER.convertValue(record, new TypeReference<LinkedHashMap<String, Object>>() {});
    }

    static TaskMandateBody typed(Map<String, Object> raw) {
        return ArohaMandateCredential.MAPPER.convertValue(raw, TaskMandateBody.class);
    }
}
