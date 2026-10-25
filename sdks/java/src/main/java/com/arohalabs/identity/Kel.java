// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

package com.arohalabs.identity;

import com.arohalabs.crypto.Jcs;
import com.arohalabs.crypto.Signing;
import com.arohalabs.util.IsoTime;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Rotatable, self-certifying identifiers ({@code did:aroha:E…}) and their Key
 * Event Logs — READ-ONLY port of {@code identity/kel.ts} in @aroha-sdk/core.
 *
 * <p>This class verifies logs produced by any conformant SDK; it does not
 * create them (incept / rotate / recover / revoke stay in the TypeScript SDK
 * for now). A KEL is a JSON array of events; here each event is the
 * {@code Map<String, Object>} Jackson reads, kept raw so the digest and the
 * signature cover exactly the bytes the issuer canonicalised.
 *
 * <p>The identifier is {@code did:aroha:E<base58btc(sha256(JCS(inception without sig)))>}.
 * Every event is signed over RFC 8785 JCS of the event with {@code sig}
 * removed, and its digest is sha256 of the same bytes.
 *
 * <p>Authorisation rules, as in the reference:
 * <ul>
 *   <li>inception — signed by its own {@code keys[0]};</li>
 *   <li>rotate — signed by the pre-committed next key, revealed as {@code keys[0]};</li>
 *   <li>recover (agents) — unsigned, sealed in the controller person's KEL;</li>
 *   <li>revoke — {@code auth:"next-key"} signed by the revealed next key, or
 *       {@code auth:"controller"} unsigned and sealed;</li>
 *   <li>anchor (persons) — signed by the current key; carries seals.</li>
 * </ul>
 */
public final class Kel {

    private Kel() {}

    private static final String DID_PREFIX = "did:aroha:";

    /** Current KEL event format version. */
    public static final int KEL_VERSION = 1;

    // ── Types ─────────────────────────────────────────────────────────────────

    /** Error codes, identical to the TypeScript {@code KelErrorCode}. */
    public static final String INVALID = "invalid";
    public static final String STALE = "stale";
    public static final String DUPLICITY = "duplicity";
    public static final String CONTROLLER_UNAVAILABLE = "controller-unavailable";

    /** A KEL failed verification or reconciliation. {@link #code()} is one of the constants above. */
    public static final class KelException extends Exception {
        private final String code;

        public KelException(String code, String message) {
            super(message);
            this.code = code;
        }

        public String code() { return code; }
    }

    /** A seal a person places in an anchor event, vouching for one agent event. */
    public record Seal(String did, long seq, String digest) {}

    /** From {@code seq} on, {@code keys} were current. */
    public record KeyEstablishment(int seq, List<String> keys) {}

    /** Fetch the KEL for a DID (registry, peer, cache…); null when unknown. */
    @FunctionalInterface
    public interface KelSource {
        List<Map<String, Object>> fetch(String did) throws Exception;
    }

    /** Result of replaying a verified KEL. */
    public static final class KelState {
        public String did;
        public String kind;
        public String controller;
        /** Multibase keys valid now; empty once revoked. */
        public List<String> currentKeys = new ArrayList<>();
        /** Raw 32 bytes of currentKeys[0], or null once revoked. */
        public byte[] currentKey;
        /** Outstanding pre-rotation commitment, or null once revoked. */
        public String nextKeyDigest;
        public boolean revoked;
        public int sequence;
        public String lastDigest;
        public List<String> digests = new ArrayList<>();
        public List<KeyEstablishment> keyHistory = new ArrayList<>();
        public List<Seal> seals = new ArrayList<>();
        public List<Map<String, Object>> events = new ArrayList<>();
        public KelState controllerState;
        /** The controller's KEL was resolved and the controller revoked itself. */
        public boolean controllerRevoked;
    }

    /** Options for {@link #verifyKel}. */
    public static final class VerifyOptions {
        /** Source of the CONTROLLER's KEL; needed for recover / controller-revoke. */
        public KelSource resolveControllerKel;
        /** Fail with controller-unavailable when an agent's controller KEL cannot be fetched. */
        public boolean requireController;

        public VerifyOptions resolveControllerKel(KelSource s) { resolveControllerKel = s; return this; }
        public VerifyOptions requireController(boolean v) { requireController = v; return this; }
    }

    /** Evidence of a forked log. */
    public record DuplicityEvidence(String did, int seq, String seenDigest, String offeredDigest, String detectedAt) {}

    /** Highest-seen memory per DID (TS {@code KelStore}). */
    public interface KelStore {
        List<Map<String, Object>> get(String did);
        void put(String did, List<Map<String, Object>> events);
        void recordDuplicity(DuplicityEvidence evidence);
        DuplicityEvidence getDuplicity(String did);
    }

    /** In-memory {@link KelStore}. */
    public static final class InMemoryKelStore implements KelStore {
        private final Map<String, List<Map<String, Object>>> logs = new ConcurrentHashMap<>();
        private final Map<String, DuplicityEvidence> alarms = new ConcurrentHashMap<>();

        @Override public List<Map<String, Object>> get(String did) { return logs.get(did); }
        @Override public void put(String did, List<Map<String, Object>> events) { logs.put(did, List.copyOf(events)); }
        @Override public void recordDuplicity(DuplicityEvidence e) { alarms.putIfAbsent(e.did(), e); }
        @Override public DuplicityEvidence getDuplicity(String did) { return alarms.get(did); }
    }

    // ── Digests and identifiers ──────────────────────────────────────────────

    /** {@code E} + base58btc(sha256(bytes)). */
    public static String sha256Digest(byte[] bytes) {
        return "E" + DID.encodeBase58(sha256(bytes));
    }

    /** The pre-rotation commitment for a raw 32-byte public key. */
    public static String keyDigest(byte[] publicKey) {
        return sha256Digest(publicKey);
    }

    /** Digest of an event: sha256 over JCS of the event with {@code sig} removed. */
    public static String eventDigest(Map<String, Object> event) {
        return sha256Digest(Jcs.canonicalizeToBytes(signingBody(event)));
    }

    /** The DID an inception event creates. */
    public static String didFromInception(Map<String, Object> inception) {
        return DID_PREFIX + eventDigest(inception);
    }

    /** True for {@code did:aroha:E<base58btc(32 bytes)>}, canonically encoded. */
    public static boolean isInceptionDid(String did) {
        return inceptionDigestFromDid(did) != null;
    }

    /** The 32-byte inception digest an E-DID commits to, or null. */
    public static byte[] inceptionDigestFromDid(String did) {
        if (did == null || !did.startsWith(DID_PREFIX)) return null;
        String suffix = did.substring(DID_PREFIX.length());
        if (suffix.contains(".") || suffix.contains(":")) return null;
        return decodeDigest(suffix);
    }

    private static byte[] decodeDigest(Object digest) {
        if (!(digest instanceof String d) || !d.startsWith("E")) return null;
        try {
            byte[] bytes = DID.decodeBase58(d.substring(1));
            if (bytes.length != 32) return null;
            return ("E" + DID.encodeBase58(bytes)).equals(d) ? bytes : null;
        } catch (Exception e) {
            return null;
        }
    }

    private static byte[] decodeKey(Object k) {
        if (!(k instanceof String s) || !s.startsWith("z")) return null;
        try {
            byte[] bytes = DID.fromMultibase(s);
            return bytes.length == 32 && DID.toMultibase(bytes).equals(s) ? bytes : null;
        } catch (Exception e) {
            return null;
        }
    }

    private static Map<String, Object> signingBody(Map<String, Object> event) {
        Map<String, Object> body = new LinkedHashMap<>(event);
        body.remove("sig");
        return body;
    }

    private static byte[] sha256(byte[] b) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(b);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    // ── Shape checks ─────────────────────────────────────────────────────────

    private record Key(String multibase, byte[] bytes) {}

    private static Key singleKey(Object keys, String where) throws KelException {
        if (!(keys instanceof List<?> list) || list.size() != 1) {
            throw new KelException(INVALID, where + ": keys must be an array of exactly one Ed25519 key in KEL v1");
        }
        byte[] bytes = decodeKey(list.get(0));
        if (bytes == null) throw new KelException(INVALID, where + ": keys[0] is not a multibase Ed25519 public key");
        return new Key((String) list.get(0), bytes);
    }

    private static void requireDigest(Object d, String where, String field) throws KelException {
        if (decodeDigest(d) == null) throw new KelException(INVALID, where + ": " + field + " is not an E-digest");
    }

    private static void requireTime(Object t, String where, String field) throws KelException {
        if (IsoTime.parseMillis(t) == null) {
            throw new KelException(INVALID, where + ": " + field + " is not an ISO 8601 timestamp");
        }
    }

    /** JS {@code x === n} for a JSON number. */
    private static boolean numberEquals(Object x, long n) {
        return x instanceof Number num && num.doubleValue() == n;
    }

    private static boolean isInteger(Object x) {
        if (!(x instanceof Number num)) return false;
        double d = num.doubleValue();
        return !Double.isInfinite(d) && d == Math.rint(d);
    }

    private static boolean verifySig(Map<String, Object> event, byte[] publicKey) {
        if (!(event.get("sig") instanceof String sig)) return false;
        try {
            byte[] sigBytes = Base64.getUrlDecoder().decode(sig);
            return Signing.verifyBytes(Jcs.canonicalizeToBytes(signingBody(event)), sigBytes, publicKey);
        } catch (Exception e) {
            return false;
        }
    }

    private static String safeDigest(Map<String, Object> event, String where) throws KelException {
        try {
            return eventDigest(event);
        } catch (Exception e) {
            throw new KelException(INVALID, where + ": event cannot be canonicalised (" + e.getMessage() + ")");
        }
    }

    // ── Verification ─────────────────────────────────────────────────────────

    /** {@link #verifyKel(String, List, VerifyOptions)} with default options. */
    public static KelState verifyKel(String did, List<Map<String, Object>> events) throws KelException {
        return verifyKel(did, events, new VerifyOptions());
    }

    /**
     * Replay a KEL and return the identity's current state, exactly as the
     * TypeScript {@code verifyKel}: DID ↔ inception digest, inception
     * self-signature and non-trivial commitment, then for every later event
     * DID/seq/prior chaining and its type's authorisation rule, and finally the
     * controller's seals for agents. Throws {@link KelException} on any failure.
     */
    @SuppressWarnings("unchecked")
    public static KelState verifyKel(String did, List<Map<String, Object>> events, VerifyOptions options)
            throws KelException {
        VerifyOptions opts = options != null ? options : new VerifyOptions();
        if (!isInceptionDid(did)) throw new KelException(INVALID, did + " is not an inception (E-form) DID");
        if (events == null || events.isEmpty()) throw new KelException(INVALID, "empty KEL");

        // ── Inception ──
        Object incRaw = events.get(0);
        if (!(incRaw instanceof Map<?, ?> incMap) || !numberEquals(incMap.get("v"), KEL_VERSION)
                || !"inception".equals(incMap.get("type"))) {
            throw new KelException(INVALID, "event 0 is not a v1 inception event");
        }
        Map<String, Object> inception = (Map<String, Object>) incMap;
        Object kind = inception.get("kind");
        if (!"person".equals(kind) && !"agent".equals(kind)) {
            throw new KelException(INVALID, "inception: kind must be \"person\" or \"agent\"");
        }
        String where0 = "inception";
        Key k0 = singleKey(inception.get("keys"), where0);
        requireDigest(inception.get("nextKeyDigest"), where0, "nextKeyDigest");
        requireTime(inception.get("createdAt"), where0, "createdAt");
        if (inception.containsKey("controller")) {
            if ("person".equals(kind)) throw new KelException(INVALID, "inception: a person has no controller");
            if (!(inception.get("controller") instanceof String c) || !isInceptionDid(c)) {
                throw new KelException(INVALID, "inception: controller must be a person E-DID");
            }
        }

        String incDigest = safeDigest(inception, where0);
        if (!(DID_PREFIX + incDigest).equals(did)) {
            throw new KelException(INVALID, "inception digest does not match " + did
                + " — the inception event was altered or belongs to another DID");
        }
        if (!verifySig(inception, k0.bytes())) {
            throw new KelException(INVALID, "inception: signature does not verify against its own key");
        }
        if (inception.get("nextKeyDigest").equals(keyDigest(k0.bytes()))) {
            throw new KelException(INVALID,
                "inception: next-key commitment equals the current key — pre-rotation would protect nothing");
        }

        KelState state = new KelState();
        state.did = did;
        state.kind = (String) kind;
        state.controller = (String) inception.get("controller");
        state.currentKeys = List.of(k0.multibase());
        state.currentKey = k0.bytes();
        state.nextKeyDigest = (String) inception.get("nextKeyDigest");
        state.lastDigest = incDigest;
        state.digests.add(incDigest);
        state.keyHistory.add(new KeyEstablishment(0, List.of(k0.multibase())));
        state.events.add(inception);

        List<long[]> needsSealSeq = new ArrayList<>();
        List<String> needsSealDigest = new ArrayList<>();

        // ── Subsequent events ──
        for (int i = 1; i < events.size(); i++) {
            Object raw = events.get(i);
            String where = "event " + i;
            if (!(raw instanceof Map<?, ?> rm) || !numberEquals(rm.get("v"), KEL_VERSION)) {
                throw new KelException(INVALID, where + ": not a v1 KEL event");
            }
            Map<String, Object> ev = (Map<String, Object>) rm;
            Object type = ev.get("type");
            if ("inception".equals(type)) throw new KelException(INVALID, where + ": a second inception");
            if (state.revoked) throw new KelException(INVALID, where + ": event after revocation");
            if (!did.equals(ev.get("did"))) {
                throw new KelException(INVALID, where + ": names DID " + ev.get("did") + ", not " + did);
            }
            if (!numberEquals(ev.get("seq"), i)) {
                throw new KelException(INVALID, where + ": seq " + ev.get("seq") + " out of order");
            }
            if (!state.lastDigest.equals(ev.get("prior"))) {
                throw new KelException(INVALID, where + ": prior digest does not chain to event " + (i - 1));
            }
            requireTime(ev.get("at"), where, "at");
            String digest = safeDigest(ev, where);

            if ("rotate".equals(type)) {
                Key k = singleKey(ev.get("keys"), where);
                requireDigest(ev.get("nextKeyDigest"), where, "nextKeyDigest");
                if (!keyDigest(k.bytes()).equals(state.nextKeyDigest)) {
                    throw new KelException(INVALID, where + ": rotation key does not match the pre-rotation commitment");
                }
                if (!verifySig(ev, k.bytes())) {
                    throw new KelException(INVALID, where + ": rotation is not signed by the pre-committed next key");
                }
                if (ev.get("nextKeyDigest").equals(keyDigest(k.bytes()))) {
                    throw new KelException(INVALID, where + ": next-key commitment equals the new current key");
                }
                setKeys(state, k, (String) ev.get("nextKeyDigest"), i);
            } else if ("recover".equals(type)) {
                if (!"agent".equals(state.kind) || state.controller == null) {
                    throw new KelException(INVALID, where + ": recover is only defined for agents with a controller");
                }
                if (!"controller".equals(ev.get("auth"))) {
                    throw new KelException(INVALID, where + ": recover must be controller-authorised");
                }
                if (ev.containsKey("sig")) {
                    throw new KelException(INVALID, where + ": recover carries no signature (it is anchored)");
                }
                Key k = singleKey(ev.get("keys"), where);
                requireDigest(ev.get("nextKeyDigest"), where, "nextKeyDigest");
                if (ev.get("nextKeyDigest").equals(keyDigest(k.bytes()))) {
                    throw new KelException(INVALID, where + ": next-key commitment equals the new current key");
                }
                setKeys(state, k, (String) ev.get("nextKeyDigest"), i);
                needsSealSeq.add(new long[]{i});
                needsSealDigest.add(digest);
            } else if ("revoke".equals(type)) {
                if (ev.containsKey("reason") && !(ev.get("reason") instanceof String)) {
                    throw new KelException(INVALID, where + ": reason must be a string");
                }
                Object auth = ev.get("auth");
                if ("next-key".equals(auth)) {
                    byte[] revealed = decodeKey(ev.get("revealedKey"));
                    if (revealed == null) throw new KelException(INVALID, where + ": revealedKey is not an Ed25519 key");
                    if (!keyDigest(revealed).equals(state.nextKeyDigest)) {
                        throw new KelException(INVALID, where + ": revealed key does not match the pre-rotation commitment");
                    }
                    if (!verifySig(ev, revealed)) {
                        throw new KelException(INVALID, where + ": revocation is not signed by the pre-committed next key");
                    }
                } else if ("controller".equals(auth)) {
                    if (!"agent".equals(state.kind) || state.controller == null) {
                        throw new KelException(INVALID, where + ": controller revocation on an identity with no controller");
                    }
                    if (ev.containsKey("sig")) {
                        throw new KelException(INVALID,
                            where + ": a controller revocation carries no signature (it is anchored)");
                    }
                    needsSealSeq.add(new long[]{i});
                    needsSealDigest.add(digest);
                } else {
                    throw new KelException(INVALID, where + ": unknown revoke auth");
                }
                state.revoked = true;
                state.currentKeys = List.of();
                state.currentKey = null;
                state.nextKeyDigest = null;
            } else if ("anchor".equals(type)) {
                if (!"person".equals(state.kind)) throw new KelException(INVALID, where + ": only persons anchor");
                if (!(ev.get("seals") instanceof List<?> seals)) {
                    throw new KelException(INVALID, where + ": seals must be an array");
                }
                List<Seal> parsed = new ArrayList<>();
                for (Object so : seals) {
                    if (!(so instanceof Map<?, ?> s) || !(s.get("did") instanceof String sdid) || !isInceptionDid(sdid)
                            || !isInteger(s.get("seq")) || ((Number) s.get("seq")).doubleValue() < 1
                            || decodeDigest(s.get("digest")) == null) {
                        throw new KelException(INVALID, where + ": malformed seal");
                    }
                    parsed.add(new Seal(sdid, ((Number) s.get("seq")).longValue(), (String) s.get("digest")));
                }
                if (state.currentKey == null || !verifySig(ev, state.currentKey)) {
                    throw new KelException(INVALID, where + ": anchor is not signed by the current key");
                }
                state.seals.addAll(parsed);
            } else {
                throw new KelException(INVALID, where + ": unknown event type " + type);
            }

            state.sequence = i;
            state.lastDigest = digest;
            state.digests.add(digest);
            state.events.add(ev);
        }

        // ── Controller ──
        if (state.controller != null) {
            boolean needController = !needsSealSeq.isEmpty() || opts.requireController;
            List<Map<String, Object>> controllerEvents = null;
            if (opts.resolveControllerKel != null) {
                try {
                    controllerEvents = opts.resolveControllerKel.fetch(state.controller);
                } catch (KelException e) {
                    if (!CONTROLLER_UNAVAILABLE.equals(e.code())) throw e;
                    controllerEvents = null;
                } catch (Exception e) {
                    controllerEvents = null;
                }
            }
            if (controllerEvents == null || controllerEvents.isEmpty()) {
                if (needController) {
                    throw new KelException(CONTROLLER_UNAVAILABLE, !needsSealSeq.isEmpty()
                        ? did + " has controller-authorised events but the controller " + state.controller
                            + "'s KEL is unavailable"
                        : "controller " + state.controller + "'s KEL is unavailable");
                }
            } else {
                KelState ctl = verifyKel(state.controller, controllerEvents);
                if (!"person".equals(ctl.kind)) {
                    throw new KelException(INVALID, "controller " + state.controller + " is not a person");
                }
                List<Seal> mine = ctl.seals.stream().filter(s -> s.did().equals(did)).toList();
                // Authorisation before comparison: an unanchored "controller"
                // event is junk, not evidence of a fork.
                for (int n = 0; n < needsSealSeq.size(); n++) {
                    long seq = needsSealSeq.get(n)[0];
                    String dg = needsSealDigest.get(n);
                    if (mine.stream().noneMatch(s -> s.seq() == seq && s.digest().equals(dg))) {
                        throw new KelException(INVALID, "event " + seq + " claims controller authority but is not anchored in "
                            + state.controller + "'s KEL");
                    }
                }
                for (Seal seal : mine) {
                    if (seal.seq() > state.sequence) {
                        throw new KelException(STALE, "controller anchored " + did + " event " + seal.seq()
                            + ", but the log provided ends at " + state.sequence);
                    }
                    if (!state.digests.get((int) seal.seq()).equals(seal.digest())) {
                        throw new KelException(DUPLICITY, "controller anchored a different event at " + did
                            + " seq " + seal.seq() + " than the log provided");
                    }
                }
                state.controllerState = ctl;
                state.controllerRevoked = ctl.revoked;
            }
        }
        return state;
    }

    private static void setKeys(KelState state, Key k, String next, int seq) {
        state.currentKeys = List.of(k.multibase());
        state.currentKey = k.bytes();
        state.nextKeyDigest = next;
        state.keyHistory.add(new KeyEstablishment(seq, List.of(k.multibase())));
    }

    // ── Freshness ────────────────────────────────────────────────────────────

    /**
     * Verify {@code events} and reconcile them with what {@code store} has seen
     * (TS {@code acceptKel}): a recorded duplicity alarm refuses the DID; the
     * log must verify before it is compared; a disagreement at any common
     * sequence records duplicity; a shorter log is stale unless
     * {@code useStoredWhenStale}, in which case the stored, longer log answers.
     */
    public static KelState acceptKel(String did, List<Map<String, Object>> events, KelStore store,
                                     VerifyOptions options, boolean useStoredWhenStale) throws KelException {
        DuplicityEvidence alarm = store.getDuplicity(did);
        if (alarm != null) {
            throw new KelException(DUPLICITY, did + " has a recorded duplicity alarm at seq " + alarm.seq()
                + " (since " + alarm.detectedAt() + ")");
        }
        List<Map<String, Object>> stored = store.get(did);
        boolean useStored = useStoredWhenStale && stored != null && !stored.isEmpty();

        KelState state;
        try {
            state = verifyKel(did, events, options);
        } catch (KelException e) {
            if (STALE.equals(e.code()) && useStored && stored.size() > events.size()) {
                return verifyKel(did, stored, options);
            }
            throw e;
        }

        if (stored != null && !stored.isEmpty()) {
            int common = Math.min(stored.size(), state.digests.size());
            for (int i = 0; i < common; i++) {
                String seen = eventDigest(stored.get(i));
                if (!seen.equals(state.digests.get(i))) {
                    store.recordDuplicity(new DuplicityEvidence(did, i, seen, state.digests.get(i), IsoTime.now()));
                    throw new KelException(DUPLICITY, did + ": two different events at seq " + i + " — the log was forked");
                }
            }
            if (state.digests.size() < stored.size()) {
                if (useStored) return verifyKel(did, stored, options);
                throw new KelException(STALE, did + ": offered log ends at seq " + state.sequence
                    + ", but seq " + (stored.size() - 1) + " has already been seen");
            }
        }
        if (stored == null || state.events.size() > stored.size()) store.put(did, state.events);
        return state;
    }

    /**
     * Fetch, verify and (with a store) reconcile the KEL for an E-DID,
     * including its controller's (TS {@code resolveKelState}). Null when
     * {@code did} is not an E-DID or no log is found; throws when a log is
     * found but fails.
     */
    public static KelState resolveKelState(String did, KelSource source, KelStore store, boolean requireController)
            throws KelException {
        if (!isInceptionDid(did)) return null;
        List<Map<String, Object>> events = fetchLog(did, source, store);
        if (events == null) return null;

        KelSource controllerSource = cdid -> {
            List<Map<String, Object>> log = fetchLog(cdid, source, store);
            if (log == null) return null;
            if (store == null) return log;
            return acceptKel(cdid, log, store, new VerifyOptions(), true).events;
        };
        VerifyOptions vo = new VerifyOptions().resolveControllerKel(controllerSource).requireController(requireController);
        return store != null ? acceptKel(did, events, store, vo, true) : verifyKel(did, events, vo);
    }

    private static List<Map<String, Object>> fetchLog(String did, KelSource source, KelStore store) {
        List<Map<String, Object>> log;
        try {
            log = source.fetch(did);
        } catch (Exception e) {
            log = null;
        }
        if ((log == null || log.isEmpty()) && store != null) log = store.get(did);
        return log != null && !log.isEmpty() ? log : null;
    }

    /** A {@link KelSource} over logs already held, indexed by the DID each inception hashes to. */
    @SafeVarargs
    public static KelSource sourceFromLogs(List<Map<String, Object>>... logs) {
        Map<String, List<Map<String, Object>>> byDid = new HashMap<>();
        for (List<Map<String, Object>> log : logs) {
            if (log == null || log.isEmpty() || !"inception".equals(log.get(0).get("type"))) continue;
            String d;
            try {
                d = didFromInception(log.get(0));
            } catch (Exception e) {
                continue;
            }
            List<Map<String, Object>> existing = byDid.get(d);
            if (existing == null || log.size() > existing.size()) byDid.put(d, log);
        }
        return byDid::get;
    }

    /** Raw 32-byte key of a {@code z…} multibase string (helper for callers comparing keys). */
    public static byte[] keyBytes(String multibase) {
        byte[] b = decodeKey(multibase);
        return b == null ? null : Arrays.copyOf(b, b.length);
    }
}
