// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

package com.arohalabs.conversation;

import com.arohalabs.crypto.Jcs;
import com.arohalabs.crypto.Signing;
import com.arohalabs.identity.DID;
import com.arohalabs.identity.Kel;
import com.arohalabs.messages.Disclosure;
import com.arohalabs.util.IsoTime;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.*;
import java.util.regex.Pattern;

/**
 * Conversation and Memory Profile verifiers (spec aroha-1.0 §12): signed
 * rooms, hash-chained consent records and authored turns. Port of the
 * verification side of {@code packages/aroha-core/src/conversation/}; held
 * to the shared vectors in {@code spec-public/vectors/conversation-v1.json}.
 *
 * <p>Every signature is Ed25519 (base64url, no padding) over the UTF-8 bytes
 * of the RFC 8785 JCS form of:
 * <ul>
 *   <li>a room — the record minus {@code signature} (purpose {@code aroha.room/v1}),
 *       by the owner's PERSON key;</li>
 *   <li>a consent event — {@link #consentEventSigningBytes}: the record's
 *       identity and terms, the event's index, the previous event's hash
 *       and the event minus {@code sig} (purpose {@code aroha.consent-event/v1}),
 *       by that event's actor;</li>
 *   <li>a turn — {@link #turnSigningBytes} (purpose {@code aroha.turn/v1}),
 *       by the author.</li>
 * </ul>
 *
 * <p>Verification only: issuing belongs to the runtime. Objects are the raw
 * decoded JSON ({@code Map}/{@code List}/{@code String}/{@code Number}/
 * {@code Boolean}) as Jackson reads them into {@code Object}. A signer's kind
 * ("person" / "agent") always comes from the {@link KeyResolver} — from a
 * Key Event Log — never from the object being verified.
 */
public final class Conversation {

    private Conversation() {}

    public static final String ROOM_PURPOSE = "aroha.room/v1";
    public static final String CONSENT_PURPOSE = "aroha.consent/v1";
    public static final String CONSENT_EVENT_PURPOSE = "aroha.consent-event/v1";
    public static final String TURN_PURPOSE = "aroha.turn/v1";

    public static final List<String> CONSENT_PURPOSES =
        List.of("transcript_retention", "agent_use_of_messages", "memory_write", "provider_processing");

    private static final Pattern SHA256_HEX = Pattern.compile("^[0-9a-f]{64}$");

    // ── Types ─────────────────────────────────────────────────────────────────

    /** A DID's current key (32 raw bytes) and its kind, "person" or "agent". */
    public record ResolvedSigner(byte[] publicKey, String kind) {}

    /** Resolves a DID's current key and kind; null when it cannot be resolved. A throw counts as null. */
    @FunctionalInterface
    public interface KeyResolver {
        ResolvedSigner resolve(String did) throws Exception;
    }

    /** Verdict: {@code ok} with the verified object and its signer, or a reason. */
    public record Verification(boolean ok, Map<String, Object> value, ResolvedSigner signer, String reason) {
        static Verification fail(String reason) { return new Verification(false, null, null, reason); }
        static Verification pass(Map<String, Object> value, ResolvedSigner signer) {
            return new Verification(true, value, signer, null);
        }
        /** The signer's kind when ok (for a turn: the speaker kind), else null. */
        public String kind() { return signer == null ? null : signer.kind(); }
    }

    // ── Resolvers ────────────────────────────────────────────────────────────

    /**
     * Speaker-kind rule: the kind in the DID's verified KEL inception;
     * anything unresolvable that way is an "agent" — the unproven case gets
     * the lesser authority, never the greater.
     */
    public static String resolveSpeakerKind(String kelKind) {
        return "person".equals(kelKind) ? "person" : "agent";
    }

    /**
     * A resolver backed by Key Event Logs: verifies the DID's KEL and returns
     * its current key and kind. A DID without a verifiable, unrevoked KEL
     * (or whose controller has revoked itself) resolves to null.
     */
    public static KeyResolver kelResolver(Kel.KelSource source) {
        return did -> {
            List<Map<String, Object>> events = source.fetch(did);
            if (events == null || events.isEmpty()) return null;
            Kel.KelState state;
            try {
                state = Kel.verifyKel(did, events);
            } catch (Kel.KelException e) {
                return null;
            }
            if (state.revoked || state.controllerRevoked || state.currentKey == null) return null;
            return new ResolvedSigner(state.currentKey, resolveSpeakerKind(state.kind));
        };
    }

    /**
     * {@link #kelResolver} that also resolves content-addressed
     * {@code did:aroha:z…} DIDs from the DID itself — always as "agent", since
     * no KEL proves them a person.
     */
    public static KeyResolver kelResolverWithContentAddressedAgents(Kel.KelSource source) {
        KeyResolver kel = kelResolver(source);
        return did -> {
            if (did != null && did.startsWith("did:aroha:z")) {
                byte[] key = DID.fromMultibase(did.substring("did:aroha:".length()));
                return key.length == 32 ? new ResolvedSigner(key, "agent") : null;
            }
            return kel.resolve(did);
        };
    }

    // ── Shared helpers ───────────────────────────────────────────────────────

    /** JCS bytes of an object with its {@code signature} field removed (rooms, receipts). */
    public static byte[] signingBytes(Map<String, Object> obj) {
        Map<String, Object> rest = new LinkedHashMap<>(obj);
        rest.remove("signature");
        return Jcs.canonicalizeToBytes(rest);
    }

    static boolean verifySig(Object sigB64, byte[] message, byte[] publicKey) {
        if (!(sigB64 instanceof String s) || publicKey == null || publicKey.length != 32) return false;
        try {
            byte[] sig = Base64.getUrlDecoder().decode(s);
            return sig.length == 64 && Signing.verifyBytes(message, sig, publicKey);
        } catch (Exception e) {
            return false;
        }
    }

    private static ResolvedSigner resolve(KeyResolver resolver, String did) {
        try {
            ResolvedSigner s = resolver.resolve(did);
            return s == null || s.publicKey() == null ? null : s;
        } catch (Exception e) {
            return null;
        }
    }

    static boolean isNonEmpty(Object x) {
        return x instanceof String s && !s.isEmpty();
    }

    static boolean isDid(Object x) {
        return x instanceof String s && !s.isEmpty() && s.startsWith("did:");
    }

    /** JavaScript {@code Number.isInteger(x) && x >= 0}. */
    static boolean isEpoch(Object x) {
        if (!(x instanceof Number n)) return false;
        double d = n.doubleValue();
        return Double.isFinite(d) && d == Math.floor(d) && d >= 0;
    }

    static boolean isIso(Object x) {
        return IsoTime.parseMillis(x) != null;
    }

    static long epochOf(Object x) {
        return ((Number) x).longValue();
    }

    static String unknownField(Map<?, ?> obj, Set<String> known) {
        for (Object k : obj.keySet()) if (!known.contains(k)) return String.valueOf(k);
        return null;
    }

    static String sha256Hex(byte[] bytes) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    @SuppressWarnings("unchecked")
    static Map<String, Object> asMap(Object o) {
        return (Map<String, Object>) o;
    }

    // ── Room ─────────────────────────────────────────────────────────────────

    private static final Set<String> ROOM_FIELDS = Set.of("v", "purpose", "roomId", "threadId", "ownerDid", "epoch",
        "members", "historyVisibility", "invocation", "memoryPolicy", "disclosure", "updatedAt", "signature");
    private static final Set<String> MEMBER_FIELDS =
        Set.of("did", "kind", "principalId", "displayName", "role", "joinedEpoch", "leftEpoch", "consentRef");
    private static final Set<String> MEMORY_POLICY_FIELDS = Set.of("personalRead", "personalWrite", "roomMemory", "agentRead");
    private static final Set<String> ROLES = Set.of("host", "guest", "own", "invited", "delegated");

    /** Structural rules for a room record (TS {@code checkRoomShape}). Null when well-formed. */
    public static String checkRoomShape(Object value, boolean requireSignature) {
        if (!(value instanceof Map<?, ?> r)) return "room is not an object";
        if (!(r.get("v") instanceof Number v && v.doubleValue() == 1) || !ROOM_PURPOSE.equals(r.get("purpose"))) {
            return "not an aroha.room/v1 record";
        }
        String extra = unknownField(r, ROOM_FIELDS);
        if (extra != null) return "unknown field \"" + extra + "\"";
        for (String k : List.of("roomId", "threadId")) if (!isNonEmpty(r.get(k))) return k + " must be a non-empty string";
        if (!isDid(r.get("ownerDid"))) return "ownerDid must be a DID";
        if (!isEpoch(r.get("epoch"))) return "epoch must be a non-negative integer";
        Object hv = r.get("historyVisibility");
        if (!"joined".equals(hv) && !"shared".equals(hv)) return "historyVisibility is invalid";
        Object inv = r.get("invocation");
        if (!"explicit".equals(inv) && !"implicit".equals(inv)) return "invocation is invalid";
        if (!isIso(r.get("updatedAt"))) return "updatedAt must be an ISO 8601 date";
        if (!(r.get("memoryPolicy") instanceof Map<?, ?> mp)) return "memoryPolicy must be an object";
        if (unknownField(mp, MEMORY_POLICY_FIELDS) != null) return "memoryPolicy has an unknown field";
        if (!(mp.get("personalRead") instanceof Boolean) || !(mp.get("personalWrite") instanceof Boolean)) {
            return "memoryPolicy.personalRead/personalWrite must be booleans";
        }
        Object rm = mp.get("roomMemory");
        if (!"off".equals(rm) && !"consented".equals(rm)) return "memoryPolicy.roomMemory is invalid";
        if (mp.containsKey("agentRead") && !"none".equals(mp.get("agentRead")) && !"members".equals(mp.get("agentRead"))) {
            return "memoryPolicy.agentRead is invalid";
        }
        String d = Disclosure.validate(r.get("disclosure"));
        if (d != null) return "disclosure: " + d;
        if (!(r.get("members") instanceof List<?> members) || members.isEmpty()) return "members must be a non-empty array";
        long epoch = epochOf(r.get("epoch"));
        Set<Object> seen = new HashSet<>();
        int hosts = 0;
        for (int i = 0; i < members.size(); i++) {
            String where = "members[" + i + "]";
            if (!(members.get(i) instanceof Map<?, ?> m)) return where + " is not an object";
            String mx = unknownField(m, MEMBER_FIELDS);
            if (mx != null) return where + " has unknown field \"" + mx + "\"";
            if (!isDid(m.get("did"))) return where + ".did must be a DID";
            if (!seen.add(m.get("did"))) return where + ".did appears twice";
            Object kind = m.get("kind");
            if (!"person".equals(kind) && !"agent".equals(kind)) return where + ".kind is invalid";
            if (!(m.get("role") instanceof String role) || !ROLES.contains(role)) return where + ".role is invalid";
            if (!(m.get("displayName") instanceof String)) return where + ".displayName must be a string";
            if (m.containsKey("principalId") && !isNonEmpty(m.get("principalId"))) {
                return where + ".principalId must be a non-empty string";
            }
            if (!isEpoch(m.get("joinedEpoch")) || epochOf(m.get("joinedEpoch")) > epoch) {
                return where + ".joinedEpoch must be an integer ≤ epoch";
            }
            long joined = epochOf(m.get("joinedEpoch"));
            if (m.containsKey("leftEpoch")) {
                Object le = m.get("leftEpoch");
                if (!isEpoch(le) || epochOf(le) <= joined || epochOf(le) > epoch) {
                    return where + ".leftEpoch must be an integer in (joinedEpoch, epoch]";
                }
            }
            if (m.containsKey("consentRef") && !isNonEmpty(m.get("consentRef"))) {
                return where + ".consentRef must be a non-empty string";
            }
            if (role.equals("guest") && "person".equals(kind) && !m.containsKey("consentRef")) {
                return where + ": a person guest requires a consentRef";
            }
            if (role.equals("host")) {
                hosts++;
                if (!Objects.equals(m.get("did"), r.get("ownerDid")) || !"person".equals(kind)) {
                    return where + ": the host must be the owner, a person";
                }
            }
        }
        if (hosts != 1) return "exactly one member must have role host";
        if (requireSignature && !isNonEmpty(r.get("signature"))) return "signature is missing";
        return null;
    }

    /**
     * Verify a room record: shape, the owner resolves to a PERSON, and the
     * signature is by the owner's current key. A room signed by an agent key
     * is refused — a room is the host person's statement of who may speak.
     */
    public static Verification verifyRoom(Object room, KeyResolver resolver) {
        String problem = checkRoomShape(room, true);
        if (problem != null) return Verification.fail("malformed room: " + problem);
        Map<String, Object> r = asMap(room);
        String owner = (String) r.get("ownerDid");
        ResolvedSigner signer = resolve(resolver, owner);
        if (signer == null) return Verification.fail("room owner " + owner + " has no resolvable key");
        if (!"person".equals(signer.kind())) return Verification.fail("room owner " + owner + " is not a person");
        if (!verifySig(r.get("signature"), signingBytes(r), signer.publicKey())) {
            return Verification.fail("room signature does not verify");
        }
        return Verification.pass(r, signer);
    }

    /** Members at {@code epoch}: {@code joinedEpoch <= epoch < leftEpoch}. Call on a well-formed room. */
    public static List<Map<String, Object>> roomMembersAt(Map<String, Object> room, long epoch) {
        List<Map<String, Object>> out = new ArrayList<>();
        for (Object o : (List<?>) room.get("members")) {
            Map<String, Object> m = asMap(o);
            boolean joined = epochOf(m.get("joinedEpoch")) <= epoch;
            boolean notLeft = !m.containsKey("leftEpoch") || epoch < epochOf(m.get("leftEpoch"));
            if (joined && notLeft) out.add(m);
        }
        return out;
    }

    private static boolean isMemberAt(Map<String, Object> room, long epoch, Object did) {
        for (Map<String, Object> m : roomMembersAt(room, epoch)) if (Objects.equals(m.get("did"), did)) return true;
        return false;
    }

    // ── Consent ──────────────────────────────────────────────────────────────

    private static final Set<String> CONSENT_FIELDS =
        Set.of("v", "purpose", "recordId", "subjectDid", "roomId", "purposes", "withdrawalRoute", "events");
    private static final Set<String> EVENT_FIELDS = Set.of("event", "purposes", "at", "actorDid", "epoch", "sig");

    private static boolean isPurposeList(Object x) {
        if (!(x instanceof List<?> l) || l.isEmpty()) return false;
        Set<Object> seen = new HashSet<>();
        for (Object p : l) {
            if (!(p instanceof String s) || !CONSENT_PURPOSES.contains(s) || !seen.add(s)) return false;
        }
        return true;
    }

    /** SHA-256 hex of JCS of a whole event (sig included) — the next event's prevHash. */
    public static String consentEventHash(Map<String, Object> event) {
        return sha256Hex(Jcs.canonicalizeToBytes(event));
    }

    /**
     * The exact bytes event {@code index} of a record is signed over: binds
     * the event to the record's identity and terms, its position and the
     * previous event's hash.
     */
    public static byte[] consentEventSigningBytes(Map<String, Object> record, int index) {
        List<?> events = (List<?>) record.get("events");
        Map<String, Object> entry = new LinkedHashMap<>(asMap(events.get(index)));
        entry.remove("sig");
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("purpose", CONSENT_EVENT_PURPOSE);
        payload.put("recordId", record.get("recordId"));
        payload.put("subjectDid", record.get("subjectDid"));
        payload.put("roomId", record.get("roomId"));
        payload.put("purposes", record.get("purposes"));
        payload.put("withdrawalRoute", record.get("withdrawalRoute"));
        payload.put("index", index);
        payload.put("prevHash", index == 0 ? null : consentEventHash(asMap(events.get(index - 1))));
        payload.put("entry", entry);
        return Jcs.canonicalizeToBytes(payload);
    }

    /** Structural and event-order rules for a consent record (signatures not checked). */
    public static String checkConsentShape(Object value) {
        if (!(value instanceof Map<?, ?> c)) return "consent record is not an object";
        if (!(c.get("v") instanceof Number v && v.doubleValue() == 1) || !CONSENT_PURPOSE.equals(c.get("purpose"))) {
            return "not an aroha.consent/v1 record";
        }
        String extra = unknownField(c, CONSENT_FIELDS);
        if (extra != null) return "unknown field \"" + extra + "\"";
        if (!isNonEmpty(c.get("recordId")) || !isNonEmpty(c.get("roomId"))) return "recordId and roomId must be non-empty strings";
        if (!isDid(c.get("subjectDid"))) return "subjectDid must be a DID";
        if (!isPurposeList(c.get("purposes"))) return "purposes must be a non-empty list of known purposes without repeats";
        if (!isNonEmpty(c.get("withdrawalRoute"))) return "withdrawalRoute must be a non-empty string";
        if (!(c.get("events") instanceof List<?> events) || events.isEmpty()) return "events must be a non-empty array";
        List<?> recordPurposes = (List<?>) c.get("purposes");
        long last = Long.MIN_VALUE;
        long lastEpoch = -1;
        for (int i = 0; i < events.size(); i++) {
            String where = "events[" + i + "]";
            if (!(events.get(i) instanceof Map<?, ?> e)) return where + " is not an object";
            String ex = unknownField(e, EVENT_FIELDS);
            if (ex != null) return where + " has unknown field \"" + ex + "\"";
            Object ev = e.get("event");
            if (!"given".equals(ev) && !"withdrawn".equals(ev)) return where + ".event is invalid";
            if (!isPurposeList(e.get("purposes"))) return where + ".purposes is invalid";
            for (Object p : (List<?>) e.get("purposes")) {
                if (!recordPurposes.contains(p)) return where + " names a purpose the record does not ask about";
            }
            if (!isIso(e.get("at"))) return where + ".at must be an ISO 8601 date";
            long t = IsoTime.parseMillis(e.get("at"));
            if (t < last) return where + " is earlier than the event before it";
            last = t;
            if (!isEpoch(e.get("epoch")) || epochOf(e.get("epoch")) < lastEpoch) {
                return where + ".epoch must be a non-negative integer, not decreasing";
            }
            lastEpoch = epochOf(e.get("epoch"));
            if (!isDid(e.get("actorDid"))) return where + ".actorDid must be a DID";
            if (!isNonEmpty(e.get("sig"))) return where + ".sig is missing";
            // Only the subject can GIVE consent; a room member may withdraw it.
            if ("given".equals(ev) && !Objects.equals(e.get("actorDid"), c.get("subjectDid"))) {
                return where + ": only the subject can give consent";
            }
        }
        if (!"given".equals(((Map<?, ?>) events.get(0)).get("event"))) return "the first event must be \"given\"";
        return null;
    }

    /** {@link #verifyConsent(Object, KeyResolver, Map)} without a room record. */
    public static Verification verifyConsent(Object record, KeyResolver resolver) {
        return verifyConsent(record, resolver, null);
    }

    /**
     * Verify a consent record: shape, then EVERY event's signature against
     * its own actor's key (each actor must resolve to a person). When an
     * event's actor is not the subject, {@code room} is REQUIRED and that
     * actor must have been a member at the event's epoch. A verified record's
     * {@code signer} is the subject.
     */
    public static Verification verifyConsent(Object record, KeyResolver resolver, Map<String, Object> room) {
        String problem = checkConsentShape(record);
        if (problem != null) return Verification.fail("malformed consent record: " + problem);
        Map<String, Object> c = asMap(record);
        if (room != null && !Objects.equals(room.get("roomId"), c.get("roomId"))) {
            return Verification.fail("consent record is for a different room");
        }
        ResolvedSigner subjectSigner = null;
        List<?> events = (List<?>) c.get("events");
        for (int i = 0; i < events.size(); i++) {
            Map<String, Object> e = asMap(events.get(i));
            String actor = (String) e.get("actorDid");
            long ep = epochOf(e.get("epoch"));
            if (!actor.equals(c.get("subjectDid"))) {
                if (room == null) {
                    return Verification.fail("events[" + i + "] is by " + actor
                        + ", not the subject; the room record is required to check membership");
                }
                if (!(room.get("epoch") instanceof Number re) || ep > re.longValue() || !isMemberAt(room, ep, actor)) {
                    return Verification.fail("events[" + i + "]: " + actor + " was not a room member at epoch " + ep);
                }
            }
            ResolvedSigner signer = resolve(resolver, actor);
            if (signer == null) return Verification.fail("events[" + i + "]: actor " + actor + " has no resolvable key");
            if (!"person".equals(signer.kind())) return Verification.fail("events[" + i + "]: actor " + actor + " is not a person");
            if (!verifySig(e.get("sig"), consentEventSigningBytes(c, i), signer.publicKey())) {
                return Verification.fail("events[" + i + "]: signature does not verify");
            }
            if (actor.equals(c.get("subjectDid"))) subjectSigner = signer;
        }
        return Verification.pass(c, subjectSigner);
    }

    /** Purposes currently granted: given minus later withdrawn, replayed in order. Call on a VERIFIED record. */
    public static Set<String> effectiveConsent(Map<String, Object> record) {
        Set<String> granted = new LinkedHashSet<>();
        for (Object o : (List<?>) record.get("events")) {
            Map<String, Object> e = asMap(o);
            for (Object p : (List<?>) e.get("purposes")) {
                if ("given".equals(e.get("event"))) granted.add((String) p);
                else granted.remove(p);
            }
        }
        return granted;
    }

    // ── Turns ────────────────────────────────────────────────────────────────

    private static final Set<String> TURN_FIELDS = Set.of("threadId", "roomId", "epoch", "at", "contentHash",
        "addressedTo", "authorDid", "content", "authorSignature");

    /** SHA-256 hex of the UTF-8 bytes of a turn's content. */
    public static String turnContentHash(String content) {
        return sha256Hex(content.getBytes(StandardCharsets.UTF_8));
    }

    /** The exact bytes a turn signature covers (purpose {@code aroha.turn/v1}). */
    public static byte[] turnSigningBytes(Map<String, Object> turn) {
        Map<String, Object> p = new LinkedHashMap<>();
        p.put("purpose", TURN_PURPOSE);
        p.put("threadId", turn.get("threadId"));
        p.put("roomId", turn.get("roomId"));
        p.put("epoch", turn.get("epoch"));
        p.put("at", turn.get("at"));
        p.put("contentHash", turn.get("contentHash"));
        p.put("addressedTo", turn.get("addressedTo"));
        return Jcs.canonicalizeToBytes(p);
    }

    static String checkTurnShape(Object value) {
        if (!(value instanceof Map<?, ?> t)) return "turn is not an object";
        String extra = unknownField(t, TURN_FIELDS);
        if (extra != null) return "unknown field \"" + extra + "\"";
        if (!isNonEmpty(t.get("threadId")) || !isNonEmpty(t.get("roomId"))) return "threadId and roomId must be non-empty strings";
        if (!isEpoch(t.get("epoch"))) return "epoch must be a non-negative integer";
        if (!isIso(t.get("at"))) return "at must be an ISO 8601 date";
        if (!(t.get("contentHash") instanceof String h) || !SHA256_HEX.matcher(h).matches()) return "contentHash must be SHA-256 hex";
        if (!(t.get("addressedTo") instanceof List<?> to) || !to.stream().allMatch(Conversation::isDid)) {
            return "addressedTo must be an array of DIDs";
        }
        if (!isDid(t.get("authorDid"))) return "authorDid must be a DID";
        if (!(t.get("content") instanceof String)) return "content must be a string";
        if (!isNonEmpty(t.get("authorSignature"))) return "authorSignature is missing";
        return null;
    }

    /** {@link #verifyTurn(Object, KeyResolver, Map)} without a room record. */
    public static Verification verifyTurn(Object turn, KeyResolver resolver) {
        return verifyTurn(turn, resolver, null);
    }

    /**
     * Verify an authored turn: shape, contentHash matches content, the
     * signature is by the author's current key, and (with {@code room}) the
     * author was a member at the turn's epoch. The result's {@link
     * Verification#kind()} is the speaker kind — from the resolver, never
     * from the turn.
     */
    public static Verification verifyTurn(Object turn, KeyResolver resolver, Map<String, Object> room) {
        String problem = checkTurnShape(turn);
        if (problem != null) return Verification.fail("malformed turn: " + problem);
        Map<String, Object> t = asMap(turn);
        if (!turnContentHash((String) t.get("content")).equals(t.get("contentHash"))) {
            return Verification.fail("turn content does not match contentHash");
        }
        if (room != null) {
            if (!Objects.equals(room.get("roomId"), t.get("roomId")) || !Objects.equals(room.get("threadId"), t.get("threadId"))) {
                return Verification.fail("turn is for a different room or thread");
            }
            long ep = epochOf(t.get("epoch"));
            if (!isMemberAt(room, ep, t.get("authorDid"))) {
                return Verification.fail(t.get("authorDid") + " was not a room member at epoch " + ep);
            }
        }
        ResolvedSigner signer = resolve(resolver, (String) t.get("authorDid"));
        if (signer == null) return Verification.fail("turn author " + t.get("authorDid") + " has no resolvable key");
        if (!verifySig(t.get("authorSignature"), turnSigningBytes(t), signer.publicKey())) {
            return Verification.fail("turn signature does not verify");
        }
        return Verification.pass(t, signer);
    }
}
