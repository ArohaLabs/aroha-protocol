// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

package com.arohalabs.conversation;

import com.arohalabs.TestSupport;
import com.arohalabs.conversation.Conversation.KeyResolver;
import com.arohalabs.conversation.Conversation.Verification;
import com.arohalabs.crypto.Signing;
import com.arohalabs.identity.DID;
import com.arohalabs.identity.Kel;
import com.arohalabs.messages.ArohaEnvelope;
import com.arohalabs.messages.Disclosure;
import com.arohalabs.messages.NonceRegistry;
import com.arohalabs.util.IsoTime;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.*;

import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * spec-public/vectors/conversation-v1.json — the file the TypeScript and
 * Python verifiers also read: every signing payload byte for byte, every
 * valid object accepted, every invalid one refused.
 */
class ConversationVectorsTest {

    static Map<String, Object> V;
    static KeyResolver resolve;

    @BeforeAll
    static void load() throws Exception {
        Path p = TestSupport.repoFile("spec-public/vectors/conversation-v1.json");
        assumeTrue(TestSupport.exists(p), "conversation-v1.json not found (outside the monorepo)");
        V = TestSupport.readJson(p);
        Map<String, Object> kels = map(V.get("kels"));
        resolve = Conversation.kelResolverWithContentAddressedAgents(did -> list(kels.get(did)));
    }

    @SuppressWarnings("unchecked")
    static Map<String, Object> map(Object o) { return (Map<String, Object>) o; }

    @SuppressWarnings("unchecked")
    static List<Map<String, Object>> list(Object o) { return (List<Map<String, Object>>) o; }

    static String text(byte[] b) { return new String(b, StandardCharsets.UTF_8); }

    @Test
    void disclosureIsValid() {
        assertNull(Disclosure.validate(map(V.get("disclosure")).get("value")));
    }

    @Test
    void room() {
        Map<String, Object> room = map(map(V.get("room")).get("value"));
        assertEquals(map(V.get("room")).get("expectedSigningPayload"), text(Conversation.signingBytes(room)));
        Verification ok = Conversation.verifyRoom(room, resolve);
        assertTrue(ok.ok(), ok.reason());
        assertEquals("person", ok.kind());
        for (Map<String, Object> bad : list(map(V.get("room")).get("invalid"))) {
            assertFalse(Conversation.verifyRoom(bad.get("value"), resolve).ok(), (String) bad.get("name"));
        }
    }

    @Test
    void consent() {
        Map<String, Object> room = map(map(V.get("room")).get("value"));
        Map<String, Object> consent = map(V.get("consent"));
        for (String k : List.of("given", "withdrawn")) {
            Map<String, Object> c = map(consent.get(k));
            Map<String, Object> value = map(c.get("value"));
            List<?> expected = (List<?>) c.get("expectedEventSigningPayloads");
            for (int i = 0; i < expected.size(); i++) {
                assertEquals(expected.get(i), text(Conversation.consentEventSigningBytes(value, i)), k + " event " + i);
            }
            Verification r = Conversation.verifyConsent(value, resolve, room);
            assertTrue(r.ok(), k + ": " + r.reason());
            List<String> eff = new ArrayList<>(Conversation.effectiveConsent(value));
            Collections.sort(eff);
            assertEquals(c.get("effectivePurposes"), eff, k);
        }
        // A non-subject (withdrawal) event cannot be checked without the room.
        assertFalse(Conversation.verifyConsent(map(consent.get("withdrawn")).get("value"), resolve).ok());
        for (Map<String, Object> bad : list(consent.get("invalid"))) {
            assertFalse(Conversation.verifyConsent(bad.get("value"), resolve, room).ok(), (String) bad.get("name"));
        }
    }

    @Test
    void turnAndSpeakerKind() {
        Map<String, Object> room = map(map(V.get("room")).get("value"));
        Map<String, Object> t = map(V.get("turn"));
        Map<String, Object> turn = map(t.get("value"));
        assertEquals(t.get("expectedContentHash"), Conversation.turnContentHash((String) turn.get("content")));
        assertEquals(t.get("expectedSigningPayload"), text(Conversation.turnSigningBytes(turn)));
        Verification r = Conversation.verifyTurn(turn, resolve, room);
        assertTrue(r.ok(), r.reason());
        assertEquals(t.get("expectedSpeakerKind"), r.kind());
        for (Map<String, Object> bad : list(t.get("invalid"))) {
            assertFalse(Conversation.verifyTurn(bad.get("value"), resolve, room).ok(), (String) bad.get("name"));
        }
    }

    @Test
    void receipts() {
        Map<String, Object> rc = map(V.get("receipts"));
        for (String k : List.of("v1", "v2Executed", "v2Denied")) {
            Map<String, Object> r = map(rc.get(k));
            assertEquals(r.get("expectedSigningPayload"), text(Conversation.signingBytes(map(r.get("value")))), k);
            ActionReceipts.ReceiptVerification res = ActionReceipts.verify(r.get("value"), ActionReceipts::contentAddressedKey);
            assertTrue(res.ok(), k + ": " + res.reason());
        }
        Map<String, Object> v2 = map(rc.get("v2Executed"));
        assertEquals(v2.get("expectedPresentedHash"), ActionReceipts.hashPresentedContent(v2.get("presentedContent")));
        assertNull(ActionReceipts.verifyPresentedHash(map(v2.get("value")), v2.get("presentedContent")));
        assertNotNull(ActionReceipts.verifyPresentedHash(map(v2.get("value")), v2.get("mismatchedPresentedContent")));
        for (Map<String, Object> bad : list(rc.get("invalid"))) {
            assertFalse(ActionReceipts.verify(bad.get("value"), ActionReceipts::contentAddressedKey).ok(), (String) bad.get("name"));
        }
    }

    @Test
    void envelopeWithDisclosureVerifiesUnderTheEnvelopeRule() {
        Map<String, Object> e = map(V.get("envelopeWithDisclosure"));
        Map<String, Object> env = map(e.get("value"));
        assertEquals(e.get("expectedSigningPayload"), text(Signing.canonicalize(env)));
        String from = (String) env.get("from");
        assertNull(Disclosure.validate(env.get("disclosure"), from));
        assertNotNull(Disclosure.validate(env.get("disclosure"), "did:aroha:zSomeoneElse"));
        var key = new Ed25519PublicKeyParameters(DID.fromMultibase(from.substring("did:aroha:".length())), 0);
        long now = IsoTime.parseMillis(env.get("created")) + 1000;
        // The vector is historical. "now" is pinned for the time checks, but
        // NonceRegistry keeps a nonce only while expires + tolerance is in the
        // REAL future, so the tolerance stretches retention past today.
        long retention = Math.max(0, System.currentTimeMillis() - IsoTime.parseMillis(env.get("expires"))) + 86_400_000L;
        var result = ArohaEnvelope.validate(new LinkedHashMap<>(env), key, (String) env.get("to"), new NonceRegistry(),
            new ArohaEnvelope.ValidateOptions().nowMs(now).clockToleranceMs(retention).maxFutureSkewMs(30_000));
        assertTrue(result.valid(), result.reason());
    }

    @Test
    void speakerKindComesFromTheKelNotTheMessage() throws Exception {
        Map<String, Object> keys = map(V.get("keys"));
        String host = (String) map(keys.get("host")).get("did");
        String agent = (String) map(keys.get("agent")).get("did");
        assertEquals("person", resolve.resolve(host).kind());
        assertEquals("agent", resolve.resolve(agent).kind());
        assertNull(resolve.resolve("did:aroha:Eunknown"));
        // The KEL-only resolver does not resolve content-addressed DIDs at all.
        Map<String, Object> kels = map(V.get("kels"));
        assertNull(Conversation.kelResolver(did -> list(kels.get(did))).resolve(agent));
        assertEquals("agent", Conversation.resolveSpeakerKind(null));
        // A room whose owner cannot be resolved is refused even though its signature is good.
        Kel.KelSource none = did -> null;
        assertFalse(Conversation.verifyRoom(map(map(V.get("room")).get("value")), Conversation.kelResolver(none)).ok());
    }
}
