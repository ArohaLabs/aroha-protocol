// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

package com.arohalabs.identity;

import com.arohalabs.TestSupport;
import com.arohalabs.crypto.Jcs;
import com.arohalabs.identity.KelFixtures.Identity;
import com.arohalabs.mandate.ArohaMandateCredential;
import com.arohalabs.mandate.ArohaMandateCredential.SpendingConstraints;
import com.arohalabs.mandate.ArohaMandateCredential.VerifyOptions;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.*;

import static com.arohalabs.TestSupport.seed;
import static org.junit.jupiter.api.Assertions.*;

/** Mirrors L0-KEL-01..06 in packages/aroha-core/src/conformance/l0-kel-identity.conformance.test.ts. */
class KelTest {

    static final String NOW = "2026-10-07T00:00:00.000Z";

    static Kel.KelException kelError(org.junit.jupiter.api.function.Executable e) {
        return assertThrows(Kel.KelException.class, e);
    }

    @Test
    void l0Kel01PinnedFixedSeedVector() throws Exception {
        Identity id = KelFixtures.incept("person", null, seed(1), seed(2), NOW);
        Map<String, Object> body = new LinkedHashMap<>(id.kel.get(0));
        Object sig = body.remove("sig");
        assertEquals("{\"createdAt\":\"2026-10-07T00:00:00.000Z\",\"keys\":[\"zAKnL4NNf3DGWZJS6cPknBuEGnVsV4A4m5tgebLHaRSZ9\"],"
            + "\"kind\":\"person\",\"nextKeyDigest\":\"E89dkqqjMw9HTi1pqHbANSNwioHuMhmpTCXapTmfUr1EW\",\"type\":\"inception\",\"v\":1}",
            Jcs.canonicalize(body));
        assertEquals("did:aroha:EFLYfS6RfFTTMNdhSybB52jJ4KCTLsNXC4ZuBECvceFKZ", id.did);
        assertEquals("a-jO6pXYXMBFY3nEhbzzz20MlJ81pxy17L42BgphDMw8ogNyKOeLD_Rg5yMhtv22Rf6kt8d4kpW0VWrdt3TjCw", sig);

        Identity rotated = KelFixtures.rotate(id, seed(3), NOW);
        assertEquals("ED3cVEYDPescYcT6jaD4swqCa3PyGvTDUxhhahnYVFTrr", Kel.eventDigest(rotated.kel.get(1)));

        Kel.KelState st = Kel.verifyKel(id.did, rotated.kel);
        assertArrayEquals(TestSupport.pub(seed(2)), st.currentKey);
        assertEquals(1, st.sequence);
        assertEquals(2, st.keyHistory.size());
    }

    @Test
    void l0Kel02InceptionOnlyLogVerifies() throws Exception {
        Identity id = KelFixtures.incept("agent", null, seed(40), seed(41), NOW);
        assertTrue(Kel.isInceptionDid(id.did));
        assertArrayEquals(TestSupport.pub(seed(40)), Kel.verifyKel(id.did, id.kel).currentKey);
    }

    @Test
    void l0Kel03RotationMustBeSignedByTheCommittedNextKey() throws Exception {
        Identity id = KelFixtures.incept("agent", null, seed(4), seed(5), NOW);
        Identity honest = KelFixtures.rotate(id, seed(6), NOW);
        Map<String, Object> forged = new LinkedHashMap<>(honest.kel.get(1));
        forged.remove("sig");
        forged.put("sig", KelFixtures.sign(forged, id.key)); // thief holds only the CURRENT key
        assertEquals(Kel.INVALID, kelError(() -> Kel.verifyKel(id.did, List.of(id.kel.get(0), forged))).code());
        assertNotNull(Kel.verifyKel(id.did, honest.kel));
    }

    @Test
    void l0Kel04ControllerEventsNeedTheControllersLog() throws Exception {
        Identity person = KelFixtures.incept("person", null, seed(50), seed(51), NOW);
        Identity agent = KelFixtures.incept("agent", person.did, seed(52), seed(53), NOW);
        Identity[] r = KelFixtures.revokeAgent(person, agent, NOW);
        Kel.KelState st = Kel.verifyKel(agent.did, r[0].kel,
            new Kel.VerifyOptions().resolveControllerKel(Kel.sourceFromLogs(r[1].kel)));
        assertTrue(st.revoked);
        assertNull(st.currentKey);
        assertEquals(Kel.CONTROLLER_UNAVAILABLE, kelError(() -> Kel.verifyKel(agent.did, r[0].kel)).code());

        // An unanchored "controller" event is invalid (not duplicity).
        assertEquals(Kel.INVALID, kelError(() -> Kel.verifyKel(agent.did, r[0].kel,
            new Kel.VerifyOptions().resolveControllerKel(Kel.sourceFromLogs(person.kel)))).code());
        // A controller log sealing an event the agent log omits proves the agent log stale.
        assertEquals(Kel.STALE, kelError(() -> Kel.verifyKel(agent.did, agent.kel,
            new Kel.VerifyOptions().resolveControllerKel(Kel.sourceFromLogs(r[1].kel)))).code());
    }

    @Test
    void l0Kel05ForkIsDuplicity() throws Exception {
        Identity id = KelFixtures.incept("person", null, seed(60), seed(61), NOW);
        Kel.InMemoryKelStore store = new Kel.InMemoryKelStore();
        Kel.acceptKel(id.did, KelFixtures.rotate(id, seed(62), NOW).kel, store, null, false);
        assertEquals(Kel.DUPLICITY, kelError(() ->
            Kel.acceptKel(id.did, KelFixtures.rotate(id, seed(63), NOW).kel, store, null, false)).code());
        assertNotNull(store.getDuplicity(id.did));
        // and the DID is refused from then on
        assertEquals(Kel.DUPLICITY, kelError(() -> Kel.acceptKel(id.did, id.kel, store, null, true)).code());
    }

    @Test
    void l0Kel06ShorterLogIsStale() throws Exception {
        Identity id = KelFixtures.incept("person", null, seed(70), seed(71), NOW);
        Kel.InMemoryKelStore store = new Kel.InMemoryKelStore();
        Identity rotated = KelFixtures.rotate(id, seed(72), NOW);
        Kel.acceptKel(id.did, rotated.kel, store, null, false);
        assertEquals(Kel.STALE, kelError(() -> Kel.acceptKel(id.did, id.kel, store, null, false)).code());
        assertEquals(1, Kel.acceptKel(id.did, id.kel, store, null, true).sequence, "use-stored answers from the longer log");
    }

    @Test
    void alteredInceptionNoLongerMatchesTheDid() {
        Identity id = KelFixtures.incept("person", null, seed(80), seed(81), NOW);
        Map<String, Object> altered = new LinkedHashMap<>(id.kel.get(0));
        altered.put("createdAt", "2026-10-08T00:00:00.000Z");
        assertEquals(Kel.INVALID, kelError(() -> Kel.verifyKel(id.did, List.of(altered))).code());
    }

    @Test
    void selfRevocationClosesTheLog() throws Exception {
        Identity id = KelFixtures.incept("person", null, seed(82), seed(83), NOW);
        Identity revoked = KelFixtures.revokeSelf(id, NOW);
        assertTrue(Kel.verifyKel(id.did, revoked.kel).revoked);
        List<Map<String, Object>> after = new ArrayList<>(revoked.kel);
        after.add(KelFixtures.rotate(revoked, seed(84), NOW).kel.get(2));
        assertEquals(Kel.INVALID, kelError(() -> Kel.verifyKel(id.did, after)).code());
    }

    @Test
    void namedOrContentAddressedDidsAreNotInceptionDids() {
        assertFalse(Kel.isInceptionDid("did:aroha:Echo"));
        assertFalse(Kel.isInceptionDid("did:aroha:alice"));
        assertFalse(Kel.isInceptionDid(DID.generateDid(TestSupport.pub(seed(1)))));
    }

    /** Mandates rooted in a person E-DID: key from the KEL; revocation kills the chain. */
    @Test
    void mandateChainResolvesPersonRootThroughItsKel() throws Exception {
        Identity person = KelFixtures.incept("person", null, seed(90), seed(91), NOW);
        String agentDid = DID.generateDid(TestSupport.pub(seed(92)));
        var intent = ArohaMandateCredential.issueIntent(person.did, agentDid,
            SpendingConstraints.builder(100).build(), person.key, Duration.ofHours(1));

        VerifyOptions opts = new VerifyOptions().kelSource(Kel.sourceFromLogs(person.kel)).expectedRootPerson(person.did);
        var ok = ArohaMandateCredential.verifyMandateChain(intent.token(), null, opts);
        assertTrue(ok.valid(), ok.reason());

        Identity revoked = KelFixtures.revokeSelf(person, NOW);
        var dead = ArohaMandateCredential.verifyMandateChain(intent.token(), null,
            new VerifyOptions().kelSource(Kel.sourceFromLogs(revoked.kel)).requirePersonRoot(true));
        assertFalse(dead.valid());
        assertTrue(dead.reason().contains("revoked"), dead.reason());

        // requirePersonRoot without a KEL source cannot be satisfied.
        assertFalse(ArohaMandateCredential.verifyMandateChain(intent.token(), null,
            new VerifyOptions().requirePersonRoot(true)).valid());
        // The general resolver answers E-DIDs from the KEL and nothing else for them.
        var resolver = ArohaMandateCredential.createMandateKeyResolver(Kel.sourceFromLogs(person.kel), null, did -> new byte[32]);
        assertArrayEquals(TestSupport.pub(person.key), resolver.resolve(person.did));
    }
}
