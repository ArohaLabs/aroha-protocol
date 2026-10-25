// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

package com.arohalabs.identity;

import com.arohalabs.TestSupport;
import com.arohalabs.crypto.Jcs;
import com.arohalabs.crypto.Signing;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;

import java.nio.charset.StandardCharsets;
import java.util.*;

/**
 * Test-only KEL WRITER, mirroring incept / rotateKel / anchorInKel /
 * revokeAgent / revokeKelSelf from kel.ts. The SDK itself is read-only for
 * KELs; these exist to produce logs for the verifier under test.
 */
final class KelFixtures {

    private KelFixtures() {}

    static final class Identity {
        String did;
        String kind;
        Ed25519PrivateKeyParameters key;
        Ed25519PrivateKeyParameters next;
        List<Map<String, Object>> kel = new ArrayList<>();
    }

    static String sign(Map<String, Object> unsigned, Ed25519PrivateKeyParameters key) {
        byte[] payload = Jcs.canonicalize(unsigned).getBytes(StandardCharsets.UTF_8);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(Signing.signBytes(payload, key));
    }

    static Identity incept(String kind, String controller, Ed25519PrivateKeyParameters key,
                           Ed25519PrivateKeyParameters next, String now) {
        Map<String, Object> e = new LinkedHashMap<>();
        e.put("v", 1);
        e.put("type", "inception");
        e.put("kind", kind);
        e.put("keys", List.of(DID.toMultibase(TestSupport.pub(key))));
        e.put("nextKeyDigest", Kel.keyDigest(TestSupport.pub(next)));
        if (controller != null) e.put("controller", controller);
        e.put("createdAt", now);
        e.put("sig", sign(e, key));
        Identity id = new Identity();
        id.did = Kel.didFromInception(e);
        id.kind = kind;
        id.key = key;
        id.next = next;
        id.kel.add(e);
        return id;
    }

    static Map<String, Object> position(Identity id, String type, String now) {
        Map<String, Object> e = new LinkedHashMap<>();
        e.put("v", 1);
        e.put("type", type);
        e.put("did", id.did);
        e.put("seq", id.kel.size());
        e.put("prior", Kel.eventDigest(id.kel.get(id.kel.size() - 1)));
        e.put("at", now);
        return e;
    }

    /** Pre-rotation: the committed next key becomes current, {@code newNext} is committed. */
    static Identity rotate(Identity id, Ed25519PrivateKeyParameters newNext, String now) {
        Map<String, Object> e = position(id, "rotate", now);
        e.put("keys", List.of(DID.toMultibase(TestSupport.pub(id.next))));
        e.put("nextKeyDigest", Kel.keyDigest(TestSupport.pub(newNext)));
        e.put("sig", sign(e, id.next));
        Identity out = copy(id);
        out.key = id.next;
        out.next = newNext;
        out.kel.add(e);
        return out;
    }

    static Identity anchor(Identity person, String agentDid, Map<String, Object> agentEvent, String now) {
        Map<String, Object> e = position(person, "anchor", now);
        Map<String, Object> seal = new LinkedHashMap<>();
        seal.put("did", agentDid);
        seal.put("seq", agentEvent.get("seq"));
        seal.put("digest", Kel.eventDigest(agentEvent));
        e.put("seals", List.of(seal));
        e.put("sig", sign(e, person.key));
        Identity out = copy(person);
        out.kel.add(e);
        return out;
    }

    /** Controller-revokes {@code agent}; returns {agent', person'}. */
    static Identity[] revokeAgent(Identity person, Identity agent, String now) {
        Map<String, Object> e = position(agent, "revoke", now);
        e.put("auth", "controller");
        Identity a = copy(agent);
        a.kel.add(e);
        return new Identity[]{a, anchor(person, agent.did, e, now)};
    }

    static Identity revokeSelf(Identity id, String now) {
        Map<String, Object> e = position(id, "revoke", now);
        e.put("auth", "next-key");
        e.put("revealedKey", DID.toMultibase(TestSupport.pub(id.next)));
        e.put("sig", sign(e, id.next));
        Identity out = copy(id);
        out.kel.add(e);
        return out;
    }

    static Identity copy(Identity id) {
        Identity o = new Identity();
        o.did = id.did;
        o.kind = id.kind;
        o.key = id.key;
        o.next = id.next;
        o.kel = new ArrayList<>(id.kel);
        return o;
    }
}
