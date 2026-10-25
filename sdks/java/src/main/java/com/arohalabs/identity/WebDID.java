// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

package com.arohalabs.identity;

import com.arohalabs.crypto.Jcs;
import com.arohalabs.crypto.Signing;
import com.arohalabs.util.IsoTime;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;

import java.io.InputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.function.Consumer;
import java.util.regex.Pattern;

/**
 * did:aroha-web: — DNS-anchored web identity. A port of aroha-core
 * {@code identity/web-did.ts} (generateWebAgent, rotateKey, resolveWebDID).
 *
 * <p>Two channels must agree before a key is accepted: the DID document at
 * {@code https://{domain}/.well-known/aroha/agents/{path}/did.json} and the
 * TXT record {@code _aroha.{domain}} = {@code "v=aroha1; path={path}; keyhash={sha256hex(pubkey)}"}.
 *
 * <p>Documents use the TypeScript wire shape ({@code verificationMethod[]}
 * with base58btc {@code publicKeyMultibase}; {@code arohaWeb.{domain, path,
 * keyCommitmentHash, keyHistory}}, newest first). Rotation records are the
 * TypeScript {@code KeyRotationRecord}: v2 signs the JCS of
 * {@code {did, newKeyHash, predecessorKey, rotatedAt, trustAfter, v: 2}};
 * legacy v1 signs {@code predecessorKey + newKeyHash + rotatedAt}.
 */
public final class WebDID {

    private WebDID() {}

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final String PREFIX = "did:aroha-web:";

    /** Default cap on a DID document's size (64 KiB). */
    public static final int MAX_WEB_DID_DOCUMENT_BYTES = 64 * 1024;
    /** The path grammar: lowercase [a-z0-9-] segments, "/"-separated. */
    public static final Pattern WEB_DID_PATH_PATTERN = Pattern.compile("^[a-z0-9-]+(/[a-z0-9-]+)*$");
    private static final Pattern LABEL = Pattern.compile("^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$");
    private static final Pattern IPV4 = Pattern.compile("^\\d{1,3}(?:\\.\\d{1,3}){3}$");

    /** Any did:aroha-web validation or resolution failure. */
    public static final class WebDIDException extends IllegalArgumentException {
        public WebDIDException(String message) { super(message); }
    }

    // ── Parsing ───────────────────────────────────────────────────────────────

    /** Domain + path of a did:aroha-web identifier. */
    public record Parsed(String domain, String path) {}

    /** Throws unless {@code domain} is a DNS hostname (IPv4 literal only when allowed). */
    public static void assertWebDIDDomain(String domain, boolean allowIpLiteral) {
        String d = domain.toLowerCase(Locale.ROOT);
        if (d.isEmpty() || d.length() > 253) throw new WebDIDException("did:aroha-web domain has an invalid length: " + domain);
        if (IPV4.matcher(d).matches()) {
            if (allowIpLiteral && Arrays.stream(d.split("\\.")).allMatch(o -> Integer.parseInt(o) <= 255)) return;
            throw new WebDIDException("did:aroha-web domain must be a hostname, not an IP literal: " + domain);
        }
        String[] labels = d.split("\\.", -1);
        for (String l : labels) {
            if (!LABEL.matcher(l).matches()) throw new WebDIDException("did:aroha-web domain is not a valid hostname: " + domain);
        }
        if (labels[labels.length - 1].matches("\\d+")) {
            throw new WebDIDException("did:aroha-web domain is not a valid hostname: " + domain);
        }
    }

    /** Parse {@code did:aroha-web:domain[:path]}; path defaults to {@code agent}. */
    public static Parsed parseWebDID(String did, boolean allowIpLiteral) {
        if (did == null || !did.startsWith(PREFIX)) throw new WebDIDException("Not a did:aroha-web: identifier: " + did);
        String rest = did.substring(PREFIX.length());
        int i = rest.indexOf(':');
        String domain = i == -1 ? rest : rest.substring(0, i);
        String path = i == -1 ? "agent" : rest.substring(i + 1).replace(':', '/');
        assertWebDIDDomain(domain, allowIpLiteral);
        if (!WEB_DID_PATH_PATTERN.matcher(path).matches()) {
            throw new WebDIDException("did:aroha-web path must match " + WEB_DID_PATH_PATTERN + ": " + path);
        }
        return new Parsed(domain, path);
    }

    public static Parsed parseWebDID(String did) { return parseWebDID(did, false); }

    public static String buildWebDID(String domain, String path) {
        return PREFIX + domain + ":" + path.replace('/', ':');
    }

    public static boolean isWebDID(String did) { return did != null && did.startsWith(PREFIX); }

    public static String wellKnownPath(String did) {
        return "/.well-known/aroha/agents/" + parseWebDID(did).path() + "/did.json";
    }

    public static String wellKnownUrl(String did, boolean allowIpLiteral) {
        Parsed p = parseWebDID(did, allowIpLiteral);
        return "https://" + p.domain() + "/.well-known/aroha/agents/" + p.path() + "/did.json";
    }

    // ── DNS TXT / key commitment ──────────────────────────────────────────────

    public static String keyCommitmentHash(byte[] publicKey) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(publicKey));
        } catch (java.security.NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    /** The TXT value to publish at {@code _aroha.{domain}}. */
    public static String dnsTxtValue(String did, byte[] publicKey) {
        return "v=aroha1; path=" + parseWebDID(did).path() + "; keyhash=" + keyCommitmentHash(publicKey);
    }

    /** {@code {path, keyhash}} from an aroha1 TXT value, or null. */
    public static Map<String, String> parseDnsTxt(String txt) {
        if (txt == null || !txt.contains("v=aroha1")) return null;
        Map<String, String> fields = new HashMap<>();
        for (String part : txt.split(";", -1)) {
            int eq = part.indexOf('=');
            if (eq == -1) continue;
            fields.put(part.substring(0, eq).trim(), part.substring(eq + 1).trim());
        }
        String path = fields.get("path"), keyhash = fields.get("keyhash");
        if (path == null || path.isEmpty() || keyhash == null || keyhash.isEmpty()) return null;
        return Map.of("path", path, "keyhash", keyhash);
    }

    // ── Rotation records ──────────────────────────────────────────────────────

    private static boolean isTwo(Object v) {
        return v instanceof Number n && n.doubleValue() == 2.0;
    }

    private static String jsString(Object v) {
        if (v == null) return "undefined";
        if (v instanceof String s) return s;
        try { return MAPPER.writeValueAsString(v); } catch (Exception e) { return String.valueOf(v); }
    }

    /** Exact bytes a rotation record's {@code predecessorSignature} covers. */
    public static byte[] rotationSigningPayload(Map<String, Object> record) {
        if (isTwo(record.get("v"))) {
            if (!(record.get("did") instanceof String did) || did.isEmpty()) {
                throw new WebDIDException("v2 key rotation record is missing its did");
            }
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("did", did);
            m.put("newKeyHash", record.get("newKeyHash"));
            m.put("predecessorKey", record.get("predecessorKey"));
            m.put("rotatedAt", record.get("rotatedAt"));
            m.put("trustAfter", record.get("trustAfter"));
            m.put("v", 2);
            return Jcs.canonicalizeToBytes(m);
        }
        return (jsString(record.get("predecessorKey")) + jsString(record.get("newKeyHash"))
            + jsString(record.get("rotatedAt"))).getBytes(StandardCharsets.UTF_8);
    }

    /** A signed v2 rotation record. */
    public static Map<String, Object> buildRotationRecord(
            String did, Ed25519PrivateKeyParameters oldKey, byte[] newPublicKey, Instant now, Duration coolDown) {
        Map<String, Object> rec = new LinkedHashMap<>();
        rec.put("v", 2);
        rec.put("did", did);
        rec.put("rotatedAt", IsoTime.format(now));
        rec.put("trustAfter", IsoTime.format(now.plus(coolDown)));
        rec.put("predecessorKey", DID.toMultibase(oldKey.generatePublicKey().getEncoded()));
        rec.put("newKeyHash", keyCommitmentHash(newPublicKey));
        rec.put("predecessorSignature", "");
        byte[] sig = Signing.signBytes(rotationSigningPayload(rec), oldKey);
        rec.put("predecessorSignature", Base64.getUrlEncoder().withoutPadding().encodeToString(sig));
        return rec;
    }

    /** Outcome of {@link #checkKeyRotation}. */
    public record RotationCheck(boolean valid, boolean deprecated, String reason) {}

    /** Port of checkKeyRotation; {@code deprecated} for a legacy v1 record. */
    public static RotationCheck checkKeyRotation(Map<String, Object> rotation, String expectedDid) {
        Object v = rotation.get("v");
        boolean deprecated = !isTwo(v);
        if (v != null && !isTwo(v)) return new RotationCheck(false, deprecated, "has unsupported version " + v);
        if (isTwo(v) && expectedDid != null && !expectedDid.equals(rotation.get("did"))) {
            return new RotationCheck(false, deprecated, "was signed for " + rotation.get("did") + ", not " + expectedDid);
        }
        try {
            byte[] pub = DID.fromMultibase((String) rotation.get("predecessorKey"));
            byte[] sig = Base64.getUrlDecoder().decode((String) rotation.get("predecessorSignature"));
            if (pub.length == 32 && Signing.verifyBytes(rotationSigningPayload(rotation), sig, pub)) {
                return new RotationCheck(true, deprecated, null);
            }
        } catch (Exception ignored) {
            // fall through: any malformed field is an invalid signature
        }
        return new RotationCheck(false, deprecated, "has invalid predecessor signature");
    }

    public static boolean verifyKeyRotation(Map<String, Object> rotation, String expectedDid) {
        return checkKeyRotation(rotation, expectedDid).valid();
    }

    // ── Generate / rotate ─────────────────────────────────────────────────────

    /** A did:aroha-web identity: serve {@code document} at {@code wellKnownUrl}, publish {@code dnsTxtRecord}. */
    public record WebAgentKeyPair(
        String did, Ed25519PrivateKeyParameters privateKey, byte[] publicKey,
        Map<String, Object> document, String dnsTxtRecord, String wellKnownUrl) {}

    /** New identity with the TypeScript document shape; endpoint defaults to https://{domain}/aroha/v1. */
    public static WebAgentKeyPair generateWebAgent(String domain, String path, String endpoint) {
        String did = buildWebDID(domain, path);
        parseWebDID(did);
        Ed25519PrivateKeyParameters priv = new Ed25519PrivateKeyParameters(RANDOM);
        byte[] pub = priv.generatePublicKey().getEncoded();
        String keyId = did + "#key-1";
        String now = IsoTime.now();
        Map<String, Object> doc = new LinkedHashMap<>();
        doc.put("@context", List.of("https://www.w3.org/ns/did/v1",
            "https://w3id.org/security/suites/ed25519-2020/v1", "https://aroha-labs.com/contexts/aroha-web/v1"));
        doc.put("id", did);
        doc.put("verificationMethod", List.of(vm(keyId, did, pub)));
        doc.put("authentication", List.of(keyId));
        doc.put("assertionMethod", List.of(keyId));
        doc.put("keyAgreement", List.of(keyId));
        doc.put("service", List.of(Map.of("id", did + "#aroha", "type", "ArohaEndpoint",
            "serviceEndpoint", endpoint != null ? endpoint : "https://" + domain + "/aroha/v1")));
        doc.put("created", now);
        doc.put("updated", now);
        Map<String, Object> web = new LinkedHashMap<>();
        web.put("domain", domain);
        web.put("path", path);
        web.put("keyCommitmentHash", keyCommitmentHash(pub));
        web.put("keyHistory", List.of());
        doc.put("arohaWeb", web);
        return new WebAgentKeyPair(did, priv, pub, doc, dnsTxtValue(did, pub), wellKnownUrl(did, false));
    }

    private static Map<String, Object> vm(String id, String did, byte[] pub) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("id", id);
        m.put("type", "Ed25519VerificationKey2020");
        m.put("controller", did);
        m.put("publicKeyMultibase", DID.toMultibase(pub));
        return m;
    }

    /** Rotate the primary key; the old key signs a v2 record prepended to keyHistory. */
    @SuppressWarnings("unchecked")
    public static WebAgentKeyPair rotateKey(WebAgentKeyPair current, Duration coolDown, Instant now) {
        Ed25519PrivateKeyParameters priv = new Ed25519PrivateKeyParameters(RANDOM);
        byte[] pub = priv.generatePublicKey().getEncoded();
        Map<String, Object> doc = new LinkedHashMap<>(current.document());
        Map<String, Object> web = new LinkedHashMap<>((Map<String, Object>) doc.get("arohaWeb"));
        String did = buildWebDID((String) web.get("domain"), (String) web.get("path"));
        Map<String, Object> rec = buildRotationRecord(did, current.privateKey(), pub, now, coolDown);
        List<Object> vms = (List<Object>) doc.get("verificationMethod");
        String keyId = vms.isEmpty() ? did + "#key-1" : (String) ((Map<String, Object>) vms.get(0)).get("id");
        List<Object> newVms = new ArrayList<>();
        newVms.add(vm(keyId, did, pub));
        if (vms.size() > 1) newVms.addAll(vms.subList(1, vms.size()));
        doc.put("verificationMethod", newVms);
        doc.put("updated", IsoTime.format(now));
        List<Object> hist = new ArrayList<>();
        hist.add(rec);
        hist.addAll((List<Object>) web.getOrDefault("keyHistory", List.of()));
        web.put("keyCommitmentHash", keyCommitmentHash(pub));
        web.put("keyHistory", hist);
        doc.put("arohaWeb", web);
        return new WebAgentKeyPair(did, priv, pub, doc, dnsTxtValue(did, pub), wellKnownUrl(did, false));
    }

    // ── Resolve ───────────────────────────────────────────────────────────────

    /** One key a verifier may accept now; role is current, predecessor, anchored or additional. */
    public record AcceptedKey(String verificationMethodId, String publicKeyMultibase, String role) {}

    /**
     * Resolution outcome. {@code dnsVerified} is true only when a DNS
     * commitment matched a key in the verified chain (false whenever DNS was
     * not checked); {@code acceptedKeys} empty means nothing is accepted.
     */
    public record ResolutionResult(
        Map<String, Object> document, boolean dnsVerified, boolean keyTrusted, String trustReason,
        List<AcceptedKey> acceptedKeys, boolean deprecatedRotations) {}

    /** Fetches the DID document; must not follow redirects or return more than maxBytes. */
    @FunctionalInterface
    public interface HttpsFetcher {
        byte[] get(String url, Duration timeout, int maxBytes) throws Exception;
    }

    /** TXT strings at {@code _aroha.{domain}} (receives the bare domain). */
    @FunctionalInterface
    public interface DnsTxtLookup {
        List<String> txt(String domain) throws Exception;
    }

    /** Options for {@link #resolveWebDID(String, Options)}. Defaults: DNS checked via the JDK resolver. */
    public static final class Options {
        boolean verifyDns = true;
        DnsTxtLookup dnsResolver;
        boolean useSystemDns = true;
        boolean allowNoDns;
        boolean allowIpLiteral;
        HttpsFetcher fetch;
        Duration fetchTimeout = Duration.ofSeconds(10);
        int maxDocumentBytes = MAX_WEB_DID_DOCUMENT_BYTES;
        Long nowMs;
        double legacyMinCoolDownHours = 24;
        Consumer<String> logger = m -> System.err.println(m);

        /** false = HTTPS-only (logged); dnsVerified is then false. */
        public Options verifyDns(boolean v) { verifyDns = v; return this; }
        public Options dnsResolver(DnsTxtLookup v) { dnsResolver = v; return this; }
        /** false = require dnsResolver (tests); with neither, resolution throws unless allowNoDns. */
        public Options useSystemDns(boolean v) { useSystemDns = v; return this; }
        public Options allowNoDns(boolean v) { allowNoDns = v; return this; }
        public Options allowIpLiteral(boolean v) { allowIpLiteral = v; return this; }
        public Options fetch(HttpsFetcher v) { fetch = v; return this; }
        public Options fetchTimeout(Duration v) { fetchTimeout = v; return this; }
        public Options maxDocumentBytes(int v) { maxDocumentBytes = v; return this; }
        public Options nowMs(long v) { nowMs = v; return this; }
        public Options legacyMinCoolDownHours(double v) { legacyMinCoolDownHours = v; return this; }
        public Options logger(Consumer<String> v) { logger = v; return this; }
    }

    /** HTTPS GET without redirects, with a timeout and a streamed size cap. */
    static byte[] defaultFetch(String url, Duration timeout, int maxBytes) throws Exception {
        HttpClient client = HttpClient.newBuilder()
            .followRedirects(HttpClient.Redirect.NEVER).connectTimeout(timeout).build();
        HttpRequest req = HttpRequest.newBuilder(URI.create(url)).timeout(timeout)
            .header("Accept", "application/json").GET().build();
        HttpResponse<InputStream> resp = client.send(req, HttpResponse.BodyHandlers.ofInputStream());
        try (InputStream in = resp.body()) {
            int status = resp.statusCode();
            if (status >= 300 && status < 400) {
                throw new WebDIDException("DID document at " + url + " answered with a redirect (" + status + "); redirects are not followed");
            }
            if (status < 200 || status > 299) throw new WebDIDException("HTTP " + status + " from " + url);
            OptionalLong declared = resp.headers().firstValueAsLong("Content-Length");
            if (declared.isPresent() && declared.getAsLong() > maxBytes) {
                throw new WebDIDException("DID document at " + url + " is too large (" + declared.getAsLong() + " bytes > " + maxBytes + ")");
            }
            byte[] body = in.readNBytes(maxBytes + 1);
            if (body.length > maxBytes) throw new WebDIDException("DID document at " + url + " is too large (> " + maxBytes + " bytes)");
            return body;
        }
    }

    /** TXT lookup through the JDK's JNDI DNS provider; null when that provider is unavailable. */
    static DnsTxtLookup systemDns() {
        try {
            Class.forName("com.sun.jndi.dns.DnsContextFactory");
        } catch (ClassNotFoundException e) {
            return null;
        }
        return domain -> {
            Hashtable<String, String> env = new Hashtable<>();
            env.put("java.naming.factory.initial", "com.sun.jndi.dns.DnsContextFactory");
            javax.naming.directory.DirContext ctx = new javax.naming.directory.InitialDirContext(env);
            try {
                javax.naming.directory.Attribute a =
                    ctx.getAttributes("_aroha." + domain, new String[]{"TXT"}).get("TXT");
                List<String> out = new ArrayList<>();
                if (a != null) {
                    for (int i = 0; i < a.size(); i++) out.add(joinTxt(String.valueOf(a.get(i))));
                }
                return out;
            } finally {
                ctx.close();
            }
        };
    }

    /** JNDI returns a TXT record as space-separated quoted strings; rejoin them. */
    private static String joinTxt(String raw) {
        String s = raw.trim();
        if (!s.startsWith("\"")) return s;
        StringBuilder sb = new StringBuilder();
        boolean in = false;
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == '\\' && in && i + 1 < s.length()) { sb.append(s.charAt(++i)); continue; }
            if (c == '"') { in = !in; continue; }
            if (in) sb.append(c);
        }
        return sb.toString();
    }

    private static String absoluteVmId(String did, String id) {
        return id != null && id.startsWith("#") ? did + id : id;
    }

    /** Date.parse semantics: NaN (comparing false both ways) when unparseable. */
    private static double dateMs(Object v) {
        Long ms = IsoTime.parseMillis(v);
        return ms == null ? Double.NaN : ms.doubleValue();
    }

    private static String msIso(double ms) {
        return Double.isNaN(ms) ? "Invalid Date" : IsoTime.formatMillis((long) ms);
    }

    /**
     * Resolve with defaults: DNS checked through the JDK resolver. Throws
     * {@link WebDIDException} on any failure.
     */
    public static ResolutionResult resolveWebDID(String did) { return resolveWebDID(did, new Options()); }

    /**
     * Resolve a did:aroha-web identifier exactly as aroha-core resolveWebDID:
     * <ol>
     *   <li>fetch over https (no redirects, size cap, timeout); {@code id} must
     *       equal {@code did}; the primary key is hashed here and must equal
     *       {@code arohaWeb.keyCommitmentHash} when present;</li>
     *   <li>verify {@code arohaWeb.keyHistory} newest first (predecessor
     *       signatures, v2 bound to {@code did}; each record commits to its
     *       successor key; rotatedAt non-increasing);</li>
     *   <li>the NEWEST chain key whose hash {@code _aroha.{domain}} commits to
     *       is the anchor; none → {@code dnsVerified=false}, nothing accepted;</li>
     *   <li>accepted keys and {@code keyTrusted} follow the cool-down rules.</li>
     * </ol>
     */
    @SuppressWarnings("unchecked")
    public static ResolutionResult resolveWebDID(String did, Options opts) {
        Consumer<String> log = opts.logger;
        double nowMs = opts.nowMs != null ? opts.nowMs : System.currentTimeMillis();
        String url = wellKnownUrl(did, opts.allowIpLiteral);

        // ── Step 1: fetch ─────────────────────────────────────────────────────
        byte[] body;
        try {
            body = (opts.fetch != null ? opts.fetch : (HttpsFetcher) WebDID::defaultFetch)
                .get(url, opts.fetchTimeout, opts.maxDocumentBytes);
        } catch (Exception e) {
            throw new WebDIDException("Failed to resolve " + did + ": " + e.getMessage());
        }
        if (body.length > opts.maxDocumentBytes) {
            throw new WebDIDException("DID document at " + url + " is too large (> " + opts.maxDocumentBytes + " bytes)");
        }
        Object parsedDoc;
        try {
            parsedDoc = MAPPER.readValue(body, Object.class);
        } catch (Exception e) {
            throw new WebDIDException("Failed to resolve " + did + ": document at " + url + " is not JSON");
        }
        if (!(parsedDoc instanceof Map<?, ?>)) {
            throw new WebDIDException("Failed to resolve " + did + ": document at " + url + " is not an object");
        }
        Map<String, Object> doc = (Map<String, Object>) parsedDoc;
        if (!did.equals(doc.get("id"))) {
            throw new WebDIDException("DID mismatch: document claims " + doc.get("id") + ", expected " + did);
        }
        if (!(doc.get("verificationMethod") instanceof List<?> vms) || vms.isEmpty() || !(vms.get(0) instanceof Map<?, ?>)) {
            throw new WebDIDException("DID " + did + ": document has no verification methods");
        }
        Map<String, Object> primary = (Map<String, Object>) vms.get(0);
        String currentKey = primary.get("publicKeyMultibase") instanceof String s ? s : null;
        String currentHash;
        try {
            currentHash = keyCommitmentHash(DID.fromMultibase(currentKey));
        } catch (Exception e) {
            throw new WebDIDException("DID " + did + ": primary key is not a base58btc multibase key");
        }
        Map<String, Object> web = doc.get("arohaWeb") instanceof Map<?, ?> w ? (Map<String, Object>) w : Map.of();
        Object declared = web.get("keyCommitmentHash");
        if (declared != null && !declared.equals(currentHash)) {
            throw new WebDIDException("DID " + did + ": arohaWeb.keyCommitmentHash does not match the primary key");
        }

        // ── Step 2: rotation chain ────────────────────────────────────────────
        List<Map<String, Object>> history = new ArrayList<>();
        Object rawHist = web.get("keyHistory");
        if (rawHist != null) {
            if (!(rawHist instanceof List<?> l)) throw new WebDIDException("DID " + did + ": arohaWeb.keyHistory is malformed");
            for (Object r : l) {
                if (!(r instanceof Map<?, ?>)) throw new WebDIDException("DID " + did + ": arohaWeb.keyHistory is malformed");
                history.add((Map<String, Object>) r);
            }
        }
        boolean deprecated = false;
        for (int i = 0; i < history.size(); i++) {
            Map<String, Object> r = history.get(i);
            RotationCheck c = checkKeyRotation(r, did);
            if (!c.valid()) throw new WebDIDException("DID " + did + ": key rotation record (rotatedAt " + r.get("rotatedAt") + ") " + c.reason());
            deprecated |= c.deprecated();
            Object successor = i == 0 ? currentKey : history.get(i - 1).get("predecessorKey");
            String successorHash;
            try {
                successorHash = keyCommitmentHash(DID.fromMultibase((String) successor));
            } catch (Exception e) {
                successorHash = null;
            }
            if (successorHash == null || !successorHash.equals(r.get("newKeyHash"))) {
                throw new WebDIDException(i == 0
                    ? "DID " + did + ": keyHistory[0] does not commit to the current primary key"
                    : "DID " + did + ": keyHistory[" + i + "] does not commit to keyHistory[" + (i - 1)
                        + "].predecessorKey — the rotation chain is broken");
            }
            if (i > 0 && dateMs(r.get("rotatedAt")) > dateMs(history.get(i - 1).get("rotatedAt"))) {
                throw new WebDIDException("DID " + did + ": keyHistory is not newest-first at index " + i);
            }
        }
        if (deprecated) log.accept("[aroha] " + did + ": keyHistory contains legacy v1 rotation records (not DID-bound); re-rotate to upgrade");

        int n = history.size();
        List<String> chain = new ArrayList<>();
        for (int i = n - 1; i >= 0; i--) chain.add((String) history.get(i).get("predecessorKey"));
        chain.add(currentKey);
        double legacyFloor = opts.legacyMinCoolDownHours * 3_600_000;
        java.util.function.ToDoubleFunction<Map<String, Object>> effectiveTrustAfter = r -> {
            double signed = dateMs(r.get("trustAfter"));
            if (isTwo(r.get("v"))) return signed;
            double floor = dateMs(r.get("rotatedAt")) + legacyFloor;
            if (Double.isNaN(floor)) return Double.NaN; // Math.max propagates NaN
            return Math.max(Double.isNaN(signed) ? 0 : signed, floor);
        };

        // ── Step 3: DNS ───────────────────────────────────────────────────────
        Parsed p = parseWebDID(did, opts.allowIpLiteral);
        List<String> txt = null;
        if (opts.verifyDns) {
            DnsTxtLookup resolver = opts.dnsResolver != null ? opts.dnsResolver : (opts.useSystemDns ? systemDns() : null);
            if (resolver != null) {
                try {
                    txt = new ArrayList<>(resolver.txt(p.domain()));
                } catch (Exception e) {
                    txt = List.of(); // lookup failed — no commitment found, fail closed below
                }
            } else if (!opts.allowNoDns) {
                throw new WebDIDException("Cannot verify " + did + ": no DNS resolver available for the _aroha."
                    + p.domain() + " TXT key-commitment. Pass dnsResolver, or allowNoDns(true) for tests/dev only.");
            }
        }
        if (txt == null) log.accept("[aroha] " + did + ": resolved HTTPS-only — DNS key-commitment NOT checked (allowNoDns / verifyDns(false))");

        List<AcceptedKey> accepted = new ArrayList<>();
        String primaryId = absoluteVmId(did, (String) primary.get("id"));
        boolean dnsVerified = false;
        int anchor = chain.size() - 1;
        if (txt == null) {
            for (Object o : vms.subList(1, vms.size())) {
                Map<String, Object> vm = (Map<String, Object>) o;
                accepted.add(new AcceptedKey(absoluteVmId(did, (String) vm.get("id")), (String) vm.get("publicKeyMultibase"), "additional"));
            }
        } else {
            Set<String> hashes = new HashSet<>();
            for (String t : txt) {
                Map<String, String> rec = parseDnsTxt(t);
                if (rec != null && rec.get("path").equals(p.path())) hashes.add(rec.get("keyhash"));
            }
            anchor = -1;
            for (int j = chain.size() - 1; j >= 0; j--) {
                try {
                    if (hashes.contains(keyCommitmentHash(DID.fromMultibase(chain.get(j))))) { anchor = j; break; }
                } catch (Exception ignored) {
                    // not a key: cannot be committed to
                }
            }
            dnsVerified = anchor >= 0;
            if (dnsVerified) {
                for (Object o : vms.subList(1, vms.size())) {
                    Map<String, Object> vm = (Map<String, Object>) o;
                    try {
                        if (hashes.contains(keyCommitmentHash(DID.fromMultibase((String) vm.get("publicKeyMultibase"))))) {
                            accepted.add(new AcceptedKey(absoluteVmId(did, (String) vm.get("id")), (String) vm.get("publicKeyMultibase"), "additional"));
                        }
                    } catch (Exception ignored) {
                        // malformed additional key: not accepted
                    }
                }
            }
        }

        // ── Step 4: primary-slot keys accepted now ────────────────────────────
        boolean keyTrusted = false;
        String trustReason = null;
        int last = chain.size() - 1;
        if (anchor < 0) {
            trustReason = "No DNS TXT key-commitment at _aroha." + p.domain() + " matches any key in the document's rotation chain";
        } else if (anchor == last) {
            accepted.add(0, new AcceptedKey(primaryId, currentKey, "current"));
            if (n > 0 && nowMs < effectiveTrustAfter.applyAsDouble(history.get(0))) {
                accepted.add(1, new AcceptedKey(primaryId, chain.get(last - 1), "predecessor"));
                trustReason = "Key rotation cool-down active until " + msIso(effectiveTrustAfter.applyAsDouble(history.get(0)));
            } else {
                keyTrusted = true;
            }
        } else {
            int cur = anchor;
            while (cur < last && nowMs >= effectiveTrustAfter.applyAsDouble(history.get(n - (cur + 1)))) cur++;
            accepted.add(0, new AcceptedKey(primaryId, chain.get(cur), cur == last ? "current" : "anchored"));
            if (cur == last) {
                keyTrusted = true;
            } else {
                trustReason = "DNS commits to an earlier key; the newer key is not trusted until its rotation cool-down ends ("
                    + msIso(effectiveTrustAfter.applyAsDouble(history.get(n - (cur + 1)))) + ") or DNS is updated";
            }
        }
        return new ResolutionResult(doc, dnsVerified, keyTrusted, trustReason, List.copyOf(accepted), deprecated);
    }

    /** Keys that may verify a signature naming {@code verificationMethodId} (null = primary), newest first. */
    @SuppressWarnings("unchecked")
    public static List<byte[]> webDIDPublicKeys(ResolutionResult result, String verificationMethodId) {
        String did = (String) result.document().get("id");
        List<Object> vms = (List<Object>) result.document().get("verificationMethod");
        String primaryId = absoluteVmId(did, vms == null || vms.isEmpty() ? did + "#key-1"
            : (String) ((Map<String, Object>) vms.get(0)).get("id"));
        String wanted = verificationMethodId != null ? absoluteVmId(did, verificationMethodId) : primaryId;
        List<byte[]> out = new ArrayList<>();
        for (AcceptedKey k : result.acceptedKeys()) {
            if (k.verificationMethodId().equals(wanted)) out.add(DID.fromMultibase(k.publicKeyMultibase()));
        }
        return out;
    }

    /** Newest accepted key; throws when none is accepted (map that to "unknown sender"). */
    public static byte[] selectWebDIDKey(ResolutionResult result, String verificationMethodId) {
        List<byte[]> keys = webDIDPublicKeys(result, verificationMethodId);
        if (keys.isEmpty()) {
            throw new WebDIDException("DID " + result.document().get("id") + ": no accepted key for "
                + (verificationMethodId != null ? verificationMethodId : "the primary verification method")
                + (result.trustReason() != null ? " (" + result.trustReason() + ")" : ""));
        }
        return keys.get(0);
    }
}
