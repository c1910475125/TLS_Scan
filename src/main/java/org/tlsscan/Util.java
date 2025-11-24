package org.tlsscan;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;
import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.PublicKey;
import java.security.cert.*;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.*;

public final class Util {

    // ==================== TLS-Versionen ====================

    /**
     * Prüft, ob eine TLS/SSL-Version als veraltet gilt (SSLv2/3, TLS 1.0/1.1).
     */
    public static boolean isDeprecatedTlsVersion(String raw) {
        if (raw == null) return false;
        String v = raw.toUpperCase(Locale.ROOT)
                .replaceAll("\\s+", "")
                .replace("V", ""); // "TLSv1.0" -> "TLS1.0"

        return v.contains("SSL2") ||
                v.contains("SSL3") ||
                v.contains("TLS1.0") || v.contains("TLS10") ||
                v.contains("TLS1.1") || v.contains("TLS11");
    }

    // ==================== Cipher-Suites ====================

    /**
     * Prüft, ob eine Cipher-Suite als kryptographisch schwach gilt.
     * (RC4, 3DES, reine DES, NULL, EXPORT, MD5)
     */
    public static boolean isWeakCipherSuite(String cipher) {
        if (cipher == null) return false;
        String c = cipher.toUpperCase(Locale.ROOT);

        return c.contains("RC4")
                || c.contains("3DES")
                || c.contains(" DES_")     // DES (ohne 3DES)
                || c.contains("NULL")
                || c.contains("EXPORT")
                || c.contains("MD5");
    }

    // ==================== Schlüssellängen ====================

    /**
     * Ermittelt die effektive Schlüssellänge in Bits eines PublicKey.
     */
    public static Integer extractKeySizeBits(PublicKey pk) {
        if (pk == null) return null;

        if (pk instanceof RSAPublicKey rsa) {
            return rsa.getModulus().bitLength();
        }
        if (pk instanceof ECPublicKey ec) {
            return ec.getParams().getCurve().getField().getFieldSize();
        }
        if (pk instanceof DSAPublicKey dsa) {
            return dsa.getY().bitLength();
        }
        return null;
    }

    /**
     * Grobe Klassifizierung schwacher Schlüssellängen.
     * RSA/DSA < 2048 Bit, EC < 224 Bit (ggf. auf 256 verschärfen).
     */
    public static boolean isWeakKeyLength(String algo, int bits) {
        if (algo == null) return false;
        String a = algo.toUpperCase(Locale.ROOT);

        if (a.contains("RSA") || a.contains("DSA")) {
            return bits < 2048;
        }
        if (a.contains("EC") || a.contains("ECDSA") || a.contains("ECDH")) {
            return bits < 224;
        }
        return false;
    }

    // ==================== Signaturalgorithmen ====================

    /**
     * MD5 oder SHA1-basierte Signaturen gelten als kryptographisch schwach.
     */
    public static boolean isWeakSignatureAlgorithm(String sigAlg) {
        if (sigAlg == null) return false;
        String s = sigAlg.toUpperCase(Locale.ROOT);
        return s.contains("MD5") || s.contains("SHA1");
    }

    public static class WeakKeyFinding {
        final String subject;
        final String issuer;
        final String algorithm;
        final Integer bits;
        final String reason;

        WeakKeyFinding(String subject, String issuer, String algorithm, Integer bits, String reason) {
            this.subject = subject;
            this.issuer = issuer;
            this.algorithm = algorithm;
            this.bits = bits;
            this.reason = reason;
        }
    }

    public static String describeWeakKeyLengthReason(String algo, int bits) {
        if (algo == null) {
            return "Unbekannter Algorithmus mit " + bits + " Bit gilt als schwach";
        }
        String a = algo.toUpperCase(Locale.ROOT);

        if (a.contains("RSA") || a.contains("DSA")) {
            return "Schlüssellänge " + bits + " Bit < 2048 Bit (empfohlenes Minimum für " + algo + ")";
        }
        if (a.contains("EC") || a.contains("ECDSA") || a.contains("ECDH")) {
            return "Schlüssellänge " + bits + " Bit < 224 Bit (empfohlenes Minimum für " + algo + ")";
        }
        return "Schlüssellänge " + bits + " Bit gilt als schwach für " + algo;
    }

    public static class WeakSignatureFinding {
        final String subject;
        final String issuer;
        final String signatureAlgorithm;
        final String reason;

        WeakSignatureFinding(String subject, String issuer, String signatureAlgorithm, String reason) {
            this.subject = subject;
            this.issuer = issuer;
            this.signatureAlgorithm = signatureAlgorithm;
            this.reason = reason;
        }
    }

    public static String describeWeakSignatureReason(String sigAlg) {
        if (sigAlg == null) {
            return "Unbekannter Signaturalgorithmus gilt als schwach";
        }
        String s = sigAlg.toUpperCase(Locale.ROOT);

        if (s.contains("MD5")) {
            return sigAlg + " verwendet MD5 (kryptographisch gebrochen)";
        }
        if (s.contains("SHA1")) {
            return sigAlg + " verwendet SHA1 (nicht mehr als sicher eingestuft)";
        }
        return sigAlg + " gilt in dieser Konfiguration als schwach";
    }

    public static class DeprecatedTlsFinding {
        final String endpoint;
        final String tlsVersion;
        final String reason;

        DeprecatedTlsFinding(String endpoint, String tlsVersion, String reason) {
            this.endpoint = endpoint;
            this.tlsVersion = tlsVersion;
            this.reason = reason;
        }
    }

    public static String extractEndpointFromRecord(JsonNode node) {
        String ip = node.path("ip").asText(null);
        String domain = node.path("domain").asText(null);
        String port = node.path("port").asText(null);

        if (domain != null && port != null) return domain + ":" + port;
        if (ip != null && port != null) return ip + ":" + port;
        if (domain != null) return domain;
        if (ip != null) return ip;
        return "unknown-endpoint";
    }

    //    ====Revocation Util====

    public enum RevocationStatus {
        GOOD,
        REVOKED,
        UNKNOWN
    }

    private static final Set<TrustAnchor> DEFAULT_TRUST_ANCHORS = loadDefaultTrustAnchors();

    /**
     * Prüft den Revocation-Status eines Zertifikats via PKIX/OCSP.
     * Achtung: kann Netzwerkanfragen an OCSP-/CRL-Server auslösen.
     */
    public static RevocationStatus checkRevocation(
            X509Certificate leaf,
            List<X509Certificate> chain,
            boolean debug
    ) {
        if (leaf == null) {
            return RevocationStatus.UNKNOWN;
        }
        if (DEFAULT_TRUST_ANCHORS.isEmpty()) {
            if (debug) {
                System.err.println("[Revocation] Keine TrustAnchors verfügbar – Status UNKNOWN.");
            }
            return RevocationStatus.UNKNOWN;
        }

        try {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");

            List<X509Certificate> pathList = new ArrayList<>();
            pathList.add(leaf);
            if (chain != null && !chain.isEmpty()) {
                pathList.addAll(chain);
            }

            CertPath certPath = cf.generateCertPath(pathList);

            PKIXParameters params = new PKIXParameters(DEFAULT_TRUST_ANCHORS);
            params.setRevocationEnabled(false); // wir hängen expliziten RevocationChecker an

            CertPathValidator validator = CertPathValidator.getInstance("PKIX");
            PKIXRevocationChecker rc = (PKIXRevocationChecker) validator.getRevocationChecker();
            rc.setOptions(EnumSet.of(
                    PKIXRevocationChecker.Option.NO_FALLBACK
            ));
            params.addCertPathChecker(rc);

            validator.validate(certPath, params);
            return RevocationStatus.GOOD;

        } catch (CertPathValidatorException e) {
            if (e.getReason() == CertPathValidatorException.BasicReason.REVOKED) {
                if (debug) {
                    System.err.println("[Revocation] Zertifikat widerrufen: " + e.getMessage());
                }
                return RevocationStatus.REVOKED;
            }
            if (debug) {
                System.err.println("[Revocation] CertPathValidatorException (nicht REVOKED): "
                        + e.getReason() + " – " + e.getMessage());
            }
            return RevocationStatus.UNKNOWN;

        } catch (Exception e) {
            if (debug) {
                System.err.println("[Revocation] Fehler beim Revocation-Check: "
                        + e.getClass().getSimpleName() + ": " + e.getMessage());
            }
            return RevocationStatus.UNKNOWN;
        }
    }

    /**
     * Lädt Standard-TrustAnchors aus dem Default-TrustStore der JVM.
     */
    private static Set<TrustAnchor> loadDefaultTrustAnchors() {
        Set<TrustAnchor> anchors = new HashSet<>();
        try {
            TrustManagerFactory tmf = TrustManagerFactory.getInstance(
                    TrustManagerFactory.getDefaultAlgorithm());
            tmf.init((KeyStore) null); // Default-TrustStore

            for (TrustManager tm : tmf.getTrustManagers()) {
                if (tm instanceof X509TrustManager x509Tm) {
                    for (X509Certificate ca : x509Tm.getAcceptedIssuers()) {
                        anchors.add(new TrustAnchor(ca, null));
                    }
                }
            }
        } catch (Exception e) {
            System.err.println("[Revocation] Konnte Standard-TrustAnchors nicht laden: " + e.getMessage());
        }
        return Collections.unmodifiableSet(anchors);
    }

    //              ====ScanLog Util====
    public record ScanLogData(
            String ip,
            Integer port,
            String hostname,
            String tlsVersion,
            String cipherSuite,
            String countryIso,
            Long asn,
            String cityName,
            String issuerDn,
            String subjectDn,
            String issuerCountry,
            String subjectCountry,
            String leafPem,
            List<String> chainPem
    ) {
    }

    /**
     * Baut die gemeinsame JSON-Struktur für Scan-Logs.
     */
    public static ObjectNode buildLogEntry(ObjectMapper mapper, String messageType, ScanLogData data) {
        ObjectNode dataNode = mapper.createObjectNode();
        if (data.ip() != null) dataNode.put("ip", data.ip());
        if (data.port() != null) dataNode.put("port", data.port());
        if (data.hostname() != null) dataNode.put("hostname", data.hostname());
        if (data.tlsVersion() != null) dataNode.put("tls_version", data.tlsVersion());
        if (data.cipherSuite() != null) dataNode.put("cipher_suite", data.cipherSuite());
        if (data.countryIso() != null) dataNode.put("country_iso", data.countryIso());
        if (data.asn() != null) dataNode.put("asn", data.asn());
        if (data.cityName() != null) dataNode.put("city_name", data.cityName());
        if (data.issuerDn() != null) dataNode.put("issuer_dn", data.issuerDn());
        if (data.subjectDn() != null) dataNode.put("subject_dn", data.subjectDn());
        if (data.issuerCountry() != null) dataNode.put("issuer_country", data.issuerCountry());
        if (data.subjectCountry() != null) dataNode.put("subject_country", data.subjectCountry());

        if (data.leafPem() != null) {
            ObjectNode leafCertNode = mapper.createObjectNode();
            leafCertNode.put("pem", data.leafPem());
            dataNode.set("leaf_cert", leafCertNode);
        }

        if (data.chainPem() != null) {
            ArrayNode chainArr = mapper.createArrayNode();
            for (String pem : data.chainPem()) {
                chainArr.add(pem);
            }
            dataNode.set("chain", chainArr);
        }

        ObjectNode root = mapper.createObjectNode();
        root.put("message_type", messageType);
        root.set("data", dataNode);
        return root;
    }

    /**
     * Wandelt ein Zertifikat in PEM-Format um.
     */
    public static String certToPem(X509Certificate cert) {
        if (cert == null) return null;
        try {
            byte[] der = cert.getEncoded();
            String b64 = Base64.getMimeEncoder(64, new byte[]{'\n'}).encodeToString(der);
            return "-----BEGIN CERTIFICATE-----\n" + b64 + "\n-----END CERTIFICATE-----\n";
        } catch (CertificateEncodingException e) {
            return null;
        }
    }

    // ==== Certificate Helper ====

    public static X509Certificate chooseRootCertificate(Set<X509Certificate> certsInLine) {
        if (certsInLine == null || certsInLine.isEmpty()) return null;
        if (certsInLine.size() == 1) return certsInLine.iterator().next();

        for (X509Certificate candidate : certsInLine) {
            boolean hasParent = false;
            for (X509Certificate other : certsInLine) {
                if (candidate == other) continue;
                if (other.getSubjectX500Principal().equals(candidate.getIssuerX500Principal())) {
                    hasParent = true;
                    break;
                }
            }
            if (!hasParent) {
                return candidate;
            }
        }
        return certsInLine.iterator().next();
    }

    public static void extractCertificatesRecursive(
            JsonNode node,
            CertificateFactory cf,
            Set<X509Certificate> out,
            boolean debug,
            String context
    ) {
        if (node == null || node.isNull()) return;

        if (node.isTextual()) {
            String text = node.asText();
            if (text.contains("-----BEGIN CERTIFICATE-----")) {
                parsePemCertificates(text, cf, out, debug, context);
                return;
            }
            String trimmed = text.trim();
            if (trimmed.length() >= 100 && looksLikeBase64(trimmed)) {
                tryDecodeCertificate(trimmed, cf, out, debug, context);
            }
            return;
        }

        if (node.isArray()) {
            for (JsonNode child : node) {
                extractCertificatesRecursive(child, cf, out, debug, context);
            }
            return;
        }

        if (node.isObject()) {
            node.fields().forEachRemaining(entry ->
                    extractCertificatesRecursive(entry.getValue(), cf, out, debug, context));
        }
    }

    public static void parsePemCertificates(
            String pem,
            CertificateFactory cf,
            Set<X509Certificate> out,
            boolean debug,
            String context
    ) {
        String[] parts = pem.split("-----END CERTIFICATE-----");
        for (String part : parts) {
            if (!part.contains("-----BEGIN CERTIFICATE-----")) continue;
            String body = part.substring(part.indexOf("-----BEGIN CERTIFICATE-----")
                            + "-----BEGIN CERTIFICATE-----".length())
                    .replaceAll("\\s+", "");
            tryDecodeCertificate(body, cf, out, debug, context);
        }
    }

    private static void tryDecodeCertificate(
            String b64,
            CertificateFactory cf,
            Set<X509Certificate> out,
            boolean debug,
            String context
    ) {
        try {
            byte[] der = Base64.getDecoder().decode(b64);
            X509Certificate cert = (X509Certificate) cf.generateCertificate(
                    new java.io.ByteArrayInputStream(der));
            out.add(cert);
        } catch (IllegalArgumentException | CertificateException e) {
            if (debug) {
                System.err.println("[" + context + "] Zertifikat konnte nicht dekodiert werden: " + e.getMessage());
            }
        }
    }

    public static boolean looksLikeBase64(String s) {
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (!(c >= 'A' && c <= 'Z') &&
                    !(c >= 'a' && c <= 'z') &&
                    !(c >= '0' && c <= '9') &&
                    c != '+' && c != '/' && c != '=') {
                return false;
            }
        }
        return true;
    }

//    ====Country Trust Util====


    private static final ObjectMapper MAPPER = new ObjectMapper();

    public static String extractCountryFromDn(String dn) {
        if (dn == null) return null;
        String[] parts = dn.split(",");
        for (String part : parts) {
            String p = part.trim();
            if (p.toUpperCase(Locale.ROOT).startsWith("C=")) {
                String value = p.substring(2).trim();
                if (!value.isEmpty()) {
                    int idx = value.indexOf(' ');
                    if (idx > 0) {
                        value = value.substring(0, idx);
                    }
                    return value.toUpperCase(Locale.ROOT);
                }
            }
        }
        return null;
    }

    public static Map<String, Double> loadCountryScoresWithFallback(String explicitPath) throws IOException {
        Map<String, Double> result = new HashMap<>();

        // 1) expliziter Pfad (z.B. CLI-Option)
        if (explicitPath != null && !explicitPath.isBlank()) {
            Path p = Path.of(explicitPath);
            if (!Files.exists(p)) {
                throw new IOException("country_trustscores.json nicht gefunden: " + p);
            }
            try (InputStream in = Files.newInputStream(p)) {
                @SuppressWarnings("unchecked")
                Map<String, Double> m = MAPPER.readValue(in, Map.class);
                result.putAll(m);
            }
            return result;
        }

        // 2) Fallback: Ressource im Classpath
        try (InputStream in = Util.class.getResourceAsStream("/country_trustscores.json")) {
            if (in == null) {
                throw new IOException("Ressource /country_trustscores.json nicht im Classpath gefunden.");
            }
            @SuppressWarnings("unchecked")
            Map<String, Double> m = MAPPER.readValue(in, Map.class);
            result.putAll(m);
        } catch (UncheckedIOException e) {
            throw e.getCause();
        }

        return result;
    }

    public static Map<String, Double> normalizeScores(Map<String, Double> raw) {
        Map<String, Double> out = new HashMap<>();
        for (Map.Entry<String, Double> e : raw.entrySet()) {
            if (e.getKey() == null || e.getValue() == null) continue;
            String k = e.getKey().trim().toUpperCase(Locale.ROOT);
            double v = e.getValue();
            if (v <= 0) continue;
            if (v > 1.0) v = 1.0;
            out.put(k, v);
        }
        return out;
    }

    /**
     * Bestimmt den "Country-Key" für ein Zertifikat:
     * - bevorzugt Subject-Country, sonst Issuer-Country
     * - normalisiert auf Großbuchstaben
     * - "??" falls nichts gefunden wird
     */
    public static String determineCountryKeyFromCert(X509Certificate cert) {
        if (cert == null) {
            return "??";
        }

        String issuerCountry = extractCountryFromDn(
                cert.getIssuerX500Principal().getName()
        );
        String subjectCountry = extractCountryFromDn(
                cert.getSubjectX500Principal().getName()
        );

        String rawCountry = (subjectCountry != null && !subjectCountry.isBlank())
                ? subjectCountry
                : issuerCountry;

        if (rawCountry == null || rawCountry.isBlank()) {
            return "??";
        }
        return rawCountry.toUpperCase(Locale.ROOT);
    }

    /**
     * Aktualisiert die Länder-Zähler für ein Zertifikat:
     * - countByCountry: alle Zertifikate nach Country-Key
     * - countByCountryForScore: nur, wenn ein Score im countryScores-Map existiert
     */
    public static void updateCountryCountersForCert(
            X509Certificate cert,
            Map<String, Long> countByCountry,
            Map<String, Long> countByCountryForScore,
            Map<String, Double> countryScores
    ) {
        if (countByCountry == null || countByCountryForScore == null || countryScores == null) {
            return;
        }

        String countryKey = determineCountryKeyFromCert(cert);
        countByCountry.merge(countryKey, 1L, Long::sum);

        if (!"??".equals(countryKey) && countryScores.containsKey(countryKey)) {
            countByCountryForScore.merge(countryKey, 1L, Long::sum);
        }
    }

}