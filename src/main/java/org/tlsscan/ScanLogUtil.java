package org.tlsscan;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.List;

/**
 * Gemeinsame Helfer für JSON-Log-Ausgaben der Scanner.
 * Vereinheitlicht die Datenstruktur zwischen ActiveScanner und StoreScorer.
 */
public final class ScanLogUtil {

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
    ) { }

    private ScanLogUtil() {
        // Utility-Klasse
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
}

