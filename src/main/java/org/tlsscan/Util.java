package org.tlsscan;

import com.fasterxml.jackson.databind.JsonNode;
import com.maxmind.geoip2.DatabaseReader;
import com.maxmind.geoip2.exception.AddressNotFoundException;
import com.maxmind.geoip2.exception.GeoIp2Exception;
import com.maxmind.geoip2.model.AsnResponse;
import com.maxmind.geoip2.model.CityResponse;
import com.maxmind.geoip2.model.CountryResponse;

import java.io.IOException;
import java.net.InetAddress;
import java.security.PublicKey;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Locale;

public final class Util {

    private Util() {
        // Utility-Klasse, keine Instanz
    }

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
        // andere Algorithmen lassen wir erstmal außen vor
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
        // ggf. weitere Regeln
        return sigAlg + " gilt in dieser Konfiguration als schwach";
    }

    public static class DeprecatedTlsFinding {
        final String endpoint;     // z.B. "ip:port" oder Hostname
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

}