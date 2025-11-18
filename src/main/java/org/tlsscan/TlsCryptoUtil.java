package org.tlsscan;

import java.security.PublicKey;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Locale;

public final class TlsCryptoUtil {

    private TlsCryptoUtil() {
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
}
