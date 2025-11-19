package org.tlsscan;

import java.security.KeyStore;
import java.security.cert.*;
import java.util.*;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

public final class RevocationUtil {

    public enum RevocationStatus {
        GOOD,
        REVOKED,
        UNKNOWN
    }

    private static final Set<TrustAnchor> DEFAULT_TRUST_ANCHORS = loadDefaultTrustAnchors();

    private RevocationUtil() {
        // Utility-Klasse
    }

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
}