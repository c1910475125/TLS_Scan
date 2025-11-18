package org.tlsscan;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.tlsscan.RevocationUtil.RevocationStatus;

import java.io.BufferedReader;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.*;

import static org.tlsscan.RevocationUtil.checkRevocation;


public class Analyzer {

    private final ObjectMapper mapper = new ObjectMapper();

    public void analyze(Path inputJsonl,
                        String countryScoresPath,
                        boolean debug,
                        Path summaryOutput) throws IOException {

        final Map<String, Double> countryScores =
                CountryTrustUtil.normalizeScores(
                        CountryTrustUtil.loadCountryScoresWithFallback(countryScoresPath)
                );

        long lines = 0;
        long certs = 0;   // Anzahl bewerteter Zertifikate (max. 1 Root pro Zeile)

// Revocation-Infos (Leaf)
        long leafWithCrlDp = 0;
        long leafWithOcspAia = 0;
        long leafWithAnyRevocationInfo = 0;

// SCT-Infos
        long leafWithEmbeddedSct = 0;
        long chainsWithAnySct = 0;

// Rev-Infos
        long revGood = 0;
        long revRevoked = 0;
        long revUnknown = 0;


        Map<String, Long> countByCountry = new HashMap<>();
        Map<String, Long> countByCountryForScore = new HashMap<>();
        Map<String, Double> scoreByCountry = new HashMap<>();
        Map<String, Long> tlsVersionCounts = new HashMap<>();
        Map<String, Long> deprecatedTlsVersionCounts = new HashMap<>();


        Map<String, Long> cipherSuiteCounts = new HashMap<>();
        Map<String, Long> weakCipherSuiteCounts = new HashMap<>();

        Map<String, Long> keyAlgorithmCounts = new HashMap<>();
        Map<Integer, Long> keySizeCounts = new HashMap<>();
        long weakKeyCount = 0L;

        Map<String, Long> signatureAlgorithmCounts = new HashMap<>();
        long weakSignatureAlgoCount = 0L;

        Map<Integer, Long> chainLengthCounts = new HashMap<>();
        long chainsWithWeakSig = 0L; // z.B. SHA1/MD5 irgendwo in der Kette


        CertificateFactory cf;
        try {
            cf = CertificateFactory.getInstance("X.509");
        } catch (CertificateException e) {
            throw new IllegalStateException("Kann X.509 CertificateFactory nicht initialisieren", e);
        }

        try (BufferedReader br = Files.newBufferedReader(inputJsonl, StandardCharsets.UTF_8)) {
            String line;
            while ((line = br.readLine()) != null) {
                lines++;
                line = line.trim();
                if (line.isEmpty()) continue;

                JsonNode root;
                try {
                    root = mapper.readTree(line);
                    JsonNode dataNode = root.path("data");
                    if (dataNode != null && dataNode.isObject()) {

                        // --- TLS-Version -----------------------
                        String tlsVersion = dataNode.path("tls_version").asText(null);
                        if (tlsVersion != null && !tlsVersion.isBlank()) {
                            tlsVersionCounts.merge(tlsVersion, 1L, Long::sum);
                            if (TlsCryptoUtil.isDeprecatedTlsVersion(tlsVersion)) {
                                deprecatedTlsVersionCounts.merge(tlsVersion, 1L, Long::sum);
                            }
                        }

                        // --- Cipher-Suite ----------------------
                        String cipherSuite = dataNode.path("cipher_suite").asText(null);
                        if (cipherSuite != null && !cipherSuite.isBlank()) {
                            cipherSuiteCounts.merge(cipherSuite, 1L, Long::sum);
                            if (TlsCryptoUtil.isWeakCipherSuite(cipherSuite)) {
                                weakCipherSuiteCounts.merge(cipherSuite, 1L, Long::sum);
                            }
                        }

                        // --- Leaf-Zertifikat einlesen (PEM) ----
                        X509Certificate leafCert = null;
                        JsonNode leafPemNode = dataNode.path("leaf_cert").path("pem");
                        if (leafPemNode.isTextual()) {
                            String leafPem = leafPemNode.asText();
                            Set<X509Certificate> tmp = new LinkedHashSet<>();
                            // vorhandene Helfer wiederverwenden:
                            parsePemCertificates(leafPem, cf, tmp, debug);
                            if (!tmp.isEmpty()) {
                                leafCert = tmp.iterator().next();
                            }
                        }

                        // --- Kette auslesen --------------------
                        List<X509Certificate> chainCerts = new ArrayList<>();
                        JsonNode chainNode = dataNode.path("chain");
                        if (chainNode.isArray()) {
                            for (JsonNode cNode : chainNode) {
                                if (!cNode.isTextual()) continue;
                                String pem = cNode.asText();
                                Set<X509Certificate> tmp = new LinkedHashSet<>();
                                parsePemCertificates(pem, cf, tmp, debug);
                                chainCerts.addAll(tmp);
                            }
                        }

                        // --- Schlüssel-Infos aus Leaf ----------
                        if (leafCert != null) {
                            boolean hasCrl  = hasCrlDistributionPoints(leafCert);
                            boolean hasOcsp = hasAuthorityInfoAccessOcsp(leafCert);
                            boolean hasSct  = hasEmbeddedSctExtension(leafCert);
                            java.security.PublicKey pk = leafCert.getPublicKey();
                            String keyAlg = (pk != null ? pk.getAlgorithm() : null);
                            if (keyAlg != null) {
                                keyAlgorithmCounts.merge(keyAlg, 1L, Long::sum);
                            }

                            Integer bits = TlsCryptoUtil.extractKeySizeBits(pk);
                            if (bits != null && bits > 0) {
                                keySizeCounts.merge(bits, 1L, Long::sum);
                                if (TlsCryptoUtil.isWeakKeyLength(keyAlg, bits)) {
                                    weakKeyCount++;
                                }
                            }

                            String sigAlg = leafCert.getSigAlgName();
                            if (sigAlg != null && !sigAlg.isBlank()) {
                                signatureAlgorithmCounts.merge(sigAlg, 1L, Long::sum);
                                if (TlsCryptoUtil.isWeakSignatureAlgorithm(sigAlg)) {
                                    weakSignatureAlgoCount++;
                                }
                            }

                            if (hasCrl) {
                                leafWithCrlDp++;
                            }
                            if (hasOcsp) {
                                leafWithOcspAia++;
                            }
                            if (hasCrl || hasOcsp) {
                                leafWithAnyRevocationInfo++;
                            }
                            if (hasSct) {
                                leafWithEmbeddedSct++;
                            }

                            RevocationStatus status = checkRevocation(
                                    leafCert,
                                    chainCerts,
                                    debug
                            );

                            switch (status) {
                                case GOOD -> revGood++;
                                case REVOKED -> revRevoked++;
                                case UNKNOWN -> revUnknown++;
                            }

                        }

                        // --- Chain-"Qualität" ------------------
                        List<X509Certificate> fullChain = new ArrayList<>();
                        if (leafCert != null) fullChain.add(leafCert);
                        fullChain.addAll(chainCerts);

                        if (!fullChain.isEmpty()) {
                            int chainLen = fullChain.size();
                            chainLengthCounts.merge(chainLen, 1L, Long::sum);

                            boolean chainHasWeakSig = false;
                            for (X509Certificate c : fullChain) {
                                String sigAlg = c.getSigAlgName();
                                if (TlsCryptoUtil.isWeakSignatureAlgorithm(sigAlg)) {
                                    chainHasWeakSig = true;
                                    break;
                                }
                            }
                            if (chainHasWeakSig) {
                                chainsWithWeakSig++;
                            }
                        }
                    }

                } catch (Exception e) {
                    if (debug) {
                        System.err.println("[Analyzer] JSON-Parse-Fehler in Zeile " + lines + ": " + e.getMessage());
                    }
                    continue;
                }

                Set<X509Certificate> certsInLine = new HashSet<>();
                extractCertificatesRecursive(root, cf, certsInLine, debug);
                if (certsInLine.isEmpty()) continue;
                certs++;

                // Leaf-Zertifikat (für Revocation/SCT) bestimmen
                X509Certificate leaf = chooseLeafCertificate(certsInLine);

                // SCT in der gesamten Kette vorhanden?
                boolean chainHasSct = false;
                for (X509Certificate c : certsInLine) {
                    if (hasEmbeddedSctExtension(c)) {
                        chainHasSct = true;
                        break;
                    }
                }
                if (chainHasSct) {
                    chainsWithAnySct++;
                }

                // Revocation-Infos & SCT nur am Leaf auswerten
                if (leaf != null) {
                    boolean hasCrl = hasCrlDistributionPoints(leaf);
                    boolean hasOcsp = hasAuthorityInfoAccessOcsp(leaf);
                    boolean hasSct = hasEmbeddedSctExtension(leaf);

                    if (hasCrl) {
                        leafWithCrlDp++;
                    }
                    if (hasOcsp) {
                        leafWithOcspAia++;
                    }
                    if (hasCrl || hasOcsp) {
                        leafWithAnyRevocationInfo++;
                    }
                    if (hasSct) {
                        leafWithEmbeddedSct++;
                    }
                }

                // Root-/CA-Land für TrustScore-Bewertung bestimmen
                X509Certificate selected = chooseRootCertificate(certsInLine);
                if (selected == null) continue;

                certs++;

                CountryTrustUtil.updateCountryCountersForCert(
                        selected,
                        countByCountry,
                        countByCountryForScore,
                        countryScores
                );


            }
        }

        System.out.println("Zeilen gelesen     : " + lines);
        System.out.println("Zertifikate gefunden : " + certs);
        System.out.println("Zertifikate geparst  : " + certs);

        // 1) Gewichtete Länder-Beiträge berechnen
        long totalForScore = countByCountryForScore.values()
                .stream()
                .mapToLong(Long::longValue)
                .sum();

        scoreByCountry.clear();
        if (totalForScore > 0) {
            for (Map.Entry<String, Long> e : countByCountryForScore.entrySet()) {
                String country = e.getKey();
                long count = e.getValue();
                Double baseScore = countryScores.get(country);
                if (baseScore == null) continue;

                double share = (double) count / (double) totalForScore;
                scoreByCountry.put(country, share * baseScore);
            }
        }

        // 2) Tabelle ausgeben (sortiert nach Anzahl)
        System.out.println();
        System.out.println("Verteilung nach Land (Root-CA-Land):");
        System.out.printf("%-5s %10s %15s %22s%n",
                "Land", "Anzahl", "Trustscore", "Gewichteter Beitrag");

        countByCountry.entrySet().stream()
                .sorted((a, b) -> Long.compare(b.getValue(), a.getValue()))
                .forEach(e -> {
                    String country = e.getKey();
                    long count = e.getValue();

                    Double baseScore = countryScores.get(country);
                    String baseStr = baseScore != null
                            ? String.format(Locale.ROOT, "%.4f", baseScore)
                            : "-";

                    Double contrib = scoreByCountry.get(country);
                    String contribStr = contrib != null
                            ? String.format(Locale.ROOT, "%.4f", contrib)
                            : "-";

                    System.out.printf("%-5s %10d %15s %22s%n",
                            country, count, baseStr, contribStr);
                });

        // 3) Gesamtscore + Erklärung + Klassifizierung
        double totalScore = scoreByCountry.values()
                .stream()
                .mapToDouble(Double::doubleValue)
                .sum();

        System.out.println();
        System.out.println("Berechnung des gewichteten Trustscores (Root-CA-basiert):");
        System.out.println("  - Pro Root-CA-Land: (#Zertifikate Land / #Zertifikate mit Land & Score) * Trustscore(Land)");
        System.out.println("  - Zertifikate ohne identifizierbares Root-CA-Land werden in der Tabelle als \"??\" geführt,");
        System.out.println("    aber bei der Score-Berechnung ignoriert.");
        System.out.println("  - Gesamtscore = Summe aller Länderbeiträge.");

        System.out.println();
        System.out.println("Gesamtscore (gewichteter Trustscore 0–1): "
                + String.format(Locale.ROOT, "%.4f", totalScore));

        String classification;
        if (totalScore > 0.75) {
            classification = "Hohe Vertrauenswürdigkeit";
        } else if (totalScore >= 0.5) {
            classification = "Eingeschränkte Vertrauenswürdigkeit";
        } else {
            classification = "Kritische Vertrauenswürdigkeit";
        }
        System.out.println("Einstufung: " + classification);

        System.out.println();
        System.out.println("=== Technische TLS-Auswertung ===");

// TLS-Versionen
        System.out.println("TLS-Versionen (alle):");
        tlsVersionCounts.entrySet().stream()
                .sorted(Map.Entry.comparingByKey())
                .forEach(e -> System.out.printf("  %-10s %8d%n", e.getKey(), e.getValue()));

        if (!deprecatedTlsVersionCounts.isEmpty()) {
            System.out.println("Veraltete TLS-Versionen:");
            deprecatedTlsVersionCounts.entrySet().stream()
                    .sorted(Map.Entry.comparingByKey())
                    .forEach(e -> System.out.printf("  %-10s %8d%n", e.getKey(), e.getValue()));
        }

// Cipher-Suites
        System.out.println();
        System.out.println("Cipher-Suites (Top N):");
        cipherSuiteCounts.entrySet().stream()
                .sorted((a, b) -> Long.compare(b.getValue(), a.getValue()))
                .limit(20)
                .forEach(e -> System.out.printf("  %-50s %8d%n", e.getKey(), e.getValue()));

        if (!weakCipherSuiteCounts.isEmpty()) {
            System.out.println();
            System.out.println("Schwache Cipher-Suites:");
            weakCipherSuiteCounts.entrySet().stream()
                    .sorted((a, b) -> Long.compare(b.getValue(), a.getValue()))
                    .forEach(e -> System.out.printf("  %-50s %8d%n", e.getKey(), e.getValue()));
        }

// Schlüssel
        System.out.println();
        System.out.println("Public-Key-Algorithmen (Leaf):");
        keyAlgorithmCounts.forEach((alg, count) ->
                System.out.printf("  %-10s %8d%n", alg, count));

        System.out.println("Schlüssellängen (Leaf, Bits):");
        keySizeCounts.entrySet().stream()
                .sorted(Map.Entry.comparingByKey())
                .forEach(e -> System.out.printf("  %4d Bit %8d%n", e.getKey(), e.getValue()));
        System.out.println("Davon mit schwacher Schlüssellänge: " + weakKeyCount);

// Signaturalgorithmen
        System.out.println();
        System.out.println("Signaturalgorithmen (Leaf):");
        signatureAlgorithmCounts.forEach((alg, count) ->
                System.out.printf("  %-20s %8d%n", alg, count));
        System.out.println("Zertifikatsketten mit schwacher Signatur irgendwo in der Kette: "
                + chainsWithWeakSig);

// Chain-Qualität (sehr grob über Länge)
        System.out.println();
        System.out.println("=== Revocation & SCT ===");
        System.out.printf("Leaf-Zertifikate mit CRL-DP:   %d%n", leafWithCrlDp);
        System.out.printf("Leaf-Zertifikate mit OCSP-AIA: %d%n", leafWithOcspAia);
        System.out.printf("Leafs mit Revocation-Info:     %d%n", leafWithAnyRevocationInfo);
        System.out.printf("Leafs mit SCT-Extension:       %d%n", leafWithEmbeddedSct);
        System.out.printf("Ketten mit SCT-Extension:      %d%n", chainsWithAnySct);

        System.out.println();
        System.out.println("=== Revocation-Status (online geprüft) ===");
        System.out.printf("GOOD    : %d%n", revGood);
        System.out.printf("REVOKED : %d%n", revRevoked);
        System.out.printf("UNKNOWN : %d%n", revUnknown);


        if (summaryOutput != null) {
            writeSummaryJson(summaryOutput,
                    inputJsonl,
                    lines,
                    certs,
                    countByCountry,
                    scoreByCountry,
                    leafWithCrlDp,
                    leafWithOcspAia,
                    leafWithAnyRevocationInfo,
                    leafWithEmbeddedSct,
                    chainsWithAnySct,
                    revGood,
                    revRevoked,
                    revUnknown);
        }

    }

    /**
     * Wählt das Root-/Top-CA-Zertifikat:
     * - Wenn nur eins vorhanden ist -> dieses.
     * - Sonst: Zertifikat, dessen Issuer-DN NICHT als Subject-DN eines anderen Zertifikats vorkommt.
     * - Fallback: irgendein Zertifikat aus der Menge.
     */
    private X509Certificate chooseRootCertificate(Set<X509Certificate> certsInLine) {
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

    private void extractCertificatesRecursive(JsonNode node,
                                              CertificateFactory cf,
                                              Set<X509Certificate> out,
                                              boolean debug) {
        if (node == null || node.isNull()) return;

        if (node.isTextual()) {
            String text = node.asText();
            if (text.contains("-----BEGIN CERTIFICATE-----")) {
                parsePemCertificates(text, cf, out, debug);
                return;
            }
            String trimmed = text.trim();
            if (trimmed.length() >= 100 && looksLikeBase64(trimmed)) {
                tryDecodeCertificate(trimmed, cf, out, debug);
            }
            return;
        }

        if (node.isArray()) {
            for (JsonNode child : node) {
                extractCertificatesRecursive(child, cf, out, debug);
            }
            return;
        }

        if (node.isObject()) {
            node.fields().forEachRemaining(entry ->
                    extractCertificatesRecursive(entry.getValue(), cf, out, debug));
        }
    }

    private void parsePemCertificates(String pem,
                                      CertificateFactory cf,
                                      Set<X509Certificate> out,
                                      boolean debug) {
        String[] parts = pem.split("-----END CERTIFICATE-----");
        for (String part : parts) {
            if (!part.contains("-----BEGIN CERTIFICATE-----")) continue;
            String body = part.substring(part.indexOf("-----BEGIN CERTIFICATE-----")
                            + "-----BEGIN CERTIFICATE-----".length())
                    .replaceAll("\\s+", "");
            tryDecodeCertificate(body, cf, out, debug);
        }
    }

    private void tryDecodeCertificate(String b64,
                                      CertificateFactory cf,
                                      Set<X509Certificate> out,
                                      boolean debug) {
        try {
            byte[] der = Base64.getDecoder().decode(b64);
            X509Certificate cert = (X509Certificate) cf.generateCertificate(
                    new java.io.ByteArrayInputStream(der));
            out.add(cert);
        } catch (IllegalArgumentException | CertificateException e) {
            if (debug) {
                System.err.println("[Analyzer] Zertifikat konnte nicht dekodiert werden: " + e.getMessage());
            }
        }
    }

    private boolean looksLikeBase64(String s) {
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

    private X509Certificate chooseLeafCertificate(Set<X509Certificate> certsInLine) {
        if (certsInLine == null || certsInLine.isEmpty()) return null;
        if (certsInLine.size() == 1) return certsInLine.iterator().next();

        for (X509Certificate candidate : certsInLine) {
            boolean hasChild = false;
            for (X509Certificate other : certsInLine) {
                if (candidate == other) continue;
                if (candidate.getSubjectX500Principal().equals(other.getIssuerX500Principal())) {
                    hasChild = true;
                    break;
                }
            }
            if (!hasChild) {
                // Kandidat, der nichts mehr "darunter" hat -> Leaf
                return candidate;
            }
        }
        // Fallback
        return certsInLine.iterator().next();
    }

    private boolean hasCrlDistributionPoints(X509Certificate cert) {
        // OID: 2.5.29.31
        return cert.getExtensionValue("2.5.29.31") != null;
    }

    private boolean hasAuthorityInfoAccessOcsp(X509Certificate cert) {
        // OID AIA: 1.3.6.1.5.5.7.1.1
        byte[] ext = cert.getExtensionValue("1.3.6.1.5.5.7.1.1");
        if (ext == null) {
            return false;
        }
        // Grobe Heuristik: nach "ocsp" im dekodierten Bytearray suchen.
        String text = new String(ext, StandardCharsets.ISO_8859_1);
        String lower = text.toLowerCase(Locale.ROOT);
        return lower.contains("ocsp");
    }

    private boolean hasEmbeddedSctExtension(X509Certificate cert) {
        // OID Embedded SCT: 1.3.6.1.4.1.11129.2.4.2
        return cert.getExtensionValue("1.3.6.1.4.1.11129.2.4.2") != null;
    }

    private void writeSummaryJson(
            Path summaryOutput,
            Path inputJsonl,
            long lines,
            long certs,
            Map<String, Long> countByCountry,
            Map<String, Double> scoreByCountry,
            long leafWithCrlDp,
            long leafWithOcspAia,
            long leafWithAnyRevocationInfo,
            long leafWithEmbeddedSct,
            long chainsWithAnySct,
            long revGood,
            long revRevoked,
            long revUnknown
    ) {
        try {
            ObjectNode root = mapper.createObjectNode();
            root.put("input_file", inputJsonl.toString());
            root.put("lines", lines);
            root.put("cert_chains", certs);

            ObjectNode countryNode = root.putObject("root_ca_country");
            ObjectNode countsNode = countryNode.putObject("counts");
            for (Map.Entry<String, Long> e : countByCountry.entrySet()) {
                countsNode.put(e.getKey(), e.getValue());
            }
            ObjectNode scoresNode = countryNode.putObject("scores");
            for (Map.Entry<String, Double> e : scoreByCountry.entrySet()) {
                scoresNode.put(e.getKey(), e.getValue());
            }

            ObjectNode revNode = root.putObject("revocation");
            revNode.put("leaf_with_crl_dp", leafWithCrlDp);
            revNode.put("leaf_with_ocsp_aia", leafWithOcspAia);
            revNode.put("leaf_with_any_revocation_info", leafWithAnyRevocationInfo);
            revNode.put("leaf_with_sct_extension", leafWithEmbeddedSct);
            revNode.put("chains_with_sct_extension", chainsWithAnySct);
            revNode.put("status_good", revGood);
            revNode.put("status_revoked", revRevoked);
            revNode.put("status_unknown", revUnknown);

            if (summaryOutput.getParent() != null) {
                Files.createDirectories(summaryOutput.getParent());
            }
            mapper.writerWithDefaultPrettyPrinter()
                    .writeValue(summaryOutput.toFile(), root);

            System.out.println("Analyse-Summary gespeichert in: " + summaryOutput);
        } catch (IOException e) {
            System.err.println("Konnte Analyse-Summary nicht schreiben: " + e.getMessage());
        }
    }


}


