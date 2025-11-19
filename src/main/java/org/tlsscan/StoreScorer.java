package org.tlsscan;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.*;
import java.util.Base64;


public class StoreScorer {

    private final ObjectMapper mapper = new ObjectMapper();

    /**
     * Auto-Erkennung:
     * - .pem/.crt/.cer -> als PEM-Bundle bewertet
     * - sonst -> als Java-Keystore (z.B. cacerts, JKS)
     *
     * countryScoresPath = null -> immer country_trustscores.json aus Ressourcen.
     */
    public void scoreStoreAuto(Path storePath,
                               char[] passwordIgnored,
                               String countryScoresPath,
                               Path summaryOutput,
                               boolean debug) throws Exception {
        if (looksLikePemFile(storePath)) {
            scorePemBundle(storePath, countryScoresPath, summaryOutput,debug);
        } else {
            throw new IllegalArgumentException(
                    "Datei sieht nicht wie ein PEM-Zertifikatsbundle aus (kein '-----BEGIN CERTIFICATE-----' gefunden)."
            );
        }
    }


    /**
     * Kompatibilität: alte Signatur ohne debug-Flag.
     */
    public void scoreStore(Path storePath,
                           char[] password,
                           String countryScoresPath, Path summaryOutput) throws Exception {
        scoreKeystore(storePath, password, countryScoresPath, summaryOutput,false);
    }

    /**
     * Bewertet einen Java-Keystore (z.B. cacerts).
     */
    public void scoreKeystore(Path storePath,
                              char[] password,
                              String countryScoresPath,
                              Path summaryOutput,
                              boolean debug) throws Exception {

        KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
        try (InputStream in = Files.newInputStream(storePath)) {
            ks.load(in, password);
        }

        List<X509Certificate> certs = new ArrayList<>();
        Enumeration<String> aliases = ks.aliases();
        while (aliases.hasMoreElements()) {
            String alias = aliases.nextElement();
            if (!ks.isCertificateEntry(alias) && !ks.isKeyEntry(alias)) {
                continue;
            }
            Certificate c = ks.getCertificate(alias);
            if (c instanceof X509Certificate cert) {
                certs.add(cert);
            }
        }

        scoreCertificates(
                certs,
                "Java Keystore",
                storePath,
                countryScoresPath,
                summaryOutput,
                debug
        );
    }

    /**
     * Bewertet ein PEM-Bundle (z.B. Mozilla cacert.pem, Google Root-PEM).
     * Erwartet mehrere "-----BEGIN CERTIFICATE-----" Blöcke.
     */
    public void scorePemBundle(Path pemPath,
                               String countryScoresPath,
                               Path summaryOutput,
                               boolean debug) throws Exception {

        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        List<X509Certificate> certs = new ArrayList<>();

        StringBuilder sb = new StringBuilder();
        try (BufferedReader br = Files.newBufferedReader(pemPath, StandardCharsets.UTF_8)) {
            String line;
            while ((line = br.readLine()) != null) {
                sb.append(line).append('\n');
            }
        }

        String pemAll = sb.toString();
        String[] parts = pemAll.split("-----END CERTIFICATE-----");
        for (String part : parts) {
            if (!part.contains("-----BEGIN CERTIFICATE-----")) {
                continue;
            }
            String body = part.substring(part.indexOf("-----BEGIN CERTIFICATE-----")
                            + "-----BEGIN CERTIFICATE-----".length())
                    .replaceAll("\\s+", "");

            if (body.isBlank()) continue;

            try {
                byte[] der = Base64.getDecoder().decode(body);
                X509Certificate cert = (X509Certificate) cf.generateCertificate(
                        new java.io.ByteArrayInputStream(der));
                certs.add(cert);
            } catch (IllegalArgumentException | CertificateException e) {
                if (debug) {
                    System.err.println("[StoreScorer] PEM-Zertifikat konnte nicht dekodiert werden: " + e.getMessage());
                }
            }
        }

        scoreCertificates(
                certs,
                "PEM-Bundle",
                pemPath,
                countryScoresPath,
                summaryOutput,
                debug
        );
    }

    /**
     * Gemeinsame Bewertungslogik für Keystore & PEM-Bundle.
     * Gewichtung wie bei der JSONL-Analyse:
     *
     *  - Pro Land: (#Zertifikate Land / #Zertifikate mit Land & Score) * Trustscore(Land)
     *  - Gesamtscore = Summe aller Länderbeiträge, liegt in [0,1] (wenn Trustscores in [0,1] liegen)
     *  - Zertifikate ohne Land oder ohne Score werden für die Score-Berechnung ignoriert,
     *    aber in der Verteilung mitgeführt (als "??" bzw. ohne Beitrag).
     */
    private void scoreCertificates(Collection<X509Certificate> certs,
                                   String storeType,
                                   Path storePath,
                                   String countryScoresPath, Path summaryOutput,
                                   boolean debug) throws IOException {

        Map<String, Double> countryScores =
                CountryTrustUtil.normalizeScores(
                        CountryTrustUtil.loadCountryScoresWithFallback(countryScoresPath)
                );

        Map<String, Long> countByCountry = new HashMap<>();
        Map<String, Long> countByCountryForScore = new HashMap<>();
        Map<String, Double> scoreByCountry = new HashMap<>();

        long totalCerts = 0;

        Map<String, Long> keyAlgorithmCounts = new HashMap<>();
        Map<Integer, Long> keySizeCounts = new HashMap<>();
        long weakKeyCount = 0L;

        Map<String, Long> signatureAlgorithmCounts = new HashMap<>();
        long weakSignatureAlgoCount = 0L;

        Map<String, Long> basicConstraintsCounts = new HashMap<>();

        for (X509Certificate cert : certs) {
            totalCerts++;

            java.security.PublicKey pk = cert.getPublicKey();
            String keyAlg = (pk != null ? pk.getAlgorithm() : null);
            if (keyAlg != null) {
                keyAlgorithmCounts.merge(keyAlg, 1L, Long::sum);
            }

            Integer bits = Util.extractKeySizeBits(pk);
            if (bits != null && bits > 0) {
                keySizeCounts.merge(bits, 1L, Long::sum);
                if (Util.isWeakKeyLength(keyAlg, bits)) {
                    weakKeyCount++;
                }
            }

            String sigAlg = cert.getSigAlgName();
            if (sigAlg != null && !sigAlg.isBlank()) {
                signatureAlgorithmCounts.merge(sigAlg, 1L, Long::sum);
                if (Util.isWeakSignatureAlgorithm(sigAlg)) {
                    weakSignatureAlgoCount++;
                }
            }

            // BasicConstraints: ist das überhaupt ein CA-Zertifikat?
            int bc = cert.getBasicConstraints();
            String bcKey = (bc >= 0) ? "CA" : "EndEntity/Unknown";
            basicConstraintsCounts.merge(bcKey, 1L, Long::sum);

            CountryTrustUtil.updateCountryCountersForCert(
                    cert,
                    countByCountry,
                    countByCountryForScore,
                    countryScores
            );


        }

        // Gewichtete Länderbeiträge berechnen
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
                double contribution = share * baseScore;
                scoreByCountry.put(country, contribution);
            }
        }

        System.out.println("Storetyp : " + storeType);
        System.out.println("Datei    : " + storePath);
        System.out.println("Zertifikate im Store: " + totalCerts);

        System.out.println();
        System.out.println("Verteilung nach Land (Issuer/Subject):");
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

        double totalScore = scoreByCountry.values()
                .stream()
                .mapToDouble(Double::doubleValue)
                .sum();

        System.out.println();
        System.out.println("Berechnung des gewichteten Trustscores (Store-basiert):");
        System.out.println("  - Pro Land: (#Zertifikate Land / #Zertifikate mit Land & Score) * Trustscore(Land)");
        System.out.println("  - Zertifikate ohne identifizierbares Land oder ohne Score werden in der Tabelle");
        System.out.println("    geführt (z.B. als \"??\"), aber bei der Score-Berechnung ignoriert.");
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
        System.out.println("=== Technische Bewertung des Stores ===");

        System.out.println("Public-Key-Algorithmen:");
        keyAlgorithmCounts.forEach((alg, count) ->
                System.out.printf("  %-12s %8d%n", alg, count));

        System.out.println();
        System.out.println("Schlüssellängen (Bits):");
        keySizeCounts.entrySet().stream()
                .sorted(Map.Entry.comparingByKey())
                .forEach(e -> System.out.printf("  %4d Bit %8d%n", e.getKey(), e.getValue()));
        System.out.println("Davon mit schwacher Schlüssellänge: " + weakKeyCount);

        System.out.println();
        System.out.println("Signaturalgorithmen:");
        signatureAlgorithmCounts.forEach((alg, count) ->
                System.out.printf("  %-20s %8d%n", alg, count));
        System.out.println("Zertifikate mit schwachem Signaturalgorithmus (MD5/SHA1): "
                + weakSignatureAlgoCount);

        System.out.println();
        System.out.println("Basic Constraints (CA vs. End-Entity):");
        basicConstraintsCounts.forEach((k, v) ->
                System.out.printf("  %-16s %8d%n", k, v));
        System.out.println("====================================================================");

        if (summaryOutput != null) {
            writeSummaryJson(summaryOutput,
                    storePath,
                    totalCerts,
                    totalScore,
                    countByCountry,
                    scoreByCountry);
        }

    }

    // --- Hilfsfunktionen ------------------------------------------------------------------

    private boolean looksLikePemFile(Path path) {
        try (BufferedReader br = Files.newBufferedReader(path, StandardCharsets.UTF_8)) {
            String line;
            int maxLines = 2000; // reicht locker
            int count = 0;
            while ((line = br.readLine()) != null && count++ < maxLines) {
                if (line.contains("-----BEGIN CERTIFICATE-----")) {
                    return true;
                }
            }
        } catch (IOException e) {
            // wenn nicht lesbar, ist es für uns sowieso kein gültiges PEM
        }
        return false;
    }

    private void writeSummaryJson(
            Path summaryOutput,
            Path inputJsonl,
            long lines,
            double totalscore,
            Map<String, Long> countByCountry,
            Map<String, Double> scoreByCountry
    ) {
        try {
            ObjectNode root = mapper.createObjectNode();
            root.put("input_file", inputJsonl.toString());
            root.put("lines", lines);
            ObjectNode countryNode = root.putObject("root_ca_country");
            ObjectNode countsNode = countryNode.putObject("counts");
            for (Map.Entry<String, Long> e : countByCountry.entrySet()) {
                countsNode.put(e.getKey(), e.getValue());
            }
            ObjectNode scoresNode = countryNode.putObject("scores");
            for (Map.Entry<String, Double> e : scoreByCountry.entrySet()) {
                scoresNode.put(e.getKey(), e.getValue());
            }

            root.put("Total trustscore:", totalscore);

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
