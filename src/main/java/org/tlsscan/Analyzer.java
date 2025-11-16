package org.tlsscan;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.BufferedReader;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.*;

public class Analyzer {

    private final ObjectMapper mapper = new ObjectMapper();

    public void analyze(Path inputJsonl,
                        String countryScoresPath,
                        boolean debug) throws IOException {

        final Map<String, Double> countryScores =
                CountryTrustUtil.normalizeScores(
                        CountryTrustUtil.loadCountryScoresWithFallback(countryScoresPath)
                );

        long lines = 0;
        long certs = 0;   // Anzahl bewerteter Zertifikate (max. 1 Root pro Zeile)

        Map<String, Long> countByCountry = new HashMap<>();
        Map<String, Long> countByCountryForScore = new HashMap<>();
        Map<String, Double> scoreByCountry = new HashMap<>();

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
                } catch (Exception e) {
                    if (debug) {
                        System.err.println("[Analyzer] JSON-Parse-Fehler in Zeile " + lines + ": " + e.getMessage());
                    }
                    continue;
                }

                Set<X509Certificate> certsInLine = new HashSet<>();
                extractCertificatesRecursive(root, cf, certsInLine, debug);
                if (certsInLine.isEmpty()) continue;

                X509Certificate selected = chooseRootCertificate(certsInLine);
                if (selected == null) continue;

                certs++;

                String issuerCountry = CountryTrustUtil.extractCountryFromDn(
                        selected.getIssuerX500Principal().getName()
                );
                String subjectCountry = CountryTrustUtil.extractCountryFromDn(
                        selected.getSubjectX500Principal().getName()
                );

                String rawCountry = subjectCountry != null ? subjectCountry : issuerCountry;

                String countryKey;
                if (rawCountry == null || rawCountry.isBlank()) {
                    countryKey = "??";
                } else {
                    countryKey = rawCountry.toUpperCase(Locale.ROOT);
                }

                countByCountry.merge(countryKey, 1L, Long::sum);

                if (!"??".equals(countryKey) && countryScores.containsKey(countryKey)) {
                    countByCountryForScore.merge(countryKey, 1L, Long::sum);
                }
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

}
