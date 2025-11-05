package org.tlsscan;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.*;
import java.util.Base64;
import java.util.Locale;

public class Analyzer {
    private final ObjectMapper mapper = new ObjectMapper();

    public void processJsonl(String inputFile, boolean withTrustScores) {
        Map<String, Integer> byCountry = new HashMap<>();
        int total = 0;
        int parsed = 0;

        Map<String, Double> trustScores = Collections.emptyMap();
        double sumTrustScores = 0.0;
        int scoredCerts = 0;

        if (withTrustScores) {
            trustScores = loadCountryScoresWithFallback(null);
        }

        try (BufferedReader br = new BufferedReader(new FileReader(inputFile))) {
            String line;
            while ((line = br.readLine()) != null) {
                if (line.isBlank()) continue;
                total++;

                JsonNode node = mapper.readTree(line);
                JsonNode data = node.path("data");
                String pem = null;

                // CT-ähnliche Struktur (CertStream, CtPoll, ActiveScanner)
                JsonNode leaf = data.path("leaf_cert");
                if (!leaf.isMissingNode()) {
                    if (leaf.has("pem")) {
                        pem = leaf.get("pem").asText(null);
                    } else if (leaf.has("as_pem")) {
                        pem = leaf.get("as_pem").asText(null);
                    } else if (leaf.has("certificate")) {
                        pem = leaf.get("certificate").asText(null);
                    }
                }

                if (pem == null) {
                    // Fallback: falls das PEM direkt im Datenknoten liegt
                    if (data.has("pem")) pem = data.get("pem").asText(null);
                }

                if (pem == null) {
                    continue;
                }

                X509Certificate cert = pemToX509(pem);
                if (cert == null) {
                    continue;
                }
                parsed++;

                // Land primär aus Issuer (Aussteller), falls nicht vorhanden aus Subject
                String issuerCountry = extractCountryFromDn(cert.getIssuerX500Principal().getName());
                String subjectCountry = extractCountryFromDn(cert.getSubjectX500Principal().getName());

                String country = issuerCountry != null ? issuerCountry
                        : subjectCountry != null ? subjectCountry
                        : "UNKNOWN";

                String iso = country == null ? "UNKNOWN" : country.trim().toUpperCase(Locale.ROOT);
                byCountry.merge(iso, 1, Integer::sum);

                if (withTrustScores) {
                    Double ts = trustScores.get(iso);
                    if (ts != null) {
                        sumTrustScores += ts;
                        scoredCerts++;
                    }
                }
            }

            System.out.printf("Total events: %d; parsed certs: %d%n", total, parsed);
            System.out.println("Certificates per country (Issuer/Subject C=):");
            byCountry.entrySet().stream()
                    .sorted(Map.Entry.<String, Integer>comparingByValue().reversed())
                    .forEach(e ->
                            System.out.printf("  %s: %d%n", e.getKey(), e.getValue())
                    );

            if (withTrustScores) {
                System.out.println("\n--- TrustScore-Auswertung (nach Ausstellerland, country_trustscores.json) ---");
                if (scoredCerts > 0) {
                    double avg = sumTrustScores / scoredCerts;
                    System.out.println("Bewertete Zertifikate (mit bekanntem Länderscore): " + scoredCerts);
                    System.out.printf(Locale.ROOT,
                            "Durchschnittlicher TrustScore des Ausstellerlandes: %.6f%n", avg);
                } else {
                    System.out.println("Keine Zertifikate mit bekanntem Länderscore gefunden.");
                }
            }
        } catch (IOException e) {
            System.err.println("Read error: " + e.getMessage());
        }
    }

    private X509Certificate pemToX509(String pem) {
        try {
            String cleaned = pem.replaceAll("-----BEGIN CERTIFICATE-----", "")
                    .replaceAll("-----END CERTIFICATE-----", "")
                    .replaceAll("\\s", "");
            byte[] der = Base64.getDecoder().decode(cleaned);
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            return (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(der));
        } catch (Exception e) {
            return null;
        }
    }

    private String extractCountryFromDn(String dn) {
        if (dn == null) return null;
        String[] parts = dn.split(",");
        for (String p : parts) {
            String[] kv = p.trim().split("=");
            if (kv.length == 2 && kv[0].equalsIgnoreCase("C")) {
                return kv[1].trim();
            }
        }
        return null;
    }

    private Map<String, Double> loadCountryScoresWithFallback(String path) {
        Map<String, Double> m = new HashMap<>();
        try {
            if (path != null && !path.isBlank()) {
                var p = Paths.get(path);
                if (Files.exists(p)) {
                    try (InputStream in = Files.newInputStream(p)) {
                        m.putAll(normalizeScores(mapper.readValue(
                                in,
                                mapper.getTypeFactory().constructMapType(Map.class, String.class, Double.class)
                        )));
                        return m;
                    }
                }
            }
            try (InputStream in = Thread.currentThread().getContextClassLoader()
                    .getResourceAsStream("country_trustscores.json")) {
                if (in != null) {
                    m.putAll(normalizeScores(mapper.readValue(
                            in,
                            mapper.getTypeFactory().constructMapType(Map.class, String.class, Double.class)
                    )));
                } else {
                    System.err.println("country_trustscores.json nicht auf dem Classpath gefunden – TrustScores deaktiviert.");
                }
            }
        } catch (Exception e) {
            System.err.println("Konnte country_trustscores.json nicht laden: " + e.getMessage());
        }
        return m;
    }

    private Map<String, Double> normalizeScores(Map<String, Double> src) {
        Map<String, Double> norm = new HashMap<>();
        for (Map.Entry<String, Double> e : src.entrySet()) {
            norm.put(e.getKey().trim().toUpperCase(Locale.ROOT), e.getValue());
        }
        return norm;
    }
}
