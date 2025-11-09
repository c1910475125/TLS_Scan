package org.tlsscan;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.*;
import java.util.Base64;
import java.util.Locale;

public class Analyzer {
    private final ObjectMapper mapper = new ObjectMapper();

    public void analyze(Path input,
                        String countryScoresPath,
                        boolean debug) throws IOException {

        Map<String, Double> countryScores = loadCountryScoresWithFallback(countryScoresPath);

        long lines = 0;
        long certs = 0;
        long parsed = 0;

        Map<String, Long> countByCountry = new HashMap<>();
        Map<String, Double> scoreByCountry = new HashMap<>();

        try (BufferedReader br = Files.newBufferedReader(input)) {
            String line;
            while ((line = br.readLine()) != null) {
                lines++;
                if (line.isBlank()) continue;

                JsonNode root;
                try {
                    root = mapper.readTree(line);
                } catch (Exception e) {
                    if (debug) {
                        System.err.println("[Analyze] JSON-Parse-Fehler in Zeile " + lines + ": " + e.getMessage());
                    }
                    continue;
                }

                JsonNode data = root.path("data");
                if (data.isMissingNode() || data.isNull()) continue;

                JsonNode leaf = data.path("leaf_cert").path("pem");
                if (!leaf.isTextual()) {
                    continue;
                }
                certs++;
                String pem = leaf.asText();
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

                String country = issuerCountry != null ? issuerCountry : subjectCountry;
                if (country == null || country.isBlank()) {
                    country = "??";
                }

                country = country.toUpperCase(Locale.ROOT);

                countByCountry.merge(country, 1L, Long::sum);

                Double s = countryScores.get(country);
                if (s != null) {
                    scoreByCountry.merge(country, s, Double::sum);
                }
            }
        }

        System.out.println("Zeilen gelesen     : " + lines);
        System.out.println("Zertifikate gefunden : " + certs);
        System.out.println("Zertifikate geparst  : " + parsed);

        System.out.println("\nVerteilung nach Land (Zertifikatsaussteller / Subject-Country):");
        List<Map.Entry<String, Long>> list = new ArrayList<>(countByCountry.entrySet());
        list.sort((a, b) -> Long.compare(b.getValue(), a.getValue()));

        for (Map.Entry<String, Long> e : list) {
            String c = e.getKey();
            long count = e.getValue();
            Double sc = scoreByCountry.get(c);
            String scoreStr = (sc != null) ? String.format(Locale.ROOT, "%.4f", sc) : "-";
            System.out.printf(Locale.ROOT, "%-4s  %,10d  ScoreSum=%s%n", c, count, scoreStr);
        }

        double totalScore = scoreByCountry.values().stream().mapToDouble(Double::doubleValue).sum();
        System.out.println("\nGesamtscore (Summe aller Länderscores): " + String.format(Locale.ROOT, "%.4f", totalScore));
    }

    private X509Certificate pemToX509(String pem) {
        try {
            String normalized = pem.replace("-----BEGIN CERTIFICATE-----", "")
                    .replace("-----END CERTIFICATE-----", "")
                    .replaceAll("\\s+", "");
            byte[] der = Base64.getDecoder().decode(normalized);
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
                    System.err.println("[Analyzer] country_trustscores.json nicht in Ressourcen gefunden.");
                }
            }
        } catch (Exception e) {
            System.err.println("[Analyzer] Fehler beim Laden der Länderscores: " + e.getMessage());
        }
        return m;
    }

    private Map<String, Double> normalizeScores(Map<String, Double> raw) {
        Map<String, Double> out = new HashMap<>();
        double sum = 0.0;
        for (Map.Entry<String, Double> e : raw.entrySet()) {
            if (e.getKey() == null || e.getValue() == null) continue;
            String k = e.getKey().trim().toUpperCase(Locale.ROOT);
            double v = e.getValue();
            if (v <= 0) continue;
            out.put(k, v);
            sum += v;
        }
        if (sum <= 0) return out;
        for (Map.Entry<String, Double> e : out.entrySet()) {
            out.put(e.getKey(), e.getValue() / sum);
        }
        return out;
    }
}
