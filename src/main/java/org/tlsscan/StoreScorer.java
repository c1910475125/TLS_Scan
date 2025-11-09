package org.tlsscan;

import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.*;

public class StoreScorer {

    private final ObjectMapper mapper = new ObjectMapper();

    public void scoreStore(Path storePath,
                           char[] password,
                           String countryScoresPath) throws Exception {

        KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
        try (InputStream in = Files.newInputStream(storePath)) {
            ks.load(in, password);
        }

        Map<String, Double> countryScores = loadCountryScoresWithFallback(countryScoresPath);

        Enumeration<String> aliases = ks.aliases();

        Map<String, Long> countByCountry = new HashMap<>();
        Map<String, Double> scoreByCountry = new HashMap<>();

        long totalCerts = 0;
        while (aliases.hasMoreElements()) {
            String alias = aliases.nextElement();
            if (!ks.isCertificateEntry(alias) && !ks.isKeyEntry(alias)) {
                continue;
            }

            java.security.cert.Certificate c = ks.getCertificate(alias);
            if (!(c instanceof X509Certificate)) {
                continue;
            }
            totalCerts++;

            X509Certificate cert = (X509Certificate) c;

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

        System.out.println("Store: " + storePath);
        System.out.println("Zertifikate im Store: " + totalCerts);

        System.out.println("\nVerteilung nach Land (Issuer/Subject):");
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
        System.out.println("\nGesamtscore (Summe aller Länderscores im Store): " +
                String.format(Locale.ROOT, "%.4f", totalScore));
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
                Path p = Paths.get(path);
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
                    System.err.println("[StoreScorer] country_trustscores.json nicht in Ressourcen gefunden.");
                }
            }
        } catch (Exception e) {
            System.err.println("[StoreScorer] Fehler beim Laden der Länderscores: " + e.getMessage());
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
