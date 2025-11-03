package org.tlsscan;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.core.type.TypeReference;

import java.io.*;
import java.nio.file.*;
import java.security.KeyStore;
import java.security.cert.*;
import java.util.*;
import java.util.stream.Collectors;
import java.util.Base64;
import java.util.Locale;

public class StoreScorer {

    private final ObjectMapper mapper = new ObjectMapper();

    public double scoreStore(String path, String type, String password,
                             String countryScoresPath, String countryFrom, boolean includeNonCa) throws Exception {

        Map<String, Double> scoreByIso2 = loadCountryScoresWithFallback(countryScoresPath);
        List<X509Certificate> certs = loadCertificates(path, type, password);

        List<X509Certificate> considered = certs.stream()
                .filter(c -> includeNonCa || isCaCert(c))
                .collect(Collectors.toList());

        if (considered.isEmpty()) {
            System.out.println("Keine (passenden) Zertifikate im Store gefunden.");
            return 0.0;
        }

        Map<String, Integer> countByCountry = new HashMap<>();
        for (X509Certificate c : considered) {
            String dn = "issuer".equalsIgnoreCase(countryFrom)
                    ? c.getIssuerX500Principal().getName()
                    : c.getSubjectX500Principal().getName();
            String country = extractCountry(dn);
            if (country == null || country.isBlank()) country = "UNKNOWN";
            country = country.toUpperCase(Locale.ROOT);
            countByCountry.merge(country, 1, Integer::sum);
        }

        int total = considered.size();
        System.out.println("=== Zusammenfassung ===");
        System.out.println("Berücksichtigte Zertifikate: " + total + (includeNonCa ? " (inkl. Nicht-CA)" : " (nur CAs)"));
        System.out.println("Landebasis: " + ("issuer".equalsIgnoreCase(countryFrom) ? "Issuer (Aussteller)" : "Subject (Inhaber)"));
        System.out.println();
        System.out.println(String.format("%-6s %10s %12s %14s %14s",
                "Land", "Anzahl", "Anteil(%)", "TrustScore", "Teilbetrag"));

        double weighted = 0.0;
        List<Map.Entry<String,Integer>> rows = new ArrayList<>(countByCountry.entrySet());
        rows.sort(Map.Entry.<String,Integer>comparingByValue().reversed());

        for (Map.Entry<String,Integer> e : rows) {
            String iso2 = e.getKey();
            int cnt = e.getValue();
            double frac = (double) cnt / (double) total;
            Double ts = scoreByIso2.get(iso2);
            double part = ts == null ? 0.0 : ts * frac;

            System.out.println(String.format(Locale.ROOT, "%-6s %10d %12.2f %14s %14.6f",
                    iso2, cnt, 100.0 * frac, ts == null ? "n/a" : String.format(Locale.ROOT, "%.6f", ts), part));

            if (ts != null) weighted += part;
        }

        return weighted;
    }

    private Map<String, Double> loadCountryScoresWithFallback(String path) throws IOException {
        if (path != null && !path.isBlank()) {
            Path p = Paths.get(path);
            if (Files.exists(p)) {
                try (InputStream in = Files.newInputStream(p)) {
                    return normalizeScores(mapper.readValue(in, new TypeReference<Map<String, Double>>(){}));
                }
            }
        }
        try (InputStream in = Thread.currentThread().getContextClassLoader()
                .getResourceAsStream("country_trustscores.json")) {
            if (in == null) {
                throw new FileNotFoundException("country_trustscores.json nicht gefunden (Pfad und Classpath geprüft).");
            }
            return normalizeScores(mapper.readValue(in, new TypeReference<Map<String, Double>>(){}));
        }
    }

    private Map<String, Double> normalizeScores(Map<String, Double> m) {
        Map<String, Double> norm = new HashMap<>();
        for (var e : m.entrySet()) {
            norm.put(e.getKey().trim().toUpperCase(Locale.ROOT), e.getValue());
        }
        return norm;
    }

    private List<X509Certificate> loadCertificates(String path, String type, String password) throws Exception {
        switch (type.toLowerCase(Locale.ROOT)) {
            case "jks":
                return loadFromKeyStore(path, "JKS", password);
            case "pkcs12":
                return loadFromKeyStore(path, "PKCS12", password);
            case "pem-bundle":
                return loadFromPemBundle(path);
            case "pem-dir":
                return loadFromPemDir(path);
            default:
                throw new IllegalArgumentException("Unbekannter Store-Typ: " + type);
        }
    }

    private List<X509Certificate> loadFromKeyStore(String path, String ksType, String password) throws Exception {
        KeyStore ks = KeyStore.getInstance(ksType);
        try (InputStream in = Files.newInputStream(Paths.get(path))) {
            ks.load(in, password != null ? password.toCharArray() : null);
        }
        List<X509Certificate> list = new ArrayList<>();
        Enumeration<String> aliases = ks.aliases();
        while (aliases.hasMoreElements()) {
            String alias = aliases.nextElement();
            Certificate cert = ks.getCertificate(alias);
            if (cert instanceof X509Certificate x) {
                list.add(x);
            } else if (cert == null) {
                Certificate[] chain = ks.getCertificateChain(alias);
                if (chain != null) for (Certificate c : chain) if (c instanceof X509Certificate x2) list.add(x2);
            }
        }
        return list;
    }

    private List<X509Certificate> loadFromPemBundle(String path) throws Exception {
        String pem = Files.readString(Paths.get(path));
        return parsePemCertificates(pem);
    }

    private List<X509Certificate> loadFromPemDir(String dir) throws Exception {
        List<X509Certificate> out = new ArrayList<>();
        try (var s = Files.walk(Paths.get(dir))) {
            for (Path p : s.filter(Files::isRegularFile).toList()) {
                String name = p.getFileName().toString().toLowerCase(Locale.ROOT);
                if (name.endsWith(".pem") || name.endsWith(".crt") || name.endsWith(".cer")) {
                    String pem = Files.readString(p);
                    out.addAll(parsePemCertificates(pem));
                }
            }
        }
        return out;
    }

    private List<X509Certificate> parsePemCertificates(String pem) throws Exception {
        List<X509Certificate> list = new ArrayList<>();
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        String[] blocks = pem.split("-----END CERTIFICATE-----");
        for (String b : blocks) {
            int start = b.indexOf("-----BEGIN CERTIFICATE-----");
            if (start >= 0) {
                String one = b.substring(start) + "-----END CERTIFICATE-----";
                String cleaned = one.replaceAll("-----BEGIN CERTIFICATE-----", "")
                        .replaceAll("-----END CERTIFICATE-----", "")
                        .replaceAll("\\s", "");
                byte[] der = Base64.getDecoder().decode(cleaned);
                try (ByteArrayInputStream bin = new ByteArrayInputStream(der)) {
                    list.add((X509Certificate) cf.generateCertificate(bin));
                }
            }
        }
        return list;
    }

    private boolean isCaCert(X509Certificate c) {
        try {
            if (c.getBasicConstraints() >= 0) return true; // CA
            boolean[] ku = c.getKeyUsage();
            if (ku != null && ku.length > 5 && ku[5]) return true; // keyCertSign
        } catch (Exception ignored) {}
        return false;
    }

    private String extractCountry(String dn) {
        String[] parts = dn.split(",");
        for (String p : parts) {
            String[] kv = p.trim().split("=");
            if (kv.length == 2 && kv[0].equalsIgnoreCase("C")) return kv[1].trim();
        }
        return null;
    }
}
