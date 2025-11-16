package org.tlsscan;

import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;

/**
 * Gemeinsame Hilfsfunktionen für:
 *  - Ländercodes aus DNs extrahieren
 *  - country_trustscores.json laden (mit Fallback auf Ressourcen)
 *  - Scores normalisieren
 */
public final class CountryTrustUtil {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private CountryTrustUtil() {
        // Utility-Klasse
    }

    public static String extractCountryFromDn(String dn) {
        if (dn == null) return null;
        String[] parts = dn.split(",");
        for (String part : parts) {
            String p = part.trim();
            if (p.toUpperCase(Locale.ROOT).startsWith("C=")) {
                String value = p.substring(2).trim();
                if (!value.isEmpty()) {
                    int idx = value.indexOf(' ');
                    if (idx > 0) {
                        value = value.substring(0, idx);
                    }
                    return value.toUpperCase(Locale.ROOT);
                }
            }
        }
        return null;
    }

    public static Map<String, Double> loadCountryScoresWithFallback(String explicitPath) throws IOException {
        Map<String, Double> result = new HashMap<>();

        // 1) expliziter Pfad (z.B. CLI-Option)
        if (explicitPath != null && !explicitPath.isBlank()) {
            Path p = Path.of(explicitPath);
            if (!Files.exists(p)) {
                throw new IOException("country_trustscores.json nicht gefunden: " + p);
            }
            try (InputStream in = Files.newInputStream(p)) {
                @SuppressWarnings("unchecked")
                Map<String, Double> m = MAPPER.readValue(in, Map.class);
                result.putAll(m);
            }
            return result;
        }

        // 2) Fallback: Ressource im Classpath
        try (InputStream in = CountryTrustUtil.class.getResourceAsStream("/country_trustscores.json")) {
            if (in == null) {
                throw new IOException("Ressource /country_trustscores.json nicht im Classpath gefunden.");
            }
            @SuppressWarnings("unchecked")
            Map<String, Double> m = MAPPER.readValue(in, Map.class);
            result.putAll(m);
        } catch (UncheckedIOException e) {
            throw e.getCause();
        }

        return result;
    }

    public static Map<String, Double> normalizeScores(Map<String, Double> raw) {
        Map<String, Double> out = new HashMap<>();
        for (Map.Entry<String, Double> e : raw.entrySet()) {
            if (e.getKey() == null || e.getValue() == null) continue;
            String k = e.getKey().trim().toUpperCase(Locale.ROOT);
            double v = e.getValue();
            if (v <= 0) continue;
            if (v > 1.0) v = 1.0;
            out.put(k, v);
        }
        return out;
    }
}
