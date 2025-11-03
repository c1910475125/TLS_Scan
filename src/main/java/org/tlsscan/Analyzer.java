package org.tlsscan;

import com.fasterxml.jackson.databind.*;
import java.io.*;
import java.security.cert.*;
import java.util.*;
import java.util.Base64;

public class Analyzer {
    private final ObjectMapper mapper = new ObjectMapper();

    public void processJsonl(String inputFile, boolean trustedByCountry) {
        Map<String, Integer> byCountry = new HashMap<>();
        int total = 0, parsed = 0;

        try (BufferedReader br = new BufferedReader(new FileReader(inputFile))) {
            String line;
            while ((line = br.readLine()) != null) {
                if (line.isBlank()) continue;
                total++;
                JsonNode node = mapper.readTree(line);
                JsonNode data = node.path("data");
                String pem = null;
                JsonNode leaf = data.path("leaf_cert");
                if (!leaf.isMissingNode()) {
                    if (leaf.has("pem")) pem = leaf.get("pem").asText(null);
                    else if (leaf.has("as_pem")) pem = leaf.get("as_pem").asText(null);
                    else if (leaf.has("certificate")) pem = leaf.get("certificate").asText(null);
                }
                if (pem == null) {
                    JsonNode chain = data.path("chain");
                    if (chain.isArray() && chain.size() > 0) {
                        JsonNode first = chain.get(0);
                        pem = first.has("pem") ? first.get("pem").asText(null) : first.asText(null);
                    }
                }
                if (pem == null) continue;

                X509Certificate cert = pemToX509(pem);
                if (cert == null) continue;
                parsed++;

                String c = extractCountryFromSubject(cert);
                if (c == null) c = "UNKNOWN";
                byCountry.merge(c.toUpperCase(Locale.ROOT), 1, Integer::sum);
            }

            System.out.printf("Total events: %d; parsed certs: %d%n", total, parsed);
            System.out.println("Certificates per country (subject C=):");
            byCountry.entrySet().stream()
                    .sorted(Map.Entry.<String,Integer>comparingByValue().reversed())
                    .forEach(e -> System.out.printf("  %s: %d%n", e.getKey(), e.getValue()));

            if (trustedByCountry) {
                System.out.println("\n(Hinweis) Vertrauensprüfung: ggf. PKIX-Validierung gegen lokalen Truststore ergänzen.");
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
        } catch (Exception e) { return null; }
    }

    private String extractCountryFromSubject(X509Certificate cert) {
        try {
            String dn = cert.getSubjectX500Principal().getName();
            String[] parts = dn.split(",");
            for (String p : parts) {
                String[] kv = p.trim().split("=");
                if (kv.length == 2 && kv[0].equalsIgnoreCase("C")) return kv[1];
            }
        } catch (Exception ignored) {}
        return null;
    }
}
