package org.tlsscan;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.io.*;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.concurrent.TimeUnit;

public class CtPoller {

    private final String logBaseUrl;
    private final long startIndex;
    private final int batchSize;
    private final int sleepMs;
    private final long maxEntries;
    private final Path outputPath;
    private final boolean certOnly;
    private final boolean noProgress;
    private final boolean debug;

    private final ObjectMapper mapper = new ObjectMapper();

    public CtPoller(String logBaseUrl,
                    long startIndex,
                    int batchSize,
                    int sleepMs,
                    long maxEntries,
                    Path outputPath,
                    boolean certOnly,
                    boolean noProgress,
                    boolean debug) {
        this.logBaseUrl = logBaseUrl;
        this.startIndex = startIndex;
        this.batchSize = batchSize;
        this.sleepMs = sleepMs;
        this.maxEntries = maxEntries;
        this.outputPath = outputPath;
        this.certOnly = certOnly;
        this.noProgress = noProgress;
        this.debug = debug;
    }

    public void run() throws Exception {
        HttpClient client = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(20))
                .build();

        try (BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(
                new FileOutputStream(outputPath.toFile(), true),
                StandardCharsets.UTF_8))) {

            long idx = startIndex;
            long written = 0;

            while (true) {
                long remaining = (maxEntries > 0) ? (maxEntries - written) : Long.MAX_VALUE;
                if (remaining <= 0) break;

                int take = (int) Math.min(batchSize, remaining);
                long end = idx + take - 1;
                String url = normalize(logBaseUrl) + "/ct/v1/get-entries?start=" + idx + "&end=" + end;

                if (debug) System.out.println("GET " + url);
                HttpRequest req = HttpRequest.newBuilder().GET().uri(URI.create(url))
                        .timeout(Duration.ofSeconds(30)).build();
                HttpResponse<String> resp = client.send(req, HttpResponse.BodyHandlers.ofString());
                if (resp.statusCode() != 200) {
                    System.err.println("HTTP " + resp.statusCode() + " bei " + url);
                    TimeUnit.MILLISECONDS.sleep(Math.max(1000, sleepMs));
                    continue;
                }

                JsonNode root = mapper.readTree(resp.body());
                JsonNode entries = root.path("entries");
                if (!entries.isArray() || entries.size() == 0) {
                    System.out.println("Keine weiteren Einträge. Stoppe.");
                    break;
                }

                for (JsonNode entry : entries) {
                    ObjectNode out = convertEntry(entry);
                    if (out == null) continue;
                    String json = mapper.writeValueAsString(out);
                    writer.write(json);
                    writer.write("\n");
                    written++;
                    if (!noProgress && written % 100 == 0) {
                        System.out.printf("[CT-Poll] Geschrieben: %,d (Index ab %d)%n",
                                written, startIndex);
                    }
                    if (maxEntries > 0 && written >= maxEntries) {
                        break;
                    }
                }

                idx = end + 1;

                if (maxEntries > 0 && written >= maxEntries) {
                    System.out.println("Maximale Anzahl Einträge erreicht.");
                    break;
                }

                TimeUnit.MILLISECONDS.sleep(sleepMs);
            }

            System.out.println("CT-Poll fertig. Geschriebene Einträge: " + written +
                    " -> " + outputPath);
        }
    }

    private String normalize(String base) {
        if (base.endsWith("/")) {
            return base.substring(0, base.length() - 1);
        }
        return base;
    }

    private ObjectNode convertEntry(JsonNode entry) {
        try {
            String leafB64 = entry.path("leaf_input").asText(null);
            if (leafB64 == null) return null;

            byte[] leafBytes = Base64.getDecoder().decode(leafB64);
            if (leafBytes.length < 4) return null;

            int len = ((leafBytes[0] & 0xff) << 8) | (leafBytes[1] & 0xff);
            if (leafBytes.length < 4 + len) return null;

            byte[] certDer = new byte[len];
            System.arraycopy(leafBytes, 4, certDer, 0, len);

            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            X509Certificate cert = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(certDer));

            String pem = derToPem(certDer);

            ObjectNode data = mapper.createObjectNode();
            ObjectNode leaf = mapper.createObjectNode();
            leaf.put("pem", pem);
            data.set("leaf_cert", leaf);

            if (!certOnly) {
                data.put("subject", cert.getSubjectX500Principal().getName());
                data.put("issuer", cert.getIssuerX500Principal().getName());
                data.put("not_before", cert.getNotBefore().toInstant().toString());
                data.put("not_after", cert.getNotAfter().toInstant().toString());
            }

            ObjectNode root = mapper.createObjectNode();
            root.put("message_type", "ct_poll");
            root.set("data", data);
            return root;
        } catch (Exception e) {
            if (debug) {
                System.err.println("[CT-Poll] Fehler beim Konvertieren eines Eintrags: " + e.getMessage());
            }
            return null;
        }
    }

    private String derToPem(byte[] der) {
        String b64 = Base64.getEncoder().encodeToString(der);
        StringBuilder sb = new StringBuilder();
        sb.append("-----BEGIN CERTIFICATE-----\n");
        for (int i = 0; i < b64.length(); i += 64) {
            int end = Math.min(i + 64, b64.length());
            sb.append(b64, i, end).append("\n");
        }
        sb.append("-----END CERTIFICATE-----\n");
        return sb.toString();
    }
}
