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
import java.util.concurrent.atomic.AtomicLong;

public class CtPoller {

    private final Path outputPath;
    private final boolean certOnly;
    private final boolean progress;
    private final boolean debug;
    private final ObjectMapper mapper = new ObjectMapper();

    public CtPoller(Path outputPath, boolean certOnly, boolean progress, boolean debug) {
        this.outputPath = outputPath;
        this.certOnly = certOnly;
        this.progress = progress;
        this.debug = debug;
    }

    public void run(String logBaseUrl, long startIndex, int batchSize, int sleepMs, long maxEntries) {
        HttpClient client = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(20))
                .build();

        AtomicLong written = new AtomicLong(0);
        long idx = startIndex;
        long remaining = maxEntries > 0 ? maxEntries : Long.MAX_VALUE;

        System.out.println("CT-Poll gestartet: " + logBaseUrl + "  -> " + outputPath);

        try (BufferedWriter bw = new BufferedWriter(new OutputStreamWriter(new FileOutputStream(outputPath.toFile(), true), StandardCharsets.UTF_8))) {
            Instant t0 = Instant.now();
            while (remaining > 0) {
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
                JsonNode entries = root.get("entries");
                if (entries == null || !entries.isArray() || entries.size() == 0) {
                    if (debug) System.out.println("Keine Einträge (leer). Warte …");
                    TimeUnit.MILLISECONDS.sleep(Math.max(1000, sleepMs));
                    continue;
                }

                int processed = 0;
                for (JsonNode e : entries) {
                    String leafInputB64 = e.path("leaf_input").asText(null);
                    String extraDataB64 = e.path("extra_data").asText(null);

                    String pem = null;
                    try {
                        if (leafInputB64 != null) {
                            byte[] leaf = Base64.getDecoder().decode(leafInputB64);
                            pem = pemFromLeafOrNull(leaf);
                        }
                        if (pem == null && extraDataB64 != null) {
                            byte[] extra = Base64.getDecoder().decode(extraDataB64);
                            pem = pemFromExtraOrNull(extra);
                        }
                    } catch (Exception ex) {
                        if (debug) System.out.println("Decode-Fehler: " + ex.getMessage());
                    }

                    ObjectNode data = mapper.createObjectNode();
                    ObjectNode leafCert = mapper.createObjectNode();
                    if (pem != null) leafCert.put("pem", pem);
                    data.set("leaf_cert", leafCert);
                    ObjectNode line = mapper.createObjectNode();
                    line.put("message_type", "certificate_update");
                    line.set("data", data);

                    String out = certOnly ? mapper.createObjectNode()
                            .put("message_type", "certificate_update")
                            .set("data", data).toString()
                            : line.toString();

                    bw.write(out);
                    bw.write("\n");
                    processed++;
                }

                bw.flush();

                written.addAndGet(processed);
                idx += processed;
                remaining -= processed;

                if (progress) {
                    double secs = Math.max(1, Duration.between(t0, Instant.now()).toSeconds());
                    double rate = written.get() / secs;
                    System.out.printf("\r[HTTP] Entries: %,d  (%.2f/s)  File: %s", written.get(), rate, outputPath);
                }

                if (sleepMs > 0) TimeUnit.MILLISECONDS.sleep(sleepMs);
            }
        } catch (Exception ex) {
            System.err.println("ct-poll Fehler: " + ex.getMessage());
        }

        if (progress) System.out.println("\nCT-Poll beendet. Geschriebene Einträge: " + written.get());
    }

    // --- Decoder-Helfer ---
    private String pemFromLeafOrNull(byte[] leaf) {
        if (leaf.length < 12) return null;
        int entryType = ((leaf[10] & 0xff) << 8) | (leaf[11] & 0xff);
        int pos = 12;
        if (entryType == 0) {
            if (leaf.length < pos + 3) return null;
            int certLen = uint24(leaf, pos); pos += 3;
            if (leaf.length < pos + certLen) return null;
            byte[] der = new byte[certLen];
            System.arraycopy(leaf, pos, der, 0, certLen);
            return derToPemIfValid(der);
        }
        return null;
    }

    private String pemFromExtraOrNull(byte[] extra) {
        try {
            if (extra.length >= 3) {
                int len = uint24(extra, 0);
                if (extra.length >= 3 + len) {
                    byte[] der = new byte[len];
                    System.arraycopy(extra, 3, der, 0, len);
                    return derToPemIfValid(der);
                }
            }
        } catch (Exception ignore) {}
        return null;
    }

    private static int uint24(byte[] a, int off) {
        return ((a[off] & 0xff) << 16) | ((a[off+1] & 0xff) << 8) | (a[off+2] & 0xff);
    }

    private String derToPemIfValid(byte[] der) {
        try {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            X509Certificate x = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(der));
            String b64 = java.util.Base64.getEncoder().encodeToString(der);
            StringBuilder sb = new StringBuilder();
            sb.append("-----BEGIN CERTIFICATE-----\n");
            for (int i=0;i<b64.length();i+=64) {
                sb.append(b64, i, Math.min(i+64, b64.length())).append("\n");
            }
            sb.append("-----END CERTIFICATE-----\n");
            return sb.toString();
        } catch (Exception e) { return null; }
    }

    private static String normalize(String base) {
        if (base.endsWith("/")) return base.substring(0, base.length()-1);
        return base;
    }
}
