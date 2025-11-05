package org.tlsscan;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import javax.net.ssl.*;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.*;
import java.util.Base64;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;

public class ActiveScanner {

    private final ObjectMapper mapper = new ObjectMapper();

    /**
     * Führt einen aktiven TLS-Scan durch und schreibt pro Ziel einen JSONL-Record.
     * Das JSON ist so aufgebaut, dass der bestehende Analyzer weiterverwendet werden kann:
     *
     * {
     *   "source": "active-scan",
     *   "scan": { "host": "...", "port": 443, "timestamp": "...", "issuer_country": "DE", "issuer_trustscore": 0.8 },
     *   "data": {
     *     "leaf_cert": { "pem": "-----BEGIN CERTIFICATE-----...", ... },
     *     "chain": [ { "pem": "...", ... }, ... ]
     *   }
     * }
     */
    public void scan(List<String> targets,
                     int defaultPort,
                     Path output,
                     String countryScoresPath,
                     boolean debug,
                     int timeoutMs) throws IOException {

        if (targets == null || targets.isEmpty()) {
            System.out.println("Keine Ziele angegeben – Scan wird abgebrochen.");
            return;
        }

        Map<String, Double> trustScores = loadCountryScoresWithFallback(countryScoresPath);

        if (output.getParent() != null) {
            Files.createDirectories(output.getParent());
        }

        DateTimeFormatter tsFmt = DateTimeFormatter.ISO_OFFSET_DATE_TIME.withZone(ZoneOffset.UTC);

        try (BufferedWriter bw = Files.newBufferedWriter(
                output,
                StandardCharsets.UTF_8,
                StandardOpenOption.CREATE,
                StandardOpenOption.APPEND
        )) {
            for (String raw : targets) {
                String target = raw.trim();
                if (target.isEmpty()) {
                    continue;
                }

                String host = target;
                int port = defaultPort;

                int idx = target.lastIndexOf(':');
                if (idx > 0 && idx < target.length() - 1) {
                    host = target.substring(0, idx);
                    try {
                        port = Integer.parseInt(target.substring(idx + 1));
                    } catch (NumberFormatException ignored) {
                        if (debug) {
                            System.err.println("Konnte Port aus '" + target + "' nicht parsen, verwende Defaultport " + defaultPort);
                        }
                        port = defaultPort;
                    }
                }

                if (debug) {
                    System.out.println("Scanne " + host + ":" + port + " …");
                }

                try {
                    List<X509Certificate> chain = fetchCertificateChain(host, port, timeoutMs);
                    if (chain.isEmpty()) {
                        if (debug) {
                            System.err.println("Keine Zertifikate von " + host + ":" + port + " erhalten.");
                        }
                        continue;
                    }

                    X509Certificate leaf = chain.get(0);
                    String issuerDn = leaf.getIssuerX500Principal().getName();
                    String issuerCountry = extractCountry(issuerDn);
                    String issuerIso = issuerCountry != null
                            ? issuerCountry.trim().toUpperCase(Locale.ROOT)
                            : "UNKNOWN";
                    Double ts = trustScores.get(issuerIso);

                    ObjectNode root = mapper.createObjectNode();
                    root.put("source", "active-scan");

                    ObjectNode scanNode = root.putObject("scan");
                    scanNode.put("host", host);
                    scanNode.put("port", port);
                    scanNode.put("timestamp", tsFmt.format(Instant.now()));
                    scanNode.put("issuer_country", issuerIso);
                    if (ts != null) {
                        scanNode.put("issuer_trustscore", ts);
                    }

                    ObjectNode dataNode = root.putObject("data");

                    ObjectNode leafNode = dataNode.putObject("leaf_cert");
                    leafNode.put("pem", toPem(leaf));
                    leafNode.put("subject", leaf.getSubjectX500Principal().getName());
                    leafNode.put("issuer", issuerDn);
                    leafNode.put("serial_hex", leaf.getSerialNumber().toString(16));
                    leafNode.put("not_before", leaf.getNotBefore().toInstant().toString());
                    leafNode.put("not_after", leaf.getNotAfter().toInstant().toString());

                    ArrayNode chainNode = dataNode.putArray("chain");
                    for (X509Certificate c : chain) {
                        ObjectNode cNode = chainNode.addObject();
                        cNode.put("pem", toPem(c));
                        cNode.put("subject", c.getSubjectX500Principal().getName());
                        cNode.put("issuer", c.getIssuerX500Principal().getName());
                    }

                    bw.write(mapper.writeValueAsString(root));
                    bw.newLine();
                    bw.flush();

                    if (debug) {
                        System.out.println("OK: " + host + ":" + port + "  issuerCountry=" + issuerIso + "  ts=" + (ts == null ? "n/a" : ts));
                    }
                } catch (Exception e) {
                    if (debug) {
                        System.err.println("Fehler bei " + host + ":" + port + " -> " + e.getClass().getSimpleName() + ": " + e.getMessage());
                    }
                }
            }
        }

        System.out.println("Aktiver Scan abgeschlossen. Output: " + output);
    }

    private List<X509Certificate> fetchCertificateChain(String host, int port, int timeoutMs) throws Exception {
        SSLContext ctx = SSLContext.getInstance("TLS");
        ctx.init(null, new TrustManager[]{new TrustAllManager()}, new SecureRandom());
        SSLSocketFactory factory = ctx.getSocketFactory();

        try (SSLSocket socket = (SSLSocket) factory.createSocket()) {
            socket.connect(new InetSocketAddress(host, port), timeoutMs);
            socket.setSoTimeout(timeoutMs);
            socket.startHandshake();

            SSLSession session = socket.getSession();
            Certificate[] peer = session.getPeerCertificates();
            List<X509Certificate> result = new ArrayList<>();
            for (Certificate c : peer) {
                if (c instanceof X509Certificate x) {
                    result.add(x);
                }
            }
            return result;
        }
    }

    private static class TrustAllManager implements X509TrustManager {
        @Override
        public void checkClientTrusted(X509Certificate[] x509Certificates, String s) { }
        @Override
        public void checkServerTrusted(X509Certificate[] x509Certificates, String s) { }
        @Override
        public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
    }

    private String toPem(X509Certificate cert) throws Exception {
        byte[] der = cert.getEncoded();
        String b64 = Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.US_ASCII)).encodeToString(der);
        return "-----BEGIN CERTIFICATE-----\n" + b64 + "\n-----END CERTIFICATE-----\n";
    }

    private Map<String, Double> loadCountryScoresWithFallback(String path) {
        Map<String, Double> m = new HashMap<>();
        try {
            if (path != null && !path.isBlank()) {
                Path p = Paths.get(path);
                if (Files.exists(p)) {
                    try (InputStream in = Files.newInputStream(p)) {
                        m.putAll(normalizeScores(mapper.readValue(in, mapper.getTypeFactory()
                                .constructMapType(Map.class, String.class, Double.class))));
                        return m;
                    }
                }
            }
            try (InputStream in = Thread.currentThread().getContextClassLoader()
                    .getResourceAsStream("country_trustscores.json")) {
                if (in != null) {
                    m.putAll(normalizeScores(mapper.readValue(in, mapper.getTypeFactory()
                            .constructMapType(Map.class, String.class, Double.class))));
                } else {
                    System.err.println("country_trustscores.json nicht gefunden – TrustScores werden nicht genutzt.");
                }
            }
        } catch (Exception e) {
            System.err.println("Konnte country_trustscores nicht laden: " + e.getMessage());
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

    private String extractCountry(String dn) {
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
}
