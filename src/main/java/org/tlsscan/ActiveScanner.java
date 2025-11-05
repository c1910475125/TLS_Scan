package org.tlsscan;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import javax.net.ssl.*;
import javax.net.ssl.SNIHostName;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.InputStream;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.cert.CertificateFactory;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.Base64;
import java.util.concurrent.*;

public class ActiveScanner {

    private final ObjectMapper mapper = new ObjectMapper();
    private static final DateTimeFormatter TS_FMT =
            DateTimeFormatter.ISO_OFFSET_DATE_TIME.withZone(ZoneOffset.UTC);

    // einfache Klassifikation, Schwellen kannst du bei Bedarf anpassen
    private static final double TRUST_HIGH_THRESHOLD = 0.75;
    private static final double TRUST_MEDIUM_THRESHOLD = 0.50;

    public void scan(List<String> rawTargets,
                     List<Integer> ports,
                     Path output,
                     String countryScoresPath,
                     boolean debug,
                     int timeoutMs,
                     int concurrency,
                     Double ratePerSecond,
                     String scanRunId) throws IOException, InterruptedException {

        if (rawTargets == null || rawTargets.isEmpty()) {
            System.out.println("Keine Ziele angegeben – Scan wird abgebrochen.");
            return;
        }

        if (ports == null || ports.isEmpty()) {
            ports = Collections.singletonList(443);
        }

        // WICHTIG: eigene (final) runId erzeugen, damit im Lambda nutzbar
        final String runId = (scanRunId == null || scanRunId.isBlank())
                ? UUID.randomUUID().toString()
                : scanRunId;

        Map<String, Double> trustScores = loadCountryScoresWithFallback(countryScoresPath);

        if (output.getParent() != null) {
            Files.createDirectories(output.getParent());
        }

        final String runStartedAt = TS_FMT.format(Instant.now());

        // alle (host,port)-Paare vorbereiten
        List<ScanTarget> targets = buildTargets(rawTargets, ports, debug);
        if (targets.isEmpty()) {
            System.out.println("Keine gültigen Zielkombinationen – nichts zu tun.");
            return;
        }

        System.out.println("Starte aktiven Scan mit " + targets.size() +
                " Ziel-Kombinationen, concurrency=" + concurrency +
                (ratePerSecond != null && ratePerSecond > 0 ? (", rate≈" + ratePerSecond + "/s") : "") +
                ", runId=" + runId);

        ExecutorService pool = Executors.newFixedThreadPool(concurrency);
        List<Future<?>> futures = new ArrayList<>();

        final double intervalMs = (ratePerSecond != null && ratePerSecond > 0)
                ? 1000.0 / ratePerSecond
                : 0;
        final long[] nextSubmitAt = {System.currentTimeMillis()};

        try (BufferedWriter bw = Files.newBufferedWriter(
                output,
                StandardCharsets.UTF_8,
                StandardOpenOption.CREATE,
                StandardOpenOption.APPEND
        )) {
            for (ScanTarget t : targets) {
                // einfaches Rate-Limit: Einreichrate steuern
                if (intervalMs > 0) {
                    long now = System.currentTimeMillis();
                    synchronized (nextSubmitAt) {
                        long wait = (long) Math.ceil(nextSubmitAt[0] - now);
                        if (wait > 0) {
                            try {
                                Thread.sleep(wait);
                            } catch (InterruptedException ie) {
                                Thread.currentThread().interrupt();
                                throw ie;
                            }
                        }
                        nextSubmitAt[0] = System.currentTimeMillis() + (long) intervalMs;
                    }
                }

                Future<?> f = pool.submit(() -> {
                    try {
                        TlsResult res = fetchCertificateChain(t.host, t.port, timeoutMs, debug);
                        if (res == null || res.chain == null || res.chain.isEmpty()) {
                            return;
                        }

                        X509Certificate leaf = res.chain.get(0);

                        String issuerDn = leaf.getIssuerX500Principal().getName();
                        String issuerCountry = extractCountryFromDn(issuerDn);
                        String issuerIso = issuerCountry != null
                                ? issuerCountry.trim().toUpperCase(Locale.ROOT)
                                : "UNKNOWN";
                        Double ts = trustScores.get(issuerIso);
                        String tsClass = null;
                        if (ts != null) {
                            if (ts >= TRUST_HIGH_THRESHOLD) {
                                tsClass = "high";
                            } else if (ts >= TRUST_MEDIUM_THRESHOLD) {
                                tsClass = "medium";
                            } else {
                                tsClass = "critical";
                            }
                        }

                        String observedAt = TS_FMT.format(Instant.now());
                        String ip = null;
                        try {
                            InetAddress addr = InetAddress.getByName(t.host);
                            ip = addr.getHostAddress();
                        } catch (Exception ignored) {}

                        ObjectNode root = mapper.createObjectNode();
                        root.put("source", "active-scan");

                        ObjectNode scanNode = root.putObject("scan");
                        scanNode.put("run_id", runId);
                        scanNode.put("run_started_at", runStartedAt);
                        scanNode.put("observed_at", observedAt);
                        scanNode.put("host", t.host);
                        if (ip != null) {
                            scanNode.put("ip", ip);
                        }
                        scanNode.put("port", t.port);
                        if (res.protocol != null) {
                            scanNode.put("tls_version", res.protocol);
                        }
                        if (res.cipherSuite != null) {
                            scanNode.put("cipher_suite", res.cipherSuite);
                        }
                        scanNode.put("issuer_country", issuerIso);
                        if (ts != null) {
                            scanNode.put("issuer_trustscore", ts);
                        }
                        if (tsClass != null) {
                            scanNode.put("issuer_trust_class", tsClass);
                        }

                        ObjectNode dataNode = root.putObject("data");

                        // TLS-Metadaten
                        ObjectNode tlsNode = dataNode.putObject("tls");
                        if (res.protocol != null) {
                            tlsNode.put("protocol", res.protocol);
                        }
                        if (res.cipherSuite != null) {
                            tlsNode.put("cipher_suite", res.cipherSuite);
                        }
                        if (res.alpn != null) {
                            tlsNode.put("alpn", res.alpn);
                        }

                        // Leaf-Zertifikat + Meta
                        ObjectNode leafNode = dataNode.putObject("leaf_cert");
                        leafNode.put("pem", toPem(leaf));
                        leafNode.put("subject", leaf.getSubjectX500Principal().getName());
                        leafNode.put("issuer", issuerDn);
                        leafNode.put("serial_hex", leaf.getSerialNumber().toString(16));
                        leafNode.put("not_before", leaf.getNotBefore().toInstant().toString());
                        leafNode.put("not_after", leaf.getNotAfter().toInstant().toString());

                        ObjectNode leafMeta = dataNode.putObject("leaf_meta");
                        addLeafMeta(leaf, leafMeta);

                        // gesamte Chain
                        ArrayNode chainNode = dataNode.putArray("chain");
                        for (X509Certificate c : res.chain) {
                            ObjectNode cNode = chainNode.addObject();
                            cNode.put("pem", toPem(c));
                            cNode.put("subject", c.getSubjectX500Principal().getName());
                            cNode.put("issuer", c.getIssuerX500Principal().getName());
                        }

                        synchronized (bw) {
                            bw.write(mapper.writeValueAsString(root));
                            bw.newLine();
                        }

                        if (debug) {
                            System.out.println("OK: " + t.host + ":" + t.port +
                                    "  issuerCountry=" + issuerIso +
                                    "  ts=" + (ts == null ? "n/a" : ts) +
                                    (tsClass != null ? " (" + tsClass + ")" : "") +
                                    "  tls=" + res.protocol + " " + res.cipherSuite);
                        }

                    } catch (Exception e) {
                        if (debug) {
                            System.err.println("Fehler bei " + t.host + ":" + t.port + " -> " +
                                    e.getClass().getSimpleName() + ": " + e.getMessage());
                        }
                    }
                });
                futures.add(f);
            }

            // auf alle Tasks warten
            for (Future<?> f : futures) {
                try {
                    f.get();
                } catch (ExecutionException e) {
                    if (debug) {
                        System.err.println("Task-Fehler: " + e.getCause());
                    }
                }
            }

        } finally {
            pool.shutdownNow();
        }

        System.out.println("Aktiver Scan abgeschlossen. Output: " + output);
    }

    private static class ScanTarget {
        final String host;
        final int port;
        ScanTarget(String host, int port) {
            this.host = host;
            this.port = port;
        }
    }

    private static class TlsResult {
        final List<X509Certificate> chain;
        final String protocol;
        final String cipherSuite;
        final String alpn;
        TlsResult(List<X509Certificate> chain, String protocol, String cipherSuite, String alpn) {
            this.chain = chain;
            this.protocol = protocol;
            this.cipherSuite = cipherSuite;
            this.alpn = alpn;
        }
    }

    private List<ScanTarget> buildTargets(List<String> rawTargets,
                                          List<Integer> ports,
                                          boolean debug) {
        List<ScanTarget> result = new ArrayList<>();
        for (String raw : rawTargets) {
            if (raw == null) continue;
            String target = raw.trim();
            if (target.isEmpty()) continue;

            String host = target;
            Integer explicitPort = null;

            int idx = target.lastIndexOf(':');
            if (idx > 0 && idx < target.length() - 1 && !target.startsWith("[")) {
                host = target.substring(0, idx);
                try {
                    explicitPort = Integer.parseInt(target.substring(idx + 1));
                } catch (NumberFormatException e) {
                    if (debug) {
                        System.err.println("Port aus '" + target + "' konnte nicht geparst werden, nutze nur Standardports.");
                    }
                    explicitPort = null;
                    host = target;
                }
            }

            if (explicitPort != null) {
                result.add(new ScanTarget(host, explicitPort));
            } else {
                for (int p : ports) {
                    result.add(new ScanTarget(host, p));
                }
            }
        }
        return result;
    }

    private TlsResult fetchCertificateChain(String host,
                                            int port,
                                            int timeoutMs,
                                            boolean debug) throws Exception {
        SSLContext ctx = SSLContext.getInstance("TLS");
        ctx.init(null, new TrustManager[]{new TrustAllManager()}, new SecureRandom());
        SSLSocketFactory factory = ctx.getSocketFactory();

        try (SSLSocket socket = (SSLSocket) factory.createSocket()) {
            socket.connect(new InetSocketAddress(host, port), timeoutMs);
            socket.setSoTimeout(timeoutMs);

            // SNI + ALPN
            SSLParameters params = socket.getSSLParameters();
            try {
                params.setServerNames(Collections.singletonList(new SNIHostName(host)));
            } catch (IllegalArgumentException ignored) {
                // host ist eventuell keine gültige SNI-Hostname – dann einfach ohne SNI
            }
            try {
                params.setApplicationProtocols(new String[]{"h2", "http/1.1"});
            } catch (UnsupportedOperationException ignored) {
                // ältere Java-Version
            }
            socket.setSSLParameters(params);

            socket.startHandshake();

            SSLSession session = socket.getSession();
            Certificate[] peer = session.getPeerCertificates();
            List<X509Certificate> chain = new ArrayList<>();
            for (Certificate c : peer) {
                if (c instanceof X509Certificate x) {
                    chain.add(x);
                }
            }
            if (chain.isEmpty()) {
                if (debug) {
                    System.err.println("Keine Zertifikate von " + host + ":" + port + " erhalten.");
                }
                return null;
            }

            String protocol = session.getProtocol();
            String cipherSuite = session.getCipherSuite();
            String alpn = null;
            try {
                alpn = socket.getApplicationProtocol();
            } catch (UnsupportedOperationException ignored) {}

            return new TlsResult(chain, protocol, cipherSuite, alpn);
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
        String b64 = Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.US_ASCII))
                .encodeToString(der);
        return "-----BEGIN CERTIFICATE-----\n" + b64 + "\n-----END CERTIFICATE-----\n";
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

    private void addLeafMeta(X509Certificate cert, ObjectNode metaNode) {
        try {
            String sigAlg = cert.getSigAlgName();
            metaNode.put("sig_alg", sigAlg);

            String pubKeyAlgo = cert.getPublicKey().getAlgorithm();
            metaNode.put("pubkey_algo", pubKeyAlgo);

            Integer keySize = null;
            if (cert.getPublicKey() instanceof RSAPublicKey rsa) {
                keySize = rsa.getModulus().bitLength();
            } else if (cert.getPublicKey() instanceof ECPublicKey ec) {
                keySize = ec.getParams().getCurve().getField().getFieldSize();
            }
            if (keySize != null) {
                metaNode.put("key_size", keySize);
            }

            metaNode.put("not_before", cert.getNotBefore().toInstant().toString());
            metaNode.put("not_after", cert.getNotAfter().toInstant().toString());

            long validityDays = (cert.getNotAfter().getTime() - cert.getNotBefore().getTime()) / (1000L * 60 * 60 * 24);
            metaNode.put("validity_days", validityDays);

            boolean weakKey = (keySize != null && keySize < 2048 && "RSA".equalsIgnoreCase(pubKeyAlgo));
            boolean weakSig = sigAlg != null && sigAlg.toUpperCase(Locale.ROOT).contains("SHA1");

            metaNode.put("weak_key", weakKey);
            metaNode.put("weak_sigalg", weakSig);
            metaNode.put("long_lived_cert", validityDays > 398);

            try {
                if (cert.getSubjectAlternativeNames() != null) {
                    int sanCount = cert.getSubjectAlternativeNames().size();
                    metaNode.put("san_count", sanCount);
                }
            } catch (java.security.cert.CertificateParsingException ignored) {}

        } catch (Exception e) {
            metaNode.put("meta_error", e.getClass().getSimpleName() + ": " + e.getMessage());
        }
    }
}
