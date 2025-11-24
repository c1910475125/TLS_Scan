package org.tlsscan;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.io.BufferedReader;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.*;

/**
 * Vergleicht zwei Scan-JSONL-Dateien (historischer Diff).
 *
 * - Liest beide JSONL-Dateien ähnlich wie Analyzer
 * - Aggregiert TLS-Versionen und Root-CA-Länder inkl. TrustScore
 * - Verknüpft pro Endpoint (ip/hostname:port) TLS-Version + Root-Zertifikat
 *   und erkennt so Chain-/Root-Wechsel.
 */
public class ScanDiff {

    private final ObjectMapper mapper = new ObjectMapper();

    public void compare(Path oldJsonl,
                        Path newJsonl,
                        String countryScoresPath,
                        boolean debug,
                        Path summaryOutput) throws IOException {

        Map<String, Double> countryScores =
                Util.normalizeScores(
                        Util.loadCountryScoresWithFallback(countryScoresPath)
                );

        ScanStats oldStats = computeStats(oldJsonl, countryScores, debug);
        ScanStats newStats = computeStats(newJsonl, countryScores, debug);

        printHumanReadableDiff(oldJsonl, newJsonl, oldStats, newStats, countryScores);

        if (summaryOutput != null) {
            writeDiffJson(summaryOutput, oldJsonl, newJsonl, oldStats, newStats);
        }
    }

    // --------------------------- Stats-Model ----------------------------

    public static class EndpointInfo {
        public final String endpoint;      // ip/hostname[:port]
        public final String tlsVersion;
        public final String cipherSuite;
        public final String rootCountry;
        public final String rootSubjectDn;
        public final String rootIssuerDn;

        public EndpointInfo(String endpoint,
                            String tlsVersion,
                            String cipherSuite,
                            String rootCountry,
                            String rootSubjectDn,
                            String rootIssuerDn) {
            this.endpoint = endpoint;
            this.tlsVersion = tlsVersion;
            this.cipherSuite = cipherSuite;
            this.rootCountry = rootCountry;
            this.rootSubjectDn = rootSubjectDn;
            this.rootIssuerDn = rootIssuerDn;
        }
    }

    public static class ScanStats {
        public long lines;
        public long chains;

        public final Map<String, Long> tlsVersionCounts = new HashMap<>();

        public final Map<String, Long> deprecatedTlsVersionCounts = new HashMap<>();

        public final Map<String, Long> cipherSuiteCounts = new HashMap<>();
        public final Map<String, Long> weakCipherSuiteCounts = new HashMap<>();

        public final Map<String, Long> keyAlgorithmCounts = new HashMap<>();
        public final Map<Integer, Long> keySizeCounts = new HashMap<>();
        public long weakKeyCount = 0L;

        public final Map<String, Long> signatureAlgorithmCounts = new HashMap<>();
        public long weakSignatureCount = 0L;

        public final Map<Integer, Long> chainLengthCounts = new HashMap<>();
        public long chainsWithWeakSig = 0L;


        public final Map<String, Long> countByCountry = new HashMap<>();
        public final Map<String, Long> countByCountryForScore = new HashMap<>();
        public final Map<String, Double> scoreByCountry = new HashMap<>();
        public double totalTrustScore;

        public final Map<String, EndpointInfo> endpoints = new HashMap<>();
    }

    // --------------------------- Kernlogik ----------------------------

    private ScanStats computeStats(Path inputJsonl,
                                   Map<String, Double> countryScores,
                                   boolean debug) throws IOException {

        ScanStats stats = new ScanStats();

        CertificateFactory cf;
        try {
            cf = CertificateFactory.getInstance("X.509");
        } catch (CertificateException e) {
            throw new IllegalStateException("Kann X.509 CertificateFactory nicht initialisieren", e);
        }

        try (BufferedReader br = Files.newBufferedReader(inputJsonl, StandardCharsets.UTF_8)) {
            String line;
            while ((line = br.readLine()) != null) {
                stats.lines++;
                line = line.trim();
                if (line.isEmpty()) continue;

                JsonNode root;
                try {
                    root = mapper.readTree(line);
                } catch (Exception e) {
                    if (debug) {
                        System.err.println("[ScanDiff] JSON-Parse-Fehler in Zeile " + stats.lines + ": " + e.getMessage());
                    }
                    continue;
                }

                JsonNode dataNode = root.path("data");
                if (!dataNode.isObject()) {
                    dataNode = null;
                }

                String endpoint = null;
                String tlsVersion = null;
                String cipherSuite = null;

                if (dataNode != null) {
                    tlsVersion = dataNode.path("tls_version").asText(null);
                    cipherSuite = dataNode.path("cipher_suite").asText(null);

                    if (tlsVersion != null && !tlsVersion.isBlank()) {
                        stats.tlsVersionCounts.merge(tlsVersion, 1L, Long::sum);
                        if (Util.isDeprecatedTlsVersion(tlsVersion)) {
                            stats.deprecatedTlsVersionCounts.merge(tlsVersion, 1L, Long::sum);
                        }
                    }

                    if (cipherSuite != null && !cipherSuite.isBlank()) {
                        stats.cipherSuiteCounts.merge(cipherSuite, 1L, Long::sum);
                        if (Util.isWeakCipherSuite(cipherSuite)) {
                            stats.weakCipherSuiteCounts.merge(cipherSuite, 1L, Long::sum);
                        }
                    }

                    endpoint = Util.extractEndpointFromRecord(dataNode);
                }

// Leaf- und Chain-Zertifikate aus JSONL (wie im Analyzer)
                X509Certificate leafCert = null;
                List<X509Certificate> chainCerts = new ArrayList<>();

                if (dataNode != null) {
                    String leafPem = dataNode.path("leaf_cert").path("pem").asText(null);
                    if (leafPem != null && !leafPem.isBlank()) {
                        Set<X509Certificate> tmp = new LinkedHashSet<>();
                        parsePemCertificates(leafPem, cf, tmp, debug);
                        if (!tmp.isEmpty()) {
                            leafCert = tmp.iterator().next();
                        }
                    }

                    JsonNode chainArr = dataNode.path("chain");
                    if (chainArr.isArray()) {
                        for (JsonNode cNode : chainArr) {
                            if (!cNode.isTextual()) continue;
                            String pem = cNode.asText();
                            if (pem == null || pem.isBlank()) continue;
                            Set<X509Certificate> tmp = new LinkedHashSet<>();
                            parsePemCertificates(pem, cf, tmp, debug);
                            chainCerts.addAll(tmp);
                        }
                    }
                }

// --- Key- & Signature-Infos aus Leaf ----------
                if (leafCert != null) {
                    java.security.PublicKey pk = leafCert.getPublicKey();
                    String keyAlg = (pk != null ? pk.getAlgorithm() : null);
                    if (keyAlg != null) {
                        stats.keyAlgorithmCounts.merge(keyAlg, 1L, Long::sum);
                    }

                    Integer bits = Util.extractKeySizeBits(pk);
                    if (bits != null) {
                        stats.keySizeCounts.merge(bits, 1L, Long::sum);
                        if (keyAlg != null && Util.isWeakKeyLength(keyAlg, bits)) {
                            stats.weakKeyCount++;
                        }
                    }

                    String sigAlg = leafCert.getSigAlgName();
                    if (sigAlg != null) {
                        stats.signatureAlgorithmCounts.merge(sigAlg, 1L, Long::sum);
                        if (Util.isWeakSignatureAlgorithm(sigAlg)) {
                            stats.weakSignatureCount++;
                        }
                    }
                }

// --- Chain-Länge & schwache Chains (weak sig irgendwo) ---
                List<X509Certificate> fullChain = new ArrayList<>();
                if (leafCert != null) fullChain.add(leafCert);
                fullChain.addAll(chainCerts);

                if (!fullChain.isEmpty()) {
                    int chainLen = fullChain.size();
                    stats.chainLengthCounts.merge(chainLen, 1L, Long::sum);

                    boolean chainHasWeakSig = false;
                    for (X509Certificate c : fullChain) {
                        String sigAlg = c.getSigAlgName();
                        if (Util.isWeakSignatureAlgorithm(sigAlg)) {
                            chainHasWeakSig = true;
                            break;
                        }
                    }
                    if (chainHasWeakSig) {
                        stats.chainsWithWeakSig++;
                    }
                }

// Root-CA bestimmen für TrustScore/Country-Stats
                Set<X509Certificate> certsForRoot = new LinkedHashSet<>();
                if (leafCert != null) certsForRoot.add(leafCert);
                certsForRoot.addAll(chainCerts);

                String rootCountry = null;
                String rootSubjectDn = null;
                String rootIssuerDn = null;

                if (!certsForRoot.isEmpty()) {
                    stats.chains++;

                    X509Certificate rootCert = chooseRootCertificate(certsForRoot);
                    if (rootCert != null) {
                        Util.updateCountryCountersForCert(
                                rootCert,
                                stats.countByCountry,
                                stats.countByCountryForScore,
                                countryScores
                        );

                        rootCountry = Util.determineCountryKeyFromCert(rootCert);
                        rootSubjectDn = rootCert.getSubjectX500Principal().getName();
                        rootIssuerDn = rootCert.getIssuerX500Principal().getName();
                    }
                }


                if (endpoint != null && !endpoint.isBlank()) {
                    // letzte Beobachtung für diesen Endpoint gewinnt
                    stats.endpoints.put(
                            endpoint,
                            new EndpointInfo(
                                    endpoint,
                                    tlsVersion,
                                    cipherSuite,
                                    rootCountry,
                                    rootSubjectDn,
                                    rootIssuerDn
                            )
                    );
                }
            }
        }

        // TrustScore berechnen
        long totalForScore = stats.countByCountryForScore.values()
                .stream()
                .mapToLong(Long::longValue)
                .sum();

        stats.scoreByCountry.clear();
        if (totalForScore > 0) {
            for (Map.Entry<String, Long> e : stats.countByCountryForScore.entrySet()) {
                String country = e.getKey();
                long count = e.getValue();
                Double baseScore = countryScores.get(country);
                if (baseScore == null) continue;

                double share = (double) count / (double) totalForScore;
                stats.scoreByCountry.put(country, share * baseScore);
            }
        }

        stats.totalTrustScore = stats.scoreByCountry.values()
                .stream()
                .mapToDouble(Double::doubleValue)
                .sum();

        return stats;
    }

    // --------------------------- Ausgabe (Text) ----------------------------

    private void printHumanReadableDiff(Path oldFile,
                                        Path newFile,
                                        ScanStats oldStats,
                                        ScanStats newStats,
                                        Map<String, Double> countryScores) {

        System.out.println("=== Scan-Diff ===");
        System.out.println("Alt: " + oldFile);
        System.out.println("Neu: " + newFile);
        System.out.println();

        System.out.printf(Locale.ROOT, "Zeilen:  alt=%d, neu=%d%n", oldStats.lines, newStats.lines);
        System.out.printf(Locale.ROOT, "Ketten:  alt=%d, neu=%d%n", oldStats.chains, newStats.chains);
        System.out.println();

        // TrustScore
        double deltaScore = newStats.totalTrustScore - oldStats.totalTrustScore;
        System.out.println("=== TrustScore (Root-CA-basiert) ===");
        System.out.printf(Locale.ROOT, "Alt: %.4f%n", oldStats.totalTrustScore);
        System.out.printf(Locale.ROOT, "Neu: %.4f%n", newStats.totalTrustScore);
        System.out.printf(Locale.ROOT, "Δ:   %+.4f%n", deltaScore);
        System.out.println();

        // TLS-Versionen
        System.out.println("=== TLS-Versionen – Vergleich ===");
        Set<String> allVersions = new TreeSet<>();
        allVersions.addAll(oldStats.tlsVersionCounts.keySet());
        allVersions.addAll(newStats.tlsVersionCounts.keySet());

        System.out.printf("%-12s %10s %10s %10s%n", "Version", "alt", "neu", "Δ");
        for (String v : allVersions) {
            long o = oldStats.tlsVersionCounts.getOrDefault(v, 0L);
            long n = newStats.tlsVersionCounts.getOrDefault(v, 0L);
            long d = n - o;
            System.out.printf("%-12s %10d %10d %10d%n", v, o, n, d);
        }
        System.out.println();

        // Deprecated TLS versions
        if (!oldStats.deprecatedTlsVersionCounts.isEmpty() || !newStats.deprecatedTlsVersionCounts.isEmpty()) {
            System.out.println("=== Deprecated TLS-Versionen – Vergleich ===");
            Set<String> allDep = new TreeSet<>();
            allDep.addAll(oldStats.deprecatedTlsVersionCounts.keySet());
            allDep.addAll(newStats.deprecatedTlsVersionCounts.keySet());
            System.out.printf("%-15s %10s %10s %10s%n", "Version", "alt", "neu", "Δ");
            for (String v : allDep) {
                long o = oldStats.deprecatedTlsVersionCounts.getOrDefault(v, 0L);
                long n = newStats.deprecatedTlsVersionCounts.getOrDefault(v, 0L);
                long d = n - o;
                System.out.printf("%-15s %10d %10d %10d%n", v, o, n, d);
            }
            System.out.println();
        }

        // Cipher suites
        System.out.println("=== Cipher-Suites – Vergleich ===");
        Set<String> allCiphers = new TreeSet<>();
        allCiphers.addAll(oldStats.cipherSuiteCounts.keySet());
        allCiphers.addAll(newStats.cipherSuiteCounts.keySet());
        System.out.printf("%-40s %10s %10s %10s%n", "Cipher", "alt", "neu", "Δ");
        for (String c : allCiphers) {
            long o = oldStats.cipherSuiteCounts.getOrDefault(c, 0L);
            long n = newStats.cipherSuiteCounts.getOrDefault(c, 0L);
            long d = n - o;
            System.out.printf("%-40s %10d %10d %10d%n", c, o, n, d);
        }
        System.out.println();

        if (!oldStats.weakCipherSuiteCounts.isEmpty() || !newStats.weakCipherSuiteCounts.isEmpty()) {
            System.out.println("=== Weak Cipher-Suites – Vergleich ===");
            Set<String> weakCiphers = new TreeSet<>();
            weakCiphers.addAll(oldStats.weakCipherSuiteCounts.keySet());
            weakCiphers.addAll(newStats.weakCipherSuiteCounts.keySet());
            System.out.printf("%-40s %10s %10s %10s%n", "WeakCipher", "alt", "neu", "Δ");
            for (String c : weakCiphers) {
                long o = oldStats.weakCipherSuiteCounts.getOrDefault(c, 0L);
                long n = newStats.weakCipherSuiteCounts.getOrDefault(c, 0L);
                long d = n - o;
                System.out.printf("%-40s %10d %10d %10d%n", c, o, n, d);
            }
            System.out.println();
        }

        // Key algorithms + sizes
        System.out.println("=== Key-Algorithmen (Leaf) – Vergleich ===");
        Set<String> allKeyAlgs = new TreeSet<>();
        allKeyAlgs.addAll(oldStats.keyAlgorithmCounts.keySet());
        allKeyAlgs.addAll(newStats.keyAlgorithmCounts.keySet());
        System.out.printf("%-12s %10s %10s %10s%n", "Algorithmus", "alt", "neu", "Δ");
        for (String a : allKeyAlgs) {
            long o = oldStats.keyAlgorithmCounts.getOrDefault(a, 0L);
            long n = newStats.keyAlgorithmCounts.getOrDefault(a, 0L);
            long d = n - o;
            System.out.printf("%-12s %10d %10d %10d%n", a, o, n, d);
        }
        System.out.println();

        if (!oldStats.keySizeCounts.isEmpty() || !newStats.keySizeCounts.isEmpty()) {
            System.out.println("=== Key-Größen (Bits, Leaf) – Vergleich ===");
            Set<Integer> allBits = new TreeSet<>();
            allBits.addAll(oldStats.keySizeCounts.keySet());
            allBits.addAll(newStats.keySizeCounts.keySet());
            System.out.printf("%-8s %10s %10s %10s%n", "Bits", "alt", "neu", "Δ");
            for (Integer b : allBits) {
                long o = oldStats.keySizeCounts.getOrDefault(b, 0L);
                long n = newStats.keySizeCounts.getOrDefault(b, 0L);
                long d = n - o;
                System.out.printf("%-8d %10d %10d %10d%n", b, o, n, d);
            }
            System.out.println();
        }

        System.out.printf(Locale.ROOT,
                "Weak Keys (Leaf): alt=%d, neu=%d, Δ=%+d%n%n",
                oldStats.weakKeyCount, newStats.weakKeyCount,
                (newStats.weakKeyCount - oldStats.weakKeyCount));

        // Signature algorithms
        System.out.println("=== Signaturalgorithmen (Leaf) – Vergleich ===");
        Set<String> allSigAlgs = new TreeSet<>();
        allSigAlgs.addAll(oldStats.signatureAlgorithmCounts.keySet());
        allSigAlgs.addAll(newStats.signatureAlgorithmCounts.keySet());
        System.out.printf("%-25s %10s %10s %10s%n", "Algorithmus", "alt", "neu", "Δ");
        for (String a : allSigAlgs) {
            long o = oldStats.signatureAlgorithmCounts.getOrDefault(a, 0L);
            long n = newStats.signatureAlgorithmCounts.getOrDefault(a, 0L);
            long d = n - o;
            System.out.printf("%-25s %10d %10d %10d%n", a, o, n, d);
        }
        System.out.println();

        System.out.printf(Locale.ROOT,
                "Weak Signatures (Leaf): alt=%d, neu=%d, Δ=%+d%n%n",
                oldStats.weakSignatureCount, newStats.weakSignatureCount,
                (newStats.weakSignatureCount - oldStats.weakSignatureCount));

        // Chain lengths and weak chains
        if (!oldStats.chainLengthCounts.isEmpty() || !newStats.chainLengthCounts.isEmpty()) {
            System.out.println("=== Chain-Längen – Vergleich ===");
            Set<Integer> allLens = new TreeSet<>();
            allLens.addAll(oldStats.chainLengthCounts.keySet());
            allLens.addAll(newStats.chainLengthCounts.keySet());
            System.out.printf("%-8s %10s %10s %10s%n", "Länge", "alt", "neu", "Δ");
            for (Integer cl : allLens) {
                long o = oldStats.chainLengthCounts.getOrDefault(cl, 0L);
                long n = newStats.chainLengthCounts.getOrDefault(cl, 0L);
                long d = n - o;
                System.out.printf("%-8d %10d %10d %10d%n", cl, o, n, d);
            }
            System.out.println();
        }

        System.out.printf(Locale.ROOT,
                "Chains mit Weak Signature: alt=%d, neu=%d, Δ=%+d%n%n",
                oldStats.chainsWithWeakSig, newStats.chainsWithWeakSig,
                (newStats.chainsWithWeakSig - oldStats.chainsWithWeakSig));


        // Root-CA-Länder
        System.out.println("=== Root-CA-Länder – Verteilung ===");
        Set<String> allCountries = new TreeSet<>();
        allCountries.addAll(oldStats.countByCountry.keySet());
        allCountries.addAll(newStats.countByCountry.keySet());

        System.out.printf("%-5s %10s %10s %10s%n", "Land", "alt", "neu", "Δ");
        for (String c : allCountries) {
            long o = oldStats.countByCountry.getOrDefault(c, 0L);
            long n = newStats.countByCountry.getOrDefault(c, 0L);
            long d = n - o;
            System.out.printf("%-5s %10d %10d %10d%n", c, o, n, d);
        }
        System.out.println();

        // Endpoint-/Chain-Wechsel
        System.out.println("=== Endpoint-/Chain-Wechsel ===");
        Set<String> oldEndpoints = oldStats.endpoints.keySet();
        Set<String> newEndpoints = newStats.endpoints.keySet();

        Set<String> onlyOld = new TreeSet<>(oldEndpoints);
        onlyOld.removeAll(newEndpoints);

        Set<String> onlyNew = new TreeSet<>(newEndpoints);
        onlyNew.removeAll(oldEndpoints);

        Set<String> intersection = new TreeSet<>(oldEndpoints);
        intersection.retainAll(newEndpoints);

        int changedTls = 0;
        int changedRoot = 0;

        List<String> sampleTlsChanges = new ArrayList<>();
        List<String> sampleRootChanges = new ArrayList<>();

        for (String ep : intersection) {
            EndpointInfo o = oldStats.endpoints.get(ep);
            EndpointInfo n = newStats.endpoints.get(ep);

            boolean tlsChanged = !Objects.equals(o.tlsVersion, n.tlsVersion);
            boolean rootChanged =
                    !Objects.equals(o.rootSubjectDn, n.rootSubjectDn) ||
                            !Objects.equals(o.rootIssuerDn, n.rootIssuerDn);

            if (tlsChanged) {
                changedTls++;
                if (sampleTlsChanges.size() < 10) {
                    sampleTlsChanges.add(String.format(
                            "%s: %s -> %s",
                            ep,
                            Objects.toString(o.tlsVersion, "null"),
                            Objects.toString(n.tlsVersion, "null")
                    ));
                }
            }

            if (rootChanged) {
                changedRoot++;
                if (sampleRootChanges.size() < 10) {
                    sampleRootChanges.add(String.format(
                            "%s: %s / %s -> %s / %s",
                            ep,
                            Objects.toString(o.rootSubjectDn, "null"),
                            Objects.toString(o.rootIssuerDn, "null"),
                            Objects.toString(n.rootSubjectDn, "null"),
                            Objects.toString(n.rootIssuerDn, "null")
                    ));
                }
            }
        }

        System.out.printf("Endpoints nur im alten Scan : %d%n", onlyOld.size());
        System.out.printf("Endpoints nur im neuen Scan : %d%n", onlyNew.size());
        System.out.printf("Gemeinsame Endpoints        : %d%n", intersection.size());
        System.out.printf("Davon mit TLS-Änderung      : %d%n", changedTls);
        System.out.printf("Davon mit Chain-/Root-Change: %d%n", changedRoot);
        System.out.println();

        if (!sampleTlsChanges.isEmpty()) {
            System.out.println("Beispiele für TLS-Änderungen:");
            sampleTlsChanges.forEach(s -> System.out.println("  " + s));
            System.out.println();
        }

        if (!sampleRootChanges.isEmpty()) {
            System.out.println("Beispiele für Chain-/Root-Wechsel:");
            sampleRootChanges.forEach(s -> System.out.println("  " + s));
            System.out.println();
        }
    }

    // --------------------------- Ausgabe (JSON) ----------------------------

    private void writeDiffJson(Path out,
                               Path oldFile,
                               Path newFile,
                               ScanStats oldStats,
                               ScanStats newStats) throws IOException {

        ObjectNode root = mapper.createObjectNode();
        root.put("old_file", oldFile.toString());
        root.put("new_file", newFile.toString());

        ObjectNode meta = root.putObject("meta");
        meta.put("lines_old", oldStats.lines);
        meta.put("lines_new", newStats.lines);
        meta.put("chains_old", oldStats.chains);
        meta.put("chains_new", newStats.chains);

        ObjectNode trust = root.putObject("trustscore");
        trust.put("old", oldStats.totalTrustScore);
        trust.put("new", newStats.totalTrustScore);
        trust.put("delta", newStats.totalTrustScore - oldStats.totalTrustScore);

        ObjectNode tlsNode = root.putObject("tls_versions");
        Set<String> allVersions = new TreeSet<>();
        allVersions.addAll(oldStats.tlsVersionCounts.keySet());
        allVersions.addAll(newStats.tlsVersionCounts.keySet());
        for (String v : allVersions) {
            ObjectNode n = tlsNode.putObject(v);
            long o = oldStats.tlsVersionCounts.getOrDefault(v, 0L);
            long nv = newStats.tlsVersionCounts.getOrDefault(v, 0L);
            n.put("old", o);
            n.put("new", nv);
            n.put("delta", nv - o);
        }

        // Deprecated TLS versions
        ObjectNode tlsDepNode = root.putObject("deprecated_tls_versions");
        Set<String> allDep = new TreeSet<>();
        allDep.addAll(oldStats.deprecatedTlsVersionCounts.keySet());
        allDep.addAll(newStats.deprecatedTlsVersionCounts.keySet());
        for (String v : allDep) {
            ObjectNode n = tlsDepNode.putObject(v);
            long o = oldStats.deprecatedTlsVersionCounts.getOrDefault(v, 0L);
            long nv = newStats.deprecatedTlsVersionCounts.getOrDefault(v, 0L);
            n.put("old", o);
            n.put("new", nv);
            n.put("delta", nv - o);
        }

        // Cipher suites
        ObjectNode cipherNode = root.putObject("cipher_suites");
        ObjectNode cipherAllNode = cipherNode.putObject("all");
        ObjectNode cipherWeakNode = cipherNode.putObject("weak");

        Set<String> allCiphers = new TreeSet<>();
        allCiphers.addAll(oldStats.cipherSuiteCounts.keySet());
        allCiphers.addAll(newStats.cipherSuiteCounts.keySet());
        for (String c : allCiphers) {
            ObjectNode n = cipherAllNode.putObject(c);
            long o = oldStats.cipherSuiteCounts.getOrDefault(c, 0L);
            long nv = newStats.cipherSuiteCounts.getOrDefault(c, 0L);
            n.put("old", o);
            n.put("new", nv);
            n.put("delta", nv - o);
        }

        Set<String> weakCiphers = new TreeSet<>();
        weakCiphers.addAll(oldStats.weakCipherSuiteCounts.keySet());
        weakCiphers.addAll(newStats.weakCipherSuiteCounts.keySet());
        for (String c : weakCiphers) {
            ObjectNode n = cipherWeakNode.putObject(c);
            long o = oldStats.weakCipherSuiteCounts.getOrDefault(c, 0L);
            long nv = newStats.weakCipherSuiteCounts.getOrDefault(c, 0L);
            n.put("old", o);
            n.put("new", nv);
            n.put("delta", nv - o);
        }

        // Key algorithms + sizes + weak count
        ObjectNode keyNode = root.putObject("keys");
        ObjectNode keyAlgNode = keyNode.putObject("algorithms");
        ObjectNode keySizeNode = keyNode.putObject("sizes_bits");
        ObjectNode weakKeyNode = keyNode.putObject("weak_keys");
        weakKeyNode.put("old", oldStats.weakKeyCount);
        weakKeyNode.put("new", newStats.weakKeyCount);
        weakKeyNode.put("delta", newStats.weakKeyCount - oldStats.weakKeyCount);

        Set<String> allKeyAlgs = new TreeSet<>();
        allKeyAlgs.addAll(oldStats.keyAlgorithmCounts.keySet());
        allKeyAlgs.addAll(newStats.keyAlgorithmCounts.keySet());
        for (String a : allKeyAlgs) {
            ObjectNode n = keyAlgNode.putObject(a);
            long o = oldStats.keyAlgorithmCounts.getOrDefault(a, 0L);
            long nv = newStats.keyAlgorithmCounts.getOrDefault(a, 0L);
            n.put("old", o);
            n.put("new", nv);
            n.put("delta", nv - o);
        }

        Set<Integer> allKeySizes = new TreeSet<>();
        allKeySizes.addAll(oldStats.keySizeCounts.keySet());
        allKeySizes.addAll(newStats.keySizeCounts.keySet());
        for (Integer b : allKeySizes) {
            ObjectNode n = keySizeNode.putObject(String.valueOf(b));
            long o = oldStats.keySizeCounts.getOrDefault(b, 0L);
            long nv = newStats.keySizeCounts.getOrDefault(b, 0L);
            n.put("old", o);
            n.put("new", nv);
            n.put("delta", nv - o);
        }

        // Signature algorithms + weak count
        ObjectNode sigNode = root.putObject("signatures");
        ObjectNode sigAlgNode = sigNode.putObject("algorithms");
        ObjectNode weakSigNode = sigNode.putObject("weak_signatures");
        weakSigNode.put("old", oldStats.weakSignatureCount);
        weakSigNode.put("new", newStats.weakSignatureCount);
        weakSigNode.put("delta", newStats.weakSignatureCount - oldStats.weakSignatureCount);

        Set<String> allSigAlgs = new TreeSet<>();
        allSigAlgs.addAll(oldStats.signatureAlgorithmCounts.keySet());
        allSigAlgs.addAll(newStats.signatureAlgorithmCounts.keySet());
        for (String a : allSigAlgs) {
            ObjectNode n = sigAlgNode.putObject(a);
            long o = oldStats.signatureAlgorithmCounts.getOrDefault(a, 0L);
            long nv = newStats.signatureAlgorithmCounts.getOrDefault(a, 0L);
            n.put("old", o);
            n.put("new", nv);
            n.put("delta", nv - o);
        }

        // Chain lengths + chains with weak sig
        ObjectNode chainNode = root.putObject("chains");
        ObjectNode chainLenNode = chainNode.putObject("lengths");
        ObjectNode chainWeakSigNode = chainNode.putObject("chains_with_weak_signature");
        chainWeakSigNode.put("old", oldStats.chainsWithWeakSig);
        chainWeakSigNode.put("new", newStats.chainsWithWeakSig);
        chainWeakSigNode.put("delta", newStats.chainsWithWeakSig - oldStats.chainsWithWeakSig);

        Set<Integer> allChainLens = new TreeSet<>();
        allChainLens.addAll(oldStats.chainLengthCounts.keySet());
        allChainLens.addAll(newStats.chainLengthCounts.keySet());
        for (Integer cl : allChainLens) {
            ObjectNode n = chainLenNode.putObject(String.valueOf(cl));
            long o = oldStats.chainLengthCounts.getOrDefault(cl, 0L);
            long nv = newStats.chainLengthCounts.getOrDefault(cl, 0L);
            n.put("old", o);
            n.put("new", nv);
            n.put("delta", nv - o);
        }


        ObjectNode countryNode = root.putObject("root_ca_country");
        Set<String> allCountries = new TreeSet<>();
        allCountries.addAll(oldStats.countByCountry.keySet());
        allCountries.addAll(newStats.countByCountry.keySet());
        for (String c : allCountries) {
            ObjectNode n = countryNode.putObject(c);
            long o = oldStats.countByCountry.getOrDefault(c, 0L);
            long nv = newStats.countByCountry.getOrDefault(c, 0L);
            n.put("old", o);
            n.put("new", nv);
            n.put("delta", nv - o);
        }

        ObjectNode epNode = root.putObject("endpoints");
        epNode.put("count_old", oldStats.endpoints.size());
        epNode.put("count_new", newStats.endpoints.size());

        Set<String> oldEndpoints = oldStats.endpoints.keySet();
        Set<String> newEndpoints = newStats.endpoints.keySet();

        Set<String> onlyOld = new TreeSet<>(oldEndpoints);
        onlyOld.removeAll(newEndpoints);

        Set<String> onlyNew = new TreeSet<>(newEndpoints);
        onlyNew.removeAll(oldEndpoints);

        Set<String> intersection = new TreeSet<>(oldEndpoints);
        intersection.retainAll(newEndpoints);

        int changedTls = 0;
        int changedRoot = 0;
        for (String ep : intersection) {
            EndpointInfo o = oldStats.endpoints.get(ep);
            EndpointInfo n = newStats.endpoints.get(ep);

            boolean tlsChanged = !Objects.equals(o.tlsVersion, n.tlsVersion);
            boolean rootChanged =
                    !Objects.equals(o.rootSubjectDn, n.rootSubjectDn) ||
                            !Objects.equals(o.rootIssuerDn, n.rootIssuerDn);

            if (tlsChanged) changedTls++;
            if (rootChanged) changedRoot++;
        }

        epNode.put("only_in_old", onlyOld.size());
        epNode.put("only_in_new", onlyNew.size());
        epNode.put("common", intersection.size());
        epNode.put("changed_tls", changedTls);
        epNode.put("changed_chain_or_root", changedRoot);

        if (out.getParent() != null) {
            Files.createDirectories(out.getParent());
        }
        mapper.writerWithDefaultPrettyPrinter().writeValue(out.toFile(), root);
        System.out.println("Diff-JSON gespeichert in: " + out);
    }

    // --------------------------- Zertifikat-Helper (aus Analyzer übernommen) ----------------------------

    private X509Certificate chooseRootCertificate(Set<X509Certificate> certsInLine) {
        if (certsInLine == null || certsInLine.isEmpty()) return null;
        if (certsInLine.size() == 1) return certsInLine.iterator().next();

        for (X509Certificate candidate : certsInLine) {
            boolean hasParent = false;
            for (X509Certificate other : certsInLine) {
                if (candidate == other) continue;
                if (other.getSubjectX500Principal().equals(candidate.getIssuerX500Principal())) {
                    hasParent = true;
                    break;
                }
            }
            if (!hasParent) {
                return candidate;
            }
        }
        return certsInLine.iterator().next();
    }

    private void extractCertificatesRecursive(JsonNode node,
                                              CertificateFactory cf,
                                              Set<X509Certificate> out,
                                              boolean debug) {
        if (node == null || node.isNull()) return;

        if (node.isTextual()) {
            String text = node.asText();
            if (text.contains("-----BEGIN CERTIFICATE-----")) {
                parsePemCertificates(text, cf, out, debug);
                return;
            }
            String trimmed = text.trim();
            if (trimmed.length() >= 100 && looksLikeBase64(trimmed)) {
                tryDecodeCertificate(trimmed, cf, out, debug);
            }
            return;
        }

        if (node.isArray()) {
            for (JsonNode child : node) {
                extractCertificatesRecursive(child, cf, out, debug);
            }
            return;
        }

        if (node.isObject()) {
            node.fields().forEachRemaining(entry ->
                    extractCertificatesRecursive(entry.getValue(), cf, out, debug));
        }
    }

    private void parsePemCertificates(String pem,
                                      CertificateFactory cf,
                                      Set<X509Certificate> out,
                                      boolean debug) {
        String[] parts = pem.split("-----END CERTIFICATE-----");
        for (String part : parts) {
            if (!part.contains("-----BEGIN CERTIFICATE-----")) continue;
            String body = part.substring(part.indexOf("-----BEGIN CERTIFICATE-----")
                            + "-----BEGIN CERTIFICATE-----".length())
                    .replaceAll("\\s+", "");
            tryDecodeCertificate(body, cf, out, debug);
        }
    }

    private void tryDecodeCertificate(String b64,
                                      CertificateFactory cf,
                                      Set<X509Certificate> out,
                                      boolean debug) {
        try {
            byte[] der = Base64.getDecoder().decode(b64);
            X509Certificate cert = (X509Certificate) cf.generateCertificate(
                    new java.io.ByteArrayInputStream(der));
            out.add(cert);
        } catch (IllegalArgumentException | CertificateException e) {
            if (debug) {
                System.err.println("[ScanDiff] Zertifikat konnte nicht dekodiert werden: " + e.getMessage());
            }
        }
    }

    private boolean looksLikeBase64(String s) {
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (!(c >= 'A' && c <= 'Z') &&
                    !(c >= 'a' && c <= 'z') &&
                    !(c >= '0' && c <= '9') &&
                    c != '+' && c != '/' && c != '=') {
                return false;
            }
        }
        return true;
    }
}
