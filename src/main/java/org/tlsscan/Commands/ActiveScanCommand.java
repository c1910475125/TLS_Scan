package org.tlsscan.Commands;

import org.tlsscan.ActiveScanner;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.*;
import java.util.concurrent.Callable;

@Command(
        name = "scan",
        description = "Aktiver TLS-Scan von Hostnamen/IPs; unterstützt Multi-Port, CIDR, IP-Ranges und erweiterte Metadaten."
)
public class ActiveScanCommand implements Callable<Integer> {

    @Option(names = {"-t", "--target"},
            description = "Ziel (Hostname oder IP, optional host:port). Kann mehrfach angegeben werden.")
    List<String> targets;

    @Option(names = {"-f", "--targets-file"},
            description = "Datei mit Zielen, eine pro Zeile (Hostname, IP oder host:port).")
    Path targetsFile;

    @Option(names = {"--cidr"},
            description = "IPv4-CIDR-Range, z.B. 192.0.2.0/24. Kann mehrfach angegeben werden.")
    List<String> cidrs;

    @Option(names = {"--ip-range"},
            description = "IPv4-Range, z.B. 192.0.2.10-192.0.2.200. Kann mehrfach angegeben werden.")
    List<String> ipRanges;

    @Option(names = {"-p", "--port"},
            description = "Einzelner Standardport (falls keine --ports angegeben).")
    Integer port;

    @Option(names = {"--ports"},
            description = "Kommagetrennte Liste von Ports, z.B. 443,8443,993.")
    String portsCsv;

    @Option(names = {"--profile"},
            description = "Port-Profil: z.B. web, mail, k8s. Ergänzt die Ports-Liste.")
    String profile;

    @Option(names = {"-o", "--output"},
            description = "Output JSONL Datei (default: ./Scanfiles/active_scan.jsonl).")
    Path output;

    @Option(names = {"--timeout-ms"},
            description = "Timeout pro Ziel in Millisekunden (default: 5000).")
    int timeoutMs = 5000;

    @Option(names = {"--country-scores"},
            description = "Pfad zu country_trustscores.json (default: Ressource auf dem Classpath).")
    Path countryScores;

    @Option(names = {"--debug"},
            description = "Debug-Logging aktivieren.")
    boolean debug = false;

    @Option(names = {"--concurrency"},
            description = "Anzahl paralleler Verbindungen (default: 50).")
    int concurrency = 50;

    @Option(names = {"--rate-per-second"},
            description = "Maximale Anzahl neuer Verbindungen pro Sekunde (soft rate limit).")
    Double ratePerSecond;

    @Option(names = {"--scan-run-id"},
            description = "Optionaler Identifier für diesen Scan-Run (default: zufällige UUID).")
    String scanRunId;

    @Override
    public Integer call() throws Exception {
        List<String> allTargets = new ArrayList<>();

        if (targets != null) {
            allTargets.addAll(targets);
        }

        if (targetsFile != null) {
            if (!Files.exists(targetsFile)) {
                System.err.println("Targets-Datei existiert nicht: " + targetsFile);
                return 2;
            }
            for (String line : Files.readAllLines(targetsFile)) {
                String s = line.trim();
                if (s.isEmpty() || s.startsWith("#")) {
                    continue;
                }
                allTargets.add(s);
            }
        }

        // CIDR & IP-Ranges expandieren
        if (cidrs != null) {
            for (String cidr : cidrs) {
                expandCidr(cidr, allTargets);
            }
        }
        if (ipRanges != null) {
            for (String range : ipRanges) {
                expandIpRange(range, allTargets);
            }
        }

        if (allTargets.isEmpty()) {
            System.err.println("Keine Ziele: mindestens --target, --targets-file, --cidr oder --ip-range angeben.");
            return 2;
        }

        List<Integer> ports = buildPorts(port, portsCsv, profile);

        Path out = (output != null)
                ? output
                : Paths.get("Scanfiles").resolve("active_scan.jsonl");

        String scoresPath = (countryScores != null) ? countryScores.toString() : null;

        new ActiveScanner().scan(allTargets, ports, out, scoresPath, debug, timeoutMs,
                concurrency, ratePerSecond, scanRunId);
        return 0;
    }

    private List<Integer> buildPorts(Integer singlePort, String portsCsv, String profile) {
        Set<Integer> set = new LinkedHashSet<>();

        if (portsCsv != null && !portsCsv.isBlank()) {
            for (String part : portsCsv.split(",")) {
                String s = part.trim();
                if (s.isEmpty()) continue;
                try {
                    set.add(Integer.parseInt(s));
                } catch (NumberFormatException ignored) { }
            }
        } else if (singlePort != null) {
            set.add(singlePort);
        }

        if (profile != null && !profile.isBlank()) {
            String p = profile.toLowerCase(Locale.ROOT);
            switch (p) {
                case "web" -> {
                    set.add(443);
                    set.add(8443);
                }
                case "mail" -> {
                    set.add(465);
                    set.add(587);
                    set.add(993);
                    set.add(995);
                }
                case "k8s" -> set.add(6443);
                default -> System.err.println("Unbekanntes Profil '" + profile + "', ignoriere.");
            }
        }

        if (set.isEmpty()) {
            set.add(443); // default
        }

        return new ArrayList<>(set);
    }

    private void expandCidr(String cidr, List<String> out) {
        if (cidr == null || cidr.isBlank()) return;
        cidr = cidr.trim();
        try {
            String[] parts = cidr.split("/");
            if (parts.length != 2) {
                System.err.println("Ungültiges CIDR: " + cidr);
                return;
            }
            String baseIp = parts[0];
            int prefix = Integer.parseInt(parts[1]);
            if (prefix < 0 || prefix > 32) {
                System.err.println("Ungültiger Präfix in CIDR: " + cidr);
                return;
            }
            long base = ipv4ToLong(baseIp);
            long mask = prefix == 0 ? 0 : ~((1L << (32 - prefix)) - 1) & 0xffffffffL;
            long network = base & mask;
            long hosts = 1L << (32 - prefix);

            // Warnung bei sehr großen Ranges
            if (hosts > 65536) {
                System.err.println("Warnung: CIDR " + cidr + " umfasst " + hosts +
                        " Adressen – Expansion kann sehr lange dauern.");
            }

            for (long i = 0; i < hosts; i++) {
                out.add(longToIpv4(network + i));
            }
        } catch (Exception e) {
            System.err.println("Fehler beim Expandieren von CIDR '" + cidr + "': " + e.getMessage());
        }
    }

    private void expandIpRange(String range, List<String> out) {
        if (range == null || range.isBlank()) return;
        range = range.trim();
        try {
            String[] parts = range.split("-");
            if (parts.length != 2) {
                System.err.println("Ungültiger IP-Range: " + range);
                return;
            }
            long start = ipv4ToLong(parts[0].trim());
            long end = ipv4ToLong(parts[1].trim());
            if (end < start) {
                System.err.println("IP-Range mit end < start: " + range);
                return;
            }
            long count = (end - start) + 1;
            if (count > 65536) {
                System.err.println("Warnung: IP-Range " + range + " umfasst " + count +
                        " Adressen – Expansion kann sehr lange dauern.");
            }
            for (long v = start; v <= end; v++) {
                out.add(longToIpv4(v));
            }
        } catch (Exception e) {
            System.err.println("Fehler beim Expandieren von IP-Range '" + range + "': " + e.getMessage());
        }
    }

    private long ipv4ToLong(String ip) {
        String[] parts = ip.trim().split("\\.");
        if (parts.length != 4) throw new IllegalArgumentException("Ungültige IPv4-Adresse: " + ip);
        long res = 0;
        for (String part : parts) {
            int v = Integer.parseInt(part);
            if (v < 0 || v > 255) throw new IllegalArgumentException("Ungültiges IPv4-Byte: " + part);
            res = (res << 8) | v;
        }
        return res;
    }

    private String longToIpv4(long val) {
        return String.format("%d.%d.%d.%d",
                (val >> 24) & 0xff,
                (val >> 16) & 0xff,
                (val >> 8) & 0xff,
                val & 0xff);
    }
}
