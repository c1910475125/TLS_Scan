package org.tlsscan;

import org.tlsscan.Commands.ActiveScanCommand;
import org.tlsscan.Commands.AnalyzeCommand;
import org.tlsscan.Commands.StoreScoreCommand;
import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;


import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.*;
import java.util.Scanner;
import java.util.concurrent.Callable;

@Command(
        name = "passive-cert-analyzer",
        mixinStandardHelpOptions = true,
        version = "0.6.2",
        description = "TLS-Zertifikatsplattform: aktiver Scan, Geo-Länderscan, Analyse & RootStore-Score."
)
public class Main implements Callable<Integer> {

    public static void main(String[] args) {
        if (args != null && args.length > 0) {
            int exit = new CommandLine(new Main())
                    .addSubcommand("scan", new ActiveScanCommand())
                    .addSubcommand("analyze", new AnalyzeCommand())
                    .addSubcommand("store-score", new StoreScoreCommand())
                    .execute(args);
            System.exit(exit);
        } else {
            new Main().runInteractive();
        }
    }

    @Override
    public Integer call() {
        runInteractive();
        return 0;
    }

    private void runInteractive() {
        interactiveMenu();
    }

    private static Path projectRoot() {
        return Paths.get(System.getProperty("user.dir"));
    }

    private static Path defaultScanDir() {
        return projectRoot().resolve("Scanfiles");
    }

    private static Path defaultOutputPath() {
        return defaultScanDir().resolve("certs.jsonl");
    }

    private static void ensureDir(Path dir) {
        try {
            if (dir != null && !Files.exists(dir)) {
                Files.createDirectories(dir);
            }
        } catch (Exception e) {
            throw new RuntimeException("Kann Ordner nicht anlegen: " + dir + " -> " + e.getMessage(), e);
        }
    }

    private static void interactiveMenu() {
        Scanner in = new Scanner(System.in);
        while (true) {
            System.out.println("\n=== TLS Analyzer – Menü ===");
            System.out.println("1) Aktiver TLS-Scan (konkrete Hosts, IPs & IP-Ranges)");
            System.out.println("2) Geo-Länderscan (GeoLite2, ganze Länder / Zufallsstichprobe)");
            System.out.println("3) JSONL analysieren");
            System.out.println("4) TrustStore bewerten");
            System.out.println("0) Beenden");

            String choice = readChoice(in, "Auswahl", Set.of("0", "1", "2", "3", "4"), null);
            switch (choice) {
                case "1" -> runIpScanInteractive(in);
                case "2" -> runCountryScanInteractive(in);
                case "3" -> runAnalyzeInteractive(in);
                case "4" -> runStoreScoreInteractive(in);
                case "0" -> {
                    System.out.println("Auf Wiedersehen.");
                    return;
                }
            }
        }
    }

    private static String ensureJsonlName(String name) {
        if (name == null || name.isBlank()) {
            return "scan.jsonl";
        }
        String trimmed = name.trim();
        if (!trimmed.toLowerCase(Locale.ROOT).endsWith(".jsonl")) {
            trimmed += ".jsonl";
        }
        return trimmed;
    }


    // --- 1) Aktiver Scan: konkrete Ziele / Ranges -----------------------------------------

    private static void runIpScanInteractive(Scanner in) {
        System.out.println("\n--- Aktiver TLS-Scan (konkrete Ziele / Ranges) ---");
        System.out.println("Basis-Output-Ordner: " + defaultScanDir());

        String outFileName = promptFree(in,
                "Output-Dateiname (ohne Pfad)",
                "active_scan_ip");

        Path outputFile = defaultScanDir().resolve(outFileName + ".jsonl");
        ensureDir(outputFile.getParent());
        System.out.println("Output:  " + outputFile);

        String targetInput = promptFree(in,
                "Ziele (Hostname/IP/host:port/CIDR, kommagetrennt, z.B. google.com,1.2.3.4,10.0.0.0/24)",
                "");
        if (targetInput == null || targetInput.isBlank()) {
            System.out.println("Keine Ziele angegeben – Abbruch.");
            return;
        }

        List<String> targets = new ArrayList<>();
        String[] parts = targetInput.split(",");
        for (String p : parts) {
            String s = p.trim();
            if (!s.isEmpty()) {
                targets.add(s);
            }
        }
        if (targets.isEmpty()) {
            System.out.println("Keine gültigen Ziele erkannt – Scan abgebrochen.");
            return;
        }

        String profile = readChoice(in,
                "Port-Profil [web|mail|k8s|custom]",
                Set.of("web", "mail", "k8s", "custom"),
                "web");
        List<Integer> ports = new ArrayList<>();
        switch (profile) {
            case "web" -> ports.add(443);
            case "mail" -> {
                ports.add(465);
                ports.add(587);
                ports.add(993);
                ports.add(995);
            }
            case "k8s" -> ports.add(6443);
            case "custom" -> {
                String pStr = promptFree(in, "Ports, kommasepariert", "443");
                for (String ps : pStr.split(",")) {
                    ps = ps.trim();
                    if (ps.isEmpty()) continue;
                    try {
                        ports.add(Integer.parseInt(ps));
                    } catch (NumberFormatException e) {
                        System.out.println("Ignoriere ungültigen Port: " + ps);
                    }
                }
                if (ports.isEmpty()) {
                    System.out.println("Keine gültigen Ports – verwende Port 443.");
                    ports.add(443);
                }
            }
        }

        boolean debug = readYesNo(in, "Debug-Logging aktivieren? [y/N]", false);

        ActiveScanner.AdvancedScanOptions adv = new ActiveScanner.AdvancedScanOptions();

        Path zgrabPath = projectRoot()
                .resolve("bin")
                .resolve("zgrab2.exe");
        adv.useZgrabOnly = true;
        adv.zgrabBinary = zgrabPath.toString();

        Path geoipDir = projectRoot().resolve("GeoIP");

        // GeoIP-MMDBs (für Geo-Infos)
        Path defCountryDb = geoipDir.resolve("GeoLite2-Country.mmdb");
        Path defAsnDb = geoipDir.resolve("GeoLite2-ASN.mmdb");
        Path defCityDb = geoipDir.resolve("GeoLite2-City.mmdb");
        if (Files.exists(defCountryDb)) {
            adv.geoipCountryDbPath = defCountryDb.toString();
            System.out.println("[GeoIP-Country] lade: " + defCountryDb);
        } else {
            System.out.println("[GeoIP-Country] Achtung: Datei nicht gefunden: " + defCountryDb);
        }
        if (Files.exists(defAsnDb)) {
            adv.geoipAsnDbPath = defAsnDb.toString();
            System.out.println("[GeoIP-ASN] lade: " + defAsnDb);
        } else {
            System.out.println("[GeoIP-ASN] Achtung: Datei nicht gefunden: " + defAsnDb);
        }
        if (Files.exists(defCityDb)) {
            adv.geoipCityDbPath = defCityDb.toString();
            System.out.println("[GeoIP-City] lade: " + defCityDb);
        } else {
            System.out.println("[GeoIP-City] Hinweis: City-DB nicht gefunden: " + defCityDb);
        }

        ActiveScanner scanner = new ActiveScanner();
        try {
            scanner.scan(
                    targets,
                    ports,
                    outputFile,
                    null,
                    debug,
                    5000,
                    100,
                    null,
                    adv
            );
        } catch (Exception e) {
            System.err.println("Fehler beim Scan: " + e.getMessage());
        }
    }

    // --- 2) Country-Scan (Geo) ------------------------------------------------------------

    private static void runCountryScanInteractive(Scanner in) {
        System.out.println("\n--- Geo-Länderscan (GeoLite2) ---");
        System.out.println("Scannt IPs, die in den GeoLite2-Country-Datenbanken liegen.");
        System.out.println("Basis-Output-Ordner: " + defaultScanDir());

        String outFileName = promptFree(in,
                "Output-Dateiname (ohne Pfad)",
                "active_scan_country");

        Path outputFile = defaultScanDir().resolve(outFileName + ".jsonl");
        ensureDir(outputFile.getParent());
        System.out.println("Output:  " + outputFile);

        String isoStr = promptFree(in,
                "Länder-ISO-Codes (z.B. AT,DE,US – leer = alle Länder in GeoLite2)",
                "");
        List<String> isoList = new ArrayList<>();
        if (isoStr != null && !isoStr.isBlank()) {
            for (String c : isoStr.split(",")) {
                c = c.trim().toUpperCase(Locale.ROOT);
                if (!c.isEmpty()) isoList.add(c);
            }
        }

        int randomCount = (int) readLong(in,
                "Zufallsstichprobe: Anzahl Hosts aus Country-Blocks-CSV (0 = vollständiger Länderscan)",
                0, 0, 1_000_000);

        boolean enableFullScan = (randomCount == 0);

        ActiveScanner.AdvancedScanOptions adv = new ActiveScanner.AdvancedScanOptions();
        adv.randomSampleCount = randomCount;
        adv.enableCountryFullScan = enableFullScan;
        adv.countryIsoCodes = isoList;

        Path zgrabPath = projectRoot()
                .resolve("bin")
                .resolve("zgrab2.exe");
        adv.useZgrabOnly = true;
        adv.zgrabBinary = zgrabPath.toString();

        Path geoipDir = projectRoot().resolve("GeoIP");

        // GeoIP-MMDBs (für Geo-Infos)
        Path defCountryDb = geoipDir.resolve("GeoLite2-Country.mmdb");
        Path defAsnDb = geoipDir.resolve("GeoLite2-ASN.mmdb");
        Path defCityDb = geoipDir.resolve("GeoLite2-City.mmdb");
        if (Files.exists(defCountryDb)) {
            adv.geoipCountryDbPath = defCountryDb.toString();
        }
        if (Files.exists(defAsnDb)) {
            adv.geoipAsnDbPath = defAsnDb.toString();
        }
        if (Files.exists(defCityDb)) {
            adv.geoipCityDbPath = defCityDb.toString();
        }

        List<Integer> ports = new ArrayList<>();
        ports.add(443);

        boolean debug = readYesNo(in, "Debug-Logging aktivieren? [y/N]", false);

        ActiveScanner scanner = new ActiveScanner();
        try {
            scanner.scan(
                    Collections.emptyList(),
                    ports,
                    outputFile,
                    null,
                    debug,
                    5000,
                    100,
                    null,
                    adv
            );
        } catch (Exception e) {
            System.err.println("Fehler beim Länderscan: " + e.getMessage());
        }
    }

    // --- 3) CT-Stream (wird im Menü nicht mehr verwendet, CLI nur noch intern) ------------

    static class CtStreamCommand implements Callable<Integer> {
        @Option(names = {"--out-dir"}, description = "Output-Ordner (default: ./Scanfiles)")
        Path outDir = defaultScanDir();
        @Option(names = {"--out-file"}, description = "Output-Dateiname (default: certs.jsonl)")
        String outFile = "certs.jsonl";
        @Option(names = {"--cert-only"}, description = "Nur ausgewählte Felder speichern.")
        boolean certOnly = false;
        @Option(names = {"--duration-seconds"}, description = "Stoppt nach N Sekunden (0 = unbegrenzt).")
        long durationSeconds = 0;
        @Option(names = {"--max-events"}, description = "Stoppt nach N Events (0 = unbegrenzt).")
        long maxEvents = 0;
        @Option(names = {"--debug"}, description = "Debug-Logging aktivieren.")
        boolean debug = false;

        @Override
        public Integer call() {
            System.out.println("CT-Stream ist deaktiviert und wird nicht mehr unterstützt.");
            return 0;
        }
    }

    static class CtPollCommand implements Callable<Integer> {
        @Option(names = {"--log"}, required = true, description = "CT-Log-Basis-URL, z.B. https://ct.googleapis.com/logs/argon2023")
        String logBase;
        @Option(names = {"--start"}, description = "Startindex")
        long start = 0;
        @Option(names = {"--batch"}, description = "Batchgröße (1-4096)")
        int batch = 256;
        @Option(names = {"--sleep-ms"}, description = "Pause zwischen Batches in ms")
        int sleepMs = 500;
        @Option(names = {"--max-entries"}, description = "Maximal Einträge (0 = unbegrenzt)")
        long maxEntries = 0;
        @Option(names = {"--out-dir"}, description = "Output-Ordner (default: ./Scanfiles)")
        Path outDir = defaultScanDir();
        @Option(names = {"--out-file"}, description = "Output-Dateiname (default: certs_poll.jsonl)")
        String outFile = "certs_poll.jsonl";
        @Option(names = {"--cert-only"}, description = "Nur reduzierte Zertifikatsfelder speichern.")
        boolean certOnly = true;
        @Option(names = {"--no-progress"}, description = "Fortschrittsanzeige unterdrücken.")
        boolean noProgress = false;
        @Option(names = {"--debug"}, description = "Debug-Logging aktivieren.")
        boolean debug = false;

        @Override
        public Integer call() {
            System.out.println("CT-Poll ist deaktiviert und wird nicht mehr unterstützt.");
            return 0;
        }
    }

    // --- 5) Analyzer ----------------------------------------------------------------------

    private static void runAnalyzeInteractive(Scanner in) {
        System.out.println("\n--- JSONL Analyse ---");
        String fileName = promptFree(in,
                "Input-Datei (relativ zu ./Scanfiles oder absolut)",
                "certs.jsonl");
        Path inPath = Paths.get(fileName);
        if (!inPath.isAbsolute()) {
            inPath = defaultScanDir().resolve(fileName);
        }

        if (!Files.exists(inPath)) {
            System.err.println("Datei existiert nicht: " + inPath);
            return;
        }

        boolean debug = readYesNo(in, "Debug-Details anzeigen? [y/N]", false);

        Analyzer analyzer = new Analyzer();
        try {
            analyzer.analyze(
                    inPath,
                    null,
                    debug
            );
        } catch (Exception e) {
            System.err.println("Fehler bei Analyse: " + e.getMessage());
        }
    }

    // --- 6) RootStore-Score ----------------------------------------------------

    private static void runStoreScoreInteractive(Scanner in) {
        System.out.println("\n--- TrustStore-/CA-Bundle-Score (PEM) ---");
        String storePathStr = promptFree(in,
                "Pfad zum CA-Bundle (PEM, z.B. cacert.pem von Mozilla/Google)",
                "cacert.pem");

        Path storePath = Paths.get(storePathStr);
        if (!Files.exists(storePath)) {
            System.err.println("Datei existiert nicht: " + storePath);
            return;
        }

        boolean debug = readYesNo(in, "Debug-Details anzeigen? [y/N]", false);

        StoreScorer scorer = new StoreScorer();
        try {
            // Passwort ist für PEM egal, wird von scoreStoreAuto ignoriert
            scorer.scoreStoreAuto(
                    storePath,
                    null,
                    null,   // immer country_trustscores.json aus Ressourcen
                    debug
            );
        } catch (Exception e) {
            System.err.println("Fehler beim Bewerten des CA-Bundles: " + e.getMessage());
        }
    }



    // --- Hilfsfunktionen ------------------------------------------------------------------

    private static String readChoice(Scanner in, String prompt, Set<String> allowed, String defaultVal) {
        while (true) {
            System.out.print(prompt + (defaultVal != null ? " [" + defaultVal + "]" : "") + ": ");
            String line = in.nextLine();
            if (line == null || line.isBlank()) {
                if (defaultVal != null) return defaultVal;
                continue;
            }
            line = line.trim();
            if (allowed.contains(line)) {
                return line;
            }
            System.out.println("Ungültige Eingabe. Erlaubt: " + allowed);
        }
    }

    private static boolean readYesNo(Scanner in, String prompt, boolean defaultVal) {
        while (true) {
            System.out.print(prompt + " ");
            String line = in.nextLine();
            if (line == null || line.isBlank()) {
                return defaultVal;
            }
            line = line.trim().toLowerCase(Locale.ROOT);
            if (line.equals("y") || line.equals("yes") || line.equals("j") || line.equals("ja")) {
                return true;
            }
            if (line.equals("n") || line.equals("no") || line.equals("nein")) {
                return false;
            }
            System.out.println("Bitte 'y' oder 'n' eingeben.");
        }
    }

    private static long readLong(Scanner in, String prompt, long defaultVal, long min, long max) {
        while (true) {
            System.out.print(prompt + " [" + defaultVal + "]: ");
            String line = in.nextLine();
            if (line == null || line.isBlank()) {
                return defaultVal;
            }
            try {
                long v = Long.parseLong(line.trim());
                if (v < min || v > max) {
                    System.out.println("Wert außerhalb des gültigen Bereichs (" + min + "–" + max + ").");
                    continue;
                }
                return v;
            } catch (NumberFormatException e) {
                System.out.println("Bitte eine gültige Zahl eingeben.");
            }
        }
    }

    private static String promptFree(Scanner in, String prompt, String defaultVal) {
        System.out.print(prompt + " [" + defaultVal + "]: ");
        String s = in.nextLine();
        if (s == null || s.isBlank()) return defaultVal;
        return s.trim();
    }

    private static Path defaultJavaCacerts() {
        String javaHome = System.getProperty("java.home");
        if (javaHome == null) return Paths.get("");
        return Paths.get(javaHome, "lib", "security", "cacerts");
    }

    private static String emptyToNull(String s) {
        return (s == null || s.isBlank()) ? null : s;
    }
}
