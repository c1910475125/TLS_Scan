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
        description = "TLS-Zertifikatsplattform: aktiver Scan, Geo-Länderscan, CT-Stream, CT-Poll, Analyse & RootStore-Score."
)
public class Main implements Callable<Integer> {

    public static void main(String[] args) {
        if (args != null && args.length > 0) {
            int exit = new CommandLine(new Main())
                    .addSubcommand("scan", new ActiveScanCommand())
                    .addSubcommand("ct-stream", new CtStreamCommand())
                    .addSubcommand("ct-poll", new CtPollCommand())
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
            System.out.println("3) CT-Stream (WebSocket, CertStream, passiv)");
            System.out.println("4) CT-Poll (HTTP, passiv)");
            System.out.println("5) JSONL analysieren");
            System.out.println("6) TrustStore bewerten");
            System.out.println("0) Beenden");

            String choice = readChoice(in, "Auswahl", Set.of("0", "1", "2", "3", "4", "5", "6"), null);
            switch (choice) {
                case "1" -> runIpScanInteractive(in);
                case "2" -> runCountryScanInteractive(in);
                case "3" -> runCtStreamInteractive(in);
                case "4" -> runCtPollInteractive(in);
                case "5" -> runAnalyzeInteractive(in);
                case "6" -> runStoreScoreInteractive(in);
                case "0" -> {
                    System.out.println("Auf Wiedersehen.");
                    return;
                }
            }
        }
    }

    // --- 1) Aktiver Scan: konkrete Ziele / Ranges -----------------------------------------

    private static void runIpScanInteractive(Scanner in) {
        System.out.println("\n--- Aktiver TLS-Scan (konkrete Ziele / Ranges) ---");
        System.out.println("Hinweis: Timeout pro Ziel = 5000 ms, max. 100 parallele Verbindungen.");
        System.out.println("Basis-Output-Ordner: " + defaultScanDir());

        String outFileName = promptFree(in,
                "Output-Dateiname (ohne Pfad)",
                "active_scan_ip.jsonl");

        Path outputFile = defaultScanDir().resolve(outFileName);
        ensureDir(outputFile.getParent());
        System.out.println("Output:  " + outputFile);

        String targetInput = promptFree(in,
                "Ziele (Hostname/IP/host:port/CIDR, kommagetrennt, z.B. google.com,1.2.3.4,10.0.0.0/24)",
                "");
        if (targetInput == null || targetInput.isBlank()) {
            System.out.println("Keine Ziele angegeben – Scan abgebrochen.");
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

        ActiveScanner.AdvancedScanOptions adv = new ActiveScanner.AdvancedScanOptions();

        // Optional: Geo-Infos aus MMDB (nur zur Anreicherung / Filterung, nicht für Zielerzeugung)
        Path geoipDir = projectRoot().resolve("GeoIP");
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

        boolean debug = readYesNo(in, "Debug-Logging aktivieren? [y/N]", false);

        ActiveScanner scanner = new ActiveScanner();
        try {
            scanner.scan(
                    targets,
                    ports,
                    outputFile,
                    null,
                    debug,
                    5000,   // Timeout
                    100,    // Parallelität
                    null,
                    adv
            );
            System.out.println("\nAktiver IP/Range-Scan abgeschlossen. Ergebnisse: " + outputFile);
        } catch (Exception e) {
            System.err.println("Fehler beim aktiven Scan: " + e.getMessage());
        }
    }

    // --- 2) Länderscan (GeoLite2) ---------------------------------------------------------

    private static void runCountryScanInteractive(Scanner in) {
        System.out.println("\n--- Geo-Länderscan (GeoLite2) ---");
        System.out.println("Scannt IPs, die in den GeoLite2-Country-Datenbanken liegen.");
        System.out.println("Hinweis: Timeout pro Ziel = 5000 ms, max. 100 parallele Verbindungen.");
        System.out.println("Basis-Output-Ordner: " + defaultScanDir());

        String outFileName = promptFree(in,
                "Output-Dateiname (ohne Pfad)",
                "active_scan_country.jsonl");

        Path outputFile = defaultScanDir().resolve(outFileName);
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
                "Zufallsstichprobe: Anzahl Hosts aus Country-Blocks-CSV (0 = keine Stichprobe)",
                0, 0, 1_000_000);

        boolean enableFullScan = readYesNo(in,
                "Vollständiger Länderscan (ein Host pro Netzblock) aktivieren? [y/N]",
                false);

        ActiveScanner.AdvancedScanOptions adv = new ActiveScanner.AdvancedScanOptions();
        adv.randomSampleCount = randomCount;
        adv.enableCountryFullScan = enableFullScan;
        adv.countryIsoCodes = isoList;

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

        // Country-CSV
        Path blocksCsv = geoipDir.resolve("GeoLite2-Country-Blocks-IPv4.csv");
        Path locCsv = geoipDir.resolve("GeoLite2-Country-Locations-en.csv");
        if (Files.exists(blocksCsv)) {
            adv.countryBlocksCsvPath = blocksCsv.toString();
        }
        if (Files.exists(locCsv)) {
            adv.countryLocationsCsvPath = locCsv.toString();
        }

        // City-CSV (optional)
        Path cityBlocksCsv = geoipDir.resolve("GeoLite2-City-Blocks-IPv4.csv");
        Path cityLocCsv = geoipDir.resolve("GeoLite2-City-Locations-en.csv");
        if (Files.exists(cityBlocksCsv)) {
            adv.cityBlocksCsvPath = cityBlocksCsv.toString();
        }
        if (Files.exists(cityLocCsv)) {
            adv.cityLocationsCsvPath = cityLocCsv.toString();
        }

        boolean debug = readYesNo(in, "Debug-Logging aktivieren? [y/N]", false);

        ActiveScanner scanner = new ActiveScanner();
        try {
            scanner.scan(
                    Collections.emptyList(),   // keine direkten Ziele
                    Collections.singletonList(443),
                    outputFile,
                    null,
                    debug,
                    5000,   // Timeout
                    100,    // Parallelität
                    null,
                    adv
            );
            System.out.println("\nGeo-Länderscan abgeschlossen. Ergebnisse: " + outputFile);
        } catch (Exception e) {
            System.err.println("Fehler beim Länderscan: " + e.getMessage());
        }
    }

    // --- 3) CT-Stream ---------------------------------------------------------------------

    private static void runCtStreamInteractive(Scanner in) {
        System.out.println("\n--- CT-Stream (CertStream, WebSocket) ---");
        Path outDir = defaultScanDir();
        ensureDir(outDir);

        String outFileName = promptFree(in,
                "Output-Dateiname (ohne Pfad)",
                "certs_stream.jsonl");
        Path outPath = outDir.resolve(outFileName);

        boolean certOnly = readYesNo(in, "Nur reduzierte Cert-Felder speichern? [y/N]", false);
        long duration = readLong(in, "Maximale Laufzeit in Sekunden (0 = unbegrenzt)", 0, 0, Long.MAX_VALUE);
        long maxEvents = readLong(in, "Max. Anzahl Events (0 = unbegrenzt)", 0, 0, Long.MAX_VALUE);
        boolean debug = readYesNo(in, "Debug-Logging aktivieren? [y/N]", false);

        ensureDir(outPath.getParent());

        System.out.println("Hinweis: Nutzung öffentlicher CT-Feeds über CertStream (passiv).");
        new CertStreamClient(outPath, certOnly, duration, maxEvents, debug, true).run();
    }

    // --- 4) CT-Poll ------------------------------------------------------------------------

    private static void runCtPollInteractive(Scanner in) {
        System.out.println("\n--- CT-Poll (passiv, HTTP RFC6962 get-entries) ---");
        String logUrl = promptFree(in, "CT-Log-Basis-URL (--log), z.B. https://ct.googleapis.com/logs/argon2023", "");
        long start = readLong(in, "Startindex (--start)", 0, 0, Long.MAX_VALUE);
        int batch = (int) readLong(in, "Batchgröße (--batch, 1-4096)", 256, 1, 4096);
        int sleepMs = (int) readLong(in, "Pause zwischen Batches in ms (--sleep-ms)", 500, 0, 60000);
        long maxEntries = readLong(in, "Maximal Einträge (--max-entries, 0 = unbegrenzt)", 0, 0, Long.MAX_VALUE);

        Path outDir = defaultScanDir();
        ensureDir(outDir);

        String outFileName = promptFree(in,
                "Output-Dateiname (ohne Pfad)",
                "certs_poll.jsonl");
        Path output = outDir.resolve(outFileName);

        boolean certOnly = readYesNo(in, "Nur reduzierte Zertifikatsfelder speichern? [y/N]", true);
        boolean noProgress = readYesNo(in, "Fortschrittsanzeige unterdrücken? [y/N]", false);
        boolean debug = readYesNo(in, "Debug-Logging aktivieren? [y/N]", false);

        try {
            CtPoller poller = new CtPoller(
                    logUrl,
                    start,
                    batch,
                    sleepMs,
                    maxEntries,
                    output,
                    certOnly,
                    noProgress,
                    debug
            );
            poller.run();
            System.out.println("\nCT-Poll abgeschlossen. Ergebnisse: " + output);
        } catch (Exception e) {
            System.err.println("Fehler beim CT-Poll: " + e.getMessage());
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

        String scoreFile = promptFree(in,
                "Path zu country_trustscores.json (leer = Default aus Ressourcen)",
                "");
        scoreFile = emptyToNull(scoreFile);

        boolean debug = readYesNo(in, "Debug-Details anzeigen? [y/N]", false);

        Analyzer analyzer = new Analyzer();
        try {
            analyzer.analyze(
                    inPath,
                    scoreFile,
                    debug
            );
        } catch (Exception e) {
            System.err.println("Fehler bei Analyse: " + e.getMessage());
        }
    }

    // --- 6) RootStore-Score ---------------------------------------------------------------

    private static void runStoreScoreInteractive(Scanner in) {
        System.out.println("\n--- TrustStore-Score ---");
        String storePathStr = promptFree(in,
                "Pfad zum RootStore (Java keystore, z.B. cacerts)",
                defaultJavaCacerts().toString());

        Path storePath = Paths.get(storePathStr);
        if (!Files.exists(storePath)) {
            System.err.println("Datei existiert nicht: " + storePath);
            return;
        }

        String password = promptFree(in,
                "Passwort für den Store (leer = 'changeit')",
                "changeit");

        String scoresFile = promptFree(in,
                "Path zu country_trustscores.json (leer = Default aus Ressourcen)",
                "");

        scoresFile = emptyToNull(scoresFile);

        StoreScorer scorer = new StoreScorer();
        try {
            scorer.scoreStore(
                    storePath,
                    password.toCharArray(),
                    scoresFile
            );
        } catch (Exception e) {
            System.err.println("Fehler beim Bewerten des Stores: " + e.getMessage());
        }
    }

    // --- Unterkommandos für picocli CLI ---------------------------------------------------

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
            ensureDir(outDir);
            Path outPath = outDir.resolve(outFile);
            ensureDir(outPath.getParent());
            new CertStreamClient(outPath, certOnly, durationSeconds, maxEvents, debug, true).run();
            return 0;
        }
    }

    static class CtPollCommand implements Callable<Integer> {
        @Option(names = {"--log"}, required = true, description = "CT-Log-Basis-URL, z.B. https://ct.googleapis.com/logs/argon2023")
        String logBase;
        @Option(names = {"--start"}, description = "Startindex (default 0)")
        long start = 0;
        @Option(names = {"--batch"}, description = "Batchgröße (default 256, max 4096)")
        int batch = 256;
        @Option(names = {"--sleep-ms"}, description = "Pause zwischen Batches in ms (default 500)")
        int sleepMs = 500;
        @Option(names = {"--max-entries"}, description = "Maximale Anzahl Einträge (0 = unbegrenzt)")
        long maxEntries = 0;
        @Option(names = {"-o", "--output"}, description = "Voller Output-Pfad (hat Vorrang vor --out-dir/--out-file).")
        Path output;
        @Option(names = {"--out-dir"}, description = "Output-Ordner (default: <Projektroot>/Scanfiles)")
        Path outDir = defaultScanDir();
        @Option(names = {"--out-file"}, description = "Output-Dateiname (default: certs_poll.jsonl)")
        String outFile = "certs_poll.jsonl";
        @Option(names = {"--cert-only"}, description = "Nur reduzierte Felder speichern (kleiner).")
        boolean certOnly = true;
        @Option(names = {"--no-progress"}, description = "Unterdrückt Live-Status.")
        boolean noProgress = false;
        @Option(names = {"--debug"}, description = "Debug-Logging aktivieren.")
        boolean debug = false;

        @Override
        public Integer call() throws Exception {
            Path outPath;
            if (output != null) {
                outPath = output;
            } else {
                ensureDir(outDir);
                outPath = outDir.resolve(outFile);
            }
            ensureDir(outPath.getParent());

            CtPoller poller = new CtPoller(
                    logBase,
                    start,
                    batch,
                    sleepMs,
                    maxEntries,
                    outPath,
                    certOnly,
                    noProgress,
                    debug
            );
            poller.run();
            return 0;
        }
    }

    // --- Utility-Methoden -----------------------------------------------------------------

    private static String readChoice(Scanner in, String label, Set<String> allowed, String defaultVal) {
        while (true) {
            System.out.print(label + (defaultVal != null ? " [" + defaultVal + "]" : "") + ": ");
            String s = in.nextLine().trim();
            if (s.isEmpty() && defaultVal != null) return defaultVal;
            if (allowed.contains(s)) return s;
            System.out.println("Ungültige Eingabe. Erlaubt: " + allowed);
        }
    }

    private static boolean readYesNo(Scanner in, String label, boolean defaultYes) {
        String def = defaultYes ? "Y/n" : "y/N";
        while (true) {
            System.out.print(label + " (" + def + "): ");
            String s = in.nextLine().trim().toLowerCase(Locale.ROOT);
            if (s.isEmpty()) return defaultYes;
            if (s.startsWith("y") || s.startsWith("j")) return true;
            if (s.startsWith("n")) return false;
            System.out.println("Bitte 'y' oder 'n' eingeben.");
        }
    }

    private static long readLong(Scanner in, String label, long def, long min, long max) {
        while (true) {
            System.out.print(label + " [" + def + "]: ");
            String s = in.nextLine().trim();
            if (s.isEmpty()) return def;
            try {
                long v = Long.parseLong(s);
                if (v < min || v > max) {
                    System.out.println("Wert außerhalb des erlaubten Bereichs (" + min + "-" + max + ").");
                    continue;
                }
                return v;
            } catch (NumberFormatException e) {
                System.out.println("Bitte eine Zahl eingeben.");
            }
        }
    }

    private static String promptFree(Scanner in, String label, String defaultVal) {
        System.out.print(label + " [" + defaultVal + "]: ");
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
