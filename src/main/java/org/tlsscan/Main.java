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
            interactiveMenu();
        }
    }

    @Override
    public Integer call() {
        System.out.println("Subcommands: 'scan' (aktiver TLS-Scan), 'ct-stream', 'ct-poll', 'analyze', 'store-score'.");
        System.out.println("Ohne Argumente startet das interaktive Menü (aktiver + passiver Betrieb).");
        return 0;
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
                String pStr = promptFree(in, "Ports, kommagetrennt (z.B. 443,8443)", "443");
                String[] pParts = pStr.split(",");
                for (String pp : pParts) {
                    String s = pp.trim();
                    if (!s.isEmpty()) {
                        try {
                            ports.add(Integer.parseInt(s));
                        } catch (NumberFormatException e) {
                            System.out.println("Ignoriere ungültigen Port: " + s);
                        }
                    }
                }
                if (ports.isEmpty()) {
                    ports.add(443);
                }
            }
        }

        ActiveScanner.AdvancedScanOptions adv = new ActiveScanner.AdvancedScanOptions();
        adv.randomSampleCount = 0;          // hier keine Zufallsstichprobe
        adv.fullScanCountries = List.of();  // kein Länderscan
        adv.enableCountryFullScan = false;

        // GeoIP-MMDBs (falls vorhanden) – für Metadaten, Filter etc.
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

    // --- 2) Geo-Länderscan -----------------------------------------------------------------

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
        List<String> isoCodes = new ArrayList<>();
        if (isoStr != null && !isoStr.isBlank()) {
            for (String c : isoStr.split(",")) {
                String s = c.trim();
                if (!s.isEmpty()) {
                    isoCodes.add(s.toUpperCase(Locale.ROOT));
                }
            }
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
                String pStr = promptFree(in, "Ports, kommagetrennt (z.B. 443,8443)", "443");
                String[] pParts = pStr.split(",");
                for (String pp : pParts) {
                    String s = pp.trim();
                    if (!s.isEmpty()) {
                        try {
                            ports.add(Integer.parseInt(s));
                        } catch (NumberFormatException e) {
                            System.out.println("Ignoriere ungültigen Port: " + s);
                        }
                    }
                }
                if (ports.isEmpty()) {
                    ports.add(443);
                }
            }
        }

        long sampleCount = readLong(in,
                "Zufällige Basis-IP-Adressen aus GeoLite2 (0 = keine Zufallsstichprobe)",
                0, 0, Integer.MAX_VALUE);
        int randomSampleCount = (int) sampleCount;

        boolean doFull = readYesNo(in,
                "Zusätzlich alle IPv4-Netzblöcke der Länder (ein Host pro Netzblock) scannen? [y/N]",
                false);

        ActiveScanner.AdvancedScanOptions adv = new ActiveScanner.AdvancedScanOptions();

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

        // ASN-CSV (optional)
        Path asnBlocksCsv = geoipDir.resolve("GeoLite2-ASN-Blocks-IPv4.csv");
        if (Files.exists(asnBlocksCsv)) {
            adv.asnBlocksCsvPath = asnBlocksCsv.toString();
        }

        if (!isoCodes.isEmpty()) {
            adv.countryIsoCodes.addAll(isoCodes);
            if (doFull) {
                adv.fullScanCountries.addAll(isoCodes);  // Vollscan nur für diese Länder
            }
        } else if (doFull) {
            // Vollscan über ALLE Länder (kein ISO-Filter)
            adv.fullScanCountries = new ArrayList<>();  // bleibt leer -> Scanner interpretiert das als "alle"
        }

        adv.randomSampleCount = randomSampleCount;
        adv.sampleFromCidr = null;
        adv.enableCountryFullScan = doFull;

        boolean debug = readYesNo(in, "Debug-Logging aktivieren? [y/N]", false);

        ActiveScanner scanner = new ActiveScanner();
        try {
            scanner.scan(
                    Collections.emptyList(), // keine direkten Targets – alles kommt aus GeoLite2
                    ports,
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

    // --- 3) CT-Stream ----------------------------------------------------------------------

    private static void runCtStreamInteractive(Scanner in) {
        System.out.println("\n--- CT-Stream (passiv, via certstream-java) ---");
        String outDir = promptFree(in, "Output-Ordner (--out-dir)", defaultScanDir().toString());
        String outFile = promptFree(in, "Output-Dateiname (--out-file)", "certs.jsonl");
        boolean certOnly = readYesNo(in, "Nur reduzierte Felder speichern? [y/N]", false);
        long duration = readLong(in, "Dauer in Sekunden (0 = unbegrenzt)", 0, 0, Long.MAX_VALUE);
        long maxEvents = readLong(in, "Max. Events (0 = unbegrenzt)", 0, 0, Long.MAX_VALUE);
        boolean debug = readYesNo(in, "Debug-Logging aktivieren? [y/N]", false);

        Path outPath = Paths.get(outDir).resolve(outFile);
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
        String outDir = promptFree(in, "Output-Ordner (--out-dir)", defaultScanDir().toString());
        String outFile = promptFree(in, "Output-Dateiname (--out-file)", "certs_poll.jsonl");
        boolean certOnly = readYesNo(in, "Nur reduzierte Felder speichern? [Y/n]", true);
        boolean noProgress = readYesNo(in, "Ohne Live-Progress? [y/N]", false);
        boolean debug = readYesNo(in, "Debug-Logging aktivieren? [y/N]", false);

        Path outPath = Paths.get(outDir).resolve(outFile);
        ensureDir(outPath.getParent());

        CtPoller poller = new CtPoller(outPath, certOnly, !noProgress, debug);
        poller.run(logUrl, start, batch, sleepMs, maxEntries);
    }

    // --- 5) Analyse ------------------------------------------------------------------------

    private static void runAnalyzeInteractive(Scanner in) {
        System.out.println("\n--- JSONL analysieren ---");
        String inputPath = promptFree(in, "Input-JSONL-Datei (--input)", defaultOutputPath().toString());
        Path input = Paths.get(inputPath);
        if (!Files.exists(input)) {
            System.err.println("Datei existiert nicht: " + input);
            return;
        }
        boolean trustedByCountry = readYesNo(in, "Vertrauensprüfung (lokaler Truststore) & Ländercounts ausgeben? [y/N]", false);
        Analyzer analyzer = new Analyzer();
        analyzer.processJsonl(input.toString(), trustedByCountry);
    }

    // --- 6) StoreScore ---------------------------------------------------------------------

    private static void runStoreScoreInteractive(Scanner in) {
        System.out.println("\n--- Store bewerten (offline) ---");
        String store = promptFree(in, "Pfad zum TrustStore (JKS/PKCS12) oder PEM (Bundle/Dir)", defaultJavaCacerts().toString());
        String type = readChoice(in, "Typ [jks|pkcs12|pem-bundle|pem-dir]", Set.of("jks", "pkcs12", "pem-bundle", "pem-dir"), "jks");
        String password = null;
        if (type.equals("jks") || type.equals("pkcs12")) {
            password = promptFree(in, "Passwort (leer = none)", type.equals("jks") ? "changeit" : "");
        }
        String countryScores = promptFree(in, "Pfad zur country_trustscores.json", "country_trustscores.json");
        String countryFrom = readChoice(in, "Länderquelle [subject|issuer]", Set.of("subject", "issuer"), "subject");
        boolean includeNonCa = readYesNo(in, "Auch Nicht-CA-Zertifikate berücksichtigen? [y/N]", false);

        try {
            StoreScorer scorer = new StoreScorer();
            double score = scorer.scoreStore(
                    store, type, emptyToNull(password), countryScores, countryFrom, includeNonCa
            );
            System.out.printf("%n===> Gesamter gewichteter TrustScore: %.6f%n", score);
        } catch (Exception e) {
            System.err.println("Fehler: " + e.getMessage());
        }
    }

    // --- CT-Subcommands für CLI -----------------------------------------------------------

    @Command(name = "ct-stream", description = "Liest öffentliche CT-Events via certstream-java und schreibt JSONL.")
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
            Path outPath = outDir.resolve(outFile);
            ensureDir(outPath.getParent());
            new CertStreamClient(outPath, certOnly, durationSeconds, maxEvents, debug, true).run();
            return 0;
        }
    }

    @Command(name = "ct-poll", description = "Liest CT-Logs via HTTP (RFC6962 get-entries) und schreibt JSONL.")
    static class CtPollCommand implements Callable<Integer> {
        @Option(names = {"--log"}, required = true, description = "CT-Log-Basis-URL, z.B. https://ct.googleapis.com/logs/argon2023")
        String logUrl;
        @Option(names = {"--start"}, description = "Startindex (default 0)")
        long start = 0;
        @Option(names = {"--batch"}, description = "Batchgröße (1-4096, default 256)")
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
        public Integer call() {
            if (batch < 1 || batch > 4096) {
                System.err.println("batch muss zwischen 1 und 4096 liegen.");
                return 2;
            }

            Path outPath;
            if (output != null) {
                outPath = output;
                ensureDir(outPath.getParent());
            } else {
                outPath = outDir.resolve(outFile);
                ensureDir(outPath.getParent());
            }

            CtPoller poller = new CtPoller(outPath, certOnly, !noProgress, debug);
            poller.run(logUrl, start, batch, sleepMs, maxEntries);
            return 0;
        }
    }

    // --- kleine Helfer --------------------------------------------------------------------

    private static String promptFree(Scanner in, String label, String def) {
        System.out.print(label + (def != null && !def.isBlank() ? " [" + def + "]" : "") + ": ");
        String s = in.nextLine().trim();
        return s.isBlank() ? def : s;
    }

    private static boolean readYesNo(Scanner in, String label, boolean def) {
        String suffix = def ? " [Y/n]" : " [y/N]";
        while (true) {
            System.out.print(label + suffix + " ");
            String line = in.nextLine().trim().toLowerCase();
            if (line.isEmpty()) return def;
            if (line.equals("y") || line.equals("yes") || line.equals("j") || line.equals("ja")) return true;
            if (line.equals("n") || line.equals("no") || line.equals("nein")) return false;
            System.out.println("Bitte 'y' oder 'n' eingeben.");
        }
    }

    private static String readChoice(Scanner in, String label, Set<String> allowed, String def) {
        while (true) {
            System.out.print(label + (def != null ? " [" + def + "]" : "") + ": ");
            String line = in.nextLine().trim();
            if (line.isEmpty() && def != null) return def;
            if (allowed.contains(line)) return line;
            System.out.println("Ungültige Eingabe. Erlaubt: " + allowed);
        }
    }

    private static long readLong(Scanner in, String label, long def, long min, long max) {
        while (true) {
            System.out.print(label + " [" + def + "]: ");
            String s = in.nextLine().trim();
            if (s.isBlank()) return def;
            try {
                long v = Long.parseLong(s);
                if (v < min || v > max) throw new NumberFormatException();
                return v;
            } catch (NumberFormatException e) {
                System.out.println("Invalid value, try again");
            }
        }
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
