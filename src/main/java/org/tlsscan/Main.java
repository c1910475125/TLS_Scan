package org.tlsscan;

import org.tlsscan.Commands.ActiveScanCommand;
import org.tlsscan.Commands.AnalyzeCommand;
import org.tlsscan.Commands.StoreScoreCommand;
import picocli.CommandLine;
import picocli.CommandLine.Command;
import org.tlsscan.Commands.CompareScanCommand;


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
                    .addSubcommand("compare-scan", new CompareScanCommand())
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
            System.out.println("2) GeoLite-Scan (Country / City / ASN)");
            System.out.println("3) JSONL analysieren");
            System.out.println("4) TrustStore bewerten");
            System.out.println("5) Scans vergleichen");
            System.out.println("0) Beenden");

            String choice = readChoice(in, "Auswahl", Set.of("0", "1", "2", "3", "4", "5"), null);
            switch (choice) {
                case "1" -> runIpScanInteractive(in);
                case "2" -> runGeoScanInteractive(in);
                case "3" -> runAnalyzeInteractive(in);
                case "4" -> runStoreScoreInteractive(in);
                case "5" -> runCompareScanInteractive(in);
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
        for (String p : targetInput.split(",")) {
            String s = p.trim();
            if (!s.isEmpty()) targets.add(s);
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

        boolean debug = readYesNo(in, "Debug-Logging aktivieren? [y/N]");

        // --- zgrab erzwingen ---------------------------------------
        ActiveScanner.AdvancedScanOptions adv = new ActiveScanner.AdvancedScanOptions();

        Path zgrabPath = projectRoot()
                .resolve("bin")
                .resolve("zgrab2.exe");
        adv.useZgrabOnly = true;
        adv.zgrabBinary = zgrabPath.toString();

        ActiveScanner scanner = new ActiveScanner();
        try {
            scanner.scan(
                    targets,
                    ports,
                    outputFile,
                    debug,
                    5000,
                    100,
                    adv
            );
        } catch (Exception e) {
            System.err.println("Fehler beim Scan: " + e.getMessage());
        }
    }


    // --- 2) Country-Scan (Geo) ------------------------------------------------------------

    private static void runGeoScanInteractive(Scanner in) {
        System.out.println("\n--- GeoLite-Scan (GeoLite2) ---");
        System.out.println("Scannt IPs, die in den GeoLite2-Datenbanken liegen (Country / City / ASN).");
        System.out.println("Basis-Output-Ordner: " + defaultScanDir());

        String outFileName = promptFree(in,
                "Output-Dateiname (ohne Pfad)",
                "active_scan_country");

        Path outputFile = defaultScanDir().resolve(outFileName + ".jsonl");
        ensureDir(outputFile.getParent());
        System.out.println("Output:  " + outputFile);

        // Auswahl des Geo-Filter-Typs
        String geoMode = readChoice(in,
                "Geo-Filter-Typ [country|city|asn]",
                Set.of("country", "city", "asn"),
                "country");

        List<String> isoList = new ArrayList<>();
        List<String> cityList = new ArrayList<>();
        List<Long> asnList = new ArrayList<>();

        switch (geoMode) {
            case "country" -> {
                String isoStr = promptFree(in,
                        "Länder-ISO-Codes (z.B. AT,DE,US – leer = alle Länder in GeoLite2)",
                        "");
                if (isoStr != null && !isoStr.isBlank()) {
                    for (String c : isoStr.split(",")) {
                        c = c.trim().toUpperCase(Locale.ROOT);
                        if (!c.isEmpty()) isoList.add(c);
                    }
                }
            }
            case "city" -> {
                String cityStr = promptFree(in,
                        "Städte (kommagetrennt, z.B. Vienna,Munich – leer = alle Cities)",
                        "");
                if (cityStr != null && !cityStr.isBlank()) {
                    for (String c : cityStr.split(",")) {
                        c = c.trim();
                        if (!c.isEmpty()) cityList.add(c);
                    }
                }
            }
            case "asn" -> {
                String asnStr = promptFree(in,
                        "ASNs (kommagetrennt, z.B. 13335 (Cloudflare), 15169 (Google) – leer = alle ASNs)",
                        "");
                if (asnStr != null && !asnStr.isBlank()) {
                    for (String a : asnStr.split(",")) {
                        a = a.trim();
                        if (a.isEmpty()) continue;
                        try {
                            asnList.add(Long.parseLong(a));
                        } catch (NumberFormatException e) {
                            System.out.println("Ignoriere ungültige ASN: " + a);
                        }
                    }
                }
            }
        }

        int randomCount = (int) readLong(in
        );

        boolean enableFullScan = (randomCount == 0);

        ActiveScanner.AdvancedScanOptions adv = new ActiveScanner.AdvancedScanOptions();
        adv.randomSampleCount = randomCount;
        adv.enableCountryFullScan = enableFullScan;
        adv.countryIsoCodes = isoList;
        adv.cityNames = cityList;
        adv.asns = asnList;

        Path zgrabPath = projectRoot()
                .resolve("bin")
                .resolve("zgrab2.exe");
        adv.useZgrabOnly = true;
        adv.zgrabBinary = zgrabPath.toString();

        configureGeoIpDefaults(adv);

        List<Integer> ports = new ArrayList<>();
        ports.add(443);

        boolean debug = readYesNo(in, "Debug-Logging aktivieren? [y/N]");

        ActiveScanner scanner = new ActiveScanner();
        try {
            scanner.scan(
                    Collections.emptyList(),
                    ports,
                    outputFile,
                    debug,
                    5000,
                    100,
                    adv
            );
        } catch (Exception e) {
            System.err.println("Fehler beim GeoLite-Scan: " + e.getMessage());
        }
    }


    // --- 3) Analyzer ----------------------------------------------------------------------

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

        boolean debug = readYesNo(in, "Debug-Details anzeigen? [y/N]");

        boolean saveSummary = readYesNo(in,
                "Analyse-Ergebnis als JSON speichern? [y/N]"
        );
        Path summaryOutput = null;
        if (saveSummary) {
            String timestamp = java.time.ZonedDateTime.now().format(
                    java.time.format.DateTimeFormatter.ofPattern("yyyyMMdd-HHmmss")
            );
            String defaultName = "analysis" + timestamp + ".json";

            String summaryName = promptFree(in,
                    "Dateiname für Summary (ohne Pfad, .json wird automatisch ergänzt)",
                    defaultName);

            if (summaryName == null || summaryName.isBlank()) {
                summaryName = defaultName;
            }
            summaryName = summaryName.trim();
            if (!summaryName.toLowerCase(Locale.ROOT).endsWith(".json")) {
                summaryName += ".json";
            }

            Path baseDir = (inPath.getParent() != null) ? inPath.getParent() : defaultScanDir();
            summaryOutput = baseDir.resolve(summaryName);
        }

        Analyzer analyzer = new Analyzer();
        try {
            analyzer.analyze(
                    inPath,
                    null,
                    debug,
                    summaryOutput
            );
        } catch (Exception e) {
            System.err.println("Fehler bei Analyse: " + e.getMessage());
        }
    }

    // --- 4) RootStore-Score ----------------------------------------------------

    private static void runStoreScoreInteractive(Scanner in) {
        System.out.println("\n--- TrustStore-/CA-Bundle-Score (PEM) ---");
        String storePathStr = promptFree(in,
                "Pfad zum CA-Bundle (PEM, z.B. cacert.pem von Mozilla/Google)",
                "cacert.pem");

        Path inPath = Paths.get(storePathStr);
        if (!inPath.isAbsolute()) {
            inPath = defaultScanDir().resolve(storePathStr);
        }

        if (!Files.exists(inPath)) {
            System.err.println("Datei existiert nicht: " + inPath);
            return;
        }

        boolean debug = readYesNo(in, "Debug-Details anzeigen? [y/N]");

        boolean saveSummary = readYesNo(in,
                "Analyse-Ergebnis als JSON speichern? [y/N]"
        );
        Path summaryOutput = null;
        if (saveSummary) {
            String timestamp = java.time.ZonedDateTime.now().format(
                    java.time.format.DateTimeFormatter.ofPattern("yyyyMMdd-HHmmss")
            );
            String defaultName = "analysis" + timestamp + ".json";

            String summaryName = promptFree(in,
                    "Dateiname für Summary (ohne Pfad, .json wird automatisch ergänzt)",
                    defaultName);

            if (summaryName == null || summaryName.isBlank()) {
                summaryName = defaultName;
            }
            summaryName = summaryName.trim();
            if (!summaryName.toLowerCase(Locale.ROOT).endsWith(".json")) {
                summaryName += ".json";
            }

            Path baseDir = (inPath.getParent() != null) ? inPath.getParent() : defaultScanDir();
            summaryOutput = baseDir.resolve(summaryName);
        }

        StoreScorer scorer = new StoreScorer();
        try {
            scorer.scoreStoreAuto(
                    inPath,
                    null,
                    summaryOutput,
                    null,
                    debug
            );
        } catch (Exception e) {
            System.err.println("Fehler beim Bewerten des CA-Bundles: " + e.getMessage());
        }
    }

    // --- 5) Scans vergleichen (Diff-Modus) -----------------------------------------

    private static void runCompareScanInteractive(Scanner in) {
        System.out.println("\n--- Scan-Vergleich (Diff-Modus) ---");
        System.out.println("Basis-Ordner für Scans: " + defaultScanDir());
        System.out.println("Hinweis: Dateinamen können relativ zu diesem Ordner oder absolut angegeben werden.\n");

        String oldName = promptFree(
                in,
                "Ältere Scan-Datei (JSONL, z.B. at.jsonl)",
                ""
        );
        if (oldName == null || oldName.isBlank()) {
            System.out.println("Keine Datei angegeben – Abbruch.");
            return;
        }

        String newName = promptFree(
                in,
                "Neuere Scan-Datei (JSONL, z.B. de.jsonl)",
                ""
        );
        if (newName == null || newName.isBlank()) {
            System.out.println("Keine Datei angegeben – Abbruch.");
            return;
        }

        String summaryOutName = promptFree(
                in,
                "Optional: Diff-Summary-Output (JSON, leer = kein JSON-Output)",
                ""
        );

        boolean debug = readYesNo(in, "Debug-Logging aktivieren? [y/N]");

        Path oldPath = resolveScanPath(oldName);
        Path newPath = resolveScanPath(newName);

        if (!Files.exists(oldPath)) {
            System.err.println("Alte Scan-Datei existiert nicht: " + oldPath);
            return;
        }
        if (!Files.exists(newPath)) {
            System.err.println("Neue Scan-Datei existiert nicht: " + newPath);
            return;
        }

        Path summaryOut = null;
        if (summaryOutName != null && !summaryOutName.isBlank()) {
            String name = summaryOutName.trim();
            if (!name.toLowerCase(Locale.ROOT).endsWith(".json")) {
                name += ".json";
            }
            summaryOut = defaultScanDir().resolve(name).normalize();
            ensureDir(summaryOut.getParent());
        }

        System.out.println("\nVergleiche:");
        System.out.println("  Alt : " + oldPath);
        System.out.println("  Neu : " + newPath);
        if (summaryOut != null) {
            System.out.println("  Diff-JSON: " + summaryOut);
        }

        try {
            ScanDiff diff = new ScanDiff();
            diff.compare(
                    oldPath,
                    newPath,
                    null,
                    debug,
                    summaryOut
            );
        } catch (Exception e) {
            System.err.println("Fehler beim Scan-Vergleich: " + e.getMessage());
            e.printStackTrace(System.err);
        }
    }

    private static Path resolveScanPath(String input) {
        String name = input.trim();

        Path raw = Paths.get(name);
        if (!raw.isAbsolute() && !name.toLowerCase(Locale.ROOT).endsWith(".jsonl")) {
            name += ".jsonl";
        }

        Path p = Paths.get(name);
        if (p.isAbsolute()) {
            return p.normalize();
        }
        return defaultScanDir().resolve(p).normalize();
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

    private static boolean readYesNo(Scanner in, String prompt) {
        while (true) {
            System.out.print(prompt + " ");
            String line = in.nextLine();
            if (line == null || line.isBlank()) {
                return false;
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

    private static void configureGeoIpDefaults(ActiveScanner.AdvancedScanOptions adv) {
        Path geoipDir = projectRoot().resolve("GeoIP");

        // MMDBs
        Path defCountryDb = geoipDir.resolve("GeoLite2-Country.mmdb");
        Path defAsnDb     = geoipDir.resolve("GeoLite2-ASN.mmdb");
        Path defCityDb    = geoipDir.resolve("GeoLite2-City.mmdb");

        if (Files.exists(defCountryDb)) {
            adv.geoipCountryDbPath = defCountryDb.toString();
        } else {
            System.out.println("[GeoIP] Warnung: Country-DB nicht gefunden: " + defCountryDb);
        }

        if (Files.exists(defAsnDb)) {
            adv.geoipAsnDbPath = defAsnDb.toString();
        } else {
            System.out.println("[GeoIP] Warnung: ASN-DB nicht gefunden: " + defAsnDb);
        }

        if (Files.exists(defCityDb)) {
            adv.geoipCityDbPath = defCityDb.toString();
        } else {
            System.out.println("[GeoIP] Hinweis: City-DB nicht gefunden: " + defCityDb);
        }

        // CSVs – nur noch Warnungen, keine „lade ...“-Logs mehr
        Path countryBlocksCsv = geoipDir.resolve("GeoLite2-Country-Blocks-IPv4.csv");
        Path countryLocCsv    = geoipDir.resolve("GeoLite2-Country-Locations-en.csv");
        if (Files.exists(countryBlocksCsv)) {
            adv.countryBlocksCsvPath = countryBlocksCsv.toString();
        } else {
            System.out.println("[GeoIP] Hinweis: Country-Blocks-CSV nicht gefunden: " + countryBlocksCsv);
        }
        if (Files.exists(countryLocCsv)) {
            adv.countryLocationsCsvPath = countryLocCsv.toString();
        } else {
            System.out.println("[GeoIP] Hinweis: Country-Locations-CSV nicht gefunden: " + countryLocCsv);
        }

        Path asnBlocksCsv = geoipDir.resolve("GeoLite2-ASN-Blocks-IPv4.csv");
        if (Files.exists(asnBlocksCsv)) {
            adv.asnBlocksCsvPath = asnBlocksCsv.toString();
        } else {
            System.out.println("[GeoIP] Hinweis: ASN-Blocks-CSV nicht gefunden: " + asnBlocksCsv);
        }

        Path cityBlocksCsv = geoipDir.resolve("GeoLite2-City-Blocks-IPv4.csv");
        Path cityLocCsv    = geoipDir.resolve("GeoLite2-City-Locations-en.csv");
        if (Files.exists(cityBlocksCsv)) {
            adv.cityBlocksCsvPath = cityBlocksCsv.toString();
        } else {
            System.out.println("[GeoIP] Hinweis: City-Blocks-CSV nicht gefunden: " + cityBlocksCsv);
        }
        if (Files.exists(cityLocCsv)) {
            adv.cityLocationsCsvPath = cityLocCsv.toString();
        } else {
            System.out.println("[GeoIP] Hinweis: City-Locations-CSV nicht gefunden: " + cityLocCsv);
        }
    }



    private static long readLong(Scanner in) {
        while (true) {
            System.out.print("Zufallsstichprobe: Anzahl Hosts aus GeoLite-Blocks-CSV (0 = vollständiger Scan)" + " [" + (long) 0 + "]: ");
            String line = in.nextLine();
            if (line == null || line.isBlank()) {
                return 0;
            }
            try {
                long v = Long.parseLong(line.trim());
                if (v < (long) 0 || v > (long) 1000000) {
                    System.out.println("Wert außerhalb des gültigen Bereichs (" + (long) 0 + "–" + (long) 1000000 + ").");
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

}