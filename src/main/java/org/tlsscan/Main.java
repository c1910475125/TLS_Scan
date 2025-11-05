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

@Command(
        name = "passive-cert-analyzer",
        mixinStandardHelpOptions = true,
        description = "Toolset zur Analyse von TLS-Zertifikaten (passiv über CT-Feeds und aktiv via Scan)."
)
public class Main implements java.util.concurrent.Callable<Integer> {

    public static void main(String[] args) {
        if (args != null && args.length > 0) {
            int exit = new CommandLine(new Main())
                    .addSubcommand("ct-stream", new CtStreamCommand())
                    .addSubcommand("ct-poll", new CtPollCommand())
                    .addSubcommand("scan", new ActiveScanCommand())
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
        System.out.println("Verwende Subcommands: 'ct-stream' / 'ct-poll' / 'scan' / 'analyze' / 'store-score'");
        System.out.println("Oder ohne Argumente starten, um das interaktive Menü zu nutzen.");
        return 0;
    }

    // ===== Defaults / Helper =====

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

    private static Path defaultJavaCacerts() {
        String javaHome = System.getProperty("java.home");
        if (javaHome == null) return Paths.get("");
        return Paths.get(javaHome, "lib", "security", "cacerts");
    }

    private static String emptyToNull(String s) {
        return (s == null || s.isBlank()) ? null : s;
    }

    // ===== Interaktives Menü =====

    private static void interactiveMenu() {
        Scanner in = new Scanner(System.in);
        while (true) {
            System.out.println("\n=== TLS Cert Analyzer – Menü ===");
            System.out.println("1) CT-Stream (WebSocket, CertStream) – passiv");
            System.out.println("2) CT-Poll (HTTP RFC6962) – passiv");
            System.out.println("3) JSONL analysieren");
            System.out.println("4) TrustStore bewerten");
            System.out.println("5) Aktiver TLS-Scan (Hosts/IPs)");
            System.out.println("0) Beenden");

            String choice = readChoice(in, "Auswahl", Set.of("0", "1", "2", "3", "4", "5"), null);

            switch (choice) {
                case "1" -> runCtStreamInteractive(in);
                case "2" -> runCtPollInteractive(in);
                case "3" -> runAnalyzeInteractive(in);
                case "4" -> runStoreScoreInteractive(in);
                case "5" -> runActiveScanInteractive(in);
                case "0" -> {
                    System.out.println("Bye.");
                    return;
                }
            }
        }
    }

    // --- Interaktiv: CT-Stream ---

    private static void runCtStreamInteractive(Scanner in) {
        System.out.println("\n--- CT-Stream (CertStream, passiv) ---");
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

    // --- Interaktiv: CT-Poll ---

    private static void runCtPollInteractive(Scanner in) {
        System.out.println("\n--- CT-Poll (passiv, HTTP RFC6962) ---");
        String logUrl = promptFree(in, "CT-Log-Basis (--log)", "https://ct.googleapis.com/logs/argon2023");
        long start = readLong(in, "Start-Index (--start)", 0, 0, Long.MAX_VALUE);
        int batch = readInt(in, "Batchgröße (--batch)", 256, 1, 4096);
        int sleepMs = readInt(in, "Pause zwischen Batches ms (--sleep-ms)", 500, 0, 60000);
        long maxEntries = readLong(in, "Max. Einträge (0 = unbegrenzt) (--max-entries)", 0, 0, Long.MAX_VALUE);
        String outDir = promptFree(in, "Output-Ordner (--out-dir)", defaultScanDir().toString());
        String outFile = promptFree(in, "Output-Dateiname (--out-file)", "certs_poll.jsonl");
        boolean certOnly = readYesNo(in, "Nur reduzierte Felder speichern? [y/N]", true);
        boolean progress = true;
        boolean debug = readYesNo(in, "Debug-Logging aktivieren? [y/N]", false);

        Path outPath = Paths.get(outDir).resolve(outFile);
        ensureDir(outPath.getParent());

        new CtPoller(outPath, certOnly, progress, debug)
                .run(logUrl, start, batch, sleepMs, maxEntries);
    }

    // --- Interaktiv: Analyse JSONL ---

    private static void runAnalyzeInteractive(Scanner in) {
        System.out.println("\n--- Analyse von JSONL ---");
        String inFile = promptFree(in, "Input-Datei (--input)", defaultOutputPath().toString());
        boolean withTs = readYesNo(in, "TrustScores pro Ausstellerland berechnen? [y/N]", false);
        new Analyzer().processJsonl(inFile, withTs);
    }

    // --- Interaktiv: Store-Score ---

    private static void runStoreScoreInteractive(Scanner in) {
        System.out.println("\n--- TrustStore bewerten ---");
        String storePath = promptFree(in, "Store-Datei (--store)", defaultJavaCacerts().toString());
        String type = promptFree(in, "Store-Typ (--type)", "jks (jks/pkcs12/pem-bundle/pem-dir)").split(" ")[0];
        String password = promptFree(in, "Store-Passwort (--password, leer=none)", "");
        String countryFrom = promptFree(in, "Land aus 'issuer' oder 'subject'? (--country-from)", "issuer");
        String scores = promptFree(in, "country_trustscores.json (leer = aus Ressourcen)", "");
        boolean includeNonCa = readYesNo(in, "Nicht-CA-Zertifikate mitbewerten? [y/N]", false);

        String scoresPath = emptyToNull(scores);
        try {
            double score = new StoreScorer().scoreStore(
                    storePath,
                    type,
                    password.isBlank() ? null : password,
                    scoresPath,
                    countryFrom,
                    includeNonCa
            );
            System.out.printf("Gesamter gewichteter TrustScore: %.6f%n", score);
        } catch (Exception e) {
            System.err.println("Fehler bei Store-Bewertung: " + e.getMessage());
        }
    }

    // --- Interaktiv: Aktiver Scan ---

    private static void runActiveScanInteractive(Scanner in) {
        System.out.println("\n--- Aktiver TLS-Scan ---");
        String inlineTargets = promptFree(in,
                "Ziele als Liste (kommagetrennt, host oder host:port) [leer = nur Datei]",
                "");
        String targetsFile = promptFree(in,
                "Optional: Datei mit Zielen (eine pro Zeile, host oder host:port) [leer = keine]",
                "");
        int port = readInt(in, "Standardport, falls nicht im Ziel angegeben", 443, 1, 65535);
        String outDir = promptFree(in, "Output-Ordner (--output)", defaultScanDir().toString());
        String outFile = promptFree(in, "Output-Dateiname", "active_scan.jsonl");
        int timeoutMs = readInt(in, "Timeout pro Ziel (ms)", 5000, 100, 60000);
        String scores = promptFree(in, "country_trustscores.json (leer = aus Ressourcen)", "");
        boolean debug = readYesNo(in, "Debug-Logging aktivieren? [y/N]", false);

        List<String> targets = new ArrayList<>();
        if (!inlineTargets.isBlank()) {
            for (String part : inlineTargets.split(",")) {
                String t = part.trim();
                if (!t.isEmpty()) targets.add(t);
            }
        }

        if (!targetsFile.isBlank()) {
            Path p = Paths.get(targetsFile);
            try {
                for (String line : Files.readAllLines(p)) {
                    String s = line.trim();
                    if (!s.isEmpty() && !s.startsWith("#")) {
                        targets.add(s);
                    }
                }
            } catch (Exception e) {
                System.err.println("Konnte Targets-Datei nicht lesen: " + e.getMessage());
            }
        }

        if (targets.isEmpty()) {
            System.out.println("Keine Ziele angegeben – Scan wird abgebrochen.");
            return;
        }

        Path outPath = Paths.get(outDir).resolve(outFile);
        ensureDir(outPath.getParent());

        String scoresPath = emptyToNull(scores);

        try {
            new ActiveScanner().scan(targets, port, outPath, scoresPath, debug, timeoutMs);
        } catch (Exception e) {
            System.err.println("Fehler beim aktiven Scan: " + e.getMessage());
        }
    }

    // ===== CLI-Input Helpers =====

    private static String promptFree(Scanner in, String label, String defaultValue) {
        System.out.print(label + (defaultValue != null ? " [" + defaultValue + "]" : "") + ": ");
        String s = in.nextLine().trim();
        if (s.isEmpty()) return defaultValue;
        return s;
    }

    private static boolean readYesNo(Scanner in, String label, boolean def) {
        while (true) {
            System.out.print(label + (def ? " [Y/n]" : " [y/N]") + ": ");
            String s = in.nextLine().trim().toLowerCase(Locale.ROOT);
            if (s.isEmpty()) return def;
            if (s.equals("y") || s.equals("yes") || s.equals("j") || s.equals("ja")) return true;
            if (s.equals("n") || s.equals("no") || s.equals("nein")) return false;
            System.out.println("Bitte 'y' oder 'n' eingeben.");
        }
    }

    private static int readInt(Scanner in, String label, int def, int min, int max) {
        while (true) {
            System.out.print(label + " [" + def + "]: ");
            String s = in.nextLine().trim();
            if (s.isEmpty()) return def;
            try {
                int v = Integer.parseInt(s);
                if (v < min || v > max) throw new NumberFormatException();
                return v;
            } catch (NumberFormatException e) {
                System.out.println("Ungültige Zahl, bitte erneut eingeben.");
            }
        }
    }

    private static long readLong(Scanner in, String label, long def, long min, long max) {
        while (true) {
            System.out.print(label + " [" + def + "]: ");
            String s = in.nextLine().trim();
            if (s.isEmpty()) return def;
            try {
                long v = Long.parseLong(s);
                if (v < min || v > max) throw new NumberFormatException();
                return v;
            } catch (NumberFormatException e) {
                System.out.println("Ungültige Zahl, bitte erneut eingeben.");
            }
        }
    }

    private static String readChoice(Scanner in, String label, Set<String> allowed, String def) {
        while (true) {
            System.out.print(label + (def != null ? " [" + def + "]" : "") + ": ");
            String s = in.nextLine().trim();
            if (s.isEmpty() && def != null) return def;
            if (allowed.contains(s)) return s;
            System.out.println("Ungültige Auswahl: " + s);
        }
    }

    // ===== Subcommands für CtStream / CtPoll =====

    @Command(name = "ct-stream", description = "Liest öffentliche CT-Events via certstream-java und schreibt JSONL.")
    static class CtStreamCommand implements java.util.concurrent.Callable<Integer> {

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
    static class CtPollCommand implements java.util.concurrent.Callable<Integer> {

        @Option(names = {"--log"}, required = true,
                description = "CT-Log-Basis-URL, z.B. https://ct.googleapis.com/logs/argon2023")
        String logUrl;

        @Option(names = {"--start"}, description = "Startindex (default 0)")
        long start = 0;

        @Option(names = {"--batch"}, description = "Batchgröße (default 256)")
        int batch = 256;

        @Option(names = {"--sleep-ms"}, description = "Pause zwischen Batches in ms (default 500)")
        int sleepMs = 500;

        @Option(names = {"--max-entries"}, description = "Max. Einträge (0 = unbegrenzt)")
        long maxEntries = 0;

        @Option(names = {"--out-dir"}, description = "Output-Ordner (default: ./Scanfiles)")
        Path outDir = defaultScanDir();

        @Option(names = {"--out-file"}, description = "Output-Dateiname (default: certs_poll.jsonl)")
        String outFile = "certs_poll.jsonl";

        @Option(names = {"--cert-only"}, description = "Nur reduzierte Felder speichern (default: true).")
        boolean certOnly = true;

        @Option(names = {"--debug"}, description = "Debug-Logging aktivieren.")
        boolean debug = false;

        @Override
        public Integer call() {
            Path outPath = outDir.resolve(outFile);
            ensureDir(outPath.getParent());
            boolean progress = true;
            new CtPoller(outPath, certOnly, progress, debug)
                    .run(logUrl, start, batch, sleepMs, maxEntries);
            return 0;
        }
    }
}
