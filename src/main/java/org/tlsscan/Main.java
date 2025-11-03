package org.tlsscan;

import org.tlsscan.Commands.AnalyzeCommand;
import org.tlsscan.Commands.StoreScoreCommand;
import picocli.CommandLine;
import picocli.CommandLine.*;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Scanner;
import java.util.Set;
import java.util.concurrent.Callable;

@Command(
        name = "passive-cert-analyzer",
        mixinStandardHelpOptions = true,
        version = "0.3.4",
        description = "Passive TLS-Zertifikatsplattform: CT-Stream (WS), CT-Poll (HTTP), Offline-Analyse & TrustStore-Score."
)
public class Main implements Callable<Integer> {

    public static void main(String[] args) {
        if (args != null && args.length > 0) {
            int exit = new CommandLine(new Main())
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
        System.out.println("passive-cert-analyzer: interaktiver Modus oder Subcommands 'ct-stream' / 'ct-poll' / 'analyze' / 'store-score'.");
        return 0;
    }

    // ===== Defaults =====
    private static Path projectRoot() { return Paths.get(System.getProperty("user.dir")); }
    private static Path defaultScanDir() { return projectRoot().resolve("Scanfiles"); }
    private static Path defaultOutputPath() { return defaultScanDir().resolve("certs.jsonl"); }
    private static void ensureDir(Path dir) {
        try { if (dir != null && !Files.exists(dir)) Files.createDirectories(dir); }
        catch (Exception e) { throw new RuntimeException("Kann Ordner nicht anlegen: " + dir + " -> " + e.getMessage()); }
    }

    // ===== Interactive Menu =====
    private static void interactiveMenu() {
        Scanner in = new Scanner(System.in);
        while (true) {
            System.out.println("\n=== Passive Cert Analyzer – Menü ===");
            System.out.println("1) CT-Stream (WebSocket) sammeln");
            System.out.println("2) CT-Poll (HTTP) sammeln");
            System.out.println("3) JSONL analysieren (Länderverteilung)");
            System.out.println("4) TrustStore bewerten (gewichteter Score)");
            System.out.println("0) Beenden");
            String choice = readChoice(in, "Auswahl", Set.of("0","1","2","3","4"), null);

            switch (choice) {
                case "1" -> runCtStreamInteractive(in);
                case "2" -> runCtPollInteractive(in);
                case "3" -> runAnalyzeInteractive(in);
                case "4" -> runStoreScoreInteractive(in);
                case "0" -> { System.out.println("Auf Wiedersehen."); return; }
            }
        }
    }

    // --- Interaktiv: CT-Stream ---
    private static void runCtStreamInteractive(Scanner in) {
        System.out.println("\n--- CT-Stream (passiv, WebSocket) ---");
        String endpoint = promptFree(in, "Endpoint (--endpoint)", "wss://certstream.calidog.io/");
        String outDir = promptFree(in, "Output-Ordner (--out-dir)", defaultScanDir().toString());
        String outFile = promptFree(in, "Output-Dateiname (--out-file)", "certs.jsonl");
        boolean certOnly = readYesNo(in, "Nur reduzierte Felder speichern? [y/N]", false);
        int reconnectDelay = readInt(in, "Reconnect-Delay (Sek.)", 10, 0, 3600);
        long duration = readLong(in, "Dauer in Sekunden (0 = unbegrenzt)");
        long maxEvents = readLong(in, "Max. Events (0 = unbegrenzt)");
        boolean debug = readYesNo(in, "Debug-Logging aktivieren? [y/N]", false);
        boolean progress = true;

        Path outPath = Paths.get(outDir).resolve(outFile);
        ensureDir(outPath.getParent());

        System.out.println("Hinweis: Passiv – KEIN aktiver Traffic zu Dritten außer dem WS-Endpoint.");
        new CertStreamClient(outPath, certOnly, reconnectDelay, duration, maxEvents, debug, progress, endpoint).run();
    }

    // --- Interaktiv: CT-Poll ---
    private static void runCtPollInteractive(Scanner in) {
        System.out.println("\n--- CT-Poll (passiv, HTTP RFC6962) ---");
        String logUrl = promptFree(in, "CT-Log-Basis (--log)", "https://ct.googleapis.com/logs/argon2023");
        long start = readLong(in, "Start-Index (--start)");
        int batch = readInt(in, "Batchgröße (--batch)", 256, 1, 4096);
        int sleepMs = readInt(in, "Pause zwischen Batches ms (--sleep-ms)", 500, 0, 60000);
        long maxEntries = readLong(in, "Max. Einträge (0 = unbegrenzt) (--max-entries)");
        String outDir = promptFree(in, "Output-Ordner (--out-dir)", defaultScanDir().toString());
        String outFile = promptFree(in, "Output-Dateiname (--out-file)", "certs_poll.jsonl");
        boolean certOnly = readYesNo(in, "Nur reduzierte Felder speichern? [y/N]", true);
        boolean progress = true;
        boolean debug = readYesNo(in, "Debug-Logging aktivieren? [y/N]", false);

        Path outPath = Paths.get(outDir).resolve(outFile);
        ensureDir(outPath.getParent());

        new CtPoller(outPath, certOnly, progress, debug).run(logUrl, start, batch, sleepMs, maxEntries);
    }

    // --- Interaktiv: Analyze ---
    private static void runAnalyzeInteractive(Scanner in) {
        System.out.println("\n--- Analyse JSONL ---");
        String input = promptFree(in, "Input JSONL (-i)", defaultOutputPath().toString());
        boolean trustedByCountry = readYesNo(in, "Vertrauensprüfung (lokaler Truststore) & Ländercounts ausgeben? [y/N]", false);
        Analyzer analyzer = new Analyzer();
        analyzer.processJsonl(input, trustedByCountry);
    }

    // --- Interaktiv: Store-Score ---
    private static void runStoreScoreInteractive(Scanner in) {
        System.out.println("\n--- Store bewerten (offline) ---");
        String store = promptFree(in, "Pfad zum TrustStore (JKS/PKCS12) oder PEM (Bundle/Dir)", defaultJavaCacerts().toString());
        String type  = readChoice(in, "Typ [jks|pkcs12|pem-bundle|pem-dir]", Set.of("jks","pkcs12","pem-bundle","pem-dir"), "jks");
        String password = null;
        if (type.equals("jks") || type.equals("pkcs12")) {
            password = promptFree(in, "Passwort (leer = none)", type.equals("jks") ? "changeit" : "");
        }
        String countryScores = promptFree(in, "Pfad zur country_trustscores.json", "country_trustscores.json");
        String countryFrom   = readChoice(in, "Länderquelle [subject|issuer]", Set.of("subject","issuer"), "subject");
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

    // ===== CLI-Subcommands =====

    @Command(name = "ct-stream", description = "Liest öffentliche CT-Events per WebSocket und schreibt JSONL.")
    static class CtStreamCommand implements Callable<Integer> {
        @Option(names={"--endpoint"}, description="WebSocket-Endpoint (default: wss://certstream.calidog.io/)")
        String endpoint = "wss://certstream.calidog.io/";
        @Option(names={"-o","--output"}, description="Voller Output-Pfad (hat Vorrang vor --out-dir/--out-file).")
        Path output;
        @Option(names={"--out-dir"}, description="Output-Ordner (default: <Projektroot>/Scanfiles)")
        Path outDir = defaultScanDir();
        @Option(names={"--out-file"}, description="Output-Dateiname (default: certs.jsonl)")
        String outFile = "certs.jsonl";
        @Option(names={"--cert-only"}, description="Nur ausgewählte Felder speichern (kleiner).")
        boolean certOnly = false;
        @Option(names={"--reconnect-delay"}, description="Reconnect delay Sekunden (default 10).")
        int reconnectDelay = 10;
        @Option(names={"--duration-seconds"}, description="Stoppt nach N Sekunden (0 = unbegrenzt).")
        long durationSeconds = 0;
        @Option(names={"--max-events"}, description="Stoppt nach N empfangenen Events (0 = unbegrenzt).")
        long maxEvents = 0;
        @Option(names={"--debug"}, description="Debug-Logging aktivieren (zeigt kurze Previews).")
        boolean debug = false;
        @Option(names={"--no-progress"}, description="Unterdrückt Live-Status in der Konsole.")
        boolean noProgress = false;

        @Override public Integer call() {
            Path outPath = (output != null) ? output : outDir.resolve(outFile);
            ensureDir(outPath.getParent());
            new CertStreamClient(outPath, certOnly, reconnectDelay, durationSeconds, maxEvents, debug, !noProgress, endpoint).run();
            return 0;
        }
    }

    @Command(name = "ct-poll", description = "Liest CT-Logs via HTTP (RFC6962 get-entries) und schreibt JSONL.")
    static class CtPollCommand implements Callable<Integer> {
        @Option(names={"--log"}, required = true, description="CT-Log-Basis-URL, z.B. https://ct.googleapis.com/logs/argon2023")
        String logUrl;
        @Option(names={"--start"}, description="Startindex (default 0)")
        long start = 0;
        @Option(names={"--batch"}, description="Batchgröße (1-4096, default 256)")
        int batch = 256;
        @Option(names={"--sleep-ms"}, description="Pause zwischen Batches in ms (default 500)")
        int sleepMs = 500;
        @Option(names={"--max-entries"}, description="Maximale Anzahl Einträge (0 = unbegrenzt)")
        long maxEntries = 0;
        @Option(names={"-o","--output"}, description="Voller Output-Pfad (hat Vorrang vor --out-dir/--out-file).")
        Path output;
        @Option(names={"--out-dir"}, description="Output-Ordner (default: <Projektroot>/Scanfiles)")
        Path outDir = defaultScanDir();
        @Option(names={"--out-file"}, description="Output-Dateiname (default: certs_poll.jsonl)")
        String outFile = "certs_poll.jsonl";
        @Option(names={"--cert-only"}, description="Nur reduzierte Felder speichern (kleiner).")
        boolean certOnly = true;
        @Option(names={"--no-progress"}, description="Unterdrückt Live-Status.")
        boolean noProgress = false;
        @Option(names={"--debug"}, description="Debug-Logging aktivieren.")
        boolean debug = false;

        @Override public Integer call() {
            if (batch < 1 || batch > 4096) {
                System.err.println("batch muss zwischen 1 und 4096 liegen.");
                return 2;
            }
            Path outPath = (output != null) ? output : outDir.resolve(outFile);
            ensureDir(outPath.getParent());
            new CtPoller(outPath, certOnly, !noProgress, debug).run(logUrl, start, batch, sleepMs, maxEntries);
            return 0;
        }
    }

    // ===== Hilfsfunktionen =====
    private static String promptFree(Scanner in, String label, String def) {
        System.out.print(label + (def != null && !def.isBlank() ? " [" + def + "]" : "") + ": ");
        String s = in.nextLine().trim();
        return s.isBlank() ? def : s;
    }
    private static String readChoice(Scanner in, String label, Set<String> allowed, String def) {
        while (true) {
            System.out.print(label + (def != null ? " [" + def + "]" : "") + ": ");
            String s = in.nextLine().trim();
            if (s.isBlank() && def != null) return def;
            String v = s.toLowerCase();
            if (allowed.contains(v)) return v;
            System.out.println("Invalid value, try again");
        }
    }
    private static boolean readYesNo(Scanner in, String label, boolean def) {
        while (true) {
            System.out.print(label + " ");
            String s = in.nextLine().trim().toLowerCase();
            if (s.isBlank()) return def;
            if (s.startsWith("y") || s.equals("ja") || s.equals("j")) return true;
            if (s.startsWith("n") || s.equals("nein")) return false;
            System.out.println("Invalid value, try again");
        }
    }
    private static int readInt(Scanner in, String label, int def, int min, int max) {
        while (true) {
            System.out.print(label + " [" + def + "]: ");
            String s = in.nextLine().trim();
            if (s.isBlank()) return def;
            try {
                int v = Integer.parseInt(s);
                if (v < min || v > max) throw new NumberFormatException();
                return v;
            } catch (NumberFormatException e) {
                System.out.println("Invalid value, try again");
            }
        }
    }
    private static long readLong(Scanner in, String label) {
        while (true) {
            System.out.print(label + " [" + (long) 0 + "]: ");
            String s = in.nextLine().trim();
            if (s.isBlank()) return 0;
            try {
                long v = Long.parseLong(s);
                if (v < (long) 0) throw new NumberFormatException();
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
    private static String emptyToNull(String s){ return (s==null||s.isBlank())?null:s; }
}
