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
        version = "0.4.4",
        description = "Passive TLS-Zertifikatsplattform: CT-Stream (CertStream), CT-Poll, Analyse & TrustStore-Score."
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
        System.out.println("Subcommands: 'ct-stream' / 'ct-poll' / 'analyze' / 'store-score', oder interaktives Menü ohne Args.");
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
            System.out.println("1) CT-Stream (WebSocket, CertStream)");
            System.out.println("2) CT-Poll (HTTP)");
            System.out.println("3) JSONL analysieren");
            System.out.println("4) TrustStore bewerten");
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

    // --- Interaktiv: CT-Poll (dein vorhandener Poller) ---
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

    // ===== Subcommands (ct-stream zusätzlich auch als CLI) =====
    @Command(name = "ct-stream", description = "Liest öffentliche CT-Events via certstream-java und schreibt JSONL.")
    static class CtStreamCommand implements Callable<Integer> {
        @Option(names={"--out-dir"}, description="Output-Ordner (default: ./Scanfiles)")
        Path outDir = defaultScanDir();
        @Option(names={"--out-file"}, description="Output-Dateiname (default: certs.jsonl)")
        String outFile = "certs.jsonl";
        @Option(names={"--cert-only"}, description="Nur ausgewählte Felder speichern.")
        boolean certOnly = false;
        @Option(names={"--duration-seconds"}, description="Stoppt nach N Sekunden (0 = unbegrenzt).")
        long durationSeconds = 0;
        @Option(names={"--max-events"}, description="Stoppt nach N Events (0 = unbegrenzt).")
        long maxEvents = 0;
        @Option(names={"--debug"}, description="Debug-Logging aktivieren.")
        boolean debug = false;

        @Override public Integer call() {
            Path outPath = outDir.resolve(outFile);
            ensureDir(outPath.getParent());
            new CertStreamClient(outPath, certOnly, durationSeconds, maxEvents, debug, true).run();
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

    // ===== Input-Helper =====
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
            if (allowed.contains(s)) return s;
            System.out.println("Invalid value, try again");
        }
    }
    private static boolean readYesNo(Scanner in, String label, boolean def) {
        while (true) {
            System.out.print(label + " ");
            String s = in.nextLine().trim().toLowerCase();
            if (s.isBlank()) return def;
            if (s.startsWith("y") || s.equals("ja") || s.equals("j")) return true;
            if (s.startsWith("n") || s.equals("nein") || s.equals("n")) return false;
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
    private static String emptyToNull(String s){ return (s==null||s.isBlank())?null:s; }
}
