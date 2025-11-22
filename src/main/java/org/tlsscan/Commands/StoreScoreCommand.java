package org.tlsscan.Commands;

import org.tlsscan.StoreScorer;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.concurrent.Callable;

@Command(
        name = "root-score",
        description = "Bewertet einen RootStore anhand der country_trustscores.json."
)
public class StoreScoreCommand implements Callable<Integer> {

    @Option(names = {"-k", "--keystore"},
            description = "Pfad zum Keystore (z.B. cacerts).",
            required = true)
    Path keystorePath;

    @Option(names = {"-p", "--password"},
            description = "Passwort für den Keystore (default: changeit).",
            defaultValue = "changeit")
    String password;

    @Option(names = {"--scores"},
            description = "Pfad zu country_trustscores.json (optional, default aus Ressourcen).")
    String scoresFile;

    @Option(names = {"-o", "--summary-output"},
            description = "Pfad für JSON-Summary der Analyse (optional).")
    Path summaryOutput;

    @Option(names = {"-j", "--json-output"},
            description = "Pfad für detailliertes JSON-Log (optional, JSONL-Format).")
    Path jsonOutput;

    @Override
    public Integer call() throws Exception {
        Path storePath = resolveRootStorePath(keystorePath);
        if (!Files.exists(storePath)) {
            System.err.println("Keystore existiert nicht: " + storePath);
            return 1;
        }

        StoreScorer scorer = new StoreScorer();
        scorer.scoreStore(
                storePath,
                password.toCharArray(),
                scoresFile,
                summaryOutput,
                jsonOutput
        );
        return 0;
    }

    private Path resolveRootStorePath(Path p) {
        if (p == null) return null;
        if (p.isAbsolute() && Files.exists(p)) return p;
        Path rootDir = Paths.get(System.getProperty("user.dir")).resolve("RootStores");
        ensureDir(rootDir);
        Path candidate = rootDir.resolve(p);
        if (Files.exists(candidate)) {
            return candidate;
        }
        return p;
    }

    private void ensureDir(Path dir) {
        try {
            if (dir != null && !Files.exists(dir)) {
                Files.createDirectories(dir);
            }
        } catch (Exception e) {
            throw new RuntimeException("Kann Ordner nicht anlegen: " + dir + " -> " + e.getMessage(), e);
        }
    }
}