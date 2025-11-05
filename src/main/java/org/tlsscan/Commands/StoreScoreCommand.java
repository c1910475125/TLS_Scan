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

    @Option(names = {"--store"}, required = true,
            description = "RootStore-Datei (Dateiname relativ zu ./RootStores oder absoluter Pfad).")
    Path store;

    @Option(names = {"--type"}, description = "Store-Typ (jks/pkcs12/pem-bundle/pem-dir). Default: jks.")
    String type = "jks";

    @Option(names = {"--password"}, description = "Store-Passwort (leer falls keins).")
    String password;

    @Option(names = {"--country-from"},
            description = "Land aus 'issuer' oder 'subject' ableiten. Default: issuer.")
    String countryFrom = "issuer";

    @Option(names = {"--country-scores"},
            description = "Pfad zu country_trustscores.json (sonst aus Ressourcen geladen).")
    Path countryScores;

    @Option(names = {"--include-non-ca"},
            description = "Auch Nicht-CA-Zertifikate im RootStore mitbewerten.")
    boolean includeNonCa = false;

    @Override
    public Integer call() {
        Path storePath = resolveRootStorePath(store);
        String scoresPath = (countryScores != null) ? countryScores.toString() : null;

        try {
            double score = new StoreScorer().scoreStore(
                    storePath.toString(),
                    type,
                    (password == null || password.isBlank()) ? null : password,
                    scoresPath,
                    countryFrom,
                    includeNonCa
            );
            System.out.printf("Gesamter gewichteter RootStore-TrustScore: %.6f%n", score);
            return 0;
        } catch (Exception e) {
            System.err.println("Fehler bei RootStore-Bewertung: " + e.getMessage());
            return 1;
        }
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
