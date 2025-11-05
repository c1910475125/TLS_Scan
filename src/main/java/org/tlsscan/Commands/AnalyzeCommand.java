package org.tlsscan.Commands;

import org.tlsscan.Analyzer;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.concurrent.Callable;

@Command(
        name = "analyze",
        description = "Analysiert JSONL (aus ct-stream / ct-poll / scan)."
)
public class AnalyzeCommand implements Callable<Integer> {

    @Option(names = {"-i", "--input"}, required = true,
            description = "Input JSONL Datei (Dateiname relativ zu ./Scanfiles oder absoluter Pfad)")
    Path input;

    @Option(names = {"--trusted-by-country"},
            description = "Berechnet zusätzlich TrustScores pro Ausstellerland (country_trustscores.json).")
    boolean trustedByCountry = false;

    @Override
    public Integer call() {
        Path effective = resolveInputPath(input);
        new Analyzer().processJsonl(effective.toString(), trustedByCountry);
        return 0;
    }

    private Path resolveInputPath(Path in) {
        if (in == null) return null;
        if (in.isAbsolute() && Files.exists(in)) return in;
        Path scanDir = Paths.get(System.getProperty("user.dir")).resolve("Scanfiles");
        Path candidate = scanDir.resolve(in);
        if (Files.exists(candidate)) {
            return candidate;
        }
        return in;
    }
}
