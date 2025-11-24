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

    @Option(names = {"-i", "--input"},
            description = "Input-Datei (JSONL). Relativ zu ./Scanfiles oder absolut.",
            required = true)
    Path input;

    @Option(names = {"--scores"},
            description = "Pfad zu country_trustscores.json (optional, default aus Ressourcen).")
    String scoresFile;

    @Option(names = {"--debug"},
            description = "Debug-Log aktivieren.")
    boolean debug;

    @Option(names = {"-o", "--summary-output"},
            description = "Pfad für JSON-Summary der Analyse (optional).")
    Path summaryOutput;

    @Override
    public Integer call() throws Exception {
        Path inPath = resolveInputPath(input);
        if (!Files.exists(inPath)) {
            System.err.println("Input-Datei existiert nicht: " + inPath);
            return 1;
        }

        Analyzer analyzer = new Analyzer();
        analyzer.analyze(
                inPath,
                scoresFile,
                debug,
                summaryOutput
        );

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