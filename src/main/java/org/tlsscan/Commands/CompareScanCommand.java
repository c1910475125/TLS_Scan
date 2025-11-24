package org.tlsscan.Commands;

import org.tlsscan.ScanDiff;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.concurrent.Callable;

@Command(
        name = "compare-scan",
        description = "Vergleicht zwei Scan-JSONL-Dateien (historischer Diff)."
)
public class CompareScanCommand implements Callable<Integer> {

    @Option(names = {"--old"},
            description = "Ältere Scan-Datei (JSONL). Relativ zu ./Scanfiles oder absolut.",
            required = true)
    Path oldInput;

    @Option(names = {"--new"},
            description = "Neuere Scan-Datei (JSONL). Relativ zu ./Scanfiles oder absolut.",
            required = true)
    Path newInput;

    @Option(names = {"--scores"},
            description = "Pfad zu country_trustscores.json (optional, default aus Ressourcen).")
    String scoresFile;

    @Option(names = {"--debug"},
            description = "Debug-Log aktivieren.")
    boolean debug;

    @Option(names = {"-o", "--summary-output"},
            description = "Pfad für JSON-Summary des Diffs (optional).")
    Path summaryOutput;

    @Override
    public Integer call() throws Exception {
        Path oldPath = resolveInputPath(oldInput);
        Path newPath = resolveInputPath(newInput);

        if (!Files.exists(oldPath)) {
            System.err.println("Alte Input-Datei existiert nicht: " + oldPath);
            return 1;
        }
        if (!Files.exists(newPath)) {
            System.err.println("Neue Input-Datei existiert nicht: " + newPath);
            return 2;
        }

        ScanDiff diff = new ScanDiff();
        diff.compare(
                oldPath,
                newPath,
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
