package org.tlsscan.Commands;

import org.tlsscan.ActiveScanner;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Callable;

@Command(
        name = "scan",
        description = "Aktiver TLS-Scan von Hostnamen/IPs; schreibt Zertifikate als JSONL."
)
public class ActiveScanCommand implements Callable<Integer> {

    @Option(names = {"-t", "--target"},
            description = "Ziel (Hostname oder IP, optional host:port). Kann mehrfach angegeben werden.")
    List<String> targets;

    @Option(names = {"-f", "--targets-file"},
            description = "Datei mit Zielen, eine pro Zeile (Hostname, IP oder host:port).")
    Path targetsFile;

    @Option(names = {"-p", "--port"},
            description = "Standardport, falls im Ziel nicht angegeben (default: 443).")
    int port = 443;

    @Option(names = {"-o", "--output"},
            description = "Output JSONL Datei (default: ./Scanfiles/active_scan.jsonl).")
    Path output;

    @Option(names = {"--timeout-ms"},
            description = "Timeout pro Ziel in Millisekunden (default: 5000).")
    int timeoutMs = 5000;

    @Option(names = {"--country-scores"},
            description = "Pfad zu country_trustscores.json (default: Ressource auf dem Classpath).")
    Path countryScores;

    @Option(names = {"--debug"},
            description = "Debug-Logging aktivieren.")
    boolean debug = false;

    @Override
    public Integer call() throws Exception {
        List<String> allTargets = new ArrayList<>();

        if (targets != null) {
            allTargets.addAll(targets);
        }

        if (targetsFile != null) {
            if (!Files.exists(targetsFile)) {
                System.err.println("Targets-Datei existiert nicht: " + targetsFile);
                return 2;
            }
            for (String line : Files.readAllLines(targetsFile)) {
                String s = line.trim();
                if (s.isEmpty() || s.startsWith("#")) {
                    continue;
                }
                allTargets.add(s);
            }
        }

        if (allTargets.isEmpty()) {
            System.err.println("Keine Ziele: mindestens --target oder --targets-file angeben.");
            return 2;
        }

        Path out = (output != null)
                ? output
                : Paths.get("Scanfiles").resolve("active_scan.jsonl");

        String scoresPath = (countryScores != null) ? countryScores.toString() : null;

        new ActiveScanner().scan(allTargets, port, out, scoresPath, debug, timeoutMs);

        return 0;
    }
}
