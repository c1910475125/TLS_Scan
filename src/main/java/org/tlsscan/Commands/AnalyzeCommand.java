package org.tlsscan.Commands;

import org.tlsscan.Analyzer;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

import java.nio.file.Path;
import java.util.concurrent.Callable;

@Command(name = "analyze", description = "Analysiert JSONL (aus ct-stream/ct-poll).")
public class AnalyzeCommand implements Callable<Integer> {

    @Option(names={"-i","--input"}, required=true,
            description="Input JSONL Datei (ct-stream/ct-poll Output)")
    Path input;

    @Option(names={"--trusted-by-country"},
            description="Zählt vertrauenswürdige Leaf-Zertifikate pro Land (lokaler Truststore).")
    boolean trustedByCountry = false;

    @Override
    public Integer call() {
        new Analyzer().processJsonl(input.toString(), trustedByCountry);
        return 0;
    }
}
