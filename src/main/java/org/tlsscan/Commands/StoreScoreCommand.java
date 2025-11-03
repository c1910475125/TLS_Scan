package org.tlsscan.Commands;

import org.tlsscan.StoreScorer;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

import java.nio.file.Path;
import java.util.concurrent.Callable;

@Command(
        name = "store-score",
        description = "Bewertet lokalen JKS/PKCS12/PEM Store (gewichteter TrustScore; pro Land Anzahl/Anteil/Score/Teilbetrag)."
)
public class StoreScoreCommand implements Callable<Integer> {

    @Option(names={"--store"}, required=true,
            description="Pfad zum TrustStore (JKS/PKCS12) oder PEM (Bundle/Dir).")
    Path store;

    @Option(names={"--type"}, required=true,
            description="Typ: jks | pkcs12 | pem-bundle | pem-dir")
    String type;

    @Option(names={"--password"},
            description="Passwort für JKS/PKCS12 (falls nötig).")
    String password;

    @Option(names={"--country-scores"}, required=true,
            description="Pfad zu ISO2->TrustScore (JSON).")
    Path countryScores;

    @Option(names={"--country-from"},
            description="Länderquelle: subject | issuer (default subject)")
    String countryFrom = "subject";

    @Option(names={"--include-non-ca"},
            description="Nicht-CA-Zertifikate mitbewerten.")
    boolean includeNonCa;

    @Override
    public Integer call() throws Exception {
        double score = new StoreScorer().scoreStore(
                store.toString(), type, password, countryScores.toString(), countryFrom, includeNonCa
        );
        System.out.println();
        System.out.printf("===> Gesamter gewichteter TrustScore: %.6f%n", score);
        return 0;
    }
}
