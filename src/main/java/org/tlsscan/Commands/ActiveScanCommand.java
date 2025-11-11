package org.tlsscan.Commands;

import org.tlsscan.ActiveScanner;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.*;
import java.util.concurrent.Callable;

/**
 * CLI-Command für den aktiven Scan.
 * - Unterstützt Geo-Länderscan (Random / Country-Full) via GeoLite2.
 * - Kann optional zgrab2 statt der internen Java-TLS-Engine nutzen.
 * - Geo-Länderscans werden immer über zgrab2 ausgeführt.
 */
@Command(
        name = "scan",
        description = {
                "Aktiver TLS-Scan von Hosts und IP-Adressen mit optionalen GeoIP-Filtern.",
                "Standard ist die interne Java-TLS-Engine.",
                "Mit --use-zgrab bzw. bei Geo-Länderscans wird zgrab2 als externer Scanner verwendet."
        }
)
public class ActiveScanCommand implements Callable<Integer> {

    private static final int DEFAULT_TIMEOUT_MS = 15000;
    private static final int DEFAULT_CONCURRENCY = 50;

    private static Path defaultOutputDir() {
        return Paths.get(System.getProperty("user.dir")).resolve("Scanfiles");
    }

    private static String defaultZgrabBinary() {
        return Paths.get(System.getProperty("user.dir"))
                .resolve("bin")
                .resolve("zgrab2.exe")   // <- statt zgrab2.bat
                .toString();
    }

    @Option(names = {"-t", "--targets"},
            description = "Ziele (Hostname/IP oder host:port, kommagetrennt)",
            split = ",")
    List<String> targets = new ArrayList<>();

    @Option(names = {"--profile"},
            description = "Port-Profil: web (443), mail (465,587,993,995), k8s (6443), custom (nur --ports)",
            defaultValue = "web")
    String profile;

    @Option(names = {"--ports"},
            description = "Ports bei Profil=custom, z.B. 443,8443",
            split = ",")
    List<Integer> customPorts = new ArrayList<>();

    @Option(names = {"--countries"},
            description = "Filter auf Länder-ISO-Codes (z.B. AT,DE,US), basierend auf GeoLite2",
            split = ",")
    List<String> countries = new ArrayList<>();

    @Option(names = {"--cities"},
            description = "Filter auf Städtenamen (z.B. Vienna,Munich), basierend auf GeoLite2 City",
            split = ",")
    List<String> cities = new ArrayList<>();

    @Option(names = {"--asns"},
            description = "ASN-Filter (z.B. 680,3320), basierend auf GeoLite2 ASN",
            split = ",")
    List<Long> asns = new ArrayList<>();

    @Option(names = {"--geoip-country-db"},
            description = "Pfad zur GeoIP Country-DB (Default: ./GeoIP/GeoLite2-Country.mmdb)")
    Path geoipCountryDb;

    @Option(names = {"--geoip-asn-db"},
            description = "Pfad zur GeoIP ASN-DB (Default: ./GeoIP/GeoLite2-ASN.mmdb)")
    Path geoipAsnDb;

    @Option(names = {"--geoip-city-db"},
            description = "Pfad zur GeoIP City-DB (Default: ./GeoIP/GeoLite2-City.mmdb)")
    Path geoipCityDb;

    @Option(names = {"--random-sample-count"},
            description = "Zufallsstichprobe aus GeoLite-Pool (0 = keine Stichprobe)",
            defaultValue = "0")
    int randomSampleCount;

    @Option(names = {"--random-sample-cidr"},
            description = "Optional: CIDR, aus dem für die Zufallsstichprobe IPs gezogen werden (z.B. 193.0.0.0/8)")
    String sampleCidr;

    @Option(names = {"--country-full"},
            description = "Vollständiger Scan aller GeoLite2-IPv4-Netzblöcke für diese Länder (ISO-Codes, z.B. AT,DE)",
            split = ",")
    List<String> fullCountries = new ArrayList<>();

    @Option(names = {"-o", "--out-file"},
            description = "Dateiname im Output-Ordner ./Scanfiles (default: active_scan.jsonl)",
            defaultValue = "active_scan.jsonl")
    String outFileName;

    @Option(names = {"--debug"},
            description = "Debug-Logging aktivieren.")
    boolean debug;

    @Option(names = {"--use-zgrab"},
            description = "Statt der internen Java-TLS-Engine zgrab2 verwenden (für Host/IP-Scans)")
    boolean useZgrab;

    @Option(names = {"--zgrab-bin"},
            description = "Pfad zum zgrab2-Binary (Default: ./bin/zgrab2.bat)")
    String zgrabBin;

    @Override
    public Integer call() throws Exception {

        // Geo-Länderscan = wenn entweder Random-Sample oder Country-Full gesetzt ist
        boolean isGeoCountryScan =
                (randomSampleCount > 0) ||
                        (fullCountries != null && !fullCountries.isEmpty());

        if ((targets == null || targets.isEmpty())
                && !isGeoCountryScan) {

            System.err.println("Es wurden weder konkrete Ziele (--targets), noch Geo-Länderoptionen (--random-sample-count oder --country-full) angegeben.");
            return 1;
        }

        List<Integer> ports = new ArrayList<>();
        switch (profile) {
            case "web" -> ports.add(443);
            case "mail" -> {
                ports.add(465);
                ports.add(587);
                ports.add(993);
                ports.add(995);
            }
            case "k8s" -> ports.add(6443);
            case "custom" -> {
                if (customPorts == null || customPorts.isEmpty()) {
                    System.err.println("Profil=custom, aber keine --ports angegeben.");
                    return 2;
                }
                ports.addAll(customPorts);
            }
            default -> {
                System.err.println("Unbekanntes Profil: " + profile + " (erlaubt: web,mail,k8s,custom)");
                return 3;
            }
        }

        Path outDir = defaultOutputDir();
        if (!Files.exists(outDir)) {
            Files.createDirectories(outDir);
        }
        Path outputFile = outDir.resolve(outFileName);

        System.out.println("[scan] Output: " + outputFile);
        System.out.println("[scan] Timeout pro Ziel = " + DEFAULT_TIMEOUT_MS + " ms, Parallelität = " + DEFAULT_CONCURRENCY);

        // Effektiv verwendete zgrab-Entscheidung:
        // - Geo-Länderscan: immer zgrab
        // - sonst: zgrab nur, wenn --use-zgrab gesetzt
        boolean useZgrabEffective = isGeoCountryScan || useZgrab;

        if (useZgrabEffective) {
            if (zgrabBin == null || zgrabBin.isBlank()) {
                zgrabBin = defaultZgrabBinary();
            }
            System.out.println("[scan] Verwende externen TLS-Scanner (zgrab2): " + zgrabBin +
                    (isGeoCountryScan ? " (Geo-Länderscan erfordert zgrab2)" : ""));
        } else {
            System.out.println("[scan] Verwende interne Java-TLS-Engine.");
        }

        Path geoipBase = Paths.get(System.getProperty("user.dir")).resolve("GeoIP");
        ActiveScanner.AdvancedScanOptions adv = new ActiveScanner.AdvancedScanOptions();

        // MMDB-Defaults
        if (geoipCountryDb != null) {
            adv.geoipCountryDbPath = geoipCountryDb.toString();
        } else {
            Path def = geoipBase.resolve("GeoLite2-Country.mmdb");
            if (Files.exists(def)) adv.geoipCountryDbPath = def.toString();
        }
        if (geoipAsnDb != null) {
            adv.geoipAsnDbPath = geoipAsnDb.toString();
        } else {
            Path def = geoipBase.resolve("GeoLite2-ASN.mmdb");
            if (Files.exists(def)) adv.geoipAsnDbPath = def.toString();
        }
        if (geoipCityDb != null) {
            adv.geoipCityDbPath = geoipCityDb.toString();
        } else {
            Path def = geoipBase.resolve("GeoLite2-City.mmdb");
            if (Files.exists(def)) adv.geoipCityDbPath = def.toString();
        }

        // Filter
        if (countries != null) {
            for (String c : countries) {
                if (c != null && !c.isBlank()) {
                    adv.countryIsoCodes.add(c.trim().toUpperCase(Locale.ROOT));
                }
            }
        }
        if (cities != null) {
            for (String c : cities) {
                if (c != null && !c.isBlank()) {
                    adv.cityNames.add(c.trim());
                }
            }
        }
        if (asns != null) {
            adv.asns.addAll(asns);
        }

        // Geo-Random-Sample
        adv.randomSampleCount = randomSampleCount;
        if (sampleCidr != null && !sampleCidr.isBlank()) {
            adv.sampleFromCidr = sampleCidr.trim();
        }

        // Geo-Country-Full
        if (fullCountries != null && !fullCountries.isEmpty()) {
            for (String c : fullCountries) {
                if (c != null && !c.isBlank()) {
                    adv.fullScanCountries.add(c.trim().toUpperCase(Locale.ROOT));
                }
            }
            adv.enableCountryFullScan = true;
        }

        // CSV-Pfade (für Random-Pool + Country-Full)
        Path blocksCsv = geoipBase.resolve("GeoLite2-Country-Blocks-IPv4.csv");
        Path locCsv = geoipBase.resolve("GeoLite2-Country-Locations-en.csv");
        if (Files.exists(blocksCsv)) {
            adv.countryBlocksCsvPath = blocksCsv.toString();
        }
        if (Files.exists(locCsv)) {
            adv.countryLocationsCsvPath = locCsv.toString();
        }

        Path asnCsv = geoipBase.resolve("GeoLite2-ASN-Blocks-IPv4.csv");
        if (Files.exists(asnCsv)) {
            adv.asnBlocksCsvPath = asnCsv.toString();
        }
        Path cityBlocksCsv = geoipBase.resolve("GeoLite2-City-Blocks-IPv4.csv");
        Path cityLocCsv = geoipBase.resolve("GeoLite2-City-Locations-en.csv");
        if (Files.exists(cityBlocksCsv)) {
            adv.cityBlocksCsvPath = cityBlocksCsv.toString();
        }
        if (Files.exists(cityLocCsv)) {
            adv.cityLocationsCsvPath = cityLocCsv.toString();
        }

        // zgrab-Steuerung
        adv.useZgrabOnly = useZgrabEffective;
        if (useZgrabEffective) {
            adv.zgrabBinary = zgrabBin;
        }

        List<String> rawTargets = (targets != null) ? targets : Collections.emptyList();

        ActiveScanner scanner = new ActiveScanner();
        scanner.scan(
                rawTargets,
                ports,
                outputFile,
                null,
                debug,
                DEFAULT_TIMEOUT_MS,
                DEFAULT_CONCURRENCY,
                null,
                adv
        );

        return 0;
    }
}
