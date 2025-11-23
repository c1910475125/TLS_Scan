package org.tlsscan;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.maxmind.geoip2.DatabaseReader;
import com.maxmind.geoip2.exception.AddressNotFoundException;
import com.maxmind.geoip2.model.AsnResponse;
import com.maxmind.geoip2.model.CityResponse;
import com.maxmind.geoip2.model.CountryResponse;
import javax.net.ssl.*;
import java.io.*;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Aktiver TLS-Scanner.
 * - Kann interne Java-TLS-Engine oder extern zgrab2 verwenden.
 * - Nutzt GeoLite2 (Country/City/ASN) für Filter & Länderscans.
 * - Liefert Zertifikats-Metadaten inkl. issuer_country / subject_country.
 */
public class ActiveScanner {

    private final ObjectMapper mapper = new ObjectMapper();
    private final Random random = new Random();

    /**
     * Erweiterte Scan-Optionen.
     */
    public static class AdvancedScanOptions {
        public String geoipCountryDbPath;
        public String geoipAsnDbPath;
        public String geoipCityDbPath;

        public List<String> countryIsoCodes = new ArrayList<>();
        public List<String> cityNames = new ArrayList<>();
        public List<Long> asns = new ArrayList<>();

        public Integer randomSampleCount = 0;
        public String sampleFromCidr;

        public boolean enableCountryFullScan = false;
        public List<String> fullScanCountries = new ArrayList<>();
        public String countryBlocksCsvPath;
        public String countryLocationsCsvPath;

        public String asnBlocksCsvPath;
        public String cityBlocksCsvPath;
        public String cityLocationsCsvPath;

        // zgrab2-Integration
        public boolean useZgrabOnly = false;
        public String zgrabBinary = "zgrab2";
    }

    public ActiveScanner() {
    }

    /**
     * Haupteinstieg: baut Ziel-Liste (Targets + Geo-Pools) und startet Scan.
     */
    public void scan(List<String> rawTargets,
                     List<Integer> ports,
                     Path outputJsonl,
                     String countryScores,
                     boolean debug,
                     int timeoutMs,
                     int concurrency,
                     Double ratePerSecond,
                     Object extra) throws IOException {

        if (rawTargets == null) {
            rawTargets = Collections.emptyList();
        }
        if (ports == null || ports.isEmpty()) {
            ports = Collections.singletonList(443);
        }

        AdvancedScanOptions adv = null;
        if (extra instanceof AdvancedScanOptions) {
            adv = (AdvancedScanOptions) extra;
        }

        // 1) Direkt übergebene Ziele / CIDR
        List<HostPort> initialTargets = new ArrayList<>();
        for (String t : rawTargets) {
            if (t == null || t.isBlank()) continue;
            String s = t.trim();
            if (s.contains("/")) {
                initialTargets.addAll(expandCidrTargets(s, ports, debug));
            } else {
                int idx = s.lastIndexOf(':');
                if (idx > 0 && idx < s.length() - 1) {
                    String host = s.substring(0, idx);
                    try {
                        int p = Integer.parseInt(s.substring(idx + 1));
                        initialTargets.add(new HostPort(host, p));
                    } catch (NumberFormatException e) {
                        for (int p : ports) {
                            initialTargets.add(new HostPort(s, p));
                        }
                    }
                } else {
                    for (int p : ports) {
                        initialTargets.add(new HostPort(s, p));
                    }
                }
            }
        }

        InternalScanner scanner = new InternalScanner(
                outputJsonl,
                debug,
                timeoutMs,
                timeoutMs,
                concurrency,
                adv
        );

        try {
            List<HostPort> allTargets = new ArrayList<>(initialTargets);

            // 2) Zufallsstichprobe aus GeoLite-CSV-Pool (KEIN Fallback mehr auf "random IP + MMDB")
            if (adv != null && adv.randomSampleCount != null && adv.randomSampleCount > 0) {
                List<HostPort> sampled = scanner.buildRandomSampleTargets(ports);
                System.out.println("[ActiveScan] Zufallsziele (GeoLite2-CSV) erzeugt: " + sampled.size());
                allTargets.addAll(sampled);
            }

            // 3) Vollständiger GeoLite-Vollscan (Country- oder City-basiert, ein Host pro Netzblock)
            if (adv != null && adv.enableCountryFullScan) {
                List<HostPort> fullTargets;

                if (adv.cityNames != null && !adv.cityNames.isEmpty()) {
                    fullTargets = scanner.buildCityFullTargets(ports);
                } else {
                    fullTargets = scanner.buildCountryFullTargets(ports);
                }

                System.out.println("[ActiveScan] GeoLite-Vollscan-Ziele (CSV) erzeugt: " + fullTargets.size());
                allTargets.addAll(fullTargets);
            }


            LinkedHashSet<HostPort> dedup = new LinkedHashSet<>(allTargets);
            allTargets = new ArrayList<>(dedup);

            if (allTargets.isEmpty()) {
                System.out.println("[ActiveScan] Es wurden keine Scan-Ziele erzeugt.");
                return;
            }

            // 4) Scan ausführen
            if (adv != null && adv.useZgrabOnly) {
                System.out.println("[ActiveScan] Verwende externen TLS-Scanner (zgrab2).");
                scanner.scanWithZgrab(allTargets);
            } else {
                System.out.println("[ActiveScan] Verwende interne Java-TLS-Engine.");
                scanner.scanHostPortList(allTargets);
            }

        } finally {
            scanner.close();
        }
    }

    /**
     * Host + Port als Target.
     */
    private static class HostPort {
        final String host;
        final int port;

        HostPort(String host, int port) {
            this.host = host;
            this.port = port;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (!(o instanceof HostPort hostPort)) return false;
            return port == hostPort.port && Objects.equals(host, hostPort.host);
        }

        @Override
        public int hashCode() {
            return Objects.hash(host, port);
        }
    }

    /**
     * Einfache IPv4-CIDR-Erweiterung (begrenzte Hostanzahl).
     */
    private List<HostPort> expandCidrTargets(String cidr, List<Integer> ports, boolean debug) {
        List<HostPort> out = new ArrayList<>();
        try {
            String[] parts = cidr.trim().split("/");
            if (parts.length != 2) return out;
            String baseIp = parts[0];
            int prefix = Integer.parseInt(parts[1]);
            if (prefix < 0 || prefix > 32) return out;

            String[] octets = baseIp.split("\\.");
            if (octets.length != 4) return out;
            long b1 = Long.parseLong(octets[0]);
            long b2 = Long.parseLong(octets[1]);
            long b3 = Long.parseLong(octets[2]);
            long b4 = Long.parseLong(octets[3]);

            long base = (b1 << 24) | (b2 << 16) | (b3 << 8) | b4;
            int hostBits = 32 - prefix;
            long totalHosts = (hostBits == 32) ? (1L << 32) : (1L << hostBits);
            long maxHosts = 65536L;

            if (totalHosts > maxHosts) {
                if (debug) {
                    System.out.printf(Locale.ROOT,
                            "[CIDR] %s umfasst %,d Hosts – begrenze auf %,d%n",
                            cidr, totalHosts, maxHosts);
                }
                totalHosts = maxHosts;
            }

            for (long i = 0; i < totalHosts; i++) {
                long ip = base + i;
                String ipStr = toIp(ip);
                if (!looksGlobalUnicast(ipStr)) continue;
                for (int p : ports) {
                    out.add(new HostPort(ipStr, p));
                }
            }
        } catch (Exception e) {
            if (debug) {
                System.err.println("[CIDR] Fehler bei " + cidr + ": " + e.getMessage());
            }
        }
        return out;
    }

    private String toIp(long ip) {
        long o1 = (ip >>> 24) & 0xFF;
        long o2 = (ip >>> 16) & 0xFF;
        long o3 = (ip >>> 8) & 0xFF;
        long o4 = ip & 0xFF;
        return o1 + "." + o2 + "." + o3 + "." + o4;
    }

    private static boolean looksGlobalUnicast(String ip) {
        String[] parts = ip.split("\\.");
        if (parts.length != 4) return false;
        try {
            int b1 = Integer.parseInt(parts[0]);
            int b2 = Integer.parseInt(parts[1]);
            if (b1 == 10) return false;
            if (b1 == 172 && b2 >= 16 && b2 <= 31) return false;
            if (b1 == 192 && b2 == 168) return false;
            if (b1 == 127) return false;
            return b1 < 224;
        } catch (NumberFormatException e) {
            return false;
        }
    }

    /**
     * Interner Scanner: hält GeoLite-DBs, Filter und implementiert
     * sowohl Java-TLS-Scan als auch zgrab-Aufrufe.
     */
    class InternalScanner {

        private final Path outputPath;
        private final boolean debug;
        private final int connectTimeoutMs;
        private final int readTimeoutMs;
        private final int maxConcurrency;
        private final AdvancedScanOptions adv;

        private final DatabaseReader countryDb;
        private final DatabaseReader asnDb;
        private final DatabaseReader cityDb;

        private final Set<String> allowedCountries;
        private final Set<String> allowedCities;
        private final Set<Long> allowedAsns;

        private final int randomSampleCount;
        private final String sampleFromCidr;

        private final List<String> fullScanCountries;
        private final String countryBlocksCsvPath;
        private final String countryLocationsCsvPath;

        private final String asnBlocksCsvPath;
        private final String cityBlocksCsvPath;
        private final String cityLocationsCsvPath;

        private final List<String> randomIpPoolFromCsv;

        InternalScanner(Path outputPath,
                        boolean debug,
                        int connectTimeoutMs,
                        int readTimeoutMs,
                        int maxConcurrency,
                        AdvancedScanOptions adv) {

            this.outputPath = outputPath;
            this.debug = debug;
            this.connectTimeoutMs = connectTimeoutMs;
            this.readTimeoutMs = readTimeoutMs;
            this.maxConcurrency = Math.max(1, maxConcurrency);
            this.adv = adv;

            if (adv != null && adv.geoipCountryDbPath != null) {
                this.countryDb = buildDbSafely(new File(adv.geoipCountryDbPath), "[GeoIP-Country]");
            } else {
                this.countryDb = null;
            }
            if (adv != null && adv.geoipAsnDbPath != null) {
                this.asnDb = buildDbSafely(new File(adv.geoipAsnDbPath), "[GeoIP-ASN]");
            } else {
                this.asnDb = null;
            }
            if (adv != null && adv.geoipCityDbPath != null) {
                this.cityDb = buildDbSafely(new File(adv.geoipCityDbPath), "[GeoIP-City]");
            } else {
                this.cityDb = null;
            }

            this.allowedCountries = new HashSet<>();
            this.allowedCities = new HashSet<>();
            this.allowedAsns = new HashSet<>();

            if (adv != null) {
                if (adv.countryIsoCodes != null) {
                    for (String c : adv.countryIsoCodes) {
                        if (c != null && !c.isBlank()) {
                            allowedCountries.add(c.trim().toUpperCase(Locale.ROOT));
                        }
                    }
                }
                if (adv.cityNames != null) {
                    for (String city : adv.cityNames) {
                        if (city != null && !city.isBlank()) {
                            allowedCities.add(city.trim().toLowerCase(Locale.ROOT));
                        }
                    }
                }
                if (adv.asns != null) {
                    allowedAsns.addAll(adv.asns);
                }
            }

            if (!allowedCountries.isEmpty() && countryDb == null && cityDb == null) {
                System.err.println("[GeoIP] Länderfilter gesetzt, aber keine Country/City-DB geladen – Länderfilter wird ignoriert.");
                allowedCountries.clear();
            }
            if (!allowedCities.isEmpty() && cityDb == null) {
                System.err.println("[GeoIP] Städtefilter gesetzt, aber keine City-DB geladen – Städtefilter wird ignoriert.");
                allowedCities.clear();
            }
            if (!allowedAsns.isEmpty() && asnDb == null) {
                System.err.println("[GeoIP] ASN-Filter gesetzt, aber keine ASN-DB geladen – ASN-Filter wird ignoriert.");
                allowedAsns.clear();
            }

            this.randomSampleCount = (adv != null && adv.randomSampleCount != null) ? adv.randomSampleCount : 0;
            this.sampleFromCidr = adv != null ? adv.sampleFromCidr : null;

            if (adv != null && adv.fullScanCountries != null && !adv.fullScanCountries.isEmpty()) {
                List<String> tmp = new ArrayList<>();
                for (String c : adv.fullScanCountries) {
                    if (c != null && !c.isBlank()) {
                        tmp.add(c.trim().toUpperCase(Locale.ROOT));
                    }
                }
                this.fullScanCountries = tmp;
            } else {
                this.fullScanCountries = new ArrayList<>();
            }

            this.countryBlocksCsvPath = (adv != null) ? adv.countryBlocksCsvPath : null;
            this.countryLocationsCsvPath = (adv != null) ? adv.countryLocationsCsvPath : null;
            this.asnBlocksCsvPath = (adv != null) ? adv.asnBlocksCsvPath : null;
            this.cityBlocksCsvPath = (adv != null) ? adv.cityBlocksCsvPath : null;
            this.cityLocationsCsvPath = (adv != null) ? adv.cityLocationsCsvPath : null;

            this.randomIpPoolFromCsv = buildRandomIpPoolFromCsv();
        }

        private DatabaseReader buildDbSafely(File f, String tag) {
            try {
                if (!f.exists()) {
                    System.err.println(tag + " Datei nicht gefunden: " + f.getAbsolutePath());
                    return null;
                }
                if (debug) {
                    System.out.println(tag + " lade: " + f.getAbsolutePath());
                }
                return new DatabaseReader.Builder(new FileInputStream(f)).build();
            } catch (IOException e) {
                System.err.println(tag + " Konnte DB nicht öffnen: " + f + " -> " + e.getMessage());
                return null;
            }
        }

        void close() {
            try { if (countryDb != null) countryDb.close(); } catch (IOException ignore) {}
            try { if (asnDb != null) asnDb.close(); } catch (IOException ignore) {}
            try { if (cityDb != null) cityDb.close(); } catch (IOException ignore) {}
        }

        // --- Hilfsfunktion: Country-Locations-CSV ---------------------------------------------

        private Map<String, String> loadCountryGeoIdToIso() {
            Map<String, String> geoIdToIso = new HashMap<>();

            if (countryLocationsCsvPath == null) {
                return geoIdToIso;
            }

            Path locPath = Path.of(countryLocationsCsvPath);
            if (!Files.exists(locPath)) {
                if (debug) {
                    System.err.println("[GeoIP] Country-Locations-CSV fehlt: " + locPath);
                }
                return geoIdToIso;
            }

            try (BufferedReader br = Files.newBufferedReader(locPath, StandardCharsets.UTF_8)) {
                String header = br.readLine();
                if (header == null) {
                    return geoIdToIso;
                }

                String[] cols = header.split(",", -1);
                int idxGeo = indexOf(cols, "geoname_id");
                int idxIso = indexOf(cols, "country_iso_code");
                if (idxGeo < 0 || idxIso < 0) {
                    if (debug) {
                        System.err.println("[GeoIP] Country-Locations-CSV hat keine Spalten geoname_id/country_iso_code.");
                    }
                    return geoIdToIso;
                }

                String line;
                while ((line = br.readLine()) != null) {
                    if (line.isBlank()) continue;
                    String[] f = line.split(",", -1);
                    if (f.length <= Math.max(idxGeo, idxIso)) continue;

                    String geoId = f[idxGeo].trim();
                    String iso = f[idxIso].trim();
                    if (!geoId.isEmpty() && !iso.isEmpty()) {
                        geoIdToIso.put(geoId, iso.toUpperCase(Locale.ROOT));
                    }
                }
            } catch (IOException e) {
                if (debug) {
                    System.err.println("[GeoIP] Fehler beim Lesen Country-Locations-CSV: " + e.getMessage());
                }
            }

            return geoIdToIso;
        }

        private Map<String, String> loadCityGeoIdToName() {
            Map<String, String> geoIdToCity = new HashMap<>();

            if (cityLocationsCsvPath == null) {
                return geoIdToCity;
            }

            Path locPath = Path.of(cityLocationsCsvPath);
            if (!Files.exists(locPath)) {
                if (debug) {
                    System.err.println("[GeoIP] City-Locations-CSV fehlt: " + locPath);
                }
                return geoIdToCity;
            }

            try (BufferedReader br = Files.newBufferedReader(locPath, StandardCharsets.UTF_8)) {
                String header = br.readLine();
                if (header == null) {
                    return geoIdToCity;
                }

                String[] cols = header.split(",", -1);
                int idxGeo  = indexOf(cols, "geoname_id");
                int idxCity = indexOf(cols, "city_name");
                if (idxGeo < 0 || idxCity < 0) {
                    if (debug) {
                        System.err.println("[GeoIP] City-Locations-CSV hat keine Spalten geoname_id/city_name.");
                    }
                    return geoIdToCity;
                }

                String line;
                while ((line = br.readLine()) != null) {
                    if (line.isBlank()) continue;
                    String[] f = line.split(",", -1);
                    if (f.length <= Math.max(idxGeo, idxCity)) continue;

                    String geoId    = f[idxGeo].trim();
                    String cityName = f[idxCity].trim();
                    if (!geoId.isEmpty() && !cityName.isEmpty()) {
                        geoIdToCity.put(geoId, cityName.trim().toLowerCase(Locale.ROOT));
                    }
                }
            } catch (IOException e) {
                if (debug) {
                    System.err.println("[GeoIP] Fehler beim Lesen City-Locations-CSV: " + e.getMessage());
                }
            }

            return geoIdToCity;
        }


        // ---------- GeoLite: IP-Pools aus CSV --------------------------------------------------

        private List<String> buildRandomIpPoolFromCsv() {
            LinkedHashSet<String> pool = new LinkedHashSet<>();

            // Country-CSV (Blocks + Locations)
            if (countryBlocksCsvPath != null) {
                Path blocksPath = Path.of(countryBlocksCsvPath);
                if (Files.exists(blocksPath)) {
                    Map<String, String> geoIdToIso = loadCountryGeoIdToIso();
                    Set<String> allowed = allowedCountries.isEmpty() ? null : allowedCountries;

                    try (BufferedReader br = Files.newBufferedReader(blocksPath, StandardCharsets.UTF_8)) {
                        String header = br.readLine();
                        if (header != null) {
                            String[] cols = header.split(",", -1);
                            int idxNetwork = indexOf(cols, "network");
                            int idxRegGeo = indexOf(cols, "registered_country_geoname_id");
                            int idxGeo = indexOf(cols, "geoname_id");
                            if (idxNetwork >= 0) {
                                String line;
                                while ((line = br.readLine()) != null) {
                                    if (line.isBlank()) continue;
                                    String[] f = line.split(",", -1);
                                    if (f.length <= idxNetwork) continue;

                                    String network = f[idxNetwork].trim();
                                    if (network.isEmpty()) continue;
                                    if (network.contains(":")) continue;

                                    String geoId = null;
                                    if (idxRegGeo >= 0 && idxRegGeo < f.length && !f[idxRegGeo].trim().isEmpty()) {
                                        geoId = f[idxRegGeo].trim();
                                    } else if (idxGeo >= 0 && idxGeo < f.length && !f[idxGeo].trim().isEmpty()) {
                                        geoId = f[idxGeo].trim();
                                    }

                                    String iso = null;
                                    if (geoId != null && !geoIdToIso.isEmpty()) {
                                        iso = geoIdToIso.get(geoId);
                                        if (iso != null) iso = iso.toUpperCase(Locale.ROOT);
                                    }

                                    if (allowed != null && iso != null && !allowed.contains(iso)) {
                                        continue;
                                    }
                                    if (allowed != null && iso == null) {
                                        continue;
                                    }

                                    String baseIp = network;
                                    int slashIdx = network.indexOf('/');
                                    if (slashIdx > 0) {
                                        baseIp = network.substring(0, slashIdx);
                                    }
                                    if (!looksGlobalUnicast(baseIp)) continue;

                                    pool.add(baseIp);
                                }
                            }
                        }
                    } catch (IOException e) {
                        if (debug) {
                            System.err.println("[RandomPool] Country-Blocks-CSV: " + e.getMessage());
                        }
                    }
                }
            }


            // ASN-CSV: nur falls ASN-Filter aktiv
            if (asnBlocksCsvPath != null && !allowedAsns.isEmpty()) {
                Path asnPath = Path.of(asnBlocksCsvPath);
                if (Files.exists(asnPath)) {
                    try (BufferedReader br = Files.newBufferedReader(asnPath, StandardCharsets.UTF_8)) {
                        String header = br.readLine();
                        if (header != null) {
                            String[] cols = header.split(",", -1);
                            int idxNetwork = indexOf(cols, "network");
                            int idxAsn = indexOf(cols, "autonomous_system_number");
                            if (idxNetwork >= 0 && idxAsn >= 0) {
                                String line;
                                while ((line = br.readLine()) != null) {
                                    if (line.isBlank()) continue;
                                    String[] f = line.split(",", -1);
                                    if (f.length <= Math.max(idxNetwork, idxAsn)) continue;

                                    String network = f[idxNetwork].trim();
                                    String asnStr = f[idxAsn].trim();
                                    if (network.isEmpty() || asnStr.isEmpty()) continue;
                                    if (network.contains(":")) continue;

                                    long asn;
                                    try {
                                        asn = Long.parseLong(asnStr);
                                    } catch (NumberFormatException e) {
                                        continue;
                                    }
                                    if (!allowedAsns.contains(asn)) continue;

                                    String baseIp = network;
                                    int slashIdx = network.indexOf('/');
                                    if (slashIdx > 0) {
                                        baseIp = network.substring(0, slashIdx);
                                    }
                                    if (!looksGlobalUnicast(baseIp)) continue;

                                    pool.add(baseIp);
                                }
                            }
                        }
                    } catch (IOException e) {
                        if (debug) {
                            System.err.println("[RandomPool] ASN-Blocks-CSV: " + e.getMessage());
                        }
                    }
                }
            }

            List<String> list = new ArrayList<>(pool);
            if (!list.isEmpty()) {
                System.out.printf(Locale.ROOT,
                        "[RandomPool] Gesamt-Poolgröße aus CSVs: %,d%n",
                        list.size());
            } else {
                System.out.println("[RandomPool] Achtung: CSV-Pool ist leer – keine Zufallsziele möglich.");
            }
            return list;
        }

        /**
         * Zufallsstichprobe N IPs aus dem über CSV aufgebauten Pool.
         * KEIN Fallback mehr auf „randomGlobalIp + MMDB“.
         */
        List<HostPort> buildRandomSampleTargets(List<Integer> ports) {
            List<HostPort> out = new ArrayList<>();
            if (randomSampleCount <= 0) return out;

            if (randomIpPoolFromCsv.isEmpty()) {
                System.err.println("[RandomSample] CSV-Pool ist leer (Country-/ASN-CSV fehlen oder keine passenden Länder/ASNs) – Zufallsstichprobe wird übersprungen.");
                return out;
            }

            List<String> pool = new ArrayList<>(randomIpPoolFromCsv);
            Collections.shuffle(pool, random);

            int count = Math.min(randomSampleCount, pool.size());
            for (int i = 0; i < count; i++) {
                String ip = pool.get(i);
                for (int p : ports) {
                    out.add(new HostPort(ip, p));
                }
            }

            System.out.printf(Locale.ROOT,
                    "[RandomSample-CSV] angefordert=%d, pool=%d, verwendet=%d%n",
                    randomSampleCount, randomIpPoolFromCsv.size(), count);
            return out;
        }

        List<HostPort> buildCountryFullTargets(List<Integer> ports) {
            List<HostPort> out = new ArrayList<>();
            if (countryBlocksCsvPath == null) {
                System.err.println("[CountryFullScan] Keine Country-Blocks-CSV konfiguriert – Vollscan nicht möglich.");
                return out;
            }

            Path blocksPath = Path.of(countryBlocksCsvPath);
            if (!Files.exists(blocksPath)) {
                System.err.println("[CountryFullScan] Country-Blocks-CSV fehlt: " + blocksPath);
                return out;
            }

            Set<String> wanted;
            boolean filterEnabled;
            if (fullScanCountries != null && !fullScanCountries.isEmpty()) {
                wanted = new HashSet<>(fullScanCountries);
                filterEnabled = true;
            } else if (!allowedCountries.isEmpty()) {
                wanted = new HashSet<>(allowedCountries);
                filterEnabled = true;
            } else {
                wanted = Collections.emptySet();
                filterEnabled = false;
            }

            Map<String, String> geoIdToIso = loadCountryGeoIdToIso();

            long countBlocks = 0;

            try (BufferedReader br = Files.newBufferedReader(blocksPath, StandardCharsets.UTF_8)) {
                String header = br.readLine();
                if (header != null) {
                    String[] cols = header.split(",", -1);
                    int idxNetwork = indexOf(cols, "network");
                    int idxRegGeo = indexOf(cols, "registered_country_geoname_id");
                    int idxGeo = indexOf(cols, "geoname_id");
                    if (idxNetwork >= 0) {
                        String line;
                        while ((line = br.readLine()) != null) {
                            if (line.isBlank()) continue;
                            String[] f = line.split(",", -1);
                            if (f.length <= idxNetwork) continue;

                            String network = f[idxNetwork].trim();
                            if (network.isEmpty()) continue;
                            if (network.contains(":")) continue;

                            String geoId = null;
                            if (idxRegGeo >= 0 && idxRegGeo < f.length && !f[idxRegGeo].trim().isEmpty()) {
                                geoId = f[idxRegGeo].trim();
                            } else if (idxGeo >= 0 && idxGeo < f.length && !f[idxGeo].trim().isEmpty()) {
                                geoId = f[idxGeo].trim();
                            }

                            String iso = null;
                            if (geoId != null && !geoIdToIso.isEmpty()) {
                                iso = geoIdToIso.get(geoId);
                                if (iso != null) iso = iso.toUpperCase(Locale.ROOT);
                            }

                            if (filterEnabled) {
                                if (iso == null || !wanted.contains(iso)) {
                                    continue;
                                }
                            }

                            countBlocks++;

                            String baseIp = network;
                            int slashIdx = network.indexOf('/');
                            if (slashIdx > 0) {
                                baseIp = network.substring(0, slashIdx);
                            }
                            if (!looksGlobalUnicast(baseIp)) continue;

                            for (int p : ports) {
                                out.add(new HostPort(baseIp, p));
                            }
                        }
                    }
                }
            } catch (IOException e) {
                System.err.println("[CountryFullScan] Fehler beim Lesen Country-Blocks-CSV: " + e.getMessage());
                return out;
            }

            System.out.printf(Locale.ROOT,
                    "[CountryFullScan] Länderfilter=%s, Blöcke=%d, Ziele=%d%n",
                    filterEnabled ? wanted : "ALLE",
                    countBlocks,
                    out.size());
            return out;
        }

        List<HostPort> buildCityFullTargets(List<Integer> ports) {
            List<HostPort> out = new ArrayList<>();

            if (cityBlocksCsvPath == null) {
                System.err.println("[CityFullScan] Keine City-Blocks-CSV konfiguriert – Vollscan nicht möglich.");
                return out;
            }

            Path blocksPath = Path.of(cityBlocksCsvPath);
            if (!Files.exists(blocksPath)) {
                System.err.println("[CityFullScan] City-Blocks-CSV fehlt: " + blocksPath);
                return out;
            }

            if (allowedCities.isEmpty()) {
                System.err.println("[CityFullScan] Warnung: allowedCities ist leer – es wird NICHT gefiltert.");
            }

            Map<String, String> geoIdToCity = loadCityGeoIdToName();

            long countBlocks = 0;

            try (BufferedReader br = Files.newBufferedReader(blocksPath, StandardCharsets.UTF_8)) {
                String header = br.readLine();
                if (header != null) {
                    String[] cols = header.split(",", -1);
                    int idxNetwork = indexOf(cols, "network");
                    int idxGeo     = indexOf(cols, "geoname_id");
                    if (idxNetwork >= 0 && idxGeo >= 0) {
                        String line;
                        while ((line = br.readLine()) != null) {
                            if (line.isBlank()) continue;
                            String[] f = line.split(",", -1);
                            if (f.length <= Math.max(idxNetwork, idxGeo)) continue;

                            String network = f[idxNetwork].trim();
                            if (network.isEmpty()) continue;
                            if (network.contains(":")) continue; // vorerst nur IPv4

                            String geoId = f[idxGeo].trim();
                            String cityName = null;
                            if (!geoId.isEmpty() && !geoIdToCity.isEmpty()) {
                                cityName = geoIdToCity.get(geoId);
                            }

                            if (!allowedCities.isEmpty()) {
                                if (cityName == null || !allowedCities.contains(cityName)) {
                                    continue;
                                }
                            }

                            countBlocks++;

                            String baseIp = network;
                            int slashIdx = network.indexOf('/');
                            if (slashIdx > 0) {
                                baseIp = network.substring(0, slashIdx);
                            }
                            if (!looksGlobalUnicast(baseIp)) continue;

                            for (int p : ports) {
                                out.add(new HostPort(baseIp, p));
                            }
                        }
                    }
                }
            } catch (IOException e) {
                System.err.println("[CityFullScan] Fehler beim Lesen City-Blocks-CSV: " + e.getMessage());
                return out;
            }

            System.out.printf(Locale.ROOT,
                    "[CityFullScan] Städtefilter=%s, Blöcke=%d, Ziele=%d%n",
                    allowedCities.isEmpty() ? "ALLE" : allowedCities,
                    countBlocks,
                    out.size());

            return out;
        }


        private int indexOf(String[] cols, String name) {
            for (int i = 0; i < cols.length; i++) {
                if (name.equalsIgnoreCase(cols[i].trim().replace("\"", ""))) {
                    return i;
                }
            }
            return -1;
        }

        // ---------- zgrab2: externer TLS-Scanner -----------------------------------------------

        void scanWithZgrab(List<HostPort> targets) throws IOException {
            if (adv == null || !adv.useZgrabOnly) {
                throw new IllegalStateException("scanWithZgrab() aufgerufen, aber useZgrabOnly=false");
            }
            if (targets == null || targets.isEmpty()) {
                System.out.println("[zgrab2] Keine Ziele übergeben.");
                return;
            }

            Path parent = outputPath.getParent();
            if (parent != null) {
                Files.createDirectories(parent);
            }

            Map<Integer, LinkedHashSet<String>> portToHosts = new HashMap<>();
            for (HostPort hp : targets) {
                portToHosts
                        .computeIfAbsent(hp.port, k -> new LinkedHashSet<>())
                        .add(hp.host);
            }

            for (Map.Entry<Integer, LinkedHashSet<String>> e : portToHosts.entrySet()) {
                int port = e.getKey();
                LinkedHashSet<String> hosts = e.getValue();
                if (hosts.isEmpty()) continue;

                Path ipFile = Files.createTempFile("zgrab_targets_", ".txt");
                try (BufferedWriter bw = Files.newBufferedWriter(ipFile, StandardCharsets.UTF_8)) {
                    for (String h : hosts) {
                        bw.write(h);
                        bw.newLine();
                    }
                    bw.flush();
                }

                try {
                    runZgrabAndConvert(ipFile, port);
                } finally {
                    try { Files.deleteIfExists(ipFile); } catch (IOException ignore) {}
                }
            }
        }

        private void runZgrabAndConvert(Path ipFile, int port) throws IOException {
            String zgrabBin = (adv != null && adv.zgrabBinary != null && !adv.zgrabBinary.isBlank())
                    ? adv.zgrabBinary
                    : "zgrab2";

            List<String> cmd = new ArrayList<>();
            cmd.add(zgrabBin);
            cmd.add("tls");
            cmd.add("--port");
            cmd.add(String.valueOf(port));
            cmd.add("-f");
            cmd.add(ipFile.toString());

            Path blocklist = Paths.get(System.getProperty("user.dir"),
                    ".config", "zgrab2", "blocklist.conf");

            int connectTimeoutSec = 5;   // z.B. 5 Sekunden für TCP-Handshake
            int targetTimeoutSec  = 10;  // z.B. 20 Sekunden für kompletten TLS-Handshake

            cmd.add("--connect-timeout");
            cmd.add(connectTimeoutSec + "s");   // Go-Duration, also "5s", "10s", ...
            cmd.add("--target-timeout");
            cmd.add(targetTimeoutSec + "s");

            int senders = 2500; // oder z.B. 500, je nach Maschine/Bandbreite

            cmd.add("--senders");
            cmd.add(String.valueOf(senders));

            try {
                Files.createDirectories(blocklist.getParent());
                if (Files.notExists(blocklist)) {
                    Files.createFile(blocklist);
                }
                cmd.add("--blocklist-file");
                cmd.add(blocklist.toString());
            } catch (IOException e) {
                if (debug) {
                    System.err.println("[zgrab2] Konnte Blocklist-Datei nicht anlegen: " + e.getMessage());
                }
                // im Worst Case verwendet zgrab2 wieder das Default-Path-Handling
            }

            if (debug) {
                System.out.println("[zgrab2] Starte: " + String.join(" ", cmd));
            }

            ProcessBuilder pb = new ProcessBuilder(cmd);
            Process p = pb.start();

            new Thread(() -> {
                try (BufferedReader err = new BufferedReader(
                        new InputStreamReader(p.getErrorStream(), StandardCharsets.UTF_8))) {
                    String el;
                    if (debug){
                    while ((el = err.readLine()) != null) {
                        System.err.println("[zgrab2] " + el);
                    }
                    } else {
                        while ((el = err.readLine()) != null) {
                            System.out.print("\r[zgrab2] " + el);
                            System.out.flush();
                        }
                    }
                } catch (IOException ignored) {}
            }).start();


            try (BufferedReader br = new BufferedReader(
                    new InputStreamReader(p.getInputStream(), StandardCharsets.UTF_8));
                 BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(
                         Files.newOutputStream(outputPath,
                                 StandardOpenOption.CREATE,
                                 StandardOpenOption.APPEND),
                         StandardCharsets.UTF_8))) {

                String line;
                long written = 0;

                while ((line = br.readLine()) != null) {
                    line = line.trim();
                    if (line.isEmpty()) continue;

                    try {
                        JsonNode root = mapper.readTree(line);
                        ObjectNode out = convertZgrabRecord(root, port);
                        if (out == null) {
                            continue;
                        }
                        writer.write(mapper.writeValueAsString(out));
                        writer.write("\n");
                        written++;
                    } catch (Exception e) {
                        if (debug) {
                            System.err.println("[zgrab2] JSON-Parse-Fehler: " + e.getMessage());
                        }
                    }
                }
                writer.flush();
                if (debug) {
                    System.out.println("[zgrab2] JSONL-Zeilen geschrieben: " + written);
                }
            } finally {
                try {
                    int exit = p.waitFor();
                    if (exit != 0 && debug) {
                        System.err.println("[zgrab2] Exit-Code: " + exit);

                    }
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            }
        }

        /**
         * Konvertiert eine zgrab2-JSON-Zeile ins active_scan-Format
         * (inkl. GeoLite-Felder & Zertifikats-Länder).
         */
        private ObjectNode convertZgrabRecord(JsonNode root, int port) {
            if (root == null || !root.isObject()) return null;

            String ip = root.path("ip").asText(null);
            if (ip == null || ip.isBlank()) return null;

            JsonNode tls = root.path("data").path("tls");
            if (tls.isMissingNode()) return null;

            String status = tls.path("status").asText("");
            if (!"success".equalsIgnoreCase(status)) {
                return null;
            }

            JsonNode result = tls.path("result");
            JsonNode handshake = result.path("handshake_log");
            JsonNode serverHello = handshake.path("server_hello");

            String version;
            JsonNode vNode = serverHello.path("version");
            if (vNode.isTextual()) {
                version = vNode.asText();
            } else {
                version = vNode.path("name").asText(null);
            }

            String cipherSuite;
            JsonNode cNode = serverHello.path("cipher_suite");
            if (cNode.isTextual()) {
                cipherSuite = cNode.asText();
            } else {
                cipherSuite = cNode.path("name").asText(null);
            }

            String leafPem = null;
            List<String> chainPem = new ArrayList<>();

            JsonNode certNode = handshake.path("server_certificates").path("certificate");
            if (certNode != null && certNode.has("raw")) {
                String raw = certNode.get("raw").asText(null);
                leafPem = derBase64ToPem(raw);
            }

            JsonNode chain = handshake.path("server_certificates").path("chain");
            if (chain != null && chain.isArray()) {
                for (JsonNode c : chain) {
                    String raw = c.path("raw").asText(null);
                    String pem = derBase64ToPem(raw);
                    if (pem != null) {
                        chainPem.add(pem);
                    }
                }
            }

            String issuerCountry = null;
            String subjectCountry = null;
            String issuerDn = null;
            String subjectDn = null;

            try {
                if (leafPem != null) {
                    X509Certificate leafCert = parsePemToX509(leafPem);
                    if (leafCert != null) {
                        issuerDn = leafCert.getIssuerX500Principal().getName();
                        subjectDn = leafCert.getSubjectX500Principal().getName();
                        issuerCountry = CountryTrustUtil.extractCountryFromDn(issuerDn);
                        subjectCountry = CountryTrustUtil.extractCountryFromDn(subjectDn);
                    }
                }
            } catch (Exception e) {
                if (debug) {
                    System.err.println("[zgrab2] Zertifikats-Parsing-Fehler: " + e.getMessage());
                }
            }

            String countryIso = null;
            Long asn = null;
            String cityName = null;

            try {
                InetAddress addr = InetAddress.getByName(ip);

                if (countryDb != null) {
                    try {
                        CountryResponse cResp = countryDb.country(addr);
                        if (cResp != null && cResp.getCountry() != null) {
                            countryIso = cResp.getCountry().getIsoCode();
                            if (countryIso != null) {
                                countryIso = countryIso.toUpperCase(Locale.ROOT);
                            }
                        }
                    } catch (AddressNotFoundException ignored) {}
                }

                if (cityDb != null) {
                    try {
                        CityResponse cityResp = cityDb.city(addr);
                        if (cityResp != null && cityResp.getCountry() != null) {
                            cityName = cityResp.getCity().getName();
                            if (cityName != null) {
                                cityName = cityName.toUpperCase(Locale.ROOT);
                            }
                        }
                            } catch (AddressNotFoundException ignored) {}
                        }

                if (asnDb != null) {
                    try {
                        AsnResponse aResp = asnDb.asn(addr);
                        if (aResp != null && aResp.getAutonomousSystemNumber() != null) {
                            asn = aResp.getAutonomousSystemNumber();
                        }
                    } catch (AddressNotFoundException ignored) {}
                }

                // Geo-Filter anwenden
                if (!allowedCountries.isEmpty()) {
                    if (countryIso == null || !allowedCountries.contains(countryIso)) {
                        return null;
                    }
                }
                if (!allowedAsns.isEmpty()) {
                    if (asn == null || !allowedAsns.contains(asn)) {
                        return null;
                    }
                }

                if (!allowedCities.isEmpty()) {
                    if (cityName == null || !allowedCities.contains(cityName)) {
                        return null;
                    }
                }

            } catch (Exception e) {
                if (debug) {
                    System.err.println("[GeoIP-zgrab] " + ip + " -> " + e.getMessage());
                }
                return null;
            }

            ScanLogUtil.ScanLogData logData = new ScanLogUtil.ScanLogData(
                    ip,
                    port,
                    ip,
                    version,
                    cipherSuite,
                    countryIso,
                    asn,
                    cityName,
                    issuerDn,
                    subjectDn,
                    issuerCountry,
                    subjectCountry,
                    leafPem,
                    chainPem
            );
            return ScanLogUtil.buildLogEntry(mapper, "active_scan", logData);
        }

        private String derBase64ToPem(String rawB64) {
            if (rawB64 == null || rawB64.isBlank()) return null;
            String b64 = rawB64.replaceAll("\\s", "");
            StringBuilder sb = new StringBuilder();
            sb.append("-----BEGIN CERTIFICATE-----\n");
            for (int i = 0; i < b64.length(); i += 64) {
                int end = Math.min(i + 64, b64.length());
                sb.append(b64, i, end).append("\n");
            }
            sb.append("-----END CERTIFICATE-----\n");
            return sb.toString();
        }

        private X509Certificate parsePemToX509(String pem) {
            if (pem == null || pem.isBlank()) return null;
            try {
                String stripped = pem
                        .replace("-----BEGIN CERTIFICATE-----", "")
                        .replace("-----END CERTIFICATE-----", "")
                        .replaceAll("\\s+", "");
                byte[] der = Base64.getDecoder().decode(stripped);
                CertificateFactory cf = CertificateFactory.getInstance("X.509");
                return (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(der));
            } catch (Exception e) {
                if (debug) {
                    System.err.println("[PEM->X509] " + e.getMessage());
                }
                return null;
            }
        }

        // ---------- interne Java-TLS-Engine -----------------------------------------------------

        void scanHostPortList(List<HostPort> targets) throws IOException {
            if (targets == null || targets.isEmpty()) {
                System.out.println("[ActiveScan] Keine Ziele übergeben.");
                return;
            }

            Path parent = outputPath.getParent();
            if (parent != null) {
                Files.createDirectories(parent);
            }
            final BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(
                    Files.newOutputStream(outputPath,
                            StandardOpenOption.CREATE,
                            StandardOpenOption.APPEND),
                    StandardCharsets.UTF_8));

            ExecutorService executor = Executors.newFixedThreadPool(maxConcurrency);
            AtomicLong counter = new AtomicLong(0);
            AtomicLong written = new AtomicLong(0);
            Instant start = Instant.now();

            try {
                List<Future<?>> futures = new ArrayList<>();
                for (HostPort hp : targets) {
                    futures.add(executor.submit(() -> {
                        try {
                            handleOneTarget(hp, writer, counter, written, start);
                        } catch (Exception e) {
                            if (debug) {
                                System.err.println("[ActiveScan] Fehler bei Ziel " + hp.host + ":" + hp.port + " -> " + e.getMessage());
                            }
                        }
                    }));
                }

                for (Future<?> f : futures) {
                    try {
                        f.get();
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                        break;
                    } catch (ExecutionException e) {
                        if (debug) {
                            System.err.println("[ActiveScan] Task-Fehler: " + e.getCause());
                        }
                    }
                }
            } finally {
                executor.shutdownNow();
                try {
                    writer.flush();
                } catch (IOException ignored) {}
                try {
                    writer.close();
                } catch (IOException ignored) {}
                Duration d = Duration.between(start, Instant.now());
                System.out.println("[ActiveScan] Fertig. Dauer: " + d.toSeconds() + " s, gescannte Ziele: " + counter.get() + ", geschrieben: " + written.get());
            }
        }

        private void handleOneTarget(HostPort hp,
                                     BufferedWriter writer,
                                     AtomicLong counter,
                                     AtomicLong written,
                                     Instant startTime) throws IOException {

            InetAddress addr;
            try {
                addr = InetAddress.getByName(hp.host);
            } catch (Exception e) {
                if (debug) {
                    System.err.println("[ActiveScan] DNS-Fehler für " + hp.host + ": " + e.getMessage());
                }
                return;
            }

            if (!passesGeoFilters(addr)) {
                if (debug) {
                    System.out.println("[ActiveScan] " + addr.getHostAddress() + " fällt durch Geo-Filter.");
                }
                return;
            }

            Socket plain = null;
            SSLSocket ssl = null;

            String protocol = null;
            String cipherSuite = null;
            X509Certificate leaf = null;
            List<String> chainPem = new ArrayList<>();

            try {
                plain = new Socket();
                plain.connect(new InetSocketAddress(addr, hp.port), connectTimeoutMs);
                plain.setSoTimeout(readTimeoutMs);

                SSLSocketFactory factory = (SSLSocketFactory) SSLSocketFactory.getDefault();
                ssl = (SSLSocket) factory.createSocket(plain, hp.host, hp.port, true);

                SSLParameters params = ssl.getSSLParameters();
                if (!isIpv4Literal(hp.host)) {
                    params.setServerNames(Collections.singletonList(new SNIHostName(hp.host)));
                }
                ssl.setSSLParameters(params);

                ssl.startHandshake();
                SSLSession session = ssl.getSession();
                protocol = session.getProtocol();
                cipherSuite = session.getCipherSuite();

                Certificate[] peer = session.getPeerCertificates();
                if (peer != null && peer.length > 0) {
                    leaf = (X509Certificate) peer[0];
                    for (Certificate c : peer) {
                        if (c instanceof X509Certificate) {
                            String pem = ScanLogUtil.certToPem((X509Certificate) c);
                            if (pem != null) {
                                chainPem.add(pem);
                            }
                        }
                    }
                }
            } catch (Exception e) {
                if (debug) {
                    System.err.println("[ActiveScan] TLS-Fehler bei " + hp.host + ":" + hp.port + " -> " + e.getMessage());
                }
                return;
            } finally {
                if (ssl != null) {
                    try { ssl.close(); } catch (IOException ignore) {}
                }
                if (plain != null) {
                    try { plain.close(); } catch (IOException ignore) {}
                }
            }

            String ipStr = addr.getHostAddress();
            String issuerCountry = null;
            String subjectCountry = null;
            String issuerDn = null;
            String subjectDn = null;

            if (leaf != null) {
                try {
                    issuerDn = leaf.getIssuerX500Principal().getName();
                    subjectDn = leaf.getSubjectX500Principal().getName();
                    issuerCountry = CountryTrustUtil.extractCountryFromDn(issuerDn);
                    subjectCountry = CountryTrustUtil.extractCountryFromDn(subjectDn);
                } catch (Exception e) {
                    if (debug) {
                        System.err.println("[ActiveScan] DN/Länder-Fehler für " + hp.host + ":" + hp.port + " -> " + e.getMessage());
                    }
                }
            }

            String countryIso = null;
            Long asn = null;
            String cityName = null;

            try {
                if (countryDb != null) {
                    try {
                        CountryResponse cResp = countryDb.country(addr);
                        if (cResp != null && cResp.getCountry() != null) {
                            countryIso = cResp.getCountry().getIsoCode();
                            if (countryIso != null) {
                                countryIso = countryIso.toUpperCase(Locale.ROOT);
                            }
                        }
                    } catch (AddressNotFoundException ignored) {}
                }
                if (cityDb != null) {
                    try {
                        CityResponse cityResp = cityDb.city(addr);
                        if (cityResp != null) {
                            if (cityResp.getCity() != null) {
                                cityName = cityResp.getCity().getName();
                            }
                            if (countryIso == null &&
                                    cityResp.getCountry() != null &&
                                    cityResp.getCountry().getIsoCode() != null) {
                                countryIso = cityResp.getCountry().getIsoCode().toUpperCase(Locale.ROOT);
                            }
                        }
                    } catch (AddressNotFoundException ignored) {}
                }
                if (asnDb != null) {
                    try {
                        AsnResponse aResp = asnDb.asn(addr);
                        if (aResp != null && aResp.getAutonomousSystemNumber() != null) {
                            asn = aResp.getAutonomousSystemNumber().longValue();
                        }
                    } catch (AddressNotFoundException ignored) {}
                }
            } catch (Exception e) {
                if (debug) {
                    System.err.println("[GeoIP] " + ipStr + " -> " + e.getMessage());
                }
            }

            String leafPem = ScanLogUtil.certToPem(leaf);

            ScanLogUtil.ScanLogData logData = new ScanLogUtil.ScanLogData(
                    ipStr,
                    hp.port,
                    hp.host,
                    protocol,
                    cipherSuite,
                    countryIso,
                    asn,
                    cityName,
                    issuerDn,
                    subjectDn,
                    issuerCountry,
                    subjectCountry,
                    leafPem,
                    chainPem
            );

            try {
                String json = mapper.writeValueAsString(
                        ScanLogUtil.buildLogEntry(mapper, "active_scan", logData)
                );
                synchronized (writer) {
                    writer.write(json);
                    writer.write("\n");
                }
                written.incrementAndGet();
            } catch (IOException e) {
                if (debug) {
                    System.err.println("[ActiveScan] Fehler beim Schreiben JSON: " + e.getMessage());
                }
            }

            long c = counter.incrementAndGet();
            if (c % 100 == 0) {
                Duration d = Duration.between(startTime, Instant.now());
                double rate = c / Math.max(1.0, d.toSeconds());
                System.out.printf(Locale.ROOT,
                        "[ActiveScan] gescannt=%,d geschrieben=%,d (%.2f Ziele/s)%n",
                        c, written.get(), rate);
            }
        }

        private boolean passesGeoFilters(InetAddress addr) {
            if (allowedCountries.isEmpty() && allowedAsns.isEmpty() && allowedCities.isEmpty()) {
                return true;
            }
            String countryIso = null;
            Long asn = null;
            String cityName = null;
            try {
                if (countryDb != null) {
                    try {
                        CountryResponse cResp = countryDb.country(addr);
                        if (cResp != null && cResp.getCountry() != null) {
                            countryIso = cResp.getCountry().getIsoCode();
                            if (countryIso != null) countryIso = countryIso.toUpperCase(Locale.ROOT);
                        }
                    } catch (AddressNotFoundException ignored) {}
                }
                if (cityDb != null) {
                    try {
                        CityResponse cityResp = cityDb.city(addr);
                        if (cityResp != null) {
                            if (cityResp.getCity() != null) {
                                cityName = cityResp.getCity().getName();
                            }
                            if (countryIso == null &&
                                    cityResp.getCountry() != null &&
                                    cityResp.getCountry().getIsoCode() != null) {
                                countryIso = cityResp.getCountry().getIsoCode().toUpperCase(Locale.ROOT);
                            }
                        }
                    } catch (AddressNotFoundException ignored) {}
                }
                if (asnDb != null) {
                    try {
                        AsnResponse aResp = asnDb.asn(addr);
                        if (aResp != null && aResp.getAutonomousSystemNumber() != null) {
                            asn = aResp.getAutonomousSystemNumber().longValue();
                        }
                    } catch (AddressNotFoundException ignored) {}
                }
            } catch (Exception e) {
                if (debug) {
                    System.err.println("[GeoIP-filter] " + addr.getHostAddress() + " -> " + e.getMessage());
                }
            }

            if (!allowedCountries.isEmpty()) {
                if (countryIso == null || !allowedCountries.contains(countryIso)) return false;
            }
            if (!allowedAsns.isEmpty()) {
                if (asn == null || !allowedAsns.contains(asn)) return false;
            }
            if (!allowedCities.isEmpty()) {
                if (cityName == null) return false;
                String norm = cityName.trim().toLowerCase(Locale.ROOT);
                return allowedCities.contains(norm);
            }
            return true;
        }

        private boolean isIpv4Literal(String host) {
            String[] parts = host.split("\\.");
            if (parts.length != 4) return false;
            for (String p : parts) {
                try {
                    int v = Integer.parseInt(p);
                    if (v < 0 || v > 255) return false;
                } catch (NumberFormatException e) {
                    return false;
                }
            }
            return true;
        }

    }
}