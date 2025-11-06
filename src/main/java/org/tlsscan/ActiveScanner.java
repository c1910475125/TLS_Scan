package org.tlsscan;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.maxmind.geoip2.DatabaseReader;
import com.maxmind.geoip2.exception.AddressNotFoundException;
import com.maxmind.geoip2.model.AsnResponse;
import com.maxmind.geoip2.model.CityResponse;
import com.maxmind.geoip2.model.CountryResponse;

import javax.net.ssl.SNIHostName;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.Base64;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicLong;

public class ActiveScanner {

    private final ObjectMapper mapper = new ObjectMapper();
    private final Random random = new Random();

    public static class AdvancedScanOptions {
        public String geoipCountryDbPath;
        public String geoipAsnDbPath;
        public String geoipCityDbPath;

        public List<String> countryIsoCodes = new ArrayList<>();
        public List<String> cityNames = new ArrayList<>();
        public List<Long> asns = new ArrayList<>();

        public Integer randomSampleCount = 0;
        public String sampleFromCidr;

        // Flag: soll überhaupt ein Ländervollscan gemacht werden?
        public boolean enableCountryFullScan = false;

        // Liste von Ländern für Vollscan (optional; sonst fallback auf countryIsoCodes / alle)
        public List<String> fullScanCountries = new ArrayList<>();
        public String countryBlocksCsvPath;     // GeoLite2-Country-Blocks-IPv4.csv
        public String countryLocationsCsvPath;  // GeoLite2-Country-Locations-en.csv

        // Zusätzliche CSVs
        public String asnBlocksCsvPath;         // GeoLite2-ASN-Blocks-IPv4.csv
        public String cityBlocksCsvPath;        // GeoLite2-City-Blocks-IPv4.csv
        public String cityLocationsCsvPath;     // GeoLite2-City-Locations-en.csv
    }

    public ActiveScanner() {
    }

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

        // 1) Ziele aus direkten Angaben / CIDR-Ranges bauen
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

        // 2) Geo-Scanner initialisieren (für Zufallsziele / Länderscan)
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

            // Zufallsstichprobe (aus GeoLite-Pool)
            if (adv != null && adv.randomSampleCount != null && adv.randomSampleCount > 0) {
                List<HostPort> sampled = scanner.buildRandomSampleTargets(ports);
                System.out.println("[ActiveScan] Zufallsziele (GeoLite2) erzeugt: " + sampled.size());
                allTargets.addAll(sampled);
            }

            // Vollständiger Länderscan (ein Host pro Netzblock aus Country-Blocks-CSV)
            if (adv != null && adv.enableCountryFullScan) {
                List<HostPort> countryTargets = scanner.buildCountryFullTargets(ports);
                System.out.println("[ActiveScan] Länderscan-Ziele (GeoLite2) erzeugt: " + countryTargets.size());
                allTargets.addAll(countryTargets);
            }

            LinkedHashSet<HostPort> dedup = new LinkedHashSet<>(allTargets);
            allTargets = new ArrayList<>(dedup);

            if (allTargets.isEmpty()) {
                System.out.println("[ActiveScan] Es wurden keine Scan-Ziele erzeugt.");
                return;
            }

            scanner.scanHostPortList(allTargets);

        } finally {
            scanner.close();
        }
    }

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
            if (!(o instanceof HostPort)) return false;
            HostPort hostPort = (HostPort) o;
            return port == hostPort.port && Objects.equals(host, hostPort.host);
        }

        @Override
        public int hashCode() {
            return Objects.hash(host, port);
        }
    }

    // --- Hilfen im äußeren Scanner --------------------------------------------------------

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

            if (totalHosts <= maxHosts) {
                for (long i = 0; i < totalHosts; i++) {
                    long ip = base + i;
                    String ipStr = toIp(ip);
                    if (!looksGlobalUnicast(ipStr)) continue;
                    for (int p : ports) {
                        out.add(new HostPort(ipStr, p));
                    }
                }
            } else {
                HashSet<Long> offsets = new HashSet<>();
                long targetCount = maxHosts;
                while (offsets.size() < targetCount) {
                    long off = (long) (random.nextDouble() * totalHosts);
                    offsets.add(off);
                }
                for (Long off : offsets) {
                    long ip = base + off;
                    String ipStr = toIp(ip);
                    if (!looksGlobalUnicast(ipStr)) continue;
                    for (int p : ports) {
                        out.add(new HostPort(ipStr, p));
                    }
                }
            }
            if (debug) {
                System.out.printf(Locale.ROOT,
                        "[CIDR] %s -> %,d Ziele%n", cidr, out.size());
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

            if (b1 == 0) return false;
            if (b1 == 10) return false;
            if (b1 == 100 && (b2 >= 64 && b2 <= 127)) return false;
            if (b1 == 127) return false;
            if (b1 == 169 && b2 == 254) return false;
            if (b1 == 172 && (b2 >= 16 && b2 <= 31)) return false;
            if (b1 == 192 && b2 == 0) return false;
            if (b1 == 192 && b2 == 168) return false;
            if (b1 == 198 && (b2 == 18 || b2 == 19)) return false;
            if (b1 >= 224) return false;
            return true;
        } catch (NumberFormatException e) {
            return false;
        }
    }

    private static boolean isIpv4Literal(String host) {
        String[] parts = host.split("\\.");
        if (parts.length != 4) return false;
        try {
            for (String p : parts) {
                int b = Integer.parseInt(p);
                if (b < 0 || b > 255) return false;
            }
            return true;
        } catch (NumberFormatException e) {
            return false;
        }
    }

    // --- innerer Scanner -------------------------------------------------------------------

    private class InternalScanner {

        private final Path outputPath;
        private final boolean debug;
        private final int connectTimeoutMs;
        private final int readTimeoutMs;
        private final int maxConcurrency;

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

            if (adv != null && adv.geoipCountryDbPath != null && !adv.geoipCountryDbPath.isBlank()) {
                this.countryDb = buildDbSafely(new File(adv.geoipCountryDbPath), "[GeoIP-Country]");
            } else {
                this.countryDb = null;
            }
            if (adv != null && adv.geoipAsnDbPath != null && !adv.geoipAsnDbPath.isBlank()) {
                this.asnDb = buildDbSafely(new File(adv.geoipAsnDbPath), "[GeoIP-ASN]");
            } else {
                this.asnDb = null;
            }
            if (adv != null && adv.geoipCityDbPath != null && !adv.geoipCityDbPath.isBlank()) {
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

            this.randomSampleCount = (adv != null && adv.randomSampleCount != null)
                    ? adv.randomSampleCount
                    : 0;
            this.sampleFromCidr = (adv != null && adv.sampleFromCidr != null && !adv.sampleFromCidr.isBlank())
                    ? adv.sampleFromCidr.trim()
                    : null;

            if (adv != null && adv.fullScanCountries != null) {
                List<String> tmp = new ArrayList<>();
                for (String c : adv.fullScanCountries) {
                    if (c != null && !c.isBlank()) {
                        tmp.add(c.trim().toUpperCase(Locale.ROOT));
                    }
                }
                this.fullScanCountries = tmp;
                this.countryBlocksCsvPath = adv.countryBlocksCsvPath;
                this.countryLocationsCsvPath = adv.countryLocationsCsvPath;
            } else {
                this.fullScanCountries = Collections.emptyList();
                this.countryBlocksCsvPath = adv != null ? adv.countryBlocksCsvPath : null;
                this.countryLocationsCsvPath = adv != null ? adv.countryLocationsCsvPath : null;
            }

            this.asnBlocksCsvPath = adv != null ? adv.asnBlocksCsvPath : null;
            this.cityBlocksCsvPath = adv != null ? adv.cityBlocksCsvPath : null;
            this.cityLocationsCsvPath = adv != null ? adv.cityLocationsCsvPath : null;

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

        private List<String> buildRandomIpPoolFromCsv() {
            LinkedHashSet<String> pool = new LinkedHashSet<>();

            // 1) Country-CSV (Blocks + Locations)
            if (countryBlocksCsvPath != null && countryLocationsCsvPath != null) {
                Path locPath = Path.of(countryLocationsCsvPath);
                Path blocksPath = Path.of(countryBlocksCsvPath);
                if (Files.exists(locPath) && Files.exists(blocksPath)) {
                    Map<String, String> geoIdToIso = new HashMap<>();
                    try (BufferedReader br = Files.newBufferedReader(locPath, StandardCharsets.UTF_8)) {
                        String header = br.readLine();
                        if (header != null) {
                            String[] cols = header.split(",", -1);
                            int idxGeo = indexOf(cols, "geoname_id");
                            int idxIso = indexOf(cols, "country_iso_code");
                            if (idxGeo >= 0 && idxIso >= 0) {
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
                            }
                        }
                    } catch (IOException e) {
                        if (debug) {
                            System.err.println("[RandomPool] Fehler beim Lesen Country-Locations-CSV: " + e.getMessage());
                        }
                    }

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
                                    if (geoId == null) continue;

                                    String iso = geoIdToIso.get(geoId);
                                    if (iso == null) continue;
                                    iso = iso.toUpperCase(Locale.ROOT);

                                    if (allowed != null && !allowed.contains(iso)) {
                                        continue;
                                    }

                                    String baseIp = network;
                                    int slashIdx = network.indexOf('/');
                                    if (slashIdx > 0) {
                                        baseIp = network.substring(0, slashIdx);
                                    }

                                    if (!looksGlobalUnicast(baseIp)) {
                                        continue;
                                    }
                                    pool.add(baseIp);
                                }
                            }
                        }
                    } catch (IOException e) {
                        if (debug) {
                            System.err.println("[RandomPool] Fehler beim Lesen Country-Blocks-CSV: " + e.getMessage());
                        }
                    }
                }
            }

            // 2) ASN-CSV (Blocks-IPv4) – nur falls ASN-Filter gesetzt
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

                                    if (!looksGlobalUnicast(baseIp)) {
                                        continue;
                                    }
                                    pool.add(baseIp);
                                }
                            }
                        }
                    } catch (IOException e) {
                        if (debug) {
                            System.err.println("[RandomPool] Fehler beim Lesen ASN-Blocks-CSV: " + e.getMessage());
                        }
                    }
                }
            }

            List<String> list = new ArrayList<>(pool);
            if (!list.isEmpty()) {
                System.out.printf(Locale.ROOT,
                        "[RandomPool] Gesamt-Poolgröße aus CSVs: %,d%n",
                        list.size());
            }
            return list;
        }

        List<HostPort> buildCountryFullTargets(List<Integer> ports) {
            List<HostPort> out = new ArrayList<>();
            if (countryBlocksCsvPath == null || countryLocationsCsvPath == null) {
                System.err.println("[CountryFullScan] CSV-Dateien nicht gesetzt – überspringe Vollscan.");
                return out;
            }

            // Wenn fullScanCountries leer ist, auf allowedCountries zurückfallen.
            // Wenn beides leer ist -> KEIN Filter (alle Länder).
            Set<String> wanted = new HashSet<>();
            if (fullScanCountries != null && !fullScanCountries.isEmpty()) {
                for (String c : fullScanCountries) {
                    if (c != null && !c.isBlank()) {
                        wanted.add(c.trim().toUpperCase(Locale.ROOT));
                    }
                }
            } else if (!allowedCountries.isEmpty()) {
                wanted.addAll(allowedCountries);
            }
            boolean filterEnabled = !wanted.isEmpty();

            Path locPath = Path.of(countryLocationsCsvPath);
            Path blocksPath = Path.of(countryBlocksCsvPath);
            if (!Files.exists(locPath) || !Files.exists(blocksPath)) {
                System.err.println("[CountryFullScan] CSV-Dateien nicht gefunden: " +
                        locPath + " / " + blocksPath);
                return out;
            }

            Map<String, String> geoIdToIso = new HashMap<>();

            try (BufferedReader br = Files.newBufferedReader(locPath, StandardCharsets.UTF_8)) {
                String header = br.readLine();
                if (header == null) {
                    System.err.println("[CountryFullScan] Locations-CSV leer: " + locPath);
                } else {
                    String[] cols = header.split(",", -1);
                    int idxGeo = indexOf(cols, "geoname_id");
                    int idxIso = indexOf(cols, "country_iso_code");
                    if (idxGeo < 0 || idxIso < 0) {
                        System.err.println("[CountryFullScan] Spalten in Locations-CSV nicht gefunden.");
                    } else {
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
                    }
                }
            } catch (IOException e) {
                System.err.println("[CountryFullScan] Fehler beim Lesen Locations-CSV: " + e.getMessage());
                return out;
            }

            long countBlocks = 0;
            try (BufferedReader br = Files.newBufferedReader(blocksPath, StandardCharsets.UTF_8)) {
                String header = br.readLine();
                if (header == null) {
                    System.err.println("[CountryFullScan] Blocks-CSV leer: " + blocksPath);
                    return out;
                }
                String[] cols = header.split(",", -1);
                int idxNetwork = indexOf(cols, "network");
                int idxRegGeo = indexOf(cols, "registered_country_geoname_id");
                int idxGeo = indexOf(cols, "geoname_id");
                if (idxNetwork < 0) {
                    System.err.println("[CountryFullScan] Spalte 'network' nicht gefunden.");
                    return out;
                }

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
                    if (geoId == null) continue;

                    String iso = geoIdToIso.get(geoId);
                    if (iso == null) continue;
                    iso = iso.toUpperCase(Locale.ROOT);

                    if (filterEnabled && !wanted.contains(iso)) {
                        continue;
                    }

                    String baseIp = network;
                    int slashIdx = network.indexOf('/');
                    if (slashIdx > 0) {
                        baseIp = network.substring(0, slashIdx);
                    }

                    if (!looksGlobalUnicast(baseIp)) {
                        continue;
                    }

                    for (int p : ports) {
                        out.add(new HostPort(baseIp, p));
                    }
                    countBlocks++;
                }
            } catch (IOException e) {
                System.err.println("[CountryFullScan] Fehler beim Lesen Blocks-CSV: " + e.getMessage());
                return out;
            }

            System.out.printf(Locale.ROOT,
                    "[CountryFullScan] Länderfilter=%s, Blöcke=%d, Ziele=%d%n",
                    filterEnabled ? wanted : "ALLE",
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

        List<HostPort> buildRandomSampleTargets(List<Integer> ports) {
            List<HostPort> out = new ArrayList<>();
            if (randomSampleCount <= 0) return out;

            if (!randomIpPoolFromCsv.isEmpty()) {
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

            if (countryDb == null && asnDb == null && cityDb == null) {
                System.err.println("[RandomSample] Keine GeoIP-DB geladen – Zufallsstichprobe wird übersprungen.");
                return out;
            }

            int maxAttempts = randomSampleCount * 2000;
            int attempts = 0;

            while (out.size() < randomSampleCount && attempts < maxAttempts) {
                attempts++;
                String ip = (sampleFromCidr != null)
                        ? randomIpInCidr(sampleFromCidr)
                        : randomGlobalIp();
                if (ip == null) continue;

                if (!looksGlobalUnicast(ip)) {
                    continue;
                }

                InetAddress addr;
                try {
                    addr = InetAddress.getByName(ip);
                } catch (Exception e) {
                    if (debug) {
                        System.err.println("[RandomSample-DNS] " + ip + " -> " + e.getMessage());
                    }
                    continue;
                }

                if (!hasAnyGeoRecord(addr)) {
                    continue;
                }

                if (!passesGeoFilters(addr)) {
                    continue;
                }

                for (int p : ports) {
                    out.add(new HostPort(ip, p));
                }
            }

            System.out.printf(Locale.ROOT,
                    "[RandomSample-Fallback] angefordert=%d, erzeugt=%d, Versuche=%d%n",
                    randomSampleCount, out.size(), attempts);

            return out;
        }

        private boolean hasAnyGeoRecord(InetAddress addr) {
            boolean found = false;
            try {
                if (countryDb != null) {
                    try {
                        countryDb.country(addr);
                        found = true;
                    } catch (AddressNotFoundException ignored) {}
                }
                if (!found && cityDb != null) {
                    try {
                        cityDb.city(addr);
                        found = true;
                    } catch (AddressNotFoundException ignored) {}
                }
                if (!found && asnDb != null) {
                    try {
                        asnDb.asn(addr);
                        found = true;
                    } catch (AddressNotFoundException ignored) {}
                }
            } catch (Exception e) {
                if (debug) {
                    System.err.println("[GeoIP-hasAny] " + addr.getHostAddress() + " -> " + e.getMessage());
                }
            }
            return found;
        }

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
                    StandardCharsets.UTF_8
            ));

            ExecutorService pool = Executors.newFixedThreadPool(maxConcurrency);
            final AtomicLong processed = new AtomicLong();
            final AtomicLong written = new AtomicLong();
            final Instant start = Instant.now();

            System.out.println("[ActiveScan] Ziele gesamt: " + targets.size() + "  -> " + outputPath);
            System.out.println("[ActiveScan] Parallelität=" + maxConcurrency +
                    ", Timeout=" + connectTimeoutMs + "/" + readTimeoutMs + " ms");

            for (HostPort hp : targets) {
                pool.submit(() -> {
                    try {
                        handleOneTarget(hp.host, hp.port, writer, written);
                    } catch (Exception e) {
                        if (debug) {
                            System.err.println("[ActiveScan] Fehler bei " + hp.host + ":" + hp.port +
                                    " -> " + e.getMessage());
                        }
                    } finally {
                        long p = processed.incrementAndGet();
                        if (p % 100 == 0) {
                            double secs = Math.max(1, Duration.between(start, Instant.now()).toSeconds());
                            double rate = p / secs;
                            System.out.printf(Locale.ROOT,
                                    "\r[ActiveScan] Verarbeitet: %,d  Geschrieben: %,d  (%.2f Ziele/s)",
                                    p, written.get(), rate);
                        }
                    }
                });
            }

            pool.shutdown();
            try {
                pool.awaitTermination(Long.MAX_VALUE, TimeUnit.SECONDS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }

            synchronized (writer) {
                try {
                    writer.flush();
                    writer.close();
                } catch (IOException ignore) {}
            }

            System.out.println();
            System.out.println("[ActiveScan] Fertig. Targets verarbeitet: " + processed.get()
                    + ", JSONL-Zeilen geschrieben: " + written.get());

            if (written.get() == 0) {
                System.out.println("[ActiveScan] Hinweis: Es wurden keine Hosts mit erfolgreichem TLS-Handshake und Zertifikat gefunden.");
            }
        }

        private void handleOneTarget(String host,
                                     int port,
                                     BufferedWriter writer,
                                     AtomicLong written) {

            InetAddress addr;
            try {
                addr = InetAddress.getByName(host);
            } catch (Exception e) {
                if (debug) System.err.println("[DNS] " + host + " -> " + e.getMessage());
                return;
            }

            String ipStr = addr.getHostAddress();

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
                        if (cityResp != null && cityResp.getCity() != null) {
                            cityName = cityResp.getCity().getName();
                        }
                        if (countryIso == null && cityResp != null &&
                                cityResp.getCountry() != null &&
                                cityResp.getCountry().getIsoCode() != null) {
                            countryIso = cityResp.getCountry().getIsoCode().toUpperCase(Locale.ROOT);
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
                if (debug) System.err.println("[GeoIP] " + ipStr + " -> " + e.getMessage());
            }

            if (!allowedCountries.isEmpty()) {
                if (countryIso == null || !allowedCountries.contains(countryIso)) {
                    return;
                }
            }
            if (!allowedAsns.isEmpty()) {
                if (asn == null || !allowedAsns.contains(asn)) {
                    return;
                }
            }
            if (!allowedCities.isEmpty()) {
                if (cityName == null) {
                    return;
                }
                String normCity = cityName.trim().toLowerCase(Locale.ROOT);
                if (!allowedCities.contains(normCity)) {
                    return;
                }
            }

            SSLSocket ssl = null;
            Socket plain = null;

            String protocol = null;
            String cipherSuite = null;
            X509Certificate leaf = null;
            List<String> chainPem = new ArrayList<>();

            try {
                plain = new Socket();
                plain.connect(new InetSocketAddress(addr, port), connectTimeoutMs);
                plain.setSoTimeout(readTimeoutMs);

                SSLSocketFactory factory = (SSLSocketFactory) SSLSocketFactory.getDefault();
                ssl = (SSLSocket) factory.createSocket(plain, host, port, true);

                SSLParameters params = ssl.getSSLParameters();
                if (!isIpv4Literal(host)) {
                    List<SNIHostName> sni = Collections.singletonList(new SNIHostName(host));
                    params.setServerNames(new ArrayList<>(sni));
                }
                ssl.setSSLParameters(params);

                ssl.startHandshake();
                SSLSession session = ssl.getSession();

                protocol = session.getProtocol();
                cipherSuite = session.getCipherSuite();
                Certificate[] chain = session.getPeerCertificates();

                if (chain != null && chain.length > 0) {
                    leaf = (X509Certificate) chain[0];
                    for (Certificate c : chain) {
                        if (c instanceof X509Certificate) {
                            String pem = certToPem((X509Certificate) c);
                            if (pem != null) {
                                chainPem.add(pem);
                            }
                        }
                    }
                }

                if (leaf == null) {
                    return;
                }

            } catch (Exception e) {
                if (debug) {
                    System.err.println("[TLS] " + host + ":" + port + " -> " +
                            e.getClass().getSimpleName() + ": " + e.getMessage());
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

            ObjectNode data = mapper.createObjectNode();
            data.put("ip", ipStr);
            data.put("port", port);
            data.put("hostname", host);
            data.put("tls_version", protocol);
            data.put("cipher_suite", cipherSuite);
            if (countryIso != null) data.put("country_iso", countryIso);
            if (asn != null) data.put("asn", asn);
            if (cityName != null) data.put("city_name", cityName);

            String leafPem = certToPem(leaf);
            if (leafPem != null) {
                ObjectNode leafCertNode = mapper.createObjectNode();
                leafCertNode.put("pem", leafPem);
                data.set("leaf_cert", leafCertNode);
            }

            ArrayNode chainArr = mapper.createArrayNode();
            for (String pem : chainPem) {
                chainArr.add(pem);
            }
            data.set("chain", chainArr);

            ObjectNode root = mapper.createObjectNode();
            root.put("message_type", "active_scan");
            root.set("data", data);

            try {
                String json = mapper.writeValueAsString(root);
                synchronized (writer) {
                    writer.write(json);
                    writer.write("\n");
                }
                written.incrementAndGet();
            } catch (IOException e) {
                if (debug) {
                    System.err.println("[Write] Fehler beim Schreiben für " + host + ":" + port +
                            " -> " + e.getMessage());
                }
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
                    System.err.println("[GeoIP-RandomFilter] " + addr.getHostAddress() +
                            " -> " + e.getMessage());
                }
            }

            if (!allowedCountries.isEmpty()) {
                if (countryIso == null || !allowedCountries.contains(countryIso)) {
                    return false;
                }
            }
            if (!allowedAsns.isEmpty()) {
                if (asn == null || !allowedAsns.contains(asn)) {
                    return false;
                }
            }
            if (!allowedCities.isEmpty()) {
                if (cityName == null) {
                    return false;
                }
                String normCity = cityName.trim().toLowerCase(Locale.ROOT);
                if (!allowedCities.contains(normCity)) {
                    return false;
                }
            }
            return true;
        }

        private String randomGlobalIp() {
            int v = random.nextInt();
            long unsigned = v & 0xFFFFFFFFL;
            long b1 = (unsigned >>> 24) & 0xFF;
            long b2 = (unsigned >>> 16) & 0xFF;
            long b3 = (unsigned >>> 8) & 0xFF;
            long b4 = unsigned & 0xFF;
            return b1 + "." + b2 + "." + b3 + "." + b4;
        }

        private String randomIpInCidr(String cidr) {
            try {
                String[] parts = cidr.trim().split("/");
                if (parts.length != 2) return null;
                String baseIp = parts[0];
                int prefix = Integer.parseInt(parts[1]);
                if (prefix < 0 || prefix > 32) return null;

                String[] octets = baseIp.split("\\.");
                if (octets.length != 4) return null;
                long b1 = Long.parseLong(octets[0]);
                long b2 = Long.parseLong(octets[1]);
                long b3 = Long.parseLong(octets[2]);
                long b4 = Long.parseLong(octets[3]);

                long base = (b1 << 24) | (b2 << 16) | (b3 << 8) | b4;
                int hostBits = 32 - prefix;
                long hostMask = hostBits == 32 ? 0xFFFFFFFFL : ((1L << hostBits) - 1);
                long randHost = (long) (random.nextDouble() * (hostMask + 1));
                long ip = (base & ~hostMask) | (randHost & hostMask);

                return toIp(ip);
            } catch (Exception e) {
                if (debug) {
                    System.err.println("[CIDR] Fehler beim Generieren aus " + cidr + ": " + e.getMessage());
                }
                return null;
            }
        }

        private String certToPem(X509Certificate cert) {
            try {
                byte[] der = cert.getEncoded();
                String b64 = Base64.getEncoder().encodeToString(der);
                StringBuilder sb = new StringBuilder();
                sb.append("-----BEGIN CERTIFICATE-----\n");
                for (int i = 0; i < b64.length(); i += 64) {
                    int end = Math.min(i + 64, b64.length());
                    sb.append(b64, i, end).append("\n");
                }
                sb.append("-----END CERTIFICATE-----\n");
                return sb.toString();
            } catch (CertificateEncodingException e) {
                if (debug) {
                    System.err.println("[PEM] Encoding-Fehler: " + e.getMessage());
                }
                return null;
            }
        }
    }
}
