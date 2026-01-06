# TLS_Scan (TLS Research Platform Prototype)

This repository contains a Java-based prototype for **scope-based / Internet-wide TLS measurements** and subsequent **analysis**.

The application exposes an interactive menu with five modules:

1. **Active TLS Scan** (explicit targets / ranges) → writes **JSONL** raw scan results
2. **GeoLite Scan** (Country / City / ASN) → writes **JSONL** raw scan results based on GeoLite-derived scopes
3. **Analyze JSONL** → prints aggregated metrics and can export a compact **summary JSON**
4. **TrustStore Scoring** → evaluates a trust store / keystore and derives **trust scores**
5. **Compare Scans** → compares two scan runs and outputs a **diff/summary**

---

## Platform Support (Important)

⚠️ **Windows only**: The scanning functionality is integrated with **zgrab2 via a Windows `.exe`**.

Therefore, the application is currently intended to be run on **Windows** (unless you replace the binary and adapt the code/config accordingly).

---

## Requirements

- **Windows 10/11**
- **Java 17+**
- **Maven 3.8+**
- GeoLite2 data from MaxMind (see Setup)

---

## Setup

### 1) Clone the repository

```bash
git clone <https://github.com/c1910475125/TLS_Scan>
cd TLS_Scan

```

### 2) Download GeoLite2 (MaxMind) Databases and place them into `TLS_Scan/GeoIP`

Download GeoLite2 DBs from MaxMind (available for free, account + license acceptance required):

- GeoLite ASN mmdb and CSV
- GeoLite City mmdb and CSV
- GeoLite Country mmdb and CSV
https://www.maxmind.com/en/geolite-free-ip-geolocation-data

Create the folder (if it does not exist yet):

```bash
mkdir -p GeoIP

```

Then place the downloaded files into:

- Windows-style path: `\\TLS_Scan\\GeoIP`
- Repo-relative path: `TLS_Scan/GeoIP/`

Recommended files:

**MMDB (used for lookups):**

- `GeoLite2-Country.mmdb`
- `GeoLite2-ASN.mmdb`
- `GeoLite2-City.mmdb` *(optional; only needed for City-based functions)*

**CSV (used for scope generation / sampling where applicable):**

- `GeoLite2-Country-Blocks-IPv4.csv`
- `GeoLite2-Country-Locations-en.csv`
- `GeoLite2-ASN-Blocks-IPv4.csv`
- `GeoLite2-City-Blocks-IPv4.csv` *(optional)*
- `GeoLite2-City-Locations-en.csv` *(optional)*

> Note: This repository does not redistribute GeoLite data.
> 

### 3) zgrab2 executable (Windows)

The application calls **zgrab2** as an external scanner binary (Windows `.exe`).

Ensure the repository contains the expected binary under `\TLS_Scan\bin\zgrab2.exe` , if you moved the executable, update the corresponding path in the configuration/code.

---

## Build (Compile)

Compile the project with Maven:

```bash
mvn clean compile

```

---

## Run (Execute `main.java`)

This project is executed via its **`main` class**.

### Option A: Run from an IDE (recommended)

1. Open the project in **IntelliJ IDEA** (or Eclipse)
2. Import as **Maven** project
3. Locate `main.java` (the project’s entry point)
4. Run `main.java`

### Option B: Run with Maven Exec Plugin (if configured)

If the Maven Exec Plugin is configured in `pom.xml`, you can run the main class from the command line:

```bash
mvn exec:java -Dexec.mainClass="<FULLY_QUALIFIED_MAIN_CLASS>"

```

Replace `<FULLY_QUALIFIED_MAIN_CLASS>` with the package + class name of your entry point, e.g.:

```bash
mvn exec:java -Dexec.mainClass="com.example.Main"

```

If you are unsure about the main class name, search for `public static void main(String[] args)` in the project.

---

## Modules (Details)

### 1) Active TLS Scan

Scan explicit targets such as:

- hostnames (e.g., `google.com`)
- IP addresses (e.g., `1.2.3.4`)
- CIDR ranges (e.g., `10.0.0.0/24`)

**Output:** `*.jsonl` (JSON Lines)

### 2) GeoLite Scan (Country / City / ASN)

Derives scan scopes from GeoLite2 data and performs scanning based on:

- **Country**
- **City** *(optional; requires City GeoLite2 data)*
- **ASN**

**Requires:** GeoLite2 files in `TLS_Scan/GeoIP/`

**Output:** `*.jsonl` (JSON Lines)

### 3) Analyze JSONL

Reads a scan output (`.jsonl`) and produces aggregated metrics.

Optionally exports a compact summary JSON for downstream tooling.

**Input:** `*.jsonl`

**Output:** console metrics + optional `*_summary.json`

### 4) TrustStore Scoring

Loads a trust store / keystore (Root CA store) and derives trust scores for certificates.

**Input:** keystore / trust store file

**Output:** score summary (JSON) and/or console output (depending on configuration)

### 5) Compare Scans

Compares two scan runs (e.g., different points in time or different scopes) and produces a diff/summary.

**Input:** two `*.jsonl` files

**Output:** diff/summary export (JSON) and/or console output (depending on configuration)

---

## Output & Folder Structure (Typical)

The exact filenames depend on your module inputs and menu choices.

- `Scanfiles/`
    
    Scan outputs and (optional) derived summaries:
    
    - `.jsonl` (raw scan results)
    - `_summary.json` (optional compact summaries)
    
    Furthermore, place trust store / keystore files here for TrustStore scoring.
    
- `GeoIP/`
    
    GeoLite2 MMDB/CSV files (see Setup).
    

---

## Recommended Workflow (Pipeline)

1. Run **Module 1** (explicit scope) or **Module 2** (GeoLite-derived scope) → generate `.jsonl`
2. Run **Module 3** on the JSONL → derive metrics + optional `_summary.json`
3. *(Optional)* Run **Module 4** → trust store scoring / trust score export
4. *(Optional)* Run **Module 5** → compare two scans and export diff/summary

---

## Troubleshooting

### GeoLite files not found

- Verify the folder is exactly `TLS_Scan/GeoIP/`
- Verify filenames match exactly

### zgrab2 issues

- Verify the `.exe` exists and is accessible
- Verify the configured path to the `.exe` matches your repo layout

### Build issues

- Ensure `java -version` shows Java **17+**
- Ensure `mvn -version` is available and uses the expected JDK

---

## Notes

- GeoLite2 is provided by MaxMind under its own license terms.
