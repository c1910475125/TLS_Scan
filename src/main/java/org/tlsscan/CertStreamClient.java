package org.tlsscan;

import com.google.gson.Gson;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import io.calidog.certstream.CertStream;

import java.io.BufferedWriter;
import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.time.*;
import java.time.format.DateTimeFormatter;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;

/**
 * CT-Stream-Client gemäß README-Beispiel:
 * - CertStream.onMessageString(System.out::println)   -> bei uns: Schreiben ins File + CLI-Echo
 * - CertStream.onMessage(msg -> System.out.println(new Gson().toJson(msg))) -> optionales Debug-Echo
 *
 * Stoppt logisch über durationSeconds / maxEvents (die Lib bietet kein explizites close()).
 */
public class CertStreamClient {

    private static final DateTimeFormatter TS = DateTimeFormatter.ofPattern("uuuu-MM-dd HH:mm:ss")
            .withZone(ZoneId.systemDefault());

    private final Path outputPath;
    private final boolean certOnly;
    private final long durationSeconds;
    private final long maxEvents;
    private final boolean debug;
    private final boolean progress;

    private final Gson gson = new Gson();

    public CertStreamClient(Path outputPath,
                            boolean certOnly,
                            long durationSeconds,
                            long maxEvents,
                            boolean debug,
                            boolean progress) {
        this.outputPath = Objects.requireNonNull(outputPath);
        this.certOnly = certOnly;
        this.durationSeconds = Math.max(0, durationSeconds);
        this.maxEvents = Math.max(0, maxEvents);
        this.debug = debug;
        this.progress = progress;
    }

    public void run() {
        try {
            Path dir = outputPath.getParent();
            if (dir != null && !Files.exists(dir)) Files.createDirectories(dir);
        } catch (IOException ioe) {
            System.err.println("Konnte Zielordner nicht anlegen: " + ioe.getMessage());
            return;
        }

        final long deadlineMillis = (durationSeconds > 0)
                ? System.currentTimeMillis() + durationSeconds * 1000L
                : Long.MAX_VALUE;

        final AtomicLong eventCount   = new AtomicLong(0);
        final AtomicLong bytesWritten = new AtomicLong(0);
        final AtomicBoolean stopped   = new AtomicBoolean(false);

        System.out.println("CT-Stream starten … Ausgabe: " + outputPath);

        try (BufferedWriter bw = new BufferedWriter(
                new OutputStreamWriter(new FileOutputStream(outputPath.toFile(), true), StandardCharsets.UTF_8))) {

            // 1) README-Variante: onMessageString(System.out::println)
            //    -> wir schreiben die Zeile ins File und zeigen sie parallel im CLI (gekürzt)
            CertStream.onMessageString((String msg) -> {
                if (stopped.get()) return;
                try {
                    long n = eventCount.incrementAndGet();

                    // ggf. auf "certOnly" eindampfen (nur message_type + data)
                    String toWrite;
                    if (certOnly) {
                        JsonObject j = JsonParser.parseString(msg).getAsJsonObject();
                        JsonObject slim = new JsonObject();
                        slim.add("message_type", j.get("message_type"));
                        slim.add("data", j.get("data"));
                        toWrite = slim.toString();
                    } else {
                        toWrite = msg;
                    }

                    // ins File
                    bw.write(toWrite);
                    bw.newLine();
                    bw.flush();
                    bytesWritten.addAndGet(toWrite.length() + 1);

                    // paralleles CLI-"Tail"
                    if (progress) {
                        String preview = toWrite.length() > 200 ? toWrite.substring(0, 200) + " …" : toWrite;
                        System.out.printf("\r[CT] #%d @ %s  -> %s%n", n, TS.format(Instant.now()), preview);
                    }

                    // Stop-Bedingungen
                    if ((maxEvents > 0 && n >= maxEvents) || (System.currentTimeMillis() >= deadlineMillis)) {
                        stopped.set(true);
                        System.out.println("\nStop-Bedingung erreicht – beende Aufnahme …");
                    }
                } catch (Exception e) {
                    System.err.println("Fehler beim Verarbeiten/Schreiben: " + e.getMessage());
                }
            });

            // 2) README-Variante: getyptes Debug-Echo über Gson (optional)
            if (debug) {
                CertStream.onMessage(msg -> {
                    if (stopped.get()) return;
                    try {
                        String pretty = gson.toJson(msg);
                        System.out.println("[DBG] " + pretty);
                    } catch (Exception ignore) {
                        // Debug-Output darf Fehler ignorieren
                    }
                });
            }

            // main wait-loop, bis logisch gestoppt
            while (!stopped.get()
                    && System.currentTimeMillis() < deadlineMillis
                    && (maxEvents == 0 || eventCount.get() < maxEvents)) {
                try { Thread.sleep(200); } catch (InterruptedException ie) { break; }
            }

        } catch (Exception e) {
            System.err.println("Fehler im CertStreamClient: " + e.getMessage());
        }

        System.out.println("\nCT-Stream beendet. Events: " + (eventCount.get()) + "  Datei: " + outputPath);
    }
}
