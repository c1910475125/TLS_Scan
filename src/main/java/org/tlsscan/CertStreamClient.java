package org.tlsscan;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.io.*;
import java.net.ProxySelector;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.WebSocket;
import java.net.http.WebSocket.Listener;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.Objects;
import java.util.Timer;
import java.util.TimerTask;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicLong;

public class CertStreamClient {

    private static final DateTimeFormatter TS = DateTimeFormatter.ofPattern("uuuu-MM-dd HH:mm:ss")
            .withZone(ZoneId.systemDefault());

    private final Path outputPath;
    private final boolean certOnly;
    private final int reconnectDelaySeconds;
    private final long durationSeconds;
    private final long maxEvents;
    private final boolean debug;
    private final boolean progress;
    private final String endpointUrl;
    private final ObjectMapper mapper = new ObjectMapper();

    public CertStreamClient(Path outputPath,
                            boolean certOnly,
                            int reconnectDelaySeconds,
                            long durationSeconds,
                            long maxEvents,
                            boolean debug,
                            boolean progress,
                            String endpointUrl) {
        this.outputPath = Objects.requireNonNull(outputPath);
        this.certOnly = certOnly;
        this.reconnectDelaySeconds = Math.max(1, reconnectDelaySeconds);
        this.durationSeconds = Math.max(0, durationSeconds);
        this.maxEvents = Math.max(0, maxEvents);
        this.debug = debug;
        this.progress = progress;
        this.endpointUrl = endpointUrl != null ? endpointUrl : "wss://certstream.calidog.io/";
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

        final AtomicLong eventCount = new AtomicLong(0);
        final AtomicLong bytesWritten = new AtomicLong(0);
        final AtomicLong lastMsgMillis = new AtomicLong(0);

        ScheduledExecutorService ticker = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "progress");
            t.setDaemon(true);
            return t;
        });

        while (true) {
            if (System.currentTimeMillis() >= deadlineMillis) break;

            CountDownLatch done = new CountDownLatch(1);
            Timer pingTimer = new Timer("ws-ping", true);
            Instant start = Instant.now();

            try (BufferedWriter bw = new BufferedWriter(
                    new OutputStreamWriter(new FileOutputStream(outputPath.toFile(), true), StandardCharsets.UTF_8))) {

                if (progress) {
                    ticker.scheduleAtFixedRate(() -> {
                        long ev = eventCount.get();
                        long b = bytesWritten.get();
                        long last = lastMsgMillis.get();
                        double secs = Math.max(1, Duration.between(start, Instant.now()).toSeconds());
                        double eps = ev / secs;
                        String lastStr = last == 0 ? "-" : TS.format(Instant.ofEpochMilli(last));
                        String line = String.format(
                                "\r[WS] Events: %,d  (%.2f/s)  Bytes: %,d  Last: %s  File: %s",
                                ev, eps, b, lastStr, outputPath);
                        System.out.print(line);
                    }, 0, 1000, TimeUnit.MILLISECONDS);
                }

                HttpClient client = HttpClient.newBuilder()
                        .connectTimeout(Duration.ofSeconds(20))
                        .proxy(ProxySelector.getDefault())
                        .build();

                if (debug) System.out.println("\nVerbinde zu: " + endpointUrl);

                WebSocket ws = client.newWebSocketBuilder()
                        .connectTimeout(Duration.ofSeconds(20))
                        .header("User-Agent", "passive-cert-analyzer/0.3.4 (Java)")
                        .header("Origin", endpointUrl.startsWith("ws") ? endpointUrl : "https://certstream.calidog.io")
                        .buildAsync(URI.create(endpointUrl), new Listener() {

                            private final StringBuilder textBuf = new StringBuilder();

                            @Override
                            public void onOpen(WebSocket webSocket) {
                                System.out.println("\nVerbunden. Schreibe nach: " + outputPath);
                                webSocket.request(1);
                                pingTimer.scheduleAtFixedRate(new TimerTask() {
                                    @Override public void run() {
                                        try { webSocket.sendPing(ByteBuffer.wrap(new byte[]{0x01})); }
                                        catch (Exception ignored) {}
                                    }
                                }, 30000, 30000);
                                Listener.super.onOpen(webSocket);
                            }

                            @Override
                            public CompletionStage<?> onText(WebSocket webSocket, CharSequence data, boolean last) {
                                try {
                                    textBuf.append(data);
                                    if (last) {
                                        String msg = textBuf.toString();
                                        textBuf.setLength(0);

                                        if (System.currentTimeMillis() >= deadlineMillis) {
                                            safeClose(webSocket, "time-limit");
                                            done.countDown();
                                            return completed();
                                        }

                                        int wrote = handleMessage(msg, bw);
                                        long n = eventCount.incrementAndGet();
                                        bytesWritten.addAndGet(wrote + 1);
                                        lastMsgMillis.set(System.currentTimeMillis());

                                        if (debug && n <= 5) {
                                            System.out.println("\n[DBG] onText #" + n + " len=" + msg.length());
                                        }
                                        if (maxEvents > 0 && n >= maxEvents) {
                                            safeClose(webSocket, "max-events");
                                            done.countDown();
                                            return completed();
                                        }
                                    }
                                } catch (Exception e) {
                                    System.err.println("\nFehler onText: " + e.getMessage());
                                } finally {
                                    webSocket.request(1);
                                }
                                return completed();
                            }

                            @Override
                            public CompletionStage<?> onBinary(WebSocket webSocket, ByteBuffer data, boolean last) {
                                try {
                                    byte[] bytes = new byte[data.remaining()];
                                    data.get(bytes);
                                    String msg = new String(bytes, StandardCharsets.UTF_8);

                                    if (System.currentTimeMillis() >= deadlineMillis) {
                                        safeClose(webSocket, "time-limit");
                                        done.countDown();
                                        return completed();
                                    }

                                    int wrote = handleMessage(msg, bw);
                                    long n = eventCount.incrementAndGet();
                                    bytesWritten.addAndGet(wrote + 1);
                                    lastMsgMillis.set(System.currentTimeMillis());

                                    if (debug && n <= 5) {
                                        System.out.println("\n[DBG] onBinary #" + n + " len=" + msg.length());
                                    }
                                    if (maxEvents > 0 && n >= maxEvents) {
                                        safeClose(webSocket, "max-events");
                                        done.countDown();
                                        return completed();
                                    }
                                } catch (Exception e) {
                                    System.err.println("\nFehler onBinary: " + e.getMessage());
                                } finally {
                                    webSocket.request(1);
                                }
                                return completed();
                            }

                            @Override
                            public CompletionStage<?> onClose(WebSocket webSocket, int statusCode, String reason) {
                                System.out.println("\nWebSocket geschlossen: " + statusCode + " (" + reason + ")");
                                try { bw.flush(); } catch (IOException ignored) {}
                                done.countDown();
                                return completed();
                            }

                            @Override
                            public void onError(WebSocket webSocket, Throwable error) {
                                System.err.println("\nWebSocket-Fehler: " + error.getMessage());
                                try { bw.flush(); } catch (IOException ignored) {}
                                done.countDown();
                            }

                            private CompletionStage<Void> completed() { return CompletableFuture.completedFuture(null); }
                            private void safeClose(WebSocket ws, String reason) { try { ws.sendClose(WebSocket.NORMAL_CLOSURE, reason); } catch (Exception ignored) {} }
                        }).join();

                done.await();
                try { ws.abort(); } catch (Exception ignored) {}
            } catch (InterruptedException ie) {
                System.out.println("\nAbbruch erkannt, beende.");
                break;
            } catch (Exception e) {
                System.err.println("\nVerbindungs-/I/O-Fehler: " + e.getMessage());
            } finally {
                if (progress) System.out.print("\r");
            }

            if (System.currentTimeMillis() >= deadlineMillis) break;

            System.out.println("Re-Connect in " + reconnectDelaySeconds + "s …");
            try { Thread.sleep(reconnectDelaySeconds * 1000L); } catch (InterruptedException ie) { break; }
        }

        if (progress) System.out.printf("WS-Stream beendet. Events geschrieben: %,d  Datei: %s%n",
                eventCount.get(), outputPath);
    }

    private int handleMessage(String text, BufferedWriter bw) throws IOException {
        if (text == null || text.isBlank()) return 0;
        String out;
        JsonNode n = mapper.readTree(text);
        if (certOnly) {
            ObjectNode obj = new ObjectMapper().createObjectNode();
            obj.set("message_type", n.get("message_type"));
            obj.set("data", n.get("data"));
            out = obj.toString();
        } else {
            out = n.toString();
        }
        bw.write(out);
        bw.write("\n");
        bw.flush();
        return out.length();
    }
}
