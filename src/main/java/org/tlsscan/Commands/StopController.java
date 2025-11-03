package org.tlsscan.Commands;

import java.io.BufferedReader;
import java.io.InputStreamReader;

/** Liest "q" + Enter und fängt Strg+C via ShutdownHook ab. */
public class StopController {

    public static CancelToken install(String prompt) {
        CancelToken token = new CancelToken();

        if (prompt != null && !prompt.isBlank()) {
            System.out.println(prompt);
        }

        Runtime.getRuntime().addShutdownHook(new Thread(token::cancel, "shutdown-cancel"));

        Thread t = new Thread(() -> {
            try (BufferedReader br = new BufferedReader(new InputStreamReader(System.in))) {
                String line;
                while (!token.isCancelled() && (line = br.readLine()) != null) {
                    line = line.trim().toLowerCase();
                    if (line.equals("q") || line.equals("quit") || line.equals("exit")) {
                        token.cancel();
                        break;
                    }
                }
            } catch (Exception ignored) {}
        }, "cancel-listener");
        t.setDaemon(true);
        t.start();

        return token;
    }
}
