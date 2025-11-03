package org.tlsscan.Commands;

import java.util.concurrent.atomic.AtomicBoolean;

public class CancelToken {
    private final AtomicBoolean cancelled = new AtomicBoolean(false);
    public void cancel() { cancelled.set(true); }
    public boolean isCancelled() { return cancelled.get(); }
}
