package at.farfeleder.localupload;

import java.time.LocalTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.regex.Pattern;

/** A per-run Python sink backed by one bounded, process-local event buffer. */
public final class ActivityLog {
    static final int LIMIT = 200;
    static final int MESSAGE_LIMIT = 1024;
    private static final DateTimeFormatter TIME = DateTimeFormatter.ofPattern("HH:mm:ss", Locale.ROOT);
    private static final Pattern URI = Pattern.compile("(?i)(?:https?://|content://)\\S+");
    private static final ArrayDeque<String> EVENTS = new ArrayDeque<>();
    private static final List<Runnable> LISTENERS = new ArrayList<>();
    private final String secret;
    private boolean active = true;

    public ActivityLog(String secret) {
        this.secret = secret;
    }

    // Public for Chaquopy; each instance retains its own run's secret during shutdown.
    public void log(String message) {
        String value = message == null ? "" : message;
        if (secret != null && !secret.isEmpty()) value = value.replace(secret, "[hidden]");
        value = URI.matcher(value).replaceAll("[uri hidden]");
        StringBuilder clean = new StringBuilder(Math.min(value.length(), MESSAGE_LIMIT));
        for (int index = 0; index < value.length() && clean.length() < MESSAGE_LIMIT;) {
            int point = value.codePointAt(index);
            index += Character.charCount(point);
            if (Character.isISOControl(point) || Character.getType(point) == Character.FORMAT
                    || point == 0x2028 || point == 0x2029) point = ' ';
            if (clean.length() + Character.charCount(point) > MESSAGE_LIMIT) break;
            clean.appendCodePoint(point);
        }
        List<Runnable> listeners;
        synchronized (ActivityLog.class) {
            if (!active) return;
            while (EVENTS.size() >= LIMIT) EVENTS.removeFirst();
            EVENTS.addLast(LocalTime.now().format(TIME) + " " + clean);
            listeners = new ArrayList<>(LISTENERS);
        }
        for (Runnable listener : listeners) listener.run();
    }

    void close() {
        synchronized (ActivityLog.class) {
            active = false;
        }
    }

    static synchronized List<String> entries() {
        return new ArrayList<>(EVENTS);
    }

    static synchronized String latest() {
        return EVENTS.peekLast();
    }

    static void clear() {
        List<Runnable> listeners;
        synchronized (ActivityLog.class) {
            EVENTS.clear();
            listeners = new ArrayList<>(LISTENERS);
        }
        for (Runnable listener : listeners) listener.run();
    }

    static synchronized void addListener(Runnable listener) {
        LISTENERS.add(listener);
    }

    static synchronized void removeListener(Runnable listener) {
        LISTENERS.remove(listener);
    }
}
