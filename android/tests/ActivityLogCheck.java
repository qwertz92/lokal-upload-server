package at.farfeleder.localupload;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

public final class ActivityLogCheck {
    private ActivityLogCheck() {}

    public static void main(String[] args) throws InterruptedException {
        ActivityLog.clear();
        ActivityLog plain = new ActivityLog(null);
        AtomicInteger changes = new AtomicInteger();
        Runnable listener = changes::incrementAndGet;
        ActivityLog.addListener(listener);
        plain.log("START\nclient\r\t\u0000\u2028\u2029\u202e Grüße 東京");
        String sanitized = ActivityLog.latest();
        assert sanitized != null && sanitized.matches("\\d{2}:\\d{2}:\\d{2} .*Grüße 東京") : sanitized;
        assert sanitized.chars().noneMatch(c -> Character.isISOControl(c)
                || Character.getType(c) == Character.FORMAT || c == 0x2028 || c == 0x2029) : sanitized;
        assert changes.get() == 1;
        ActivityLog.removeListener(listener);
        plain.log("x".repeat(5000));
        assert ActivityLog.latest().length() == 9 + 1024 : "Message bound must remain 1024 characters";
        assert changes.get() == 1 : "Stopped activity must not receive later events";
        plain.log("x".repeat(1023) + "😀");
        assert ActivityLog.latest().length() == 9 + 1023 : "Do not split a surrogate pair";
        String oldSecret = "OLD_PRIVATE_CAPABILITY";
        ActivityLog oldRun = new ActivityLog(oldSecret);
        ActivityLog newRun = new ActivityLog("NEW_PRIVATE_CAPABILITY");
        newRun.log("New run started");
        oldRun.log("Shutdown " + oldSecret);
        assert ActivityLog.latest().endsWith("Shutdown [hidden]") : "Sink must retain the old run's secret";
        oldRun.log("x".repeat(1018) + oldSecret);
        assert !ActivityLog.latest().contains("OLD_") : "Redact before truncating a secret at the boundary";
        for (String uri : List.of("http://192.168.1.4:8040/private/", "HTTPS://example.test/a?secret=x",
                "content://local.provider/tree/primary%3ADocuments")) {
            oldRun.log("Error opening " + uri + " failed");
            assert ActivityLog.latest().endsWith("Error opening [uri hidden] failed") : ActivityLog.latest();
            oldRun.log("x".repeat(1018) + uri);
            assert !ActivityLog.latest().contains(uri.substring(0, 6)) : "Mask URI before truncation";
        }
        oldRun.close();
        String beforeClosed = ActivityLog.latest();
        oldRun.log("Late event after this run closed");
        assert ActivityLog.latest().equals(beforeClosed) : "Closed run must not append stale events";
        ActivityLog.clear();
        for (int index = 0; index < 250; index++) plain.log("event " + index);
        List<String> bounded = ActivityLog.entries();
        assert bounded.size() == 200 : "Buffer must evict oldest events";
        assert bounded.get(0).endsWith("event 50") && bounded.get(199).endsWith("event 249");
        bounded.clear();
        assert ActivityLog.entries().size() == 200 : "Readers must receive independent snapshots";

        AtomicReference<Throwable> failure = new AtomicReference<>();
        List<Thread> threads = new ArrayList<>();
        for (int worker = 0; worker < 8; worker++) {
            int id = worker;
            threads.add(new Thread(() -> {
                try {
                    for (int event = 0; event < 250; event++) {
                        plain.log("worker " + id + " event " + event);
                        List<String> snapshot = ActivityLog.entries();
                        assert snapshot.size() <= 200;
                        assert snapshot.stream().allMatch(value -> value != null && value.length() >= 9
                                && value.charAt(2) == ':' && value.charAt(5) == ':');
                    }
                } catch (Throwable error) {
                    failure.compareAndSet(null, error);
                }
            }, "log-check-" + id));
        }
        for (Thread thread : threads) thread.start();
        for (Thread thread : threads) thread.join();
        assert failure.get() == null : failure.get();
        assert ActivityLog.entries().size() == 200;
        ActivityLog.clear();
        assert ActivityLog.entries().isEmpty() && ActivityLog.latest() == null;
        System.out.println("Activity log bounds, sanitization, redaction and concurrency checks passed");
    }
}
