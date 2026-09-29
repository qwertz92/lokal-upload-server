package at.farfeleder.localupload;

import android.Manifest;
import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.app.Service;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.content.pm.ServiceInfo;
import android.graphics.drawable.Icon;
import android.net.ConnectivityManager;
import android.net.LinkAddress;
import android.net.LinkProperties;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.net.NetworkRequest;
import android.os.Build;
import android.os.Handler;
import android.os.IBinder;
import android.os.Looper;
import android.os.PowerManager;

import com.chaquo.python.Python;
import com.chaquo.python.android.AndroidPlatform;

import java.net.Inet4Address;
import java.net.InetAddress;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeSet;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public final class UploadService extends Service {
    static final String ACTION_START = "at.farfeleder.localupload.START";
    static final String ACTION_STOP = "at.farfeleder.localupload.STOP";
    static final String PREFERENCES = "upload";
    static final String FOLDER_KEY = "folder";
    static final String PRIVACY_KEY = "privacy";
    static final int STOPPED = 0;
    static final int STARTING = 1;
    static final int RUNNING = 2;
    static final int STOPPING = 3;
    static final int ERROR = 4;
    private static final String CHANNEL = "local_upload";
    private static final int NOTIFICATION = 1;
    private static final long WAKE_TIMEOUT_MS = 10 * 60 * 1000L;
    // One Python runtime per process; serialization also covers a destroyed service's cleanup.
    private static final ExecutorService PYTHON = Executors.newSingleThreadExecutor();
    private static final List<Runnable> LISTENERS = new ArrayList<>();
    private static Snapshot snapshot = new Snapshot(STOPPED, Collections.emptyList(), null);
    private static UploadService owner;

    static final class Snapshot {
        final int state;
        final List<String> urls;
        final String error;

        Snapshot(int state, List<String> urls, String error) {
            this.state = state;
            this.urls = Collections.unmodifiableList(new ArrayList<>(urls));
            this.error = error;
        }

        boolean active() {
            return state == STARTING || state == RUNNING || state == STOPPING;
        }
    }

    static Snapshot snapshot() {
        return snapshot;
    }

    static void addListener(Runnable listener) {
        LISTENERS.add(listener);
    }

    static void removeListener(Runnable listener) {
        LISTENERS.remove(listener);
    }

    private final Handler main = new Handler(Looper.getMainLooper());
    private final RunState commands = new RunState();
    private final Map<Network, LinkProperties> networks = new LinkedHashMap<>();
    private ConnectivityManager connectivity;
    private PowerManager.WakeLock wakeLock;
    private boolean destroyed;
    private boolean callbackRegistered;
    private String token;
    private ActivityLog activityLog = new ActivityLog(null);
    private int port;
    private int lastStartId;

    private final Runnable renewWakeLock = new Runnable() {
        @Override public void run() {
            if (!destroyed && commands.shouldRun()) {
                wakeLock.acquire(WAKE_TIMEOUT_MS);
                main.postDelayed(this, WAKE_TIMEOUT_MS / 2);
            }
        }
    };

    private final ConnectivityManager.NetworkCallback networkCallback =
            new ConnectivityManager.NetworkCallback() {
        @Override public void onAvailable(Network network) {
            updateNetwork(network, connectivity.getLinkProperties(network));
        }

        @Override public void onCapabilitiesChanged(Network network, NetworkCapabilities capabilities) {
            updateNetwork(network, connectivity.getLinkProperties(network));
        }

        @Override public void onLinkPropertiesChanged(Network network, LinkProperties properties) {
            updateNetwork(network, properties);
        }

        @Override public void onLost(Network network) {
            networks.remove(network);
            publishNetwork();
        }
    };

    @Override public void onCreate() {
        super.onCreate();
        owner = this;
        connectivity = getSystemService(ConnectivityManager.class);
        wakeLock = getSystemService(PowerManager.class).newWakeLock(
                PowerManager.PARTIAL_WAKE_LOCK, "LocalUpload:server");
        wakeLock.setReferenceCounted(false);
        getSystemService(NotificationManager.class).createNotificationChannel(new NotificationChannel(
                CHANNEL, getString(R.string.notification_channel), NotificationManager.IMPORTANCE_LOW));
        NetworkRequest request = new NetworkRequest.Builder()
                .addTransportType(NetworkCapabilities.TRANSPORT_WIFI)
                .addTransportType(NetworkCapabilities.TRANSPORT_ETHERNET)
                .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
                .build();
        connectivity.registerNetworkCallback(request, networkCallback, main);
        callbackRegistered = true;
    }

    @Override public int onStartCommand(Intent intent, int flags, int startId) {
        lastStartId = startId;
        if (intent != null && ACTION_START.equals(intent.getAction())) {
            startServer();
        } else {
            stopServer();
        }
        return START_NOT_STICKY;
    }

    private void startServer() {
        long command = commands.start();
        if (command == -1) return;
        String tree = getSharedPreferences(PREFERENCES, MODE_PRIVATE).getString(FOLDER_KEY, null);
        if (tree == null) {
            fail(getString(R.string.folder_missing));
            return;
        }
        if (Build.VERSION.SDK_INT >= 37 && checkSelfPermission(Manifest.permission.ACCESS_LOCAL_NETWORK)
                != PackageManager.PERMISSION_GRANTED) {
            fail(getString(R.string.network_permission_required));
            return;
        }
        token = null;
        if (getSharedPreferences(PREFERENCES, MODE_PRIVATE).getBoolean(PRIVACY_KEY, false)) {
            byte[] random = new byte[24];
            new SecureRandom().nextBytes(random);
            token = Base64.getUrlEncoder().withoutPadding().encodeToString(random);
        }
        String runToken = token;
        ActivityLog previousLog = activityLog;
        ActivityLog runLog = new ActivityLog(runToken);
        activityLog = runLog;
        runLog.log("Server starting (" + (runToken == null ? "normal mode" : "privacy mode") + ")");
        publish(STARTING, null);
        try {
            if (Build.VERSION.SDK_INT >= 29) {
                startForeground(NOTIFICATION, notification(),
                        ServiceInfo.FOREGROUND_SERVICE_TYPE_CONNECTED_DEVICE);
            } else {
                startForeground(NOTIFICATION, notification());
            }
            main.removeCallbacks(renewWakeLock);
            renewWakeLock.run();
        } catch (RuntimeException failure) {
            fail(message(failure, runToken));
            return;
        }
        PYTHON.execute(() -> {
            int actualPort = 0;
            String error = null;
            try {
                if (!Python.isStarted()) Python.start(new AndroidPlatform(getApplicationContext()));
                Python.getInstance().getModule("android_server").callAttr("stop");
                previousLog.close();
                SafStorage storage = new SafStorage(getApplicationContext(), tree);
                storage.validate();
                actualPort = Python.getInstance().getModule("android_server")
                        .callAttr("start", storage, runToken, 8040, runLog).toInt();
                if (actualPort < 1 || actualPort > 65535) {
                    throw new IllegalStateException("The server returned an invalid port");
                }
            } catch (Exception failure) {
                error = message(failure, runToken);
                String cleanupError = stopPython(runToken);
                if (cleanupError != null) error += "\n" + cleanupError;
            } finally {
                previousLog.close();
            }
            int resultPort = actualPort;
            String resultError = error;
            main.post(() -> {
                if (!current(command)) return;
                if (resultError != null) {
                    fail(resultError);
                } else {
                    port = resultPort;
                    runLog.log("Server running on port " + resultPort);
                    publish(RUNNING, null);
                    updateNotification();
                }
            });
        });
    }

    private void stopServer() {
        long command = commands.stop();
        String runToken = token;
        ActivityLog runLog = activityLog;
        runLog.log("Server stopping");
        token = null;
        publish(STOPPING, null);
        PYTHON.execute(() -> {
            String error = stopPython(runToken);
            runLog.log(error == null ? "Server stopped" : "Stop error: " + error);
            runLog.close();
            main.post(() -> {
                if (!current(command)) return;
                releaseWakeLock();
                stopForeground(STOP_FOREGROUND_REMOVE);
                publish(error == null ? STOPPED : ERROR, error);
                stopSelfResult(lastStartId);
            });
        });
    }

    private static String stopPython(String secret) {
        try {
            if (Python.isStarted()) Python.getInstance().getModule("android_server").callAttr("stop");
            return null;
        } catch (RuntimeException failure) {
            return message(failure, secret);
        }
    }

    private boolean current(long command) {
        return !destroyed && owner == this && commands.accepts(command);
    }

    private void fail(String error) {
        activityLog.log("Server error: " + error);
        activityLog.close();
        commands.stop();
        token = null;
        releaseWakeLock();
        stopForeground(STOP_FOREGROUND_REMOVE);
        publish(ERROR, error);
        stopSelfResult(lastStartId);
    }

    private static String message(Exception failure, String secret) {
        String text = failure.getMessage();
        if (text == null || text.isEmpty()) text = failure.getClass().getSimpleName();
        return secret == null ? text : text.replace(secret, "[hidden]");
    }

    private void updateNetwork(Network network, LinkProperties properties) {
        if (destroyed) return;
        NetworkCapabilities capabilities = connectivity.getNetworkCapabilities(network);
        if (capabilities != null && properties != null
                && !capabilities.hasTransport(NetworkCapabilities.TRANSPORT_VPN)
                && (capabilities.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)
                    || capabilities.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET))) {
            networks.put(network, properties);
        } else {
            networks.remove(network);
        }
        publishNetwork();
    }

    private List<String> urls() {
        if (snapshot.state != RUNNING) return Collections.emptyList();
        TreeSet<String> result = new TreeSet<>();
        for (LinkProperties properties : networks.values()) {
            for (LinkAddress link : properties.getLinkAddresses()) {
                InetAddress address = link.getAddress();
                if (address instanceof Inet4Address && !address.isLoopbackAddress()
                        && !address.isLinkLocalAddress() && !address.isAnyLocalAddress()
                        && !address.isMulticastAddress()) {
                    result.add("http://" + address.getHostAddress() + ":" + port + "/"
                            + (token == null ? "" : token + "/"));
                }
            }
        }
        return new ArrayList<>(result);
    }

    private void publish(int state, String error) {
        snapshot = new Snapshot(state, Collections.emptyList(), error);
        snapshot = new Snapshot(state, urls(), error);
        for (Runnable listener : new ArrayList<>(LISTENERS)) listener.run();
    }

    private void publishNetwork() {
        if (destroyed || owner != this || snapshot.state != RUNNING) return;
        List<String> addresses = urls();
        if (!addresses.equals(snapshot.urls)) {
            snapshot = new Snapshot(RUNNING, addresses, null);
            for (Runnable listener : new ArrayList<>(LISTENERS)) listener.run();
            updateNotification();
        }
    }

    private Notification notification() {
        PendingIntent open = PendingIntent.getActivity(this, 0,
                new Intent(this, MainActivity.class), PendingIntent.FLAG_IMMUTABLE | PendingIntent.FLAG_UPDATE_CURRENT);
        PendingIntent stop = PendingIntent.getService(this, 1,
                new Intent(this, UploadService.class).setAction(ACTION_STOP), PendingIntent.FLAG_IMMUTABLE);
        int text = snapshot.state == STARTING ? R.string.server_starting
                : snapshot.urls.isEmpty() ? R.string.notification_offline : R.string.notification_running;
        return new Notification.Builder(this, CHANNEL)
                .setSmallIcon(R.drawable.ic_upload)
                .setContentTitle(getString(R.string.app_name))
                .setContentText(getString(text))
                .setContentIntent(open)
                .setOngoing(true)
                .setOnlyAlertOnce(true)
                .setCategory(Notification.CATEGORY_SERVICE)
                .addAction(new Notification.Action.Builder(Icon.createWithResource(this, R.drawable.ic_upload),
                        getString(R.string.stop), stop).build())
                .build();
    }

    private void updateNotification() {
        getSystemService(NotificationManager.class).notify(NOTIFICATION, notification());
    }

    private void releaseWakeLock() {
        main.removeCallbacks(renewWakeLock);
        if (wakeLock != null && wakeLock.isHeld()) wakeLock.release();
    }

    @Override public void onDestroy() {
        destroyed = true;
        commands.stop();
        String runToken = token;
        ActivityLog runLog = activityLog;
        token = null;
        if (callbackRegistered) connectivity.unregisterNetworkCallback(networkCallback);
        releaseWakeLock();
        PYTHON.execute(() -> {
            stopPython(runToken);
            runLog.close();
        });
        if (owner == this) {
            if (snapshot.state != ERROR) publish(STOPPED, null);
            owner = null;
        }
        super.onDestroy();
    }

    @Override public IBinder onBind(Intent intent) {
        return null;
    }
}
