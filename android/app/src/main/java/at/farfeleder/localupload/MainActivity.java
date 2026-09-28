package at.farfeleder.localupload;

import android.Manifest;
import android.app.Activity;
import android.app.AlertDialog;
import android.content.ActivityNotFoundException;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.pm.PackageManager;
import android.graphics.Insets;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.os.PersistableBundle;
import android.provider.DocumentsContract;
import android.provider.Settings;
import android.text.method.ScrollingMovementMethod;
import android.view.View;
import android.view.WindowInsets;
import android.widget.Button;
import android.widget.CheckBox;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

import java.util.ArrayList;
import java.util.List;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;

public final class MainActivity extends Activity {
    private static final int PICK_FOLDER = 1;
    private static final int PERMISSIONS = 2;
    private TextView folder;
    private TextView status;
    private TextView address;
    private Button choose;
    private Button open;
    private Button start;
    private Button stop;
    private Button copy;
    private Button share;
    private CheckBox privacy;
    private boolean pendingStart;
    private final Runnable update = this::render;

    @Override public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        folder = findViewById(R.id.folder);
        status = findViewById(R.id.status);
        address = findViewById(R.id.address);
        choose = findViewById(R.id.choose_folder);
        open = findViewById(R.id.open_folder);
        start = findViewById(R.id.start);
        stop = findViewById(R.id.stop);
        copy = findViewById(R.id.copy);
        share = findViewById(R.id.share);
        privacy = findViewById(R.id.privacy);
        privacy.setOnCheckedChangeListener((button, checked) -> {
            if (!UploadService.snapshot().active()) {
                preferences().edit().putBoolean(UploadService.PRIVACY_KEY, checked).apply();
            }
        });
        status.setMovementMethod(ScrollingMovementMethod.getInstance());
        address.setMovementMethod(ScrollingMovementMethod.getInstance());
        choose.setOnClickListener(view -> pickFolder());
        open.setOnClickListener(view -> openFolder());
        start.setOnClickListener(view -> requestStart());
        stop.setOnClickListener(view -> startService(
                new Intent(this, UploadService.class).setAction(UploadService.ACTION_STOP)));
        copy.setOnClickListener(view -> copyAddress());
        share.setOnClickListener(view -> shareAddress());
        findViewById(R.id.licenses).setOnClickListener(view -> showLicenses());
        if (Build.VERSION.SDK_INT >= 28) {
            for (int heading : new int[] {R.id.title, R.id.folder_heading, R.id.server_heading, R.id.address_heading}) {
                findViewById(heading).setAccessibilityHeading(true);
            }
        }
        View page = findViewById(R.id.page);
        int padding = page.getPaddingLeft();
        page.setOnApplyWindowInsetsListener((view, insets) -> {
            if (Build.VERSION.SDK_INT >= 30) {
                Insets bars = insets.getInsets(WindowInsets.Type.systemBars() | WindowInsets.Type.displayCutout());
                view.setPadding(padding + bars.left, padding + bars.top,
                        padding + bars.right, padding + bars.bottom);
            } else {
                applyLegacyInsets(view, insets, padding);
            }
            return insets;
        });
        pendingStart = savedInstanceState != null && savedInstanceState.getBoolean("pendingStart");
        render();
        // Only a fresh launcher creation starts automatically; onStart/onResume never restart a stopped server.
        if (savedInstanceState == null && launcherIntent(getIntent())
                && !UploadService.snapshot().active()) {
            if (tree() == null) pickFolder();
            else requestStart();
        }
    }

    @Override public void onNewIntent(Intent intent) {
        super.onNewIntent(intent);
        setIntent(intent);
        if (launcherIntent(intent) && !UploadService.snapshot().active()) requestStart();
    }

    private static boolean launcherIntent(Intent intent) {
        return Intent.ACTION_MAIN.equals(intent.getAction()) && intent.hasCategory(Intent.CATEGORY_LAUNCHER);
    }

    // Native fallback on Android 8/9; Insets#getInsets is available only from Android 11.
    @SuppressWarnings("deprecation")
    private static void applyLegacyInsets(View view, WindowInsets insets, int padding) {
        view.setPadding(padding + insets.getSystemWindowInsetLeft(), padding + insets.getSystemWindowInsetTop(),
                padding + insets.getSystemWindowInsetRight(), padding + insets.getSystemWindowInsetBottom());
    }

    @Override public void onStart() {
        super.onStart();
        UploadService.addListener(update);
        render();
    }

    @Override public void onStop() {
        UploadService.removeListener(update);
        super.onStop();
    }

    @Override public void onSaveInstanceState(Bundle state) {
        state.putBoolean("pendingStart", pendingStart);
        super.onSaveInstanceState(state);
    }

    private SharedPreferences preferences() {
        return getSharedPreferences(UploadService.PREFERENCES, MODE_PRIVATE);
    }

    private String tree() {
        return preferences().getString(UploadService.FOLDER_KEY, null);
    }

    private void render() {
        UploadService.Snapshot current = UploadService.snapshot();
        String selected = tree();
        folder.setText(selected == null ? getString(R.string.folder_missing)
                : DocumentsContract.getTreeDocumentId(Uri.parse(selected)));
        int message;
        switch (current.state) {
            case UploadService.STARTING: message = R.string.server_starting; break;
            case UploadService.RUNNING:
                message = current.urls.isEmpty() ? R.string.server_offline : R.string.server_running;
                break;
            case UploadService.STOPPING: message = R.string.server_stopping; break;
            default: message = R.string.server_stopped;
        }
        status.setText(current.state == UploadService.ERROR
                ? getString(R.string.server_error, current.error) : getString(message));
        address.setText(current.urls.isEmpty() ? getString(R.string.address_missing) : String.join("\n\n", current.urls));
        choose.setEnabled(!current.active());
        privacy.setChecked(preferences().getBoolean(UploadService.PRIVACY_KEY, false));
        privacy.setEnabled(!current.active());
        open.setEnabled(selected != null);
        start.setEnabled(!current.active());
        stop.setEnabled(current.state == UploadService.STARTING || current.state == UploadService.RUNNING);
        copy.setEnabled(!current.urls.isEmpty());
        share.setEnabled(!current.urls.isEmpty());
    }

    // The platform picker callback avoids an AndroidX dependency solely for activity results.
    @SuppressWarnings("deprecation")
    private void pickFolder() {
        Intent intent = new Intent(Intent.ACTION_OPEN_DOCUMENT_TREE)
                .addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION | Intent.FLAG_GRANT_WRITE_URI_PERMISSION
                        | Intent.FLAG_GRANT_PERSISTABLE_URI_PERMISSION | Intent.FLAG_GRANT_PREFIX_URI_PERMISSION);
        try {
            startActivityForResult(intent, PICK_FOLDER);
        } catch (ActivityNotFoundException failure) {
            showError(getString(R.string.folder_permission_error));
        }
    }

    // See pickFolder: this is the native Activity result contract.
    @SuppressWarnings("deprecation")
    @Override public void onActivityResult(int requestCode, int resultCode, Intent result) {
        super.onActivityResult(requestCode, resultCode, result);
        if (requestCode != PICK_FOLDER || resultCode != RESULT_OK || result == null || result.getData() == null) return;
        Uri selected = result.getData();
        int flags = result.getFlags() & (Intent.FLAG_GRANT_READ_URI_PERMISSION | Intent.FLAG_GRANT_WRITE_URI_PERMISSION);
        if (flags != (Intent.FLAG_GRANT_READ_URI_PERMISSION | Intent.FLAG_GRANT_WRITE_URI_PERMISSION)) {
            showError(getString(R.string.folder_permission_error));
            return;
        }
        try {
            getContentResolver().takePersistableUriPermission(selected,
                    Intent.FLAG_GRANT_READ_URI_PERMISSION | Intent.FLAG_GRANT_WRITE_URI_PERMISSION);
            String previous = tree();
            preferences().edit().putString(UploadService.FOLDER_KEY, selected.toString()).apply();
            if (previous != null && !previous.equals(selected.toString())) {
                try {
                    getContentResolver().releasePersistableUriPermission(Uri.parse(previous),
                            Intent.FLAG_GRANT_READ_URI_PERMISSION | Intent.FLAG_GRANT_WRITE_URI_PERMISSION);
                } catch (SecurityException alreadyRevoked) {
                    // The old permission may already have been revoked in Android settings.
                }
            }
            render();
            requestStart();
        } catch (SecurityException failure) {
            showError(getString(R.string.folder_permission_error));
        }
    }

    private void requestStart() {
        if (UploadService.snapshot().active()) return;
        if (tree() == null) {
            pickFolder();
            return;
        }
        List<String> missing = new ArrayList<>();
        if (Build.VERSION.SDK_INT >= 37 && checkSelfPermission(Manifest.permission.ACCESS_LOCAL_NETWORK)
                != PackageManager.PERMISSION_GRANTED) {
            missing.add(Manifest.permission.ACCESS_LOCAL_NETWORK);
        }
        if (Build.VERSION.SDK_INT >= 33 && !preferences().getBoolean("notificationAsked", false)
                && checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED) {
            preferences().edit().putBoolean("notificationAsked", true).apply();
            missing.add(Manifest.permission.POST_NOTIFICATIONS);
        }
        if (!missing.isEmpty()) {
            pendingStart = true;
            requestPermissions(missing.toArray(new String[0]), PERMISSIONS);
            return;
        }
        pendingStart = false;
        try {
            startForegroundService(new Intent(this, UploadService.class).setAction(UploadService.ACTION_START));
        } catch (RuntimeException failure) {
            showError(failure.getMessage() == null ? failure.getClass().getSimpleName() : failure.getMessage());
        }
    }

    @Override public void onRequestPermissionsResult(int requestCode, String[] permissions, int[] grants) {
        super.onRequestPermissionsResult(requestCode, permissions, grants);
        if (requestCode != PERMISSIONS || !pendingStart) return;
        pendingStart = false;
        if (Build.VERSION.SDK_INT >= 37 && checkSelfPermission(Manifest.permission.ACCESS_LOCAL_NETWORK)
                != PackageManager.PERMISSION_GRANTED) {
            new AlertDialog.Builder(this)
                    .setMessage(R.string.network_permission_required)
                    .setPositiveButton(R.string.open_settings, (dialog, which) -> startActivity(
                            new Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS,
                                    Uri.parse("package:" + getPackageName()))))
                    .setNegativeButton(R.string.close, null).show();
        } else {
            requestStart();
        }
    }

    private void openFolder() {
        String selected = tree();
        if (selected == null) return;
        Uri treeUri = Uri.parse(selected);
        Uri document = DocumentsContract.buildDocumentUriUsingTree(treeUri, DocumentsContract.getTreeDocumentId(treeUri));
        try {
            startActivity(new Intent(Intent.ACTION_VIEW)
                    .setDataAndType(document, DocumentsContract.Document.MIME_TYPE_DIR)
                    .addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION | Intent.FLAG_GRANT_WRITE_URI_PERMISSION));
        } catch (ActivityNotFoundException | SecurityException failure) {
            Toast.makeText(this, R.string.folder_open_error, Toast.LENGTH_LONG).show();
        }
    }

    private void copyAddress() {
        List<String> urls = UploadService.snapshot().urls;
        if (urls.isEmpty()) return;
        ClipData clip = ClipData.newPlainText(getString(R.string.address_heading), urls.get(0));
        PersistableBundle extras = new PersistableBundle();
        extras.putBoolean("android.content.extra.IS_SENSITIVE", true);
        clip.getDescription().setExtras(extras);
        getSystemService(ClipboardManager.class).setPrimaryClip(clip);
        if (Build.VERSION.SDK_INT < 33) Toast.makeText(this, R.string.address_copied, Toast.LENGTH_SHORT).show();
    }

    private void shareAddress() {
        List<String> urls = UploadService.snapshot().urls;
        if (urls.isEmpty()) return;
        startActivity(Intent.createChooser(new Intent(Intent.ACTION_SEND).setType("text/plain")
                .putExtra(Intent.EXTRA_TEXT, urls.get(0)), getString(R.string.share_address)));
    }

    private void showError(String error) {
        status.setText(getString(R.string.server_error, error));
    }

    private void showLicenses() {
        StringBuilder notices = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(
                getAssets().open("third_party_notices.txt"), StandardCharsets.UTF_8))) {
            String line;
            while ((line = reader.readLine()) != null) notices.append(line).append('\n');
        } catch (IOException failure) {
            Toast.makeText(this, R.string.licenses_error, Toast.LENGTH_LONG).show();
            return;
        }
        TextView text = new TextView(this);
        text.setText(notices);
        text.setTextIsSelectable(true);
        int padding = (int) (20 * getResources().getDisplayMetrics().density);
        text.setPadding(padding, padding, padding, padding);
        ScrollView scroll = new ScrollView(this);
        scroll.addView(text);
        new AlertDialog.Builder(this).setTitle(R.string.licenses).setView(scroll)
                .setPositiveButton(R.string.close, null).show();
    }
}
