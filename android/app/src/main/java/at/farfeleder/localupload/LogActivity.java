package at.farfeleder.localupload;

import android.app.Activity;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.graphics.Insets;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.os.PersistableBundle;
import android.text.Layout;
import android.view.MotionEvent;
import android.view.View;
import android.view.ViewTreeObserver;
import android.view.WindowInsets;
import android.widget.Button;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

import java.util.Collections;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;

public final class LogActivity extends Activity {
    private final Handler main = new Handler(Looper.getMainLooper());
    private final AtomicBoolean pending = new AtomicBoolean();
    private volatile boolean visible;
    private TextView text;
    private ScrollView scroll;
    private Button copy;
    private Button clear;
    private int restoreY = -1;
    private boolean touching;
    private boolean deferredRender;
    private List<String> shownEntries = Collections.emptyList();
    private ViewTreeObserver.OnPreDrawListener afterLayout;
    private final Runnable refresh = () -> {
        pending.set(false);
        if (visible) render();
    };
    private final Runnable changed = () -> {
        if (visible && pending.compareAndSet(false, true)) main.postDelayed(refresh, 100);
    };

    @Override public void onCreate(Bundle state) {
        super.onCreate(state);
        setContentView(R.layout.activity_log);
        text = findViewById(R.id.log_text);
        scroll = findViewById(R.id.log_scroll);
        copy = findViewById(R.id.log_copy);
        clear = findViewById(R.id.log_clear);
        copy.setOnClickListener(view -> copyLog());
        clear.setOnClickListener(view -> ActivityLog.clear());
        restoreY = state == null ? -1 : state.getInt("logScroll", 0);
        if (Build.VERSION.SDK_INT >= 28) findViewById(R.id.log_title).setAccessibilityHeading(true);
        View page = findViewById(R.id.log_page);
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
    }

    // The same native fallback used by the main screen on Android 8/9.
    @SuppressWarnings("deprecation")
    private static void applyLegacyInsets(View view, WindowInsets insets, int padding) {
        view.setPadding(padding + insets.getSystemWindowInsetLeft(), padding + insets.getSystemWindowInsetTop(),
                padding + insets.getSystemWindowInsetRight(), padding + insets.getSystemWindowInsetBottom());
    }

    @Override public void onStart() {
        super.onStart();
        visible = true;
        ActivityLog.addListener(changed);
        render();
    }

    @Override public void onStop() {
        visible = false;
        ActivityLog.removeListener(changed);
        main.removeCallbacks(refresh);
        pending.set(false);
        touching = false;
        deferredRender = false;
        removeAfterLayout();
        super.onStop();
    }

    @Override public boolean dispatchTouchEvent(MotionEvent event) {
        int action = event.getActionMasked();
        if (action == MotionEvent.ACTION_DOWN) touching = true;
        else if (action == MotionEvent.ACTION_UP || action == MotionEvent.ACTION_CANCEL) {
            touching = false;
            if (deferredRender) {
                deferredRender = false;
                changed.run();
            }
        }
        return super.dispatchTouchEvent(event);
    }

    @Override public void onSaveInstanceState(Bundle state) {
        state.putInt("logScroll", scroll.getScrollY());
        super.onSaveInstanceState(state);
    }

    private void render() {
        if (touching) {
            deferredRender = true;
            return;
        }
        List<String> entries = ActivityLog.entries();
        boolean restoring = restoreY >= 0;
        int previous = restoring ? restoreY : scroll.getScrollY();
        boolean follow = !restoring && !scroll.canScrollVertically(1);
        int target = entries.isEmpty() ? 0 : previous;
        if (!restoring && !follow && !entries.isEmpty() && !shownEntries.isEmpty()) {
            int removed = 0;
            int offset = 0;
            // Snapshots retain each immutable event String, even when text is identical.
            while (removed < shownEntries.size() && shownEntries.get(removed) != entries.get(0)) {
                offset += shownEntries.get(removed++).length() + 1;
            }
            Layout layout = text.getLayout();
            if (removed == shownEntries.size() || layout == null) target = 0;
            else if (removed > 0) target = Math.max(0,
                    previous - layout.getLineTop(layout.getLineForOffset(offset)));
        }
        restoreY = -1;
        shownEntries = entries;
        removeAfterLayout();
        text.setText(entries.isEmpty() ? getString(R.string.log_empty) : String.join("\n", entries));
        copy.setEnabled(!entries.isEmpty());
        clear.setEnabled(!entries.isEmpty());
        int targetY = target;
        // setText can reset ScrollView position; restore only after the new height is known.
        afterLayout = () -> {
            removeAfterLayout();
            if (visible) {
                int bottom = Math.max(0, text.getHeight() - scroll.getHeight()
                        + scroll.getPaddingTop() + scroll.getPaddingBottom());
                scroll.scrollTo(0, follow ? bottom : targetY);
            }
            return true;
        };
        scroll.getViewTreeObserver().addOnPreDrawListener(afterLayout);
    }

    private void removeAfterLayout() {
        if (afterLayout == null) return;
        ViewTreeObserver observer = scroll.getViewTreeObserver();
        if (observer.isAlive()) observer.removeOnPreDrawListener(afterLayout);
        afterLayout = null;
    }

    private void copyLog() {
        List<String> entries = ActivityLog.entries();
        if (entries.isEmpty()) return;
        ClipData clip = ClipData.newPlainText(getString(R.string.log_title), String.join("\n", entries));
        PersistableBundle extras = new PersistableBundle();
        extras.putBoolean("android.content.extra.IS_SENSITIVE", true);
        clip.getDescription().setExtras(extras);
        getSystemService(ClipboardManager.class).setPrimaryClip(clip);
        if (Build.VERSION.SDK_INT < 33) Toast.makeText(this, R.string.log_copied, Toast.LENGTH_SHORT).show();
    }
}
