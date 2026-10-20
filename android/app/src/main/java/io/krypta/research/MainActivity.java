package io.krypta.research;

import android.app.Activity;
import android.os.Bundle;
import android.graphics.Color;
import android.graphics.Typeface;
import android.graphics.drawable.GradientDrawable;
import android.view.View;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

/**
 * UI-only architecture scaffold. This APK DOES NOT encrypt files or the phone.
 * Android FBE/Keystore integration requires device-aware native implementation.
 */
public final class MainActivity extends Activity {
    private static final int BG = Color.rgb(7, 14, 11);
    private static final int PANEL = Color.rgb(13, 26, 19);
    private static final int BORDER = Color.rgb(39, 83, 57);
    private static final int PHOSPHOR = Color.rgb(140, 245, 167);
    private static final int MUTED = Color.rgb(151, 181, 159);
    private static final int AMBER = Color.rgb(235, 195, 126);

    @Override
    public void onCreate(Bundle state) {
        super.onCreate(state);
        getWindow().setStatusBarColor(BG);
        getWindow().setNavigationBarColor(BG);
        ScrollView scroll = new ScrollView(this);
        scroll.setFillViewport(true);
        scroll.setBackgroundColor(BG);
        LinearLayout content = new LinearLayout(this);
        content.setOrientation(LinearLayout.VERTICAL);
        int p = dp(22);
        content.setPadding(p, dp(38), p, dp(22));
        scroll.addView(content);
        label(content, "K R Y P T A", 28, PHOSPHOR, true);
        label(content, "SECURITY WORKSTATION  /  MOBILE", 11, MUTED, false);
        spacer(content, 25);
        label(content, "ALPHA // RESEARCH UI", 15, AMBER, true);
        label(content,
                "NOT PROTECTING THIS DEVICE. Encryption, full-device locking and password vault are not implemented in this APK.",
                13, AMBER, false);
        spacer(content, 20);
        panel(content, "01 / DEVICE SHIELD", "NOT IMPLEMENTED",
                "Android File-Based Encryption, secure startup and hardware-bound unlock policies require OS integration.");
        panel(content, "02 / FILE VAULT", "NOT IMPLEMENTED",
                "Desktop research file format is not available on this Android application yet.");
        panel(content, "03 / PASSWORD SHIELD", "NOT IMPLEMENTED",
                "Protected secrets and per-use reauthentication require Keystore and biometric/credential integration.");
        panel(content, "04 / DRIVE SHIELD", "NOT IMPLEMENTED",
                "Removable drive encryption needs validated backends, recovery procedures and device-specific testing.");
        spacer(content, 14);
        label(content, "LOCAL INTERFACE // NO INTERNET PERMISSION", 11, PHOSPHOR, false);
        label(content, "Independent KRYPTA project · private development", 11, MUTED, false);
        setContentView(scroll);
    }

    private void panel(LinearLayout parent, String title, String status, String body) {
        LinearLayout frame = new LinearLayout(this);
        frame.setOrientation(LinearLayout.VERTICAL);
        frame.setPadding(dp(17), dp(14), dp(17), dp(14));
        GradientDrawable border = new GradientDrawable();
        border.setColor(PANEL);
        border.setCornerRadius(dp(8));
        border.setStroke(dp(1), BORDER);
        frame.setBackground(border);
        label(frame, title, 14, PHOSPHOR, true);
        label(frame, status, 11, AMBER, true);
        label(frame, body, 12, MUTED, false);
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT);
        lp.bottomMargin = dp(12);
        parent.addView(frame, lp);
    }

    private void label(LinearLayout parent, String content, int size, int color, boolean bold) {
        TextView t = new TextView(this);
        t.setText(content);
        t.setTextSize(size);
        t.setTextColor(color);
        t.setTypeface(Typeface.MONOSPACE, bold ? Typeface.BOLD : Typeface.NORMAL);
        t.setLineSpacing(dp(3), 1f);
        t.setPadding(0, 0, 0, dp(7));
        parent.addView(t);
    }

    private void spacer(LinearLayout parent, int height) {
        View spacer = new View(this);
        parent.addView(spacer, new LinearLayout.LayoutParams(1, dp(height)));
    }

    private int dp(float value) {
        return (int) (value * getResources().getDisplayMetrics().density + 0.5f);
    }
}