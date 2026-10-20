package io.krypta.research;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.Context;
import android.content.res.Configuration;
import android.os.Bundle;
import android.graphics.Color;
import android.graphics.Typeface;
import android.graphics.drawable.GradientDrawable;
import android.view.View;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import java.util.Locale;

/**
 * Localized, UI-only architecture scaffold. NO ENCRYPTION IS IMPLEMENTED.
 * Language choice is the only data kept in private app preferences.
 * Android FBE/Keystore integration requires device-aware native implementation.
 */
public final class MainActivity extends Activity {
    private static final int BG = Color.rgb(7, 14, 11);
    private static final int PANEL = Color.rgb(13, 26, 19);
    private static final int BORDER = Color.rgb(39, 83, 57);
    private static final int PHOSPHOR = Color.rgb(140, 245, 167);
    private static final int MUTED = Color.rgb(151, 181, 159);
    private static final int AMBER = Color.rgb(235, 195, 126);
    private static final String[] CODES = {
            "en", "pl", "ru", "zh", "es", "ar", "hi", "pt", "fr", "de", "id"
    };
    private static final String[] NAMES = {
            "English", "Polski", "Русский", "简体中文", "Español", "العربية",
            "हिन्दी", "Português", "Français", "Deutsch", "Bahasa Indonesia"
    };

    @Override
    protected void attachBaseContext(Context base) {
        String selected = base.getSharedPreferences("krypta-ui", MODE_PRIVATE)
                .getString("locale", "system");
        if (!"system".equals(selected)) {
            Configuration config = new Configuration(base.getResources().getConfiguration());
            config.setLocale(Locale.forLanguageTag("zh".equals(selected) ? "zh-CN" : selected));
            base = base.createConfigurationContext(config);
        }
        super.attachBaseContext(base);
    }

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
        Locale actual = getResources().getConfiguration().getLocales().get(0);
        content.setLayoutDirection("ar".equals(actual.getLanguage())
                ? View.LAYOUT_DIRECTION_RTL : View.LAYOUT_DIRECTION_LTR);
        int p = dp(22);
        content.setPadding(p, dp(38), p, dp(22));
        scroll.addView(content);
        label(content, "K R Y P T A", 28, PHOSPHOR, true);
        label(content, getString(R.string.mobile_subtitle), 11, MUTED, false);
        TextView selector = label(content, getString(R.string.language) + "  ▾", 12, PHOSPHOR, true);
        selector.setContentDescription(getString(R.string.choose_language));
        selector.setOnClickListener(v -> chooseLanguage());
        spacer(content, 25);
        label(content, getString(R.string.mobile_status), 15, AMBER, true);
        label(content, getString(R.string.mobile_not_protected), 13, AMBER, false);
        spacer(content, 20);
        panel(content, "01 / " + getString(R.string.android_shield), getString(R.string.planned),
                getString(R.string.mobile_device_body));
        panel(content, "02 / " + getString(R.string.file_vault), getString(R.string.planned),
                getString(R.string.mobile_file_body));
        panel(content, "03 / " + getString(R.string.password_shield), getString(R.string.planned),
                getString(R.string.mobile_password_body));
        panel(content, "04 / " + getString(R.string.drive_shield), getString(R.string.planned),
                getString(R.string.mobile_drive_body));
        spacer(content, 14);
        label(content, getString(R.string.mobile_offline), 11, PHOSPHOR, false);
        label(content, getString(R.string.mobile_private), 11, MUTED, false);
        setContentView(scroll);
    }

    private void chooseLanguage() {
        String[] options = new String[CODES.length + 1];
        options[0] = "AUTO / SYSTEM";
        System.arraycopy(NAMES, 0, options, 1, NAMES.length);
        new AlertDialog.Builder(this)
                .setTitle(R.string.choose_language)
                .setItems(options, (dialog, which) -> {
                    String value = which == 0 ? "system" : CODES[which - 1];
                    getSharedPreferences("krypta-ui", MODE_PRIVATE).edit()
                            .putString("locale", value).apply();
                    recreate();
                })
                .show();
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

    private TextView label(LinearLayout parent, String content, int size, int color, boolean bold) {
        TextView t = new TextView(this);
        t.setText(content);
        t.setTextSize(size);
        t.setTextColor(color);
        // Android font fallback supports Arabic, Devanagari and CJK script better
        // than forcing a missing Latin-only monospace font.
        t.setTypeface(Typeface.DEFAULT, bold ? Typeface.BOLD : Typeface.NORMAL);
        t.setLineSpacing(dp(3), 1f);
        t.setPadding(0, 0, 0, dp(7));
        parent.addView(t);
        return t;
    }

    private void spacer(LinearLayout parent, int height) {
        View spacer = new View(this);
        parent.addView(spacer, new LinearLayout.LayoutParams(1, dp(height)));
    }

    private int dp(float value) {
        return (int) (value * getResources().getDisplayMetrics().density + 0.5f);
    }
}