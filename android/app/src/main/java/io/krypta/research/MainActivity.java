package io.krypta.research;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.Context;
import android.app.KeyguardManager;
import android.content.Intent;
import android.net.Uri;
import android.provider.DocumentsContract;
import android.os.Build;
import android.view.WindowManager;
import android.widget.Button;
import java.io.File;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.SecureRandom;
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
 * Multilingual research app with selected-file AES-256-GCM encryption in KRYPTA-MOBILE/1.
 * AndroidKeyStore holds an authentication-bound nonexportable wrapping key.
 * NOT phone-wide disk encryption; files are selected via Storage Access Framework.
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

    private static final int PICK_SOURCE = 101;
    private static final int AUTHENTICATE = 102;
    private static final int PICK_OUTPUT = 103;
    private Uri sourceUri;
    private Uri destinationUri;
    private boolean decryptMode;
    private boolean busy;
    private TextView vaultResult;

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
        getWindow().addFlags(WindowManager.LayoutParams.FLAG_SECURE);
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
        label(content, getString(R.string.vault_status), 15, AMBER, true);
        label(content, getString(R.string.vault_warning), 13, AMBER, false);
        spacer(content, 20);
        panel(content, "01 / " + getString(R.string.android_shield), getString(R.string.planned),
                getString(R.string.mobile_device_body));
        panel(content, "02 / " + getString(R.string.file_vault), getString(R.string.available),
                getString(R.string.vault_body));
        Button enc = actionButton(getString(R.string.vault_encrypt));
        content.addView(enc);
        enc.setOnClickListener(v -> startVaultOperation(false));
        Button dec = actionButton(getString(R.string.vault_decrypt));
        content.addView(dec);
        dec.setOnClickListener(v -> startVaultOperation(true));
        vaultResult = label(content, getString(R.string.vault_idle), 12, PHOSPHOR, false);
        panel(content, "03 / " + getString(R.string.password_shield), getString(R.string.planned),
                getString(R.string.mobile_password_body));
        panel(content, "04 / " + getString(R.string.drive_shield), getString(R.string.planned),
                getString(R.string.mobile_drive_body));
        spacer(content, 14);
        label(content, getString(R.string.mobile_offline), 11, PHOSPHOR, false);
        label(content, getString(R.string.mobile_private), 11, MUTED, false);
        setContentView(scroll);
    }

    private Button actionButton(String title) {
        Button button = new Button(this);
        button.setText(title);
        button.setTextColor(PHOSPHOR);
        button.setBackgroundTintList(android.content.res.ColorStateList.valueOf(BORDER));
        button.setAllCaps(false);
        return button;
    }

    private void startVaultOperation(boolean decrypt) {
        if (busy) return;
        KeyguardManager keyguard = (KeyguardManager) getSystemService(KEYGUARD_SERVICE);
        if (keyguard == null || !keyguard.isDeviceSecure()) {
            showError(getString(R.string.vault_need_lock));
            return;
        }
        decryptMode = decrypt;
        sourceUri = null;
        destinationUri = null;
        Intent pick = new Intent(Intent.ACTION_OPEN_DOCUMENT);
        pick.addCategory(Intent.CATEGORY_OPENABLE);
        pick.setType("*/*");
        startActivityForResult(pick, PICK_SOURCE);
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (resultCode != RESULT_OK) {
            if (vaultResult != null) vaultResult.setText(getString(R.string.vault_cancelled));
            return;
        }
        if (requestCode == PICK_SOURCE) {
            if (data == null || data.getData() == null) return;
            sourceUri = data.getData();
            KeyguardManager manager = (KeyguardManager) getSystemService(KEYGUARD_SERVICE);
            if (manager == null || !manager.isDeviceSecure()) {
                showError(getString(R.string.vault_need_lock));
                return;
            }
            Intent confirm = manager.createConfirmDeviceCredentialIntent(
                    getString(R.string.vault_auth_title), getString(R.string.vault_auth_body));
            if (confirm == null) {
                showError(getString(R.string.vault_need_lock));
                return;
            }
            startActivityForResult(confirm, AUTHENTICATE);
        } else if (requestCode == AUTHENTICATE) {
            Intent save = new Intent(Intent.ACTION_CREATE_DOCUMENT);
            save.addCategory(Intent.CATEGORY_OPENABLE);
            save.setType("application/octet-stream");
            save.putExtra(Intent.EXTRA_TITLE, decryptMode
                    ? "KRYPTA-restored-TEST.bin" : "KRYPTA-encrypted-TEST.kma");
            startActivityForResult(save, PICK_OUTPUT);
        } else if (requestCode == PICK_OUTPUT) {
            if (data == null || data.getData() == null || sourceUri == null) return;
            destinationUri = data.getData();
            if (sourceUri.equals(destinationUri)) {
                showError(getString(R.string.vault_same_file));
                return;
            }
            runVaultWorker();
        }
    }

    private void runVaultWorker() {
        if (busy || sourceUri == null || destinationUri == null) return;
        busy = true;
        vaultResult.setText(getString(R.string.processing));
        final Uri input = sourceUri;
        final Uri output = destinationUri;
        final boolean decrypt = decryptMode;
        new Thread(() -> {
            File temp = null;
            boolean success = false;
            String errorText = null;
            try {
                javax.crypto.SecretKey wrapping = AndroidVaultKey.getOrCreate(this);
                if (decrypt) {
                    // Authenticate ENTIRE source before exporting any plaintext to SAF.
                    temp = File.createTempFile("krypta-mobile-", ".tmp", getCacheDir());
                    try (InputStream in = getContentResolver().openInputStream(input);
                         FileOutputStream tempOut = new FileOutputStream(temp)) {
                        if (in == null) throw new java.io.IOException("No input stream");
                        VaultFormat.decrypt(wrapping, in, tempOut);
                        tempOut.getFD().sync();
                    }
                    try (FileInputStream verified = new FileInputStream(temp);
                         OutputStream out = getContentResolver().openOutputStream(output, "w")) {
                        if (out == null) throw new java.io.IOException("No output stream");
                        byte[] bytes = new byte[64 * 1024];
                        int count;
                        while ((count = verified.read(bytes)) != -1) out.write(bytes, 0, count);
                        out.flush();
                        java.util.Arrays.fill(bytes, (byte) 0);
                    }
                } else {
                    try (InputStream in = getContentResolver().openInputStream(input);
                         OutputStream out = getContentResolver().openOutputStream(output, "w")) {
                        if (in == null || out == null) throw new java.io.IOException("Document provider unavailable");
                        VaultFormat.encrypt(wrapping, in, out, new SecureRandom());
                    }
                }
                success = true;
            } catch (Exception e) {
                // Do not include URIs, user data, cryptographic internals or secrets in logs.
                errorText = getString(R.string.vault_failed);
            } finally {
                if (temp != null && temp.exists()) {
                    // Best effort only: this is NOT a guarantee of secure deletion from flash.
                    temp.delete();
                }
            }
            final boolean passed = success;
            final String message = passed ? getString(R.string.vault_success) : errorText;
            runOnUiThread(() -> {
                busy = false;
                vaultResult.setText(message);
                new AlertDialog.Builder(this)
                        .setTitle(passed ? getString(R.string.success) : getString(R.string.failure))
                        .setMessage(message).setPositiveButton(android.R.string.ok, null).show();
            });
        }, "KRYPTA-Mobile-Vault").start();
    }

    private void showError(String text) {
        new AlertDialog.Builder(this).setTitle(R.string.failure)
                .setMessage(text).setPositiveButton(android.R.string.ok, null).show();
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