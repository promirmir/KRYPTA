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
import java.io.BufferedInputStream;
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
    private static final int PICK_RECOVERY_EXPORT = 104;
    private static final int PICK_RECOVERY_IMPORT = 105;
    private byte[] pendingRecoveryKey;
    private Uri exportedRecoveryUri;
    private Uri recoveryInputUri;
    private boolean independentRecoveryMode;
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
        Button recover = actionButton(getString(R.string.vault_recover_external));
        content.addView(recover);
        recover.setOnClickListener(v -> startIndependentRecovery());
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

    private void clearPendingRecoveryKey() {
        exportedRecoveryUri = null;
        if (pendingRecoveryKey != null) {
            java.util.Arrays.fill(pendingRecoveryKey, (byte) 0);
            pendingRecoveryKey = null;
        }
    }

    private void startVaultOperation(boolean decrypt) {
        startVaultOperation(decrypt, false);
    }

    private void startVaultOperation(boolean decrypt, boolean recovery) {
        if (busy) return;
        clearPendingRecoveryKey();
        recoveryInputUri = null;
        independentRecoveryMode = false;
        KeyguardManager keyguard = (KeyguardManager) getSystemService(KEYGUARD_SERVICE);
        if (keyguard == null || !keyguard.isDeviceSecure()) {
            showError(getString(R.string.vault_need_lock));
            return;
        }
        decryptMode = decrypt;
        independentRecoveryMode = recovery;
        sourceUri = null;
        destinationUri = null;
        Intent pick = new Intent(Intent.ACTION_OPEN_DOCUMENT);
        pick.addCategory(Intent.CATEGORY_OPENABLE);
        pick.setType("*/*");
        startActivityForResult(pick, PICK_SOURCE);
    }

    private void startIndependentRecovery() {
        // Screen lock + explicit credential confirmation remain required,
        // but old AndroidKeystore key is never needed on a replacement phone.
        startVaultOperation(true, true);
    }

    private void requestRecoveryKeyInput() {
        new AlertDialog.Builder(this)
                .setTitle(R.string.vault_recovery_title)
                .setMessage(R.string.vault_recovery_import_warning)
                .setNegativeButton(android.R.string.cancel,
                        (dialog, which) -> recoveryInputUri = null)
                .setPositiveButton(android.R.string.ok, (dialog, which) -> {
                    Intent pick = new Intent(Intent.ACTION_OPEN_DOCUMENT);
                    pick.addCategory(Intent.CATEGORY_OPENABLE);
                    pick.setType("application/octet-stream");
                    startActivityForResult(pick, PICK_RECOVERY_IMPORT);
                }).show();
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (resultCode != RESULT_OK) {
            clearPendingRecoveryKey();
            recoveryInputUri = null;
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
            if (independentRecoveryMode) {
                requestRecoveryKeyInput();
            } else if (decryptMode) {
                requestEncryptedOutput();
            } else {
                new AlertDialog.Builder(this)
                        .setTitle(R.string.vault_recovery_title)
                        .setMessage(R.string.vault_recovery_warning)
                        .setNegativeButton(android.R.string.cancel,
                                (dialog, which) -> clearPendingRecoveryKey())
                        .setPositiveButton(android.R.string.ok, (dialog, which) -> {
                            Intent saveKey = new Intent(Intent.ACTION_CREATE_DOCUMENT);
                            saveKey.addCategory(Intent.CATEGORY_OPENABLE);
                            saveKey.setType("application/octet-stream");
                            saveKey.putExtra(Intent.EXTRA_TITLE, "KRYPTA-independent-recovery-KEY.krc");
                            startActivityForResult(saveKey, PICK_RECOVERY_EXPORT);
                        }).show();
            }
        } else if (requestCode == PICK_RECOVERY_IMPORT) {
            if (data == null || data.getData() == null || sourceUri == null) return;
            recoveryInputUri = data.getData();
            if (sourceUri.equals(recoveryInputUri)) {
                recoveryInputUri = null;
                showError(getString(R.string.vault_same_file));
                return;
            }
            requestEncryptedOutput();
        } else if (requestCode == PICK_RECOVERY_EXPORT) {
            if (data == null || data.getData() == null) return;
            byte[] freshKey = new byte[32];
            boolean handedOff = false;
            try {
                new SecureRandom().nextBytes(freshKey);
                Uri uri = data.getData();
                if (uri.equals(sourceUri)) throw new java.io.IOException("Recovery destination equals source");
                try (OutputStream out = getContentResolver().openOutputStream(uri, "w")) {
                    if (out == null) throw new java.io.IOException("No keyfile output");
                    out.write(freshKey);
                    out.flush();
                }
                // Require read-back of all bytes, including EOF. Refuse providers
                // that cannot prove the exported secret was persisted intact.
                byte[] check = new byte[33];
                int total = 0;
                try (InputStream in = getContentResolver().openInputStream(uri)) {
                    if (in == null) throw new java.io.IOException("No keyfile read-back");
                    while (total < check.length) {
                        int n = in.read(check, total, check.length - total);
                        if (n < 0) break;
                        if (n == 0) {
                            int c = in.read();
                            if (c < 0) break;
                            check[total++] = (byte) c;
                        } else total += n;
                    }
                }
                if (total != 32 || !java.security.MessageDigest.isEqual(
                        freshKey, java.util.Arrays.copyOf(check, 32)))
                    throw new java.io.IOException("Recovery keyfile read-back mismatch");
                clearPendingRecoveryKey();
                pendingRecoveryKey = freshKey;
                handedOff = true;
                exportedRecoveryUri = uri;
                java.util.Arrays.fill(check, (byte) 0);
                requestEncryptedOutput();
            } catch (Exception exc) {
                clearPendingRecoveryKey();
                showError(getString(R.string.vault_recovery_failed));
            } finally {
                if (!handedOff) java.util.Arrays.fill(freshKey, (byte) 0);
            }
        } else if (requestCode == PICK_OUTPUT) {
            if (data == null || data.getData() == null || sourceUri == null) return;
            destinationUri = data.getData();
            if (sourceUri.equals(destinationUri) ||
                    (exportedRecoveryUri != null && exportedRecoveryUri.equals(destinationUri)) ||
                    (recoveryInputUri != null && recoveryInputUri.equals(destinationUri))) {
                clearPendingRecoveryKey();
                showError(getString(R.string.vault_same_file));
                return;
            }
            runVaultWorker();
        }
    }

    private void requestEncryptedOutput() {
        Intent save = new Intent(Intent.ACTION_CREATE_DOCUMENT);
        save.addCategory(Intent.CATEGORY_OPENABLE);
        save.setType("application/octet-stream");
        save.putExtra(Intent.EXTRA_TITLE, decryptMode
                ? "KRYPTA-restored-TEST.bin" : "KRYPTA-encrypted-recoverable-TEST.km2");
        startActivityForResult(save, PICK_OUTPUT);
    }

    private void runVaultWorker() {
        if (busy || sourceUri == null || destinationUri == null) return;
        busy = true;
        vaultResult.setText(getString(R.string.processing));
        final Uri input = sourceUri;
        final Uri output = destinationUri;
        final boolean decrypt = decryptMode;
        final boolean recover = independentRecoveryMode;
        final Uri keyUri = recoveryInputUri;
        recoveryInputUri = null;
        final byte[] recoveryKey = pendingRecoveryKey;
        pendingRecoveryKey = null;
        exportedRecoveryUri = null;
        if (recover && (keyUri == null || !decrypt)) {
            busy = false;
            showError(getString(R.string.vault_recovery_failed));
            return;
        }
        if (!decrypt && (recoveryKey == null || recoveryKey.length != 32)) {
            busy = false;
            showError(getString(R.string.vault_recovery_failed));
            return;
        }
        new Thread(() -> {
            File temp = null;
            boolean success = false;
            String errorText = null;
            try {
                javax.crypto.SecretKey wrapping = recover ? null : AndroidVaultKey.getOrCreate(this);
                if (decrypt) {
                    // Authenticate ENTIRE source before exporting any plaintext to SAF.
                    temp = File.createTempFile("krypta-mobile-", ".tmp", getCacheDir());
                    try (InputStream in = getContentResolver().openInputStream(input);
                         FileOutputStream tempOut = new FileOutputStream(temp)) {
                        if (in == null) throw new java.io.IOException("No input stream");
                        BufferedInputStream inspected = new BufferedInputStream(in);
                        inspected.mark(MobileRecoveryFormat.MAGIC.length);
                        byte[] magic = new byte[MobileRecoveryFormat.MAGIC.length];
                        int length = 0;
                        while (length < magic.length) {
                            int n = inspected.read(magic, length, magic.length - length);
                            if (n < 0) break;
                            if (n == 0) {
                                int one = inspected.read();
                                if (one < 0) break;
                                magic[length++] = (byte) one;
                            } else length += n;
                        }
                        inspected.reset();
                        if (recover) {
                            if (!java.util.Arrays.equals(magic, MobileRecoveryFormat.MAGIC))
                                throw new java.io.IOException("Only portable MOBILE/2 files support offline recovery");
                            byte[] imported = null;
                            try (InputStream keyIn = getContentResolver().openInputStream(keyUri)) {
                                imported = MobileRecoveryKeyReader.readExact(keyIn);
                                MobileRecoveryFormat.recover(imported, inspected, tempOut);
                            } finally {
                                if (imported != null) java.util.Arrays.fill(imported, (byte) 0);
                            }
                        } else if (java.util.Arrays.equals(magic, MobileRecoveryFormat.MAGIC)) {
                            MobileRecoveryFormat.decrypt(wrapping, inspected, tempOut);
                        } else {
                            VaultFormat.decrypt(wrapping, inspected, tempOut);
                        }
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
                        MobileRecoveryFormat.encrypt(wrapping, recoveryKey, in, out, new SecureRandom());
                    }
                }
                success = true;
            } catch (Exception e) {
                // Do not include URIs, user data, cryptographic internals or secrets in logs.
                errorText = getString(R.string.vault_failed);
            } finally {
                if (recoveryKey != null) java.util.Arrays.fill(recoveryKey, (byte) 0);
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

    @Override
    protected void onDestroy() {
        clearPendingRecoveryKey();
        super.onDestroy();
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