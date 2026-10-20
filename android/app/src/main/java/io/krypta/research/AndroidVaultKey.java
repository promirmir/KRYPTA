package io.krypta.research;

import android.app.KeyguardManager;
import android.content.Context;
import android.os.Build;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import java.security.KeyStore;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

/**
 * Device-local AES wrapping key. Requires device screen-lock confirmation.
 * Not a KRYPTA 1-digit PIN, and no key recovery/migration is implemented.
 */
public final class AndroidVaultKey {
    private static final String ALIAS = "KRYPTA_MOBILE_RESEARCH_WRAP_V1";
    private AndroidVaultKey() {}

    public static SecretKey getOrCreate(Context context) throws Exception {
        KeyguardManager lock = (KeyguardManager) context.getSystemService(Context.KEYGUARD_SERVICE);
        if (lock == null || !lock.isDeviceSecure())
            throw new IllegalStateException("Secure Android device lock required");
        KeyStore store = KeyStore.getInstance("AndroidKeyStore");
        store.load(null);
        if (store.containsAlias(ALIAS)) {
            java.security.Key entry = store.getKey(ALIAS, null);
            if (!(entry instanceof SecretKey))
                throw new IllegalStateException("Unexpected Keystore key type");
            return (SecretKey) entry;
        }
        KeyGenerator gen = KeyGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore");
        KeyGenParameterSpec.Builder spec = new KeyGenParameterSpec.Builder(ALIAS,
                KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                .setKeySize(256)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setRandomizedEncryptionRequired(true)
                .setUserAuthenticationRequired(true);
        if (Build.VERSION.SDK_INT >= 30) {
            spec.setUserAuthenticationParameters(120, KeyProperties.AUTH_DEVICE_CREDENTIAL);
        } else {
            spec.setUserAuthenticationValidityDurationSeconds(120);
        }
        gen.init(spec.build());
        return gen.generateKey();
    }
}