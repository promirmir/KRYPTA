package io.krypta.research;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.HexFormat;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import org.junit.Test;
import static org.junit.Assert.*;

/** JVM format validation only; no Android Keystore/hardware claims. */
public final class MobileRecoveryFormatTest {
    private static final String FIXTURE =
            "4b52595054412d4d4f42494c452f320a606162636465666768696a6b6c6d6e6f707172735731329034b4be137d4624e027cb96dd86b6e9d7a63acd3de74894d9d47936bc32a6fa8eaeef30c5a52ebe21e6e9c1477475767778797a7b7c7d7e7fe958af410a3ef53ab31024a64c86cf313938ad31f62a5c3cd8177af6931a7a64bf2c0903e4ced04d321d2f7ad23108330000004980cc61581e4126a3194dc003b719f2707ee5f57b5ed67be6164da0803d007dd43d0ff9291a024db8a5c7ef9af306df3053775f1b1e48fe9acd92cd3a49a12c35a8df20818796b325da00000010606b20c73242d926c6880c23ae83fbd3";
    private static final String PLAIN =
            "4b525950544120706f727461626c6520416e64726f6964207265636f7665727920696e7465726f7065726162696c69747920746573740001fe";
    private static final byte[] RECOVERY = HexFormat.of().parseHex(
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");

    private static SecretKey deviceKey() throws GeneralSecurityException {
        KeyGenerator gen = KeyGenerator.getInstance("AES");
        gen.init(256);
        return gen.generateKey();
    }

    private static byte[] encrypted(SecretKey device, byte[] recovery, byte[] bytes)
            throws Exception {
        ByteArrayOutputStream target = new ByteArrayOutputStream();
        MobileRecoveryFormat.encrypt(device, recovery, new ByteArrayInputStream(bytes),
                target, new SecureRandom());
        return target.toByteArray();
    }

    private static byte[] recovered(byte[] key, byte[] cipher) throws Exception {
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        MobileRecoveryFormat.recover(key, new ByteArrayInputStream(cipher), output);
        return output.toByteArray();
    }

    private static byte[] deviceDecrypt(SecretKey key, byte[] cipher) throws Exception {
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        MobileRecoveryFormat.decrypt(key, new ByteArrayInputStream(cipher), output);
        return output.toByteArray();
    }

    @Test public void pythonFixtureRecoveredOnJVM() throws Exception {
        byte[] cipher = HexFormat.of().parseHex(FIXTURE);
        byte[] plain = HexFormat.of().parseHex(PLAIN);
        assertArrayEquals(plain, recovered(RECOVERY, cipher));
        byte[] device = new byte[32];
        for (int i = 0; i < 32; i++) device[i] = (byte)(i + 32);
        assertArrayEquals(plain,
                deviceDecrypt(new SecretKeySpec(device, "AES"), cipher));
    }

    @Test public void freshJavaEncryptionSupportsIndependentRecovery() throws Exception {
        byte[] recovery = new byte[32];
        new SecureRandom().nextBytes(recovery);
        SecretKey device = deviceKey();
        for (int size : new int[] {0, 1, 65535, 65536, 65537, 131071}) {
            byte[] sample = new byte[size];
            new SecureRandom().nextBytes(sample);
            byte[] ct = encrypted(device, recovery, sample);
            assertArrayEquals(sample, recovered(recovery, ct));
            assertArrayEquals(sample, deviceDecrypt(device, ct));
            assertFalse(Arrays.equals(sample, ct));
        }
    }

    @Test public void wrongDeviceAndRecoveryCannotDecrypt() throws Exception {
        byte[] ct = encrypted(deviceKey(), RECOVERY, new byte[100]);
        try {
            deviceDecrypt(deviceKey(), ct);
            fail("Unrelated Android Keystore key was accepted");
        } catch (GeneralSecurityException expected) {}
        byte[] wrong = RECOVERY.clone();
        wrong[0] ^= 1;
        try {
            recovered(wrong, ct);
            fail("Wrong independent recovery key accepted");
        } catch (GeneralSecurityException expected) {}
    }

    @Test public void payloadHeaderAndEOFManipulationRejected() throws Exception {
        byte[] ct = encrypted(deviceKey(), RECOVERY, new byte[66000]);
        for (int offset : new int[] {0, 25, 90, 125, ct.length - 1, ct.length - 24}) {
            byte[] corrupted = ct.clone();
            corrupted[offset] ^= 1;
            try {
                recovered(RECOVERY, corrupted);
                fail("Tampered archive accepted at offset " + offset);
            } catch (GeneralSecurityException | IOException expected) {}
        }
        for (int n : new int[] {0, 20, 100, ct.length - 1}) {
            try {
                recovered(RECOVERY, Arrays.copyOf(ct, n));
                fail("Truncation accepted");
            } catch (GeneralSecurityException | IOException expected) {}
        }
        byte[] appended = Arrays.copyOf(ct, ct.length + 1);
        try {
            recovered(RECOVERY, appended);
            fail("Trailing byte accepted");
        } catch (GeneralSecurityException | IOException expected) {}
    }

    @Test public void missingRecoveryKeyIsRejected() throws Exception {
        try {
            encrypted(deviceKey(), new byte[31], b(17));
            fail("Weak/short key accepted");
        } catch (GeneralSecurityException expected) {}
    }

    private static byte[] b(int length) { return new byte[length]; }
}
