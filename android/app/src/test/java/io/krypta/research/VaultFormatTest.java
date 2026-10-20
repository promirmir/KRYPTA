package io.krypta.research;

import org.junit.Test;
import static org.junit.Assert.*;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Arrays;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

/** Pure software JCE regression tests; NOT Android device/Keystore hardware tests. */
public final class VaultFormatTest {
    private static SecretKey randomKey() throws Exception {
        KeyGenerator gen = KeyGenerator.getInstance("AES");
        gen.init(256);
        return gen.generateKey();
    }
    private static byte[] encrypt(SecretKey k, byte[] plain) throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        VaultFormat.encrypt(k, new ByteArrayInputStream(plain), out, new SecureRandom());
        return out.toByteArray();
    }
    private static byte[] decrypt(SecretKey k, byte[] ciphertext) throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        VaultFormat.decrypt(k, new ByteArrayInputStream(ciphertext), out);
        return out.toByteArray();
    }
    private static void roundtrip(int size) throws Exception {
        byte[] plain = new byte[size];
        new SecureRandom().nextBytes(plain);
        SecretKey key = randomKey();
        byte[] sealed = encrypt(key, plain);
        assertArrayEquals(plain, decrypt(key, sealed));
        assertFalse(Arrays.equals(plain, sealed));
    }
    @Test public void emptyFile() throws Exception { roundtrip(0); }
    @Test public void singleByte() throws Exception { roundtrip(1); }
    @Test public void justUnderChunk() throws Exception { roundtrip(65535); }
    @Test public void exactlyChunk() throws Exception { roundtrip(65536); }
    @Test public void crossChunk() throws Exception { roundtrip(65537); }
    @Test public void multipleChunks() throws Exception { roundtrip(196621); }

    @Test public void twoEncryptionsAreDifferent() throws Exception {
        SecretKey key = randomKey();
        assertFalse(Arrays.equals(encrypt(key, new byte[150]), encrypt(key, new byte[150])));
    }
    @Test public void wrongKeyRejected() throws Exception {
        byte[] ct = encrypt(randomKey(), new byte[300]);
        try { decrypt(randomKey(), ct); fail("Wrong Keystore key accepted"); }
        catch (GeneralSecurityException expected) {}
    }
    @Test public void headerCorruptionRejected() throws Exception {
        SecretKey key = randomKey();
        byte[] ct = encrypt(key, new byte[32]);
        ct[0] ^= 1;
        try { decrypt(key, ct); fail("Corrupt header accepted"); }
        catch (IOException expected) {}
    }
    @Test public void wrappedDekTamperingRejected() throws Exception {
        SecretKey key = randomKey();
        byte[] ct = encrypt(key, new byte[300]);
        ct[33] ^= 1;
        try { decrypt(key, ct); fail("Corrupted key envelope accepted"); }
        catch (GeneralSecurityException expected) {}
    }
    @Test public void ciphertextTamperingRejected() throws Exception {
        SecretKey key = randomKey();
        byte[] ct = encrypt(key, new byte[300]);
        ct[ct.length - 35] ^= 1;
        try { decrypt(key, ct); fail("Corrupted data accepted"); }
        catch (GeneralSecurityException expected) {}
    }
    @Test public void tamperedTerminalRejected() throws Exception {
        SecretKey key = randomKey();
        byte[] ct = encrypt(key, new byte[0]);
        ct[ct.length - 1] ^= 1;
        try { decrypt(key, ct); fail("Wrong EOF tag accepted"); }
        catch (GeneralSecurityException expected) {}
    }
    @Test public void trailingJunkRejected() throws Exception {
        SecretKey key = randomKey();
        byte[] ct = encrypt(key, new byte[0]);
        byte[] enlarged = Arrays.copyOf(ct, ct.length + 1);
        try { decrypt(key, enlarged); fail("Trailing junk accepted"); }
        catch (IOException expected) {}
    }
    @Test public void allTruncatedPrefixesRejected() throws Exception {
        SecretKey key = randomKey();
        byte[] ct = encrypt(key, new byte[70]);
        for (int n = 0; n < ct.length; n++) {
            try { decrypt(key, Arrays.copyOf(ct, n)); fail("Accepted truncation at " + n); }
            catch (IOException | GeneralSecurityException expected) {}
        }
    }
    @Test public void wrongRecordLengthRejected() throws Exception {
        SecretKey key = randomKey();
        byte[] ct = encrypt(key, new byte[200]);
        final int recordLengthOffset = "KRYPTA-MOBILE/1\n".length() + 8 + 12 + 48;
        Arrays.fill(ct, recordLengthOffset, recordLengthOffset + 4, (byte)0xFF);
        try { decrypt(key, ct); fail("Bad record size accepted"); }
        catch (IOException expected) {}
    }
}