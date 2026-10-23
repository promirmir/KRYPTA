package io.krypta.research;

import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * KRYPTA-MOBILE/2: two independent wraps for a random file DEK.
 *
 * Android Keystore remains the everyday unlock factor. The *independent*
 * 256-bit offline recovery secret permits verified recovery on a new phone
 * or on desktop. The secret MUST be backed up outside the Android device.
 * This is selected-file encryption only, not OS-wide FBE.
 *
 * Public format: magic(16), nonce prefix(8), Android wrap IV(12),
 * Android wrapped DEK(48), recovery IV(12), recovery wrapped DEK(48),
 * followed by authenticated 64 KiB streaming records. The entire public
 * header and sequence/size/EOF flags are bound into AES-GCM AAD.
 */
public final class MobileRecoveryFormat {
    public static final byte[] MAGIC = "KRYPTA-MOBILE/2\n".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] RECOVERY_DOMAIN = "RECOVERY/2".getBytes(StandardCharsets.US_ASCII);
    private static final String CIPHER = "AES/GCM/NoPadding";
    private static final int CHUNK = 65536, TAG = 16, MAX_RECORDS = 1 << 20;
    private static final int HEADER_LENGTH = MAGIC.length + 8 + 12 + 48 + 12 + 48;
    private MobileRecoveryFormat() {}

    private static byte[] nonce(byte[] prefix, int index) {
        return ByteBuffer.allocate(12).put(prefix).putInt(index).array();
    }

    private static void aad(Cipher cipher, byte[] header, int index, int size, boolean end) {
        cipher.updateAAD(header);
        cipher.updateAAD(ByteBuffer.allocate(9).putInt(index).putInt(size)
                .put((byte) (end ? 1 : 0)).array());
    }

    private static void wrapAad(Cipher cipher, byte[] prefix, boolean recovery) {
        cipher.updateAAD(MAGIC);
        cipher.updateAAD(prefix);
        if (recovery) cipher.updateAAD(RECOVERY_DOMAIN);
    }

    private static void checkRecoveryKey(byte[] key) throws GeneralSecurityException {
        if (key == null || key.length != 32)
            throw new GeneralSecurityException("An independent 32-byte recovery key is required");
    }

    private static int fill(InputStream input, byte[] dest) throws IOException {
        int n = 0;
        while (n < dest.length) {
            int count = input.read(dest, n, dest.length - n);
            if (count < 0) break;
            if (count == 0) {
                int single = input.read();
                if (single < 0) break;
                dest[n++] = (byte) single;
            } else n += count;
        }
        return n;
    }

    public static long encrypt(SecretKey deviceKey, byte[] recoveryKey,
                               InputStream source, OutputStream destination,
                               SecureRandom random) throws IOException, GeneralSecurityException {
        checkRecoveryKey(recoveryKey);
        if (deviceKey == null || random == null)
            throw new GeneralSecurityException("Device key and secure RNG are required");
        byte[] dek = new byte[32];
        byte[] prefix = new byte[8];
        byte[] buffer = new byte[CHUNK];
        random.nextBytes(dek);
        random.nextBytes(prefix);
        try {
            Cipher deviceWrap = Cipher.getInstance(CIPHER);
            deviceWrap.init(Cipher.ENCRYPT_MODE, deviceKey, random);
            wrapAad(deviceWrap, prefix, false);
            byte[] deviceIv = deviceWrap.getIV();
            byte[] deviceWrapped = deviceWrap.doFinal(dek);

            Cipher recoveryWrap = Cipher.getInstance(CIPHER);
            recoveryWrap.init(Cipher.ENCRYPT_MODE,
                    new SecretKeySpec(recoveryKey, "AES"), random);
            wrapAad(recoveryWrap, prefix, true);
            byte[] recoveryIv = recoveryWrap.getIV();
            byte[] recoveryWrapped = recoveryWrap.doFinal(dek);
            if (deviceIv.length != 12 || recoveryIv.length != 12 ||
                    deviceWrapped.length != 48 || recoveryWrapped.length != 48)
                throw new GeneralSecurityException("Unexpected AES-GCM wrap size");

            ByteArrayOutputStream headerBytes = new ByteArrayOutputStream(HEADER_LENGTH);
            headerBytes.write(MAGIC);
            headerBytes.write(prefix);
            headerBytes.write(deviceIv);
            headerBytes.write(deviceWrapped);
            headerBytes.write(recoveryIv);
            headerBytes.write(recoveryWrapped);
            byte[] header = headerBytes.toByteArray();
            SecretKey dataKey = new SecretKeySpec(dek, "AES");
            DataOutputStream out = new DataOutputStream(destination);
            out.write(header);
            int index = 0;
            long total = 0;
            while (true) {
                int count = fill(source, buffer);
                if (count == 0) break;
                if (index >= MAX_RECORDS) throw new IOException("Encrypted file record limit reached");
                Cipher cipher = Cipher.getInstance(CIPHER);
                cipher.init(Cipher.ENCRYPT_MODE, dataKey,
                        new GCMParameterSpec(128, nonce(prefix, index)));
                aad(cipher, header, index, count, false);
                byte[] sealed = cipher.doFinal(buffer, 0, count);
                out.writeInt(sealed.length);
                out.write(sealed);
                total += count;
                index++;
            }
            Cipher finalCipher = Cipher.getInstance(CIPHER);
            finalCipher.init(Cipher.ENCRYPT_MODE, dataKey,
                    new GCMParameterSpec(128, nonce(prefix, index)));
            aad(finalCipher, header, index, 0, true);
            out.writeInt(TAG);
            out.write(finalCipher.doFinal(new byte[0]));
            out.flush();
            return total;
        } finally {
            Arrays.fill(dek, (byte) 0);
            Arrays.fill(buffer, (byte) 0);
        }
    }

    public static long decrypt(SecretKey deviceKey, InputStream encrypted,
                               OutputStream verifiedTemp)
            throws IOException, GeneralSecurityException {
        if (deviceKey == null) throw new GeneralSecurityException("Missing Android device key");
        return decryptInternal(deviceKey, null, encrypted, verifiedTemp);
    }

    public static long recover(byte[] recoveryKey, InputStream encrypted,
                               OutputStream verifiedTemp)
            throws IOException, GeneralSecurityException {
        checkRecoveryKey(recoveryKey);
        return decryptInternal(null, recoveryKey, encrypted, verifiedTemp);
    }

    /**
     * Authenticates all records and final marker. Callers MUST output to an
     * app-private disposable temp file; earlier verified chunks are written
     * before later chunks can be checked, so never stream directly to SAF.
     */
    private static long decryptInternal(SecretKey deviceKey, byte[] recoveryKey,
                                        InputStream encrypted, OutputStream temp)
            throws IOException, GeneralSecurityException {
        DataInputStream input = new DataInputStream(encrypted);
        byte[] header = new byte[HEADER_LENGTH];
        input.readFully(header);
        for (int i = 0; i < MAGIC.length; i++)
            if (header[i] != MAGIC[i]) throw new IOException("Unsupported mobile recovery format");
        int position = MAGIC.length;
        byte[] prefix = Arrays.copyOfRange(header, position, position + 8);
        position += 8;
        int wrapOffset = recoveryKey == null ? position : position + 12 + 48;
        byte[] iv = Arrays.copyOfRange(header, wrapOffset, wrapOffset + 12);
        byte[] wrapped = Arrays.copyOfRange(header, wrapOffset + 12, wrapOffset + 60);
        Cipher unwrap = Cipher.getInstance(CIPHER);
        unwrap.init(Cipher.DECRYPT_MODE,
                recoveryKey == null ? deviceKey : new SecretKeySpec(recoveryKey, "AES"),
                new GCMParameterSpec(128, iv));
        wrapAad(unwrap, prefix, recoveryKey != null);
        byte[] dek = unwrap.doFinal(wrapped);
        if (dek.length != 32) throw new GeneralSecurityException("Invalid decrypted file key");
        try {
            SecretKey dataKey = new SecretKeySpec(dek, "AES");
            long total = 0;
            for (int i = 0; i <= MAX_RECORDS; i++) {
                int size;
                try { size = input.readInt(); }
                catch (EOFException exc) { throw new IOException("Missing authenticated EOF", exc); }
                if (size < TAG || size > CHUNK + TAG) throw new IOException("Invalid encrypted record length");
                byte[] ciphertext = new byte[size];
                input.readFully(ciphertext);
                boolean terminal = size == TAG;
                Cipher cipher = Cipher.getInstance(CIPHER);
                cipher.init(Cipher.DECRYPT_MODE, dataKey,
                        new GCMParameterSpec(128, nonce(prefix, i)));
                aad(cipher, header, i, size - TAG, terminal);
                byte[] plaintext = cipher.doFinal(ciphertext);
                if (terminal) {
                    if (plaintext.length != 0 || input.read() != -1)
                        throw new IOException("Invalid authenticated EOF or appended data");
                    temp.flush();
                    return total;
                }
                if (i == MAX_RECORDS || plaintext.length != size - TAG ||
                        plaintext.length == 0)
                    throw new IOException("Invalid record");
                temp.write(plaintext);
                total += plaintext.length;
                Arrays.fill(plaintext, (byte) 0);
            }
            throw new IOException("Too many encrypted records");
        } finally {
            Arrays.fill(dek, (byte) 0);
        }
    }
}
