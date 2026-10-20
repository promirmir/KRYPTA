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
 * Research-only Android KRYPTA-MOBILE/1; NOT compatible with desktop .kry.
 * Per-file random 256-bit DEK, wrapped with AndroidKeystore AES-GCM.
 * Independent AES-GCM authenticated 64KiB chunks and an authenticated EOF.
 * Decryption callers MUST use a disposable app-private temp file until all
 * chunks are verified. This is not entire-phone encryption or key recovery.
 */
public final class VaultFormat {
    private VaultFormat() {}
    private static final byte[] MAGIC = "KRYPTA-MOBILE/1\n".getBytes(StandardCharsets.US_ASCII);
    private static final int CHUNK = 65536, TAG = 16, MAX_RECORDS = 1 << 20;
    private static final int HEADER_BYTES = MAGIC.length + 8 + 12 + 48;
    private static final String CIPHER = "AES/GCM/NoPadding";

    private static byte[] nonce(byte[] prefix, int index) {
        return ByteBuffer.allocate(12).put(prefix).putInt(index).array();
    }
    private static void aad(Cipher cipher, byte[] header, int index, int length, boolean terminal) {
        cipher.updateAAD(header);
        cipher.updateAAD(ByteBuffer.allocate(9).putInt(index).putInt(length)
                .put((byte)(terminal ? 1 : 0)).array());
    }
    private static int fill(InputStream src, byte[] buffer) throws IOException {
        int used = 0;
        while (used < buffer.length) {
            int n = src.read(buffer, used, buffer.length - used);
            if (n < 0) break;
            if (n == 0) {
                int c = src.read();
                if (c < 0) break;
                buffer[used++] = (byte)c;
            } else used += n;
        }
        return used;
    }

    public static long encrypt(SecretKey wrappingKey, InputStream source,
                               OutputStream target, SecureRandom random)
            throws IOException, GeneralSecurityException {
        byte[] dek = new byte[32], prefix = new byte[8];
        random.nextBytes(dek);
        random.nextBytes(prefix);
        try {
            Cipher wrap = Cipher.getInstance(CIPHER);
            wrap.init(Cipher.ENCRYPT_MODE, wrappingKey, random);
            byte[] wrapIv = wrap.getIV();
            if (wrapIv.length != 12) throw new GeneralSecurityException("Invalid key-wrap IV");
            wrap.updateAAD(MAGIC);
            wrap.updateAAD(prefix);
            byte[] wrapped = wrap.doFinal(dek);
            if (wrapped.length != 48) throw new GeneralSecurityException("Invalid key envelope");
            ByteArrayOutputStream hb = new ByteArrayOutputStream(HEADER_BYTES);
            hb.write(MAGIC);
            hb.write(prefix);
            hb.write(wrapIv);
            hb.write(wrapped);
            byte[] header = hb.toByteArray();
            DataOutputStream out = new DataOutputStream(target);
            out.write(header);
            SecretKey dataKey = new SecretKeySpec(dek, "AES");
            byte[] block = new byte[CHUNK];
            long total = 0;
            int index = 0;
            try {
                while (true) {
                    int n = fill(source, block);
                    if (n == 0) break;
                    if (index >= MAX_RECORDS) throw new IOException("File capacity limit");
                    Cipher cipher = Cipher.getInstance(CIPHER);
                    cipher.init(Cipher.ENCRYPT_MODE, dataKey,
                            new GCMParameterSpec(128, nonce(prefix, index)));
                    aad(cipher, header, index, n, false);
                    byte[] encrypted = cipher.doFinal(block, 0, n);
                    out.writeInt(encrypted.length);
                    out.write(encrypted);
                    total += n;
                    index++;
                }
                Cipher end = Cipher.getInstance(CIPHER);
                end.init(Cipher.ENCRYPT_MODE, dataKey,
                        new GCMParameterSpec(128, nonce(prefix, index)));
                aad(end, header, index, 0, true);
                byte[] last = end.doFinal(new byte[0]);
                out.writeInt(last.length);
                out.write(last);
                out.flush();
                return total;
            } finally {
                Arrays.fill(block, (byte)0);
            }
        } finally {
            Arrays.fill(dek, (byte)0);
        }
    }

    /**
     * This method may write authenticated PLAINTEXT before later corruption is
     * detected. Destination MUST be app-private temporary storage and discarded
     * on ANY failure before user-selected plaintext export.
     */
    public static long decrypt(SecretKey wrappingKey, InputStream source, OutputStream target)
            throws IOException, GeneralSecurityException {
        DataInputStream input = new DataInputStream(source);
        byte[] header = new byte[HEADER_BYTES];
        input.readFully(header);
        for (int i = 0; i < MAGIC.length; i++)
            if (header[i] != MAGIC[i]) throw new IOException("Unsupported mobile format");
        int p = MAGIC.length;
        byte[] prefix = Arrays.copyOfRange(header, p, p + 8);
        p += 8;
        byte[] iv = Arrays.copyOfRange(header, p, p + 12);
        p += 12;
        byte[] wrapped = Arrays.copyOfRange(header, p, p + 48);
        Cipher unwrap = Cipher.getInstance(CIPHER);
        unwrap.init(Cipher.DECRYPT_MODE, wrappingKey, new GCMParameterSpec(128, iv));
        unwrap.updateAAD(MAGIC);
        unwrap.updateAAD(prefix);
        byte[] dek = unwrap.doFinal(wrapped);
        try {
            if (dek.length != 32) throw new GeneralSecurityException("Invalid data key");
            SecretKey dk = new SecretKeySpec(dek, "AES");
            long total = 0;
            for (int i = 0; i <= MAX_RECORDS; i++) {
                int length;
                try { length = input.readInt(); }
                catch (EOFException exc) { throw new IOException("Authenticated EOF missing", exc); }
                if (length < TAG || length > CHUNK + TAG)
                    throw new IOException("Invalid chunk length");
                byte[] ciphertext = new byte[length];
                input.readFully(ciphertext);
                boolean terminal = length == TAG;
                Cipher cipher = Cipher.getInstance(CIPHER);
                cipher.init(Cipher.DECRYPT_MODE, dk,
                        new GCMParameterSpec(128, nonce(prefix, i)));
                aad(cipher, header, i, length - TAG, terminal);
                byte[] plaintext = cipher.doFinal(ciphertext);
                if (terminal) {
                    if (plaintext.length != 0 || input.read() != -1)
                        throw new IOException("Invalid EOF / trailing data");
                    target.flush();
                    return total;
                }
                if (i >= MAX_RECORDS || plaintext.length != length - TAG || plaintext.length == 0)
                    throw new IOException("Invalid data record");
                target.write(plaintext);
                total += plaintext.length;
                Arrays.fill(plaintext, (byte)0);
            }
            throw new IOException("Too many encrypted records");
        } finally {
            Arrays.fill(dek, (byte)0);
        }
    }
}