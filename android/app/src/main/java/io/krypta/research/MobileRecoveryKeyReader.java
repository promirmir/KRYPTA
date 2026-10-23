package io.krypta.research;

import java.io.IOException;
import java.io.InputStream;
import java.util.Arrays;

/**
 * Exact-length reader for independent portable recovery secret files.
 * No text, hex, passphrase, or shortened PIN is accepted as a 256-bit key.
 */
public final class MobileRecoveryKeyReader {
    private MobileRecoveryKeyReader() {}

    public static byte[] readExact(InputStream source) throws IOException {
        if (source == null) throw new IOException("Recovery keyfile is unavailable");
        byte[] candidate = new byte[33];
        int used = 0;
        try {
            while (used < candidate.length) {
                int n = source.read(candidate, used, candidate.length - used);
                if (n < 0) break;
                if (n == 0) {
                    int one = source.read();
                    if (one < 0) break;
                    candidate[used++] = (byte) one;
                } else used += n;
            }
            if (used != 32) throw new IOException("Recovery keyfile must contain exactly 32 raw bytes");
            return Arrays.copyOf(candidate, 32);
        } finally {
            Arrays.fill(candidate, (byte) 0);
        }
    }
}
