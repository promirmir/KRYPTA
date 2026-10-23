package io.krypta.research;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.SecureRandom;
import java.util.Arrays;
import org.junit.Test;
import static org.junit.Assert.*;

public final class MobileRecoveryKeyReaderTest {
    @Test public void acceptsOnlyExactlyThirtyTwoBytes() throws Exception {
        byte[] raw = new byte[32];
        new SecureRandom().nextBytes(raw);
        assertArrayEquals(raw, MobileRecoveryKeyReader.readExact(
                new ByteArrayInputStream(raw)));
        for (int n : new int[] {0, 1, 16, 31, 33, 64}) {
            try {
                MobileRecoveryKeyReader.readExact(
                        new ByteArrayInputStream(Arrays.copyOf(raw, n)));
                fail("Accepted keyfile length " + n);
            } catch (IOException expected) {}
        }
    }

    @Test public void handlesFragmentedAndZeroLengthProviderReads() throws Exception {
        byte[] raw = new byte[32];
        Arrays.fill(raw, (byte) 77);
        InputStream provider = new ByteArrayInputStream(raw) {
            private boolean zeroNext = true;
            @Override public synchronized int read(byte[] b, int off, int len) {
                if (zeroNext) {
                    zeroNext = false;
                    return 0;
                }
                zeroNext = true;
                return super.read(b, off, Math.min(1, len));
            }
        };
        assertArrayEquals(raw, MobileRecoveryKeyReader.readExact(provider));
    }

    @Test public void doesNotCloseCallerOwnedStream() throws Exception {
        class Owned extends ByteArrayInputStream {
            boolean closed;
            Owned() { super(new byte[32]); }
            @Override public void close() throws IOException { closed = true; super.close(); }
        }
        Owned source = new Owned();
        assertEquals(32, MobileRecoveryKeyReader.readExact(source).length);
        assertFalse(source.closed);
    }

    @Test public void rejectsMissingInput() {
        try {
            MobileRecoveryKeyReader.readExact(null);
            fail("Missing provider stream accepted");
        } catch (IOException expected) {}
    }
}
