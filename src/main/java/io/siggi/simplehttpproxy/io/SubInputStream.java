package io.siggi.simplehttpproxy.io;

import java.io.IOException;
import java.io.InputStream;

public final class SubInputStream extends InputStream {

    private final InputStream in;
    private long left;

    public SubInputStream(InputStream in, long maxRead) {
        this.in = in;
        this.left = maxRead;
    }

    @Override
    public int read() throws IOException {
        if (left == 0L) {
            return -1;
        }
        int read = in.read();
        if (read == -1) {
            return -1;
        }
        left -= 1;
        return read;
    }

    @Override
    public int read(byte[] b) throws IOException {
        return read(b, 0, b.length);
    }

    @Override
    public int read(byte[] b, int offset, int len) throws IOException {
        if (left == 0L) {
            return -1;
        }
        int max = Math.min(len, (int) Math.min(Integer.MAX_VALUE, left));
        int amountRead = in.read(b, offset, max);
        if (amountRead >= 0) {
            left -= amountRead;
        }
        return amountRead;
    }

}
