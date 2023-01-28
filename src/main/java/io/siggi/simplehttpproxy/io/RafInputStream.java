package io.siggi.simplehttpproxy.io;

import java.io.IOException;
import java.io.InputStream;
import java.io.RandomAccessFile;

public class RafInputStream extends InputStream {

    private final RandomAccessFile raf;
    private final boolean autoClose;
    private long markPos = -1L;

    public RafInputStream(RandomAccessFile raf, boolean autoClose) {
        this.raf = raf;
        this.autoClose = autoClose;
    }

    @Override
    public int read() throws IOException {
        return raf.read();
    }

    @Override
    public int read(byte[] b) throws IOException {
        return raf.read(b);
    }

    @Override
    public int read(byte[] b, int o, int l) throws IOException {
        return raf.read(b, o, l);
    }

    @Override
    public void mark(int limit) {
        try {
            markPos = raf.getFilePointer();
        } catch (IOException ex) {
            markPos = -2L;
        }
    }

    @Override
    public boolean markSupported() {
        return true;
    }

    @Override
    public void reset() throws IOException {
        if (markPos == -2L) {
            throw new IOException("Mark failed");
        }
        if (markPos == -1L) {
            throw new IOException("Never marked");
        }
        raf.seek(markPos);
    }

    @Override
    public long skip(long n) throws IOException {
        return raf.skipBytes((int) Math.min(n, Integer.MAX_VALUE));
    }

    @Override
    public void close() throws IOException {
        if (autoClose) {
            raf.close();
        }
    }

}
