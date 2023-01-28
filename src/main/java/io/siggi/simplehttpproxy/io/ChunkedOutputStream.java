package io.siggi.simplehttpproxy.io;

import java.io.IOException;
import java.io.OutputStream;

public final class ChunkedOutputStream extends OutputStream {

    private final OutputStream out;
    private boolean closed = false;
    public ChunkedOutputStream(OutputStream out) {
        this.out = out;
    }

    @Override
    public void write(int b) throws IOException {
        if (closed) {
            throw new IOException("Stream closed!");
        }
        out.write((Integer.toString(1, 16)).getBytes());
        out.write(0x0D);
        out.write(0x0A);
        out.write(b);
        out.write(0x0D);
        out.write(0x0A);
    }

    @Override
    public void write(byte[] b) throws IOException {
        write(b, 0, b.length);
    }

    @Override
    public void write(byte[] b, int off, int len) throws IOException {
        if (closed) {
            throw new IOException("Stream closed!");
        }
        out.write((Integer.toString(len, 16)).getBytes());
        out.write(0x0D);
        out.write(0x0A);
        out.write(b, off, len);
        out.write(0x0D);
        out.write(0x0A);
    }

    @Override
    public void flush() throws IOException {
        if (closed) {
            return;
        }
        out.flush();
    }

    @Override
    public void close() throws IOException {
        if (closed) {
            return;
        }
        closed = true;
        out.flush();
        out.write(0x30);
        out.write(0x0D);
        out.write(0x0A);
        out.write(0x0D);
        out.write(0x0A);
    }
}
