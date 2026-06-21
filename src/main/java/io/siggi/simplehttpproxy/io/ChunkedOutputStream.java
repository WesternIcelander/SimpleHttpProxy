package io.siggi.simplehttpproxy.io;

import java.io.IOException;
import java.io.OutputStream;

public final class ChunkedOutputStream extends OutputStream {

    private final OutputStream out;
    private boolean closed = false;
    private byte[] buffer = new byte[4096];
    public ChunkedOutputStream(OutputStream out) {
        this.out = out;
    }

    @Override
    public void write(int b) throws IOException {
        if (closed) {
            throw new IOException("Stream closed!");
        }
        buffer[0] = (byte) 0x31;
        buffer[1] = (byte) 0x0D;
        buffer[2] = (byte) 0x0A;
        buffer[3] = (byte) b;
        buffer[4] = (byte) 0x0D;
        buffer[5] = (byte) 0x0A;
        out.write(buffer, 0, 6);
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
        byte[] integerBytes = Integer.toString(len, 16).getBytes();
        int minBufferSize = integerBytes.length + len + 4;
        if (buffer.length < minBufferSize) {
            buffer = new byte[minBufferSize];
        }
        int bOffset = 0;
        System.arraycopy(integerBytes, 0, buffer, bOffset, integerBytes.length);
        bOffset += integerBytes.length;
        buffer[bOffset++] = (byte) 0x0D;
        buffer[bOffset++] = (byte) 0x0A;
        System.arraycopy(b, off, buffer, bOffset, len);
        bOffset += len;
        buffer[bOffset++] = (byte) 0x0D;
        buffer[bOffset++] = (byte) 0x0A;
        out.write(buffer, 0, bOffset);
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
        buffer[0] = (byte) 0x30;
        buffer[1] = (byte) 0x0D;
        buffer[2] = (byte) 0x0A;
        buffer[3] = (byte) 0x0D;
        buffer[4] = (byte) 0x0A;
        out.write(buffer, 0, 5);
        out.flush();
    }
}
