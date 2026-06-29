package io.siggi.simplehttpproxy.io;

import java.io.IOException;
import java.io.OutputStream;

public class ToggleableBufferedOutputStream extends OutputStream {
    private final OutputStream out;
    private boolean active = false;
    private int count = 0;
    private final byte[] buffer;

    public ToggleableBufferedOutputStream(OutputStream out) {
        this(out, 8192);
    }

    public ToggleableBufferedOutputStream(OutputStream out, int bufferSize) {
        if (out == null) throw new NullPointerException();
        if (bufferSize <= 0) throw new IllegalArgumentException("Buffer size <= 0");
        this.out = out;
        this.buffer = new byte[bufferSize];
    }

    @Override
    public void write(int b) throws IOException {
        if (active) {
            if (count >= buffer.length) flushBuffer();
            buffer[count++] = (byte) b;
        } else if (count > 0 && count < buffer.length) {
            buffer[count++] = (byte) b;
            flushBuffer();
        } else {
            flushBuffer();
            out.write(b);
        }
    }

    @Override
    public void write(byte[] b, int off, int len) throws IOException {
        if (active) {
            if (count > 0) {
                int initialCopySize = Math.min(len, buffer.length - count);
                System.arraycopy(b, off, buffer, count, initialCopySize);
                count += initialCopySize;
                off += initialCopySize;
                len -= initialCopySize;
                if (count == buffer.length) flushBuffer();
            }
            if (len >= buffer.length) {
                flushBuffer();
                out.write(b, off, len);
            } else {
                System.arraycopy(b, off, buffer, count, len);
                count += len;
            }
        } else {
            if (count > 0) {
                int initialCopySize = Math.min(len, buffer.length - count);
                System.arraycopy(b, off, buffer, count, initialCopySize);
                count += initialCopySize;
                off += initialCopySize;
                len -= initialCopySize;
                flushBuffer();
            }
            if (len > 0) {
                out.write(b, off, len);
            }
        }
    }

    public void startBuffering() {
        active = true;
    }

    public void stopBuffering() throws IOException {
        stopBuffering(false);
    }

    public void stopBuffering(boolean delayedFlush) throws IOException {
        active = false;
        if (!delayedFlush) {
            flushBuffer();
        }
    }

    private void flushBuffer() throws IOException {
        if (count > 0) {
            out.write(buffer, 0, count);
            count = 0;
        }
    }

    @Override
    public void flush() throws IOException {
        flushBuffer();
        out.flush();
    }

    @Override
    public void close() throws IOException {
        flush();
        out.close();
    }
}
