package io.siggi.simplehttpproxy.io;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;

/**
 * An {@link OutputStream} that writes data in HTTP chunked encoding.
 */
public final class ChunkedOutputStream extends OutputStream {

    private final OutputStream out;
    private boolean closed = false;
    private final int maxBufferSize;
    private final boolean relayClose;
    private int bufferSize = 0;
    private byte[] buffer;
    private int dataStart;
    private int bufferOffset;

    private boolean buffering = true;

    private int chunkStart = 0;
    private int chunkLength = 0;

    public ChunkedOutputStream(OutputStream out) {
        this(out, true);
    }

    public ChunkedOutputStream(OutputStream out, boolean relayClose) {
        this(out, 8192, 16384, relayClose);
    }

    public ChunkedOutputStream(OutputStream out, int initialBufferSize, int maxBufferSize, boolean relayClose) {
        this.out = out;
        this.maxBufferSize = maxBufferSize;
        this.relayClose = relayClose;
        newBuffer(initialBufferSize);
    }

    private static int chunkOverhead(int bufferSize) {
        return 4 + Integer.toString(bufferSize, 16).length();
    }

    /**
     * Set whether to buffer writes which may be combined into a single chunk, or to send writes immediately. When
     * disabling buffering, any data that's buffered will remain buffered until the next write or when you flush or
     * close the stream, whichever happens first.
     *
     * @param buffering true to buffer writes, false to send writes immediately
     */
    public void setBuffering(boolean buffering) {
        this.buffering = buffering;
    }

    public boolean isBuffering() {
        return buffering;
    }

    @Override
    public void write(int b) throws IOException {
        if (closed) {
            throw new IOException("Stream closed!");
        }
        if (freeSpaceInBuffer() < 1) sendChunk();
        buffer[bufferOffset++] = (byte) b;
        if (!buffering) sendChunk();
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
        if (len == 0) return;
        while (len > 0) {
            int freeSpace = freeSpaceInBuffer();
            if (freeSpace < len && bufferOffset == dataStart) {
                newBuffer(len);
            }
            int writeAmount = Math.min(len, freeSpace);
            if (writeAmount > 0) {
                System.arraycopy(b, off, buffer, bufferOffset, writeAmount);
                bufferOffset += writeAmount;
                off += writeAmount;
                len -= writeAmount;
            }
            if (len == 0) break;
            sendChunk();
        }
        if (!buffering) sendChunk();
    }

    private void newBuffer(int newSize) {
        newSize = Math.min(Math.max(newSize, bufferSize * 2), maxBufferSize);
        if (bufferSize == newSize) return;
        int chunkOverhead = chunkOverhead(newSize);
        bufferSize = newSize;
        buffer = new byte[newSize + chunkOverhead];
        dataStart = chunkOverhead - 2;
        bufferOffset = dataStart;
    }

    private int freeSpaceInBuffer() {
        return buffer.length - 2 - bufferOffset;
    }

    private void finalizeChunk() {
        byte[] chunkSize = Integer.toString(bufferOffset - dataStart, 16).getBytes(StandardCharsets.UTF_8);
        chunkStart = dataStart - 2 - chunkSize.length;
        chunkLength = bufferOffset - chunkStart + 2;
        System.arraycopy(chunkSize, 0, buffer, chunkStart, chunkSize.length);
        buffer[dataStart - 2] = (byte) 0x0D;
        buffer[dataStart - 1] = (byte) 0x0A;
        buffer[chunkStart + chunkLength - 2] = (byte) 0x0D;
        buffer[chunkStart + chunkLength - 1] = (byte) 0x0A;
    }

    private void sendChunk() throws IOException {
        if (bufferOffset == dataStart) return;
        finalizeChunk();
        out.write(buffer, chunkStart, chunkLength);
        bufferOffset = dataStart;
    }

    @Override
    public void flush() throws IOException {
        if (closed) {
            return;
        }
        sendChunk();
        out.flush();
    }

    @Override
    public void close() throws IOException {
        if (closed) {
            return;
        }
        closed = true;
        IOException exception = null;
        try {
            finalizeChunk();
            int length = chunkLength;
            boolean additionalFinalizeAndSend = false;
            if (bufferOffset != dataStart) {
                if (freeSpaceInBuffer() >= 5) {
                    int pos = chunkStart + chunkLength;
                    buffer[pos++] = (byte) 0x30;
                    buffer[pos++] = (byte) 0x0D;
                    buffer[pos++] = (byte) 0x0A;
                    buffer[pos++] = (byte) 0x0D;
                    buffer[pos++] = (byte) 0x0A;
                    length += 5;
                } else {
                    additionalFinalizeAndSend = true;
                }
            }
            out.write(buffer, chunkStart, length);
            bufferOffset = dataStart;
            if (additionalFinalizeAndSend) {
                finalizeChunk();
                out.write(buffer, chunkStart, chunkLength);
            }
            out.flush();
        } catch (IOException ioe) {
            exception = ioe;
        } finally {
            if (relayClose) {
                try {
                    out.close();
                } catch (IOException ioe) {
                    if (exception != null) exception.addSuppressed(ioe);
                    else exception = ioe;
                }
            }
        }
        if (exception != null) throw exception;
    }
}
