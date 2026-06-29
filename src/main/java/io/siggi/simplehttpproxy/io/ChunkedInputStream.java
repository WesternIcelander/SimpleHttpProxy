package io.siggi.simplehttpproxy.io;

import java.io.IOException;
import java.io.InputStream;
import java.util.Arrays;

public final class ChunkedInputStream extends InputStream {

    private final InputStream in;
    private final byte[] singleByte = new byte[1];
    private long remainingInChunk = 0;
    private boolean endOfStream = false;
    private boolean receivedTerminatorChunk = false;
    private boolean expectCRLFBeforeChunkSize = false;

    public ChunkedInputStream(InputStream in) {
        this.in = in;
    }

    private static final int[] decodeCharset = new int[0x67];
    static {
        Arrays.fill(decodeCharset, -1);
        decodeCharset['0'] = 0;
        decodeCharset['1'] = 1;
        decodeCharset['2'] = 2;
        decodeCharset['3'] = 3;
        decodeCharset['4'] = 4;
        decodeCharset['5'] = 5;
        decodeCharset['6'] = 6;
        decodeCharset['7'] = 7;
        decodeCharset['8'] = 8;
        decodeCharset['9'] = 9;

        decodeCharset['A'] = 10;
        decodeCharset['B'] = 11;
        decodeCharset['C'] = 12;
        decodeCharset['D'] = 13;
        decodeCharset['E'] = 14;
        decodeCharset['F'] = 15;

        decodeCharset['a'] = 10;
        decodeCharset['b'] = 11;
        decodeCharset['c'] = 12;
        decodeCharset['d'] = 13;
        decodeCharset['e'] = 14;
        decodeCharset['f'] = 15;
    }

    private long readChunkSize(boolean needNow) throws IOException {
        if (expectCRLFBeforeChunkSize) {
            if (!needNow && in.available() < 2) return -1L;
            if (in.read() != 0x0D || in.read() != 0x0A) {
                throw new IOException("Expected CRLF at end of chunk");
            }
            expectCRLFBeforeChunkSize = false;
        }
        if (!needNow && in.available() < 1) return -1L;
        long size = 0L;
        int sizeOfSize = 0;
        do {
            int c = in.read();
            if (c == 0x0D) {
                if (in.read() == 0x0A) {
                    if (size == 0L) {
                        receivedTerminatorChunk = true;
                        if (in.read() != 0x0D || in.read() != 0x0A) {
                            throw new IOException("Expected CRLF at end of chunk");
                        }
                    }
                    expectCRLFBeforeChunkSize = true;
                    return size;
                } else {
                    throw new IOException("Malformed chunk size encoding");
                }
            }
            if ((++sizeOfSize) > 16) throw new IOException("Malformed chunk size encoding");
            if (c < 0 || c > decodeCharset.length) throw new IOException("Malformed chunk size encoding");
            int value = decodeCharset[c];
            if (value == -1) throw new IOException("Malformed chunk size encoding");
            size <<= 4;
            size |= value;
            if (size < 0L) throw new IOException("Malformed chunk size encoding");
        } while (true);
    }

    @Override
    public int read() throws IOException {
        int read = read(singleByte, 0, 1);
        if (read == -1) {
            return -1;
        }
        return ((int) (singleByte[0])) & 0xff;
    }

    @Override
    public int read(byte[] buffer) throws IOException {
        return read(buffer, 0, buffer.length);
    }

    @Override
    public int read(byte[] buffer, int offset, int length) throws IOException {
        if (endOfStream) {
            return -1;
        }
        int maxRead;
        if (remainingInChunk <= 0L) {
            remainingInChunk = readChunkSize(true);
            if (remainingInChunk == 0L) {
                endOfStream = true;
                return -1;
            }
        }
        if (remainingInChunk > Integer.MAX_VALUE) {
            maxRead = Integer.MAX_VALUE;
        } else {
            maxRead = (int) remainingInChunk;
        }
        int actualLength = Math.min(length, maxRead);
        int readAmount = in.read(buffer, offset, actualLength);
        if (readAmount == -1) {
            endOfStream = true;
            return readAmount;
        }
        remainingInChunk -= readAmount;
        if (remainingInChunk == 0L) {
            remainingInChunk = readChunkSize(false);
            if (remainingInChunk == 0L) {
                endOfStream = true;
            }
        }
        return readAmount;
    }

    public boolean didReceiveTerminatorChunk() {
        return receivedTerminatorChunk;
    }
}
