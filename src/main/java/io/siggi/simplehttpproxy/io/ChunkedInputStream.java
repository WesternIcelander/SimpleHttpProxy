package io.siggi.simplehttpproxy.io;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;

public final class ChunkedInputStream extends InputStream {

    private final InputStream in;
    private final byte[] singleByte = new byte[1];
    private long remainingInChunk = 0;
    private boolean endOfStream = false;
    private boolean receivedTerminatorChunk = false;

    public ChunkedInputStream(InputStream in) {
        this.in = in;
    }

    private String readLine() throws IOException {
        int c;
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        boolean eof = true;
        while ((c = in.read()) != -1) {
            eof = false;
            if (c == 0x0A) {
                break;
            }
            baos.write(c);
        }
        String line = new String(baos.toByteArray(), StandardCharsets.UTF_8);
        if (line.endsWith("\r")) {
            line = line.substring(0, line.length() - 1);
        }
        if (line.isEmpty() && eof) {
            return null;
        }
        return line;
    }

    private long getChunkSize() throws IOException {
        int c = 0;
        String line;
        while ((line = readLine()) != null) {
            try {
                long s = Long.parseLong(line, 16);
                if (s == 0) {
                    receivedTerminatorChunk = true;
                }
                return s;
            } catch (Exception e) {
            }
            c += 1;
            if (c >= 3) {
                return 0L;
            }
        }
        return 0L;
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
            remainingInChunk = getChunkSize();
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
        return readAmount;
    }

    public boolean didReceiveTerminatorChunk() {
        return receivedTerminatorChunk;
    }
}
