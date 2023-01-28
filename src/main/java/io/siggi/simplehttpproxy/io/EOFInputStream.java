package io.siggi.simplehttpproxy.io;

import java.io.IOException;
import java.io.InputStream;
import java.util.Arrays;

public final class EOFInputStream extends InputStream {

    private final SecureBufferedInputStream in;
    private final byte[] singleByte = new byte[1];
    // the buffer is only used inside read0()
    // it is safe to overwrite the buffer with 0's outside of read0() as
    // data written to it is never reused after exiting the method
    private byte[] buffer = new byte[4096];
    private byte[] eofSequence = null;
    private boolean reachedEofSequence = false;

    public EOFInputStream(InputStream in) {
        if (in instanceof SecureBufferedInputStream) {
            this.in = (SecureBufferedInputStream) in;
        } else {
            this.in = new SecureBufferedInputStream(in);
        }
    }

    /**
     *
     */
    public void nextEofSequence() {
        clearEofSequence();
    }

    private void clearEofSequence() {
        if (reachedEofSequence) {
            if (this.eofSequence != null) {
                try {
                    in.skip(this.eofSequence.length);
                } catch (Exception e) {
                }
            }
        }
        reachedEofSequence = false;
    }

    /**
     * Treat these bytes as EOF. The bytes are consumed from the stream if they
     * are reached. They're not considered reached if no read operation returned
     * a -1 yet. Set to null to disable this feature when not needed.
     *
     * @param eofSequence
     */
    public void setEofSequence(byte[] eofSequence) {
        clearEofSequence();
        if (eofSequence == null || eofSequence.length == 0) {
            this.eofSequence = null;
            return;
        }
        this.eofSequence = new byte[eofSequence.length];
        System.arraycopy(eofSequence, 0, this.eofSequence, 0, eofSequence.length);
    }

    /**
     * This does absolutely nothing, use doClose() instead to close the stream.
     */
    @Override
    public void close() {
    }

    public void doClose() throws IOException {
        in.close();
    }

    @Override
    public int read() throws IOException {
        if (read(singleByte) == -1) {
            return -1;
        } else {
            return singleByte[0] & 0xff;
        }
    }

    @Override
    public int read(byte[] b) throws IOException {
        return read(b, 0, b.length);
    }

    @Override
    public int read(byte[] b, int offset, int length) throws IOException {
        int x = read0(b, offset, length);
        if (x <= 0) {
            x = -1;
        }
        return x;
    }

    private int read0(byte[] b, int offset, int length) throws IOException {
        if (reachedEofSequence) {
            return -1;
        }
        if (eofSequence == null) {
            return in.read(b, offset, length);
        }
        int bufferSize = length + eofSequence.length;
        in.mark(bufferSize);
        if (buffer.length < bufferSize) {
            for (int i = 0; i < buffer.length; i++) {
                buffer[i] = (byte) 0;
            }
            buffer = new byte[bufferSize];
        }
        int amountRead = in.read(buffer, 0, bufferSize);
        if (amountRead == -1) {
            return -1;
        }
        int initialSearch = search(buffer, amountRead, eofSequence);
        if (initialSearch < 0) {
            if (amountRead > length) {
                in.reset();
                in.skip(length);
                amountRead = length;
            }
            System.arraycopy(buffer, 0, b, offset, amountRead);
            return amountRead;
        } else if (initialSearch == 0) {
            if (amountRead >= eofSequence.length) {
                reachedEofSequence = true;
                in.reset();
                return -1;
            }
            while (true) {
                int r = in.read(buffer, amountRead, bufferSize - amountRead);
                if (r == -1) {
                    int amountToCopy = Math.min(length, amountRead);
                    System.arraycopy(buffer, 0, b, offset, amountToCopy);
                    in.reset();
                    in.skip(amountToCopy);
                    return amountToCopy;
                }
                amountRead += r;
                initialSearch = search(buffer, amountRead, eofSequence);
                if (amountRead >= eofSequence.length && initialSearch == 0) {
                    reachedEofSequence = true;
                    in.reset();
                    return -1;
                } else if (initialSearch < 0) {
                    if (amountRead > length) {
                        in.reset();
                        in.skip(length);
                        amountRead = length;
                    }
                    System.arraycopy(buffer, 0, b, offset, amountRead);
                    return amountRead;
                } else if (initialSearch > 0) {
                    if (amountRead - initialSearch >= eofSequence.length) {
                        reachedEofSequence = true;
                    }
                    int amountToCopy = Math.min(length, initialSearch);
                    System.arraycopy(buffer, 0, b, offset, amountToCopy);
                    in.reset();
                    in.skip(amountToCopy);
                    return amountToCopy;
                }
            }
        } else {
            if (amountRead - initialSearch >= eofSequence.length) {
                reachedEofSequence = true;
            }
            int amountToCopy = Math.min(length, initialSearch);
            System.arraycopy(buffer, 0, b, offset, amountToCopy);
            in.reset();
            in.skip(amountToCopy);
            return amountToCopy;
        }
    }

    private int search(byte[] haystack, int haystackLength, byte[] needle) {
        search:
        for (int i = 0; i < haystackLength; i++) {
            for (int j = 0; j < needle.length && i + j < haystackLength; j++) {
                if (haystack[i + j] != needle[j]) {
                    continue search;
                }
            }
            return i;
        }
        return -1;
    }

    public void eraseFreeSpace() {
        Arrays.fill(buffer, (byte) 0);
        in.eraseFreeSpace();
    }
}
