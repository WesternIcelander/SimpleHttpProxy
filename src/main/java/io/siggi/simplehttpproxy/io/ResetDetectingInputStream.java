package io.siggi.simplehttpproxy.io;

import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.SocketException;

/**
 * Remembers whether a read failed because the remote end reset the
 * connection (TCP RST), so read failures can be told apart from failures
 * writing to the other side.
 */
public final class ResetDetectingInputStream extends FilterInputStream {

    private boolean reset = false;

    public ResetDetectingInputStream(InputStream in) {
        super(in);
    }

    public boolean wasReset() {
        return reset;
    }

    @Override
    public int read() throws IOException {
        try {
            return super.read();
        } catch (IOException e) {
            throw check(e);
        }
    }

    @Override
    public int read(byte[] b) throws IOException {
        return read(b, 0, b.length);
    }

    @Override
    public int read(byte[] b, int off, int len) throws IOException {
        try {
            return super.read(b, off, len);
        } catch (IOException e) {
            throw check(e);
        }
    }

    @Override
    public long skip(long n) throws IOException {
        try {
            return super.skip(n);
        } catch (IOException e) {
            throw check(e);
        }
    }

    private IOException check(IOException e) {
        if (isConnectionReset(e)) reset = true;
        return e;
    }

    public static boolean isConnectionReset(Throwable t) {
        // An SSLSocket may wrap the SocketException, so walk the cause chain
        for (int depth = 0; t != null && depth < 10; t = t.getCause(), depth++) {
            if (t instanceof SocketException) {
                String message = t.getMessage();
                if (message != null && message.startsWith("Connection reset")) return true;
            }
        }
        return false;
    }
}
