package io.siggi.simplehttpproxy.io;

import io.siggi.simplehttpproxy.exception.TooBigException;

import java.io.IOException;
import java.io.InputStream;

public final class ReadLimitInputStream extends InputStream {

    private final InputStream in;
    private long left;
    private boolean hitException = false;

    public ReadLimitInputStream(InputStream in, long maxBytes) {
        this.in = in;
        this.left = maxBytes;
    }

    @Override
    public int read() throws IOException {
        if (hitException) {
            throw new TooBigException();
        }
        int a = in.read();
        if (a != -1) {
            left -= 1;
        }
        if (left < 0) {
            hitException = true;
            throw new TooBigException();
        }
        return a;
    }

    @Override
    public int read(byte[] b) throws IOException {
        if (hitException) {
            throw new TooBigException();
        }
        int a = in.read(b);
        if (a > 0) {
            left -= a;
            if (left < 0) {
                hitException = true;
                throw new TooBigException();
            }
        }
        return a;
    }

    @Override
    public int read(byte[] b, int off, int len) throws IOException {
        if (hitException) {
            throw new TooBigException();
        }
        int a = in.read(b, off, len);
        if (a > 0) {
            left -= a;
            if (left < 0) {
                hitException = true;
                throw new TooBigException();
            }
        }
        return a;
    }

}
