package io.siggi.simplehttpproxy.io;

import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.SocketTimeoutException;

public class SometimesTimeoutInputStream extends FilterInputStream {

    public SometimesTimeoutInputStream(InputStream in) {
        super(in);
    }

    private int throwTimeoutException = 0;

    public void setThrowTimeoutException(boolean throwTimeoutException) {
        this.throwTimeoutException = throwTimeoutException ? 1 : 0;
    }

    private boolean checkThrowException() {
        if (throwTimeoutException == 0) return false;
        if (throwTimeoutException == 1) {
            throwTimeoutException = 2;
            return false;
        }
        return true;
    }

    @Override
    public int read() throws IOException {
        while (true) {
            try {
                return super.read();
            } catch (SocketTimeoutException e) {
                if (checkThrowException()) throw e;
            }
        }
    }

    @Override
    public int read(byte[] buffer) throws IOException {
        while (true) {
            try {
                return super.read(buffer);
            } catch (SocketTimeoutException e) {
                if (checkThrowException()) throw e;
            }
        }
    }

    @Override
    public int read(byte[] buffer, int offset, int length) throws IOException {
        while (true) {
            try {
                return super.read(buffer, offset, length);
            } catch (SocketTimeoutException e) {
                if (checkThrowException()) throw e;
            }
        }
    }

    @Override
    public long skip(long count) throws IOException {
        while (true) {
            try {
                return super.skip(count);
            } catch (SocketTimeoutException e) {
                if (checkThrowException()) throw e;
            }
        }
    }
}
