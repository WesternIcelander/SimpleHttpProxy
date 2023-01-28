package io.siggi.simplehttpproxy.io;

import java.io.IOException;
import java.io.OutputStream;

public final class TeeOutputStream extends OutputStream {

    private final OutputStream out1;
    private final OutputStream out2;

    public TeeOutputStream(OutputStream out1, OutputStream out2) {
        this.out1 = out1;
        this.out2 = out2;
    }

    @Override
    public void close() throws IOException {
        try {
            out1.close();
        } catch (Exception e) {
        }
        try {
            out2.close();
        } catch (Exception e) {
        }
    }

    @Override
    public void flush() throws IOException {
        out1.flush();
        out2.flush();
    }

    @Override
    public void write(byte[] b) throws IOException {
        out1.write(b);
        out2.write(b);
    }

    @Override
    public void write(byte[] b, int offset, int length) throws IOException {
        out1.write(b, offset, length);
        out2.write(b, offset, length);
    }

    @Override
    public void write(int b) throws IOException {
        out1.write(b);
        out2.write(b);
    }

}
