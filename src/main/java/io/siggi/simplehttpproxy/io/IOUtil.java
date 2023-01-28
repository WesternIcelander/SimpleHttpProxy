package io.siggi.simplehttpproxy.io;

import java.io.IOException;
import java.io.InputStream;

public class IOUtil {

    private IOUtil() {
    }

    private static IOException eof() {
        return new IOException("End of stream");
    }

    public static int read(InputStream in) throws IOException {
        int c = in.read();
        if (c == -1) {
            throw eof();
        }
        return c;
    }

    private static long readL(InputStream in) throws IOException {
        return read(in);
    }

    public static int readShortBE(InputStream in) throws IOException {
        return (read(in) << 8) + (read(in));
    }

    public static int readShortLE(InputStream in) throws IOException {
        return (read(in)) + (read(in) << 8);
    }

    public static int readInt24BE(InputStream in) throws IOException {
        return (read(in) << 16) + (read(in) << 8) + (read(in));
    }

    public static int readInt24LE(InputStream in) throws IOException {
        return (read(in)) + (read(in) << 8) + (read(in) << 16);
    }

    public static int readIntBE(InputStream in) throws IOException {
        return (read(in) << 24) + (read(in) << 16) + (read(in) << 8) + (read(in));
    }

    public static int readIntLE(InputStream in) throws IOException {
        return (read(in)) + (read(in) << 8) + (read(in) << 16) + (read(in) << 24);
    }

    public static long readLongBE(InputStream in) throws IOException {
        return (readL(in) << 56L) + (readL(in) << 48L) + (readL(in) << 40L) + (readL(in) << 32L)
                + (readL(in) << 24L) + (readL(in) << 16L) + (readL(in) << 8L) + (readL(in));
    }

    public static long readLongLE(InputStream in) throws IOException {
        return (readL(in)) + (readL(in) << 8L) + (readL(in) << 16L) + (readL(in) << 24L)
                + (readL(in) << 32L) + (readL(in) << 40L) + (readL(in) << 48L) + (readL(in) << 56L);
    }

    public static byte[] readFully(InputStream in, int length) throws IOException {
        return readFully(in, new byte[length], 0, length);
    }

    public static byte[] readFully(InputStream in, byte[] buffer, int offset, int length) throws IOException {
        int amountRead = 0;
        while (amountRead < length) {
            int c = in.read(buffer, offset + amountRead, length - amountRead);
            if (c == -1) {
                throw eof();
            }
            amountRead += c;
        }
        return buffer;
    }
}
