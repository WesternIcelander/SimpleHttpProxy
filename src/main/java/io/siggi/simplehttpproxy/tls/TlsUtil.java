package io.siggi.simplehttpproxy.tls;

import io.siggi.simplehttpproxy.io.IOUtil;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;

public class TlsUtil {

    private TlsUtil() {
    }

    public static byte[] readTlsPacket(InputStream in) throws IOException {
        return readTlsPacket(in, -1);
    }

    public static byte[] readTlsPacket(InputStream in, int maximumSize) throws IOException {
        int packetType = IOUtil.read(in);
        try {
            int versionMajor = IOUtil.read(in);
            int versionMinor = IOUtil.read(in);
            int length = IOUtil.readShortBE(in);
            if (maximumSize >= 0 && length > maximumSize) {
                throw new IOException("TLS packet exceeded maximum size");
            }
            byte[] buffer = new byte[5 + length];
            buffer[0] = (byte) packetType;
            buffer[1] = (byte) versionMajor;
            buffer[2] = (byte) versionMinor;
            buffer[3] = (byte) ((length >> 8) & 0xff);
            buffer[4] = (byte) (length & 0xff);
            IOUtil.readFully(in, buffer, 5, length);
            return buffer;
        } catch (IOException ioe) {
            throw new IOException("Malformed TLS packet");
        }
    }

    public static String readSNI(byte[] clientHello) {
        try {
            ByteArrayInputStream in = new ByteArrayInputStream(clientHello);
            // TLS fragment
            int packetType = in.read(); // should be 22
            if (packetType != 22) {
                return null;
            }
            int versionMajor = IOUtil.read(in);
            int versionMinor = IOUtil.read(in);
            int length = IOUtil.readShortBE(in);
            // handshake protocol
            int handshakeType = in.read();
            if (handshakeType != 1) { // clientHello
                return null;
            }

            in.skip(5);
            //int handshakeLength = IOUtil.readInt24BE(in);
            //int versionMajor2 = IOUtil.read(in);
            //int versionMinor2 = IOUtil.read(in);

            in.skip(32);
            //byte[] randomData = IOUtil.readFully(in, 32);

            in.skip(IOUtil.read(in));
            //byte[] sessionId = IOUtil.readFully(in, IOUtil.read(in));

            in.skip(IOUtil.readShortBE(in));
            //byte[] cipherSuites = IOUtil.readFully(in, IOUtil.readShortBE(in));

            in.skip(IOUtil.read(in));
            //byte[] compressionMethods = IOUtil.readFully(in, IOUtil.read(in));

            int extensionsLength = IOUtil.readShortBE(in);

            while (in.available() > 0) {
                int extType = IOUtil.readShortBE(in);
                int extLength = IOUtil.readShortBE(in);
                if (extType == 0) { // server_name
                    int listLength = IOUtil.readShortBE(in);
                    byte[] list = IOUtil.readFully(in, listLength);
                    ByteArrayInputStream sIn = new ByteArrayInputStream(list);
                    while (sIn.available() > 0) {
                        int serverNameType = sIn.read();
                        int serverNameLength = IOUtil.readShortBE(sIn);
                        byte[] serverName = IOUtil.readFully(sIn, serverNameLength);
                        if (serverNameType == 0) { // host_name
                            return new String(serverName, StandardCharsets.UTF_8);
                        }
                    }
                    return null;
                } else {
                    in.skip(extLength);
                }
            }
        } catch (IOException ioe) {
            return null;
        }
        return null;
    }
}
