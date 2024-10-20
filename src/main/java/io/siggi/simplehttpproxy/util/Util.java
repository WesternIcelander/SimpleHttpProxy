package io.siggi.simplehttpproxy.util;

import io.siggi.simplehttpproxy.exception.TooBigException;

import javax.net.ssl.SSLSocketFactory;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.MessageDigest;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.TimeZone;

public class Util {

    private static final SSLSocketFactory sslsf = (SSLSocketFactory) SSLSocketFactory.getDefault();

    public static String readCRLF(InputStream in, int sizeLimit) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream(sizeLimit > 0 ? Math.min(16384, sizeLimit) : 16384);
        int c;
        boolean cr = false;
        boolean r = false;
        while ((c = in.read()) != -1) {
            if (baos.size() >= sizeLimit) {
                throw new TooBigException();
            }
            r = true;
            if (c == 0x0D) {
                cr = true;
            } else if (cr && c == 0x0A) {
                break;
            } else {
                if (cr) {
                    cr = false;
                    baos.write(0x0D);
                }
                baos.write(c);
            }
        }
        if (!r) {
            return null;
        }
        return new String(baos.toByteArray(), StandardCharsets.UTF_8);
    }

    public static CaseInsensitiveHashMap<List<String>> readHeaders(InputStream in, int sizeLimit) throws IOException {
        CaseInsensitiveHashMap<List<String>> headers = new CaseInsensitiveHashMap<>();
        if (!readHeaders(in, headers, sizeLimit)) {
            return null;
        }
        return headers;
    }

    public static boolean readHeaders(InputStream in, Map<String, List<String>> headers, int sizeLimit) throws IOException {
        int totalSize = 0;
        String line;
        String key = null;
        String val = null;
        boolean readSomething = false;
        while ((line = readCRLF(in, sizeLimit)) != null) {
            totalSize += line.length() + 2;
            if (sizeLimit > 0 && totalSize > sizeLimit) {
                throw new TooBigException();
            }
            readSomething = true;
            if (line.isEmpty()) {
                break;
            }
            String trim = line.trim();
            if (trim.isEmpty()) {
                continue;
            }
            if (line.charAt(0) != trim.charAt(0)) {
                val += trim;
            } else {
                if (key != null && val != null) {
                    List<String> h = headers.get(key);
                    if (h == null) {
                        headers.put(key, h = new ArrayList<>());
                    }
                    h.add(val);
                    key = val = null;
                }
                int pos = line.indexOf(":");
                if (pos == -1) {
                    continue;
                }
                key = line.substring(0, pos).trim();
                val = line.substring(pos + 1).trim();
            }
        }
        if (key != null && val != null) {
            List<String> h = headers.get(key);
            if (h == null) {
                headers.put(key, h = new ArrayList<>());
            }
            h.add(val);
        }
        return readSomething;
    }

    public static void writeHeaders(Map<String, List<String>> headers, OutputStream out) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        for (Map.Entry<String, List<String>> entry : headers.entrySet()) {
            String header = entry.getKey();
            List<String> list = entry.getValue();
            for (String str : list) {
                writeCRLF(header + ": " + str, baos);
            }
        }
        writeCRLF("", baos);
        out.write(baos.toByteArray());
    }

    public static void writeCRLF(String str, OutputStream out) throws IOException {
        out.write((str + "\r\n").getBytes(StandardCharsets.UTF_8));
    }

    public static HttpHeader readHeader(InputStream in, int sizeLimit) throws IOException {
        String firstLine;
        do {
            firstLine = readCRLF(in, sizeLimit);
            if (firstLine == null) {
                return null;
            }
        } while (firstLine.isEmpty());
        CaseInsensitiveHashMap<List<String>> headers = readHeaders(in, sizeLimit);
        if (headers == null) {
            return null;
        }
        return new HttpHeader(firstLine, headers);
    }

    public static void writeHeader(OutputStream out, HttpHeader header) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        writeCRLF(header.getFirstLine(), baos);
        writeHeaders(header.getHeaders(), baos);
        out.write(baos.toByteArray());
    }

    public static Socket connect(String addr) throws IOException {
        String proto = "http";
        int protoSplitter = addr.indexOf("://");
        if (protoSplitter >= 0) {
            proto = addr.substring(0, protoSplitter);
            addr = addr.substring(protoSplitter + 3);
        } else if (addr.startsWith("//")) {
            addr = addr.substring(2);
        }
        String a;
        int pr;
        int p = addr.lastIndexOf(":");
        if (p == -1) {
            a = addr;
            pr = proto.equals("https") ? 443 : 80;
        } else {
            a = addr.substring(0, p);
            pr = Integer.parseInt(addr.substring(p + 1));
        }
        if (proto.equals("http")) {
            return new Socket(a, pr);
        } else if (proto.equals("https")) {
            String sniAddress = a;
            int openBracket = a.indexOf("{");
            if (openBracket >= 0) {
                int closeBracket = a.indexOf("}", openBracket);
                if (closeBracket >= 0) {
                    sniAddress = a.substring(openBracket + 1, closeBracket);
                    a = a.substring(0, openBracket);
                }
            }
            Socket rawSocket = new Socket(a, pr);
            return sslsf.createSocket(rawSocket, sniAddress, pr, true);
        } else {
            throw new IOException("Unknown protocol " + proto);
        }
    }

    public static void copy(InputStream in, OutputStream out) throws IOException {
        copy(in, out, null);
    }

    public static void copy(InputStream in, OutputStream out, CopyActivityMonitor monitor) throws IOException {
        byte[] buffer = new byte[4096];
        int c;
        while ((c = in.read(buffer, 0, buffer.length)) != -1) {
            if (monitor != null) monitor.copyActivity(c);
            if (out != null) {
                out.write(buffer, 0, c);
            }
        }
    }

    @FunctionalInterface
    public interface CopyActivityMonitor {
        void copyActivity(int amount);
    }

    public static void copyToDigest(InputStream in, MessageDigest digest) throws IOException {
        byte[] buffer = new byte[4096];
        int c;
        while ((c = in.read(buffer, 0, buffer.length)) != -1) {
            if (digest != null) {
                digest.update(buffer, 0, c);
            }
        }
    }

    public static String byteToHex(byte[] bytes) {
        if (bytes == null) {
            return null;
        }
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            int c = b & 0xff;
            if (c < 16) {
                sb.append("0");
            }
            sb.append(Integer.toString(c, 16));
        }
        return sb.toString();
    }

    public static byte[] hexToByte(String hex) {
        if (hex == null) {
            return null;
        }
        int length = hex.length();
        if (hex.length() % 2 != 0) {
            throw new IllegalArgumentException();
        }
        try {
            byte[] bytes = new byte[length / 2];
            for (int i = 0; i < bytes.length; i++) {
                int start = i * 2;
                int end = start + 2;
                bytes[i] = (byte) Integer.parseInt(hex.substring(start, end), 16);
            }
            return bytes;
        } catch (NumberFormatException nfe) {
            throw new IllegalArgumentException();
        }
    }

    public static boolean parseBoolean(String string) {
        if (string == null) {
            return false;
        }
        return string.equals("1") || string.equalsIgnoreCase("true") || string.equalsIgnoreCase("yes");
    }

    public static String determineServer(String path) {
        if (!path.contains("/")) {
            return path;
        }
        int minPos = 0;
        if (path.contains("://")) {
            minPos = path.indexOf("://") + 3;
        } else if (path.startsWith("//")) {
            minPos = 2;
        }
        int pos = path.indexOf("/", minPos);
        if (pos >= 0) {
            return path.substring(0, pos);
        }
        return path;
    }

    public static String determinePath(String path) {
        if (!path.contains("/")) {
            return null;
        }
        int minPos = 0;
        if (path.contains("://")) {
            minPos = path.indexOf("://") + 3;
        } else if (path.startsWith("//")) {
            minPos = 2;
        }
        int pos = path.indexOf("/", minPos);
        if (pos >= 0) {
            return path.substring(pos);
        }
        return null;
    }

    public static void delete(File f) {
        if (f.isDirectory() && !Files.isSymbolicLink(f.toPath())) {
            for (File file : f.listFiles()) {
                delete(file);
            }
        }
        f.delete();
    }

    public static void deleteEmptyDirectories(File f) {
        if (f.isDirectory()) {
            for (File file : f.listFiles()) {
                deleteEmptyDirectories(file);
            }
            if (f.listFiles().length == 0) {
                f.delete();
            }
        }
    }

    // <editor-fold defaultstate="collapsed" desc="Date Format">

    /**
     * Get the SimpleDateFormat for HTTP.
     *
     * @return a SimpleDateFormat
     */
    public static SimpleDateFormat getSimpleDateFormat() {
        SimpleDateFormat simpleDateFormat = new SimpleDateFormat("EEE, d MMM yyyy HH:mm:ss z");
        simpleDateFormat.setTimeZone(TimeZone.getTimeZone("GMT"));
        return simpleDateFormat;
    }
    // </editor-fold>
}
