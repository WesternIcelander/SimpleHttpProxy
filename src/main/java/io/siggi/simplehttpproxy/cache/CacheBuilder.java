package io.siggi.simplehttpproxy.cache;

import io.siggi.simplehttpproxy.util.HttpHeader;
import io.siggi.simplehttpproxy.util.Util;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.UUID;

public class CacheBuilder extends OutputStream {

    private final File destinationDir;
    private final File tmpFile;
    private final OutputStream out;
    private final UUID uuid;
    private boolean closed = false;
    private boolean finished = false;

    CacheBuilder(File destinationDir, File tmpDir, HttpHeader requestHeader, HttpHeader responseHeader) throws IOException {
        this.destinationDir = destinationDir;
        tmpDir.mkdirs();
        this.tmpFile = new File(tmpDir, (uuid = UUID.randomUUID()) + ".dat");
        this.out = new FileOutputStream(tmpFile);
        out.write((System.currentTimeMillis() + "\r\n").getBytes(StandardCharsets.UTF_8));
        Util.writeHeader(out, requestHeader);
        Util.writeHeader(out, responseHeader);
    }

    @Override
    public void close() {
        if (closed) {
            return;
        }
        closed = true;
        try {
            out.close();
        } catch (Exception e) {
        }
        if (!finished) {
            tmpFile.delete();
            return;
        }
        if (!tmpFile.exists()) {
            return;
        }
        destinationDir.mkdirs();
        tmpFile.renameTo(new File(destinationDir, uuid.toString() + ".dat"));
    }

    @Override
    public void write(int b) throws IOException {
        if (closed) {
            return;
        }
        this.out.write(b);
    }

    @Override
    public void write(byte[] b) throws IOException {
        if (closed) {
            return;
        }
        this.out.write(b);
    }

    @Override
    public void write(byte[] b, int o, int l) throws IOException {
        if (closed) {
            return;
        }
        this.out.write(b, o, l);
    }

    @Override
    public void flush() throws IOException {
        if (closed) {
            return;
        }
        this.out.flush();
    }

    public void finished() {
        finished = true;
    }
}
