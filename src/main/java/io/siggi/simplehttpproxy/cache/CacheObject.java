package io.siggi.simplehttpproxy.cache;

import io.siggi.simplehttpproxy.io.RafInputStream;
import io.siggi.simplehttpproxy.util.HttpHeader;
import io.siggi.simplehttpproxy.util.Util;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.RandomAccessFile;
import java.util.List;

public class CacheObject {

    private final File file;
    private final long date;
    private final long expires;
    private final long contentLength;
    private final long offset;
    private final HttpHeader requestHeader;
    private final HttpHeader responseHeader;

    CacheObject(File file) throws IOException {
        this.file = file;
        try (RandomAccessFile raf = new RandomAccessFile(file, "r")) {
            InputStream in = new RafInputStream(raf, false);
            this.date = Long.parseLong(Util.readCRLF(in, Integer.MAX_VALUE));
            this.requestHeader = Util.readHeader(in, Integer.MAX_VALUE);
            this.responseHeader = Util.readHeader(in, Integer.MAX_VALUE);
            this.offset = raf.getFilePointer();
            this.contentLength = raf.length() - offset;
        }
        long exp = date + 14L * 86400000L;
        try {
            List<String> headers = this.responseHeader.getHeaders("Cache-Control");
            if (headers != null) {
                for (String header : headers) {
                    for (String h : header.split(",")) {
                        h = h.trim();
                        if (h.startsWith("max-age=")) {
                            long maxAge = Long.parseLong(h.substring(8));
                            exp = date + (maxAge * 1000L);
                        }
                    }
                }
            }
        } catch (Exception e) {
        }
        this.expires = exp;
    }

    public long getDate() {
        return date;
    }

    public long getExpiryDate() {
        return expires;
    }

    public long getContentLength() {
        return contentLength;
    }

    public HttpHeader getRequestHeader() {
        return requestHeader;
    }

    public HttpHeader getResponseHeader() {
        return responseHeader;
    }

    public InputStream getInputStream() throws IOException {
        FileInputStream in = new FileInputStream(file);
        in.skip(offset);
        return in;
    }

    boolean matches(HttpHeader clientRequestHeader) {
        String requestedWith = clientRequestHeader.getHeader("X-Requested-With");
        if (requestedWith != null && requestedWith.equalsIgnoreCase("XMLHttpRequest")) {
            return false;
        }
        List<String> varyHeaders = responseHeader.getHeaders("Vary");
        if (varyHeaders != null) {
            for (String varyHeader : varyHeaders) {
                for (String vary : varyHeader.split(",")) {
                    vary = vary.trim();
                    List<String> request = clientRequestHeader.getHeaders(vary);
                    List<String> cachedRequest = requestHeader.getHeaders(vary);
                    if ((request == null && cachedRequest != null)
                            || cachedRequest == null
                            || !request.equals(cachedRequest)) {
                        return false;
                    }
                }
            }
        }
        return true;
    }
}
