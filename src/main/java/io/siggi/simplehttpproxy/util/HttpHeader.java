package io.siggi.simplehttpproxy.util;

import io.siggi.simplehttpproxy.io.ChunkedInputStream;
import io.siggi.simplehttpproxy.io.ChunkedOutputStream;
import io.siggi.simplehttpproxy.io.SubInputStream;

import java.io.InputStream;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

public class HttpHeader {

    private final CaseInsensitiveHashMap<List<String>> headers;
    private String firstLine;

    public HttpHeader(String firstLine, CaseInsensitiveHashMap<List<String>> headers) {
        if (firstLine == null || headers == null) {
            throw new NullPointerException();
        }
        this.firstLine = firstLine;
        this.headers = headers;
    }

    public String getFirstLine() {
        return firstLine;
    }

    public void setFirstLine(String firstLine) {
        if (firstLine == null) {
            throw new NullPointerException();
        }
        this.firstLine = firstLine;
    }

    public Map<String, List<String>> getHeaders() {
        return headers;
    }

    public void addHeader(String key, String val) {
        List<String> h = headers.get(key);
        if (h == null) {
            setHeader(key, val);
        } else {
            h.add(val);
        }
    }

    public void setHeader(String key, String val) {
        List<String> h = new ArrayList<>();
        h.add(val);
        headers.put(key, h);
    }

    public String getHeader(String key) {
        List<String> g = headers.get(key);
        if (g == null || g.isEmpty()) {
            return null;
        }
        return g.get(0);
    }

    public void deleteHeader(String key) {
        headers.remove(key);
    }

    public List<String> getHeaders(String key) {
        return headers.get(key);
    }

    public InputStream wrapInputStream(InputStream in) {
        if (firstLine.toLowerCase().startsWith("HEAD ")) {
            return null;
        }
        long contentLength = -1L;
        boolean chunked = false;
        List<String> cl = headers.get("Content-Length");
        if (cl != null && !cl.isEmpty()) {
            try {
                contentLength = Long.parseLong(cl.get(0));
            } catch (Exception e) {
            }
        }
        List<String> te = headers.get("Transfer-Encoding");
        if (te != null && !te.isEmpty()) {
            try {
                if (te.get(0).equalsIgnoreCase("chunked")) {
                    chunked = true;
                }
            } catch (Exception e) {
            }
        }
        if (chunked) {
            return new ChunkedInputStream(in);
        } else if (contentLength >= 0L) {
            return new SubInputStream(in, contentLength);
        } else {
            return null;
        }
    }

    public OutputStream wrapOutputStream(OutputStream out) {
        if (firstLine.toLowerCase().startsWith("HEAD ")) {
            return null;
        }
        long contentLength = -1L;
        boolean chunked = false;
        List<String> cl = headers.get("Content-Length");
        if (cl != null && !cl.isEmpty()) {
            try {
                contentLength = Long.parseLong(cl.get(0));
            } catch (Exception e) {
            }
        }
        List<String> te = headers.get("Transfer-Encoding");
        if (te != null && !te.isEmpty()) {
            try {
                if (te.get(0).equalsIgnoreCase("chunked")) {
                    chunked = true;
                }
            } catch (Exception e) {
            }
        }
        if (chunked) {
            return new ChunkedOutputStream(out);
        } else if (contentLength >= 0L) {
            return out;
        } else {
            return null;
        }
    }

    public String getCFRay() {
        try {
            for (Map.Entry<String, List<String>> en : headers.entrySet()) {
                if (en.getKey().equalsIgnoreCase("CF-Ray")) {
                    return en.getValue().get(0);
                }
            }
        } catch (Exception e) {
        }
        return null;
    }

    public HttpHeader copy() {
        CaseInsensitiveHashMap<List<String>> newHeaders = new CaseInsensitiveHashMap<>();
        for (Map.Entry<String, List<String>> header : headers.entrySet()) {
            String key = header.getKey();
            List<String> val = header.getValue();
            List<String> headerItems = new ArrayList<>(val.size());
            headerItems.addAll(val);
            newHeaders.put(key, headerItems);
        }
        return new HttpHeader(firstLine, newHeaders);
    }
}
