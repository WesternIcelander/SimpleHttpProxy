package io.siggi.simplehttpproxy.cache;

import io.siggi.simplehttpproxy.util.Hash;
import io.siggi.simplehttpproxy.util.HttpHeader;
import io.siggi.simplehttpproxy.util.Util;

import java.io.File;
import java.io.IOException;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public class CacheManager {

    private static final Set<String> uncacheableMimes = new HashSet<>();

    static {
        uncacheableMimes.add("text/html");
        uncacheableMimes.add("application/json");
        uncacheableMimes.add("application/xhtml+xml");
    }

    private final File root;
    private final File tmp;

    public CacheManager(File root) {
        this.root = root;
        this.tmp = new File(root, "tmp");
        if (tmp.exists()) {
            Util.delete(tmp);
        }
        tmp.mkdirs();
    }

    private static boolean isUncacheable(String contentType) {
        int semicolonPos = contentType.indexOf(";");
        if (semicolonPos >= 0) {
            contentType = contentType.substring(0, semicolonPos);
        }
        return uncacheableMimes.contains(contentType.trim().toLowerCase());
    }

    private File getCacheDir(String cacheHash) {
        return new File(root, "data/" + cacheHash.substring(0, 2) + "/" + cacheHash.substring(2, 4) + "/" + cacheHash);
    }

    public CacheBuilder createCache(String cacheIdentifier, HttpHeader requestHeader, HttpHeader responseHeader) throws IOException {
        String cacheHash = Util.byteToHex(Hash.hash(Hash.sha1(), cacheIdentifier));
        if (shouldCacheResponse(requestHeader, responseHeader)) {
            return new CacheBuilder(getCacheDir(cacheHash), tmp, requestHeader, responseHeader);
        } else {
            return null;
        }
    }

    public CacheObject retrieveCacheObject(String cacheIdentifier, HttpHeader clientRequestHeader) {
        long maxAge = Long.MAX_VALUE;
        try {
            List<String> headers = clientRequestHeader.getHeaders("Cache-Control");
            if (headers != null) {
                for (String header : headers) {
                    for (String h : header.split(",")) {
                        h = h.trim();
                        if (h.startsWith("max-age=")) {
                            maxAge = Long.parseLong(h.substring(8)) * 1000L;
                        } else if (h.equals("no-cache") || h.equals("no-store")) {
                            return null;
                        }
                    }
                }
            }
        } catch (Exception e) {
        }
        if (maxAge <= 0L) {
            return null;
        }
        String cacheHash = Util.byteToHex(Hash.hash(Hash.sha1(), cacheIdentifier));
        File cacheDir = getCacheDir(cacheHash);
        if (!cacheDir.exists()) {
            return null;
        }
        File[] files = cacheDir.listFiles();
        long now = System.currentTimeMillis();
        CacheObject co = null;
        for (File file : files) {
            String name = file.getName();
            if (!name.endsWith(".dat")) {
                file.delete();
                continue;
            }
            try {
                CacheObject object = new CacheObject(file);
                if (object.getExpiryDate() < now) {
                    continue;
                }
                if ((now - object.getDate()) > maxAge) {
                    continue;
                }
                if (object.matches(clientRequestHeader)) {
                    if (co == null || co.getDate() < object.getDate()) {
                        co = object;
                    }
                }
            } catch (IOException ioe) {
            }
        }
        return co;
    }

    public boolean shouldCacheResponse(HttpHeader clientRequestHeader, HttpHeader serverResponseHeader) {
        String firstLine = serverResponseHeader.getFirstLine();
        int firstSpace = firstLine.indexOf(" ");
        int secondSpace = firstLine.indexOf(" ", firstSpace + 1);
        if (secondSpace == -1) {
            return false;
        }
        int responseCode = Integer.parseInt(firstLine.substring(firstSpace + 1, secondSpace));
        if (responseCode != 200) {
            return false;
        }
        String contentType = serverResponseHeader.getHeader("Content-Type");
        if (contentType == null) {
            contentType = "text/html";
        }
        if (clientRequestHeader.getHeader("Authorization") != null
                || isUncacheable(contentType)) {
            return false;
        }
        String requestedWith = clientRequestHeader.getHeader("X-Requested-With");
        if (requestedWith != null && requestedWith.equalsIgnoreCase("XMLHttpRequest")) {
            return false;
        }
        List<String> headers = serverResponseHeader.getHeaders("Cache-Control");
        if (headers != null) {
            for (String header : headers) {
                for (String h : header.split(",")) {
                    h = h.trim();
                    if (h.equals("no-store") || h.equals("no-cache") || h.equals("private")) {
                        return false;
                    }
                }
            }
        }
        return true;
    }

    public void startCleanupThread() {
        new Thread(() -> {
            while (true) {
                try {
                    cleanup();
                } catch (Exception e) {
                }
                try {
                    Thread.sleep(1800000L);
                } catch (Exception e) {
                }
            }
        }, "CacheCleanup").start();
    }

    private void cleanup() {
        long now = System.currentTimeMillis();
        File dataRoot = new File(root, "data");
        cleanup(now, dataRoot);
        Util.deleteEmptyDirectories(dataRoot);
    }

    private void cleanup(long now, File f) {
        for (File file : f.listFiles()) {
            if (file.isDirectory()) {
                cleanup(now, file);
            } else {
                String name = f.getName();
                if (!name.endsWith(".dat")) {
                    f.delete();
                    continue;
                }
                try {
                    CacheObject co = new CacheObject(file);
                    if (co.getExpiryDate() < now) {
                        f.delete();
                    }
                } catch (Exception e) {
                    f.delete();
                }
            }
        }
    }
}
