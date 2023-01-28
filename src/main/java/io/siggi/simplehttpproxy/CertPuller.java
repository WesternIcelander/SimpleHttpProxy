package io.siggi.simplehttpproxy;

import io.siggi.simplehttpproxy.util.Util;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.Date;
import java.util.Map;
import java.util.UUID;

public class CertPuller {

    private final SimpleHttpProxy proxy;
    private boolean started = false;
    private boolean stopped = false;
    private Thread thread;
    private volatile Map<String, CertPullerInfo> map = null;
    CertPuller(SimpleHttpProxy proxy) {
        this.proxy = proxy;
    }

    private static void protect(File file) {
        try {
            boolean interrupt = false;
            while (true) {
                Process process = Runtime.getRuntime().exec(new String[]{"chmod", "600", file.getAbsolutePath()});
                try {
                    process.waitFor();
                    break;
                } catch (InterruptedException ie) {
                    interrupt = true;
                }
            }
            if (interrupt) {
                Thread.currentThread().interrupt();
            }
        } catch (IOException e) {
        }
    }

    private static File createTempFile(File dir, String prefix, String suffix) throws IOException {
        File f = new File(dir, prefix + (UUID.randomUUID().toString().replace("-", "").toLowerCase()) + suffix);
        try (FileOutputStream fos = new FileOutputStream(f)) {
        }
        return f;
    }

    public void set(Map<String, CertPullerInfo> map) {
        this.map = map;
        if (!started) {
            start();
        }
    }

    private void start() {
        if (started || stopped) {
            return;
        }
        started = true;
        (thread = new Thread(this::run, "CertPuller")).start();
    }

    public void stop() {
        stopped = true;
        try {
            thread.interrupt();
        } catch (Exception e) {
        }
    }

    private void run() {
        while (true) {
            runOnce();
            try {
                Thread.sleep(1800000L);
            } catch (InterruptedException ie) {
                if (stopped) {
                    break;
                }
            }
        }
    }

    private void runOnce() {
        Map<String, CertPullerInfo> m = this.map;
        for (CertPullerInfo cpi : m.values()) {
            try {
                pull(cpi.url, cpi.saveDestination, cpi.apiKey);
            } catch (IOException e) {
                proxy.log("Failed to update certificate", e);
            }
        }
    }

    private void pull(String url, File saveDestination, String apiKey) throws IOException {
        URL u = new URL(url);
        HttpURLConnection connection = (HttpURLConnection) u.openConnection();
        connection.setRequestProperty("X-Api-Key", apiKey);
        if (saveDestination.exists()) {
            long lastModified = saveDestination.lastModified();
            connection.setRequestProperty("If-Modified-Since", Util.getSimpleDateFormat().format(new Date(lastModified)));
        }
        int responseCode = connection.getResponseCode();
        if (responseCode == 304) {
            return;
        } else if (responseCode != 200) {
            throw new IOException("Expected response code " + responseCode + ", got " + responseCode);
        }
        File tmpFile = null;
        try {
            tmpFile = createTempFile(saveDestination.getParentFile(), "download", ".tmp");
            protect(tmpFile);
            InputStream in = connection.getInputStream();
            try (FileOutputStream out = new FileOutputStream(tmpFile)) {
                Util.copy(in, out);
            }
            long lastModified = connection.getHeaderFieldDate("Last-Modified", -1L);
            if (lastModified != -1L) {
                tmpFile.setLastModified(lastModified);
            }
            if (saveDestination.exists()) {
                saveDestination.delete();
            }
            tmpFile.renameTo(saveDestination);
            proxy.log("Updated certificate " + saveDestination.getName());
        } finally {
            if (tmpFile != null && tmpFile.exists()) {
                tmpFile.delete();
            }
        }
    }

    public static class CertPullerInfo {

        private final String url;
        private final File saveDestination;
        private final String apiKey;

        CertPullerInfo(String url, File saveDestination, String apiKey) {
            this.url = url;
            this.saveDestination = saveDestination;
            this.apiKey = apiKey;
        }
    }
}
