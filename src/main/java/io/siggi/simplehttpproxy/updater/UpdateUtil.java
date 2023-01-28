package io.siggi.simplehttpproxy.updater;

import io.siggi.simplehttpproxy.util.Hash;
import io.siggi.simplehttpproxy.util.Util;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.HashMap;
import java.util.Map;

class UpdateUtil {

    private UpdateUtil() {
    }
    static boolean delete(File f) {
        try {
            return Runtime.getRuntime().exec(new String[]{"rm", "-rf", f.getAbsolutePath()}).waitFor() == 0;
        } catch (Exception e) {
            return false;
        }
    }

    static HttpURLConnection openConnection(String urlString) throws IOException {
        URL url = new URL(urlString);
        HttpURLConnection urlConnection = (HttpURLConnection) url.openConnection();
        urlConnection.setConnectTimeout(5000);
        urlConnection.setReadTimeout(5000);
        urlConnection.setRequestProperty("User-Agent", "SimpleHttpProxyUpdater");
        return urlConnection;
    }

    static void setupPerms(File file) throws Exception {
        Runtime.getRuntime().exec(new String[]{"chown", "0:0", file.getAbsolutePath()}).waitFor();
        Runtime.getRuntime().exec(new String[]{"chmod", "755", file.getAbsolutePath()}).waitFor();
    }

    static void download(String url, File file, String expectedHash) throws IOException {
        if (expectedHash == null) {
            throw new NullPointerException("expectedHash");
        }
        HttpURLConnection httpURLConnection = openConnection(url);
        InputStream in = httpURLConnection.getInputStream();
        try (FileOutputStream out = new FileOutputStream(file)) {
            Util.copy(in, out);
        }
        httpURLConnection.disconnect();
        String fileHash = hashFile(file);
        if (!expectedHash.equals(fileHash)) {
            throw new IOException("File hash does not match expected hash");
        }
    }

    static String hashFile(File file) throws IOException {
        return Util.byteToHex(Hash.hash(Hash.sha256(), file));
    }

    static Map<String, String> readShasums(InputStream in) throws IOException {
        BufferedReader reader = new BufferedReader(new InputStreamReader(in));
        Map<String, String> map = new HashMap<>();
        String line;
        while ((line = reader.readLine()) != null) {
            int separatorPosition = line.indexOf("  ");
            String hash = line.substring(0, separatorPosition);
            String file = line.substring(separatorPosition + 2);
            map.put(file, hash);
        }
        return map;
    }

    static String getJavaPath() {
        return System.getProperty("java.home") + "/bin/java";
    }
}
