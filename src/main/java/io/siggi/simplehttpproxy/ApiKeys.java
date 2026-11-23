package io.siggi.simplehttpproxy;

import io.siggi.simplehttpproxy.util.Util;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

class ApiKeys {
    private final List<ApiKey> keys = new ArrayList<>();
    public ApiKeys() {
    }
    public ApiKeys(File file) {
        try (BufferedReader reader = new BufferedReader(new FileReader(file))) {
            String line;
            while ((line = reader.readLine()) != null) {
                if (line.startsWith("sha256:")) {
                    keys.add(new Sha256Key(line));
                }
            }
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
    public boolean checkKey(String key) {
        if (key == null) return false;
        Map<String, byte[]> cache = new HashMap<>();
        for (ApiKey k : keys) {
            if (k.matches(key, cache)) return true;
        }
        return false;
    }
    interface ApiKey {
        boolean matches(String key, Map<String, byte[]> cache);
    }
    static class Sha256Key implements ApiKey {
        private final byte[] key;
        Sha256Key(String key) {
            if (key.startsWith("sha256:")) key = key.substring(7);
            this.key = Util.hexToByte(key);
        }
        @Override
        public boolean matches(String key, Map<String, byte[]> cache) {
            try {
                byte[] hash = cache.computeIfAbsent("sha256", (k) -> {
                    try {
                        MessageDigest digest = MessageDigest.getInstance("SHA-256");
                        return digest.digest(key.getBytes(StandardCharsets.UTF_8));
                    } catch (NoSuchAlgorithmException e) {
                        throw new RuntimeException(e);
                    }
                });

                return MessageDigest.isEqual(hash, this.key);
            } catch (Exception e) {
                return false;
            }
        }
    }
}
