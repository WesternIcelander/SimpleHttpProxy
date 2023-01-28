package io.siggi.simplehttpproxy.util;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class Hash {
    private Hash() {
    }

    public static MessageDigest sha1() {
        try {
            return MessageDigest.getInstance("SHA-1");
        } catch (NoSuchAlgorithmException ex) {
            throw new RuntimeException(ex);
        }
    }

    public static MessageDigest sha256() {
        try {
            return MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException ex) {
            throw new RuntimeException(ex);
        }
    }

    public static byte[] hash(MessageDigest digest, File file) throws IOException {
        try (FileInputStream in = new FileInputStream(file)) {
            Util.copyToDigest(in, digest);
            return digest.digest();
        }
    }

    public static byte[] hash(MessageDigest digest, String str) {
        digest.update(str.getBytes(StandardCharsets.UTF_8));
        return digest.digest();
    }
}
