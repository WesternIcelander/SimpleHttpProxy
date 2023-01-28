package io.siggi.simplehttpproxy;

import io.siggi.iphelper.IP;
import io.siggi.simplehttpproxy.util.Util;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class BasicAuth {

    private final File f;
    private final String realm;
    private final List<IP> whitelist;

    public BasicAuth(File f) {
        String realm = null;
        List<IP> whitelist = new ArrayList<>();
        try (BufferedReader reader = new BufferedReader(new FileReader(f))) {
            String line;
            while ((line = reader.readLine()) != null) {
                if (line.contains(":")) {
                    break;
                }
                int pos = line.indexOf("=");
                if (pos == -1) {
                    continue;
                }
                String key = line.substring(0, pos).trim();
                String val = line.substring(pos + 1).trim();
                if (key.equals("realm")) {
                    realm = val;
                } else if (key.equals("whitelist")) {
                    whitelist.add(IP.getIP(val));
                }
            }
        } catch (Exception e) {
        }
        this.f = f;
        this.realm = realm;
        this.whitelist = Collections.unmodifiableList(whitelist);
    }

    public static boolean checkPassword(String enteredPassword, String password) {
        int pos = password.indexOf(":");
        if (pos == -1) {
            return password.equals(enteredPassword);
        }
        String type = password.substring(0, pos).trim();
        String passwordData = password.substring(pos + 1).trim();
        switch (type) {
            case "plain": {
                return passwordData.equals(enteredPassword);
            }
            case "PBKDF2WithHmacSHA512": {
                try {
                    String[] split = passwordData.split("/");
                    String correctHash = split[0];
                    byte[] salt = Util.hexToByte(split[1]);
                    int iterations = Integer.parseInt(split[2]);
                    int keyLength = Integer.parseInt(split[3]);
                    String finalHash = Util.byteToHex(hashPassword(enteredPassword.toCharArray(), salt, iterations, keyLength));
                    return correctHash.equalsIgnoreCase(finalHash);
                } catch (Exception e) {
                }
            }
        }
        return false;
    }

    public static byte[] hashPassword(final char[] password, final byte[] salt, final int iterations, final int keyLength) {
        // https://www.owasp.org/index.php/Hashing_Java
        try {
            SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512");
            PBEKeySpec spec = new PBEKeySpec(password, salt, iterations, keyLength);
            SecretKey key = skf.generateSecret(spec);
            byte[] res = key.getEncoded();
            return res;
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new RuntimeException(e);
        }
    }

    public static String createHash(final char[] password, final int iterations) {
        byte[] salt = new byte[32];
        SecureRandom random = new SecureRandom();
        random.nextBytes(salt);
        int keyLength = 32 * 8;
        String correctHash = Util.byteToHex(hashPassword(password, salt, iterations, keyLength));
        return "PBKDF2WithHmacSHA512:" + correctHash + "/" + Util.byteToHex(salt) + "/" + iterations + "/" + keyLength;
    }

    public String getRealm() {
        return realm;
    }

    public boolean isWhitelisted(String ip) {
        return isWhitelisted(IP.getIP(ip));
    }

    public boolean isWhitelisted(IP ip) {
        for (IP whitelisted : whitelist) {
            if (whitelisted.contains(ip)) {
                return true;
            }
        }
        return false;
    }

    public boolean checkLogin(String username, String password) {
        try (BufferedReader reader = new BufferedReader(new FileReader(f))) {
            String line;
            while ((line = reader.readLine()) != null) {
                int pos = line.indexOf("#");
                if (pos != -1) {
                    line = line.substring(0, pos);
                }
                pos = line.indexOf(":");
                if (pos == -1) {
                    continue;
                }
                String user = line.substring(0, pos).trim();
                String pass = line.substring(pos + 1).trim();
                if (!user.equals(username)) {
                    continue;
                }
                return checkPassword(password, pass);
            }
        } catch (Exception e) {
        }
        return false;
    }
}
