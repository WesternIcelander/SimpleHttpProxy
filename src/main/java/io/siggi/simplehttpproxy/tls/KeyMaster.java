package io.siggi.simplehttpproxy.tls;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;
import java.io.File;
import java.io.FileInputStream;
import java.security.KeyStore;

public class KeyMaster {

    public static SSLSocketFactory getSSLSocketFactory(KeyStore trustKey, String password, String sslAlgorithm) {
        try {
            KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            kmf.init(trustKey, password.toCharArray());

            TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tmf.init(trustKey);

            SSLContext context = SSLContext.getInstance(sslAlgorithm);
            context.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);

            return context.getSocketFactory();
        } catch (Exception e) {
            log("Err: getSSLSocketFactory(), ");
        }
        return null;
    }

    public static SSLServerSocketFactory getSSLServerSocketFactory(KeyStore trustKey, String password, String sslAlgorithm) {
        try {
            KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            kmf.init(trustKey, password.toCharArray());

            TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tmf.init(trustKey);

            SSLContext context = SSLContext.getInstance(sslAlgorithm);
            context.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);

            return context.getServerSocketFactory();
        } catch (Exception e) {
            log("Err: getSSLSocketFactory(), ");
        }
        return null;
    }

    public static SSLServerSocket getSSLServerSocket(SSLServerSocketFactory socketFactory, int port) {
        try {
            return (SSLServerSocket) socketFactory.createServerSocket(port);
        } catch (Exception e) {
            log("Err: getSSLSocket(), ");
        }
        return null;
    }

    public static KeyStore getFromPath(File file, String algorithm, String filePassword) {
        try {
            if (!file.exists()) {
                throw new RuntimeException("Err: File not found.");
            }

            KeyStore keystore;
            try (FileInputStream keyFile = new FileInputStream(file)) {
                keystore = KeyStore.getInstance(algorithm);
                keystore.load(keyFile, filePassword.toCharArray());
            }

            return keystore;
        } catch (Exception e) {
            log("Err: getFromPath(), " + e);
        }
        return null;
    }

    private static void log(String msg) {
        System.err.println(msg);
    }
}
