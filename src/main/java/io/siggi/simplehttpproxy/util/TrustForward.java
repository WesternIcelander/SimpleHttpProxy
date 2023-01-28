package io.siggi.simplehttpproxy.util;

import io.siggi.iphelper.IP;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.locks.ReentrantReadWriteLock;

public class TrustForward {

    private static final ReentrantReadWriteLock lock = new ReentrantReadWriteLock();
    private static final ReentrantReadWriteLock.ReadLock read = lock.readLock();
    private static final ReentrantReadWriteLock.WriteLock write = lock.writeLock();
    private static long lastUpdate = 0L;
    private static List<IP> trustedAddresses = null;
    private TrustForward() {
    }

    public static boolean isTrusted(String ip) {
        long now = System.currentTimeMillis();
        boolean doUpdate = false;
        List<IP> trustedAddresses;
        read.lock();
        try {
            trustedAddresses = TrustForward.trustedAddresses;
            if (trustedAddresses == null || lastUpdate + 60000L < now) {
                doUpdate = true;
            }
        } finally {
            read.unlock();
        }
        if (doUpdate) {
            write.lock();
            try {
                trustedAddresses = TrustForward.trustedAddresses;
                if (trustedAddresses == null || lastUpdate + 60000L < now) {
                    File file = new File("trust-forward-ips.txt");
                    if (trustedAddresses == null || file.lastModified() > lastUpdate) {
                        TrustForward.trustedAddresses = trustedAddresses = new ArrayList<>();
                        try (BufferedReader reader = new BufferedReader(new FileReader(file))) {
                            String line;
                            while ((line = reader.readLine()) != null) {
                                int pos = line.indexOf("#");
                                if (pos >= 0) {
                                    line = line.substring(0, pos);
                                }
                                line = line.trim();
                                if (line.contains(".") || line.contains(":")) {
                                    IP ipAddr = IP.getIP(line);
                                    if (ipAddr != null) trustedAddresses.add(ipAddr);
                                }
                            }
                        } catch (IOException ioe) {
                        }
                    }
                    lastUpdate = System.currentTimeMillis();
                }
            } finally {
                write.unlock();
            }
        }
        try {
            IP ipAddr = IP.getIP(ip);
            for (IP trustedAddress : trustedAddresses) {
                if (trustedAddress.contains(ipAddr)) return true;
            }
        } catch (Exception e) {
        }
        return false;
    }
}
