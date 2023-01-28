package io.siggi.simplehttpproxy.util;

import io.siggi.iphelper.IP;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.InputStreamReader;
import java.net.InetAddress;
import java.net.URL;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantReadWriteLock;

public class CloudFlare {
    private static final ReentrantReadWriteLock lock = new ReentrantReadWriteLock();
    private static final Lock readLock = lock.readLock();
    private static final Lock writeLock = lock.writeLock();

    private static final List<IP> cloudFlareRanges = new ArrayList<>();
    private static final File ipListFile = new File("cloudflare-ips.txt");
    private static final boolean enabled;
    private static long lastUpdate = 0L;
    private static boolean updatingRanges = false;

    static {
        boolean enableCF = false;
        writeLock.lock();
        try {
            if (ipListFile.exists()) {
                enableCF = true;
                try (BufferedReader reader = new BufferedReader(new FileReader(ipListFile))) {
                    String line = reader.readLine();
                    lastUpdate = Long.parseLong(line);
                    while ((line = reader.readLine()) != null) {
                        cloudFlareRanges.add(IP.getIP(line));
                    }
                } catch (Exception e) {
                }
            }
        } finally {
            writeLock.unlock();
        }
        enabled = enableCF;
    }

    public static boolean isCloudFlare(InetAddress add) {
        String address = add.getHostAddress();
        return isCloudFlare(address);
    }

    public static boolean isCloudFlare(String address) {
        do {
            readBlock:
            {
                readLock.lock();
                try {
                    if (shouldUpdateRemoteRanges()) {
                        break readBlock;
                    }
                    IP check;
                    try {
                        check = IP.getIP(address);
                    } catch (IllegalArgumentException e) {
                        return false;
                    }
                    for (IP ip : cloudFlareRanges) {
                        if (ip.contains(check)) {
                            return true;
                        }
                    }
                    return false;
                } finally {
                    readLock.unlock();
                }
            }
            writeLock.lock();
            try {
                if (shouldUpdateRemoteRanges()) {
                    updateRemoteRanges();
                }
            } finally {
                writeLock.unlock();
            }
        } while (true);
    }

    private static boolean shouldUpdateRemoteRanges() {
        return enabled && !updatingRanges && (System.currentTimeMillis() - lastUpdate) > (86400000L * 7L);
    }

    private static void updateRemoteRanges() {
        updatingRanges = true;
        Thread updaterThread = new Thread(CloudFlare::doUpdateRemoteRanges, "CloudFlare-Update");
        updaterThread.setDaemon(true);
        updaterThread.start();
    }

    private static void doUpdateRemoteRanges() {
        try {
            List<IP> newOnes = new LinkedList<>();
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(
                    new URL("https://www.cloudflare.com/ips-v4").openConnection().getInputStream()
            ))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    try {
                        newOnes.add(IP.getIP(line));
                    } catch (Exception e) {
                    }
                }
            }
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(
                    new URL("https://www.cloudflare.com/ips-v6").openConnection().getInputStream()
            ))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    try {
                        newOnes.add(IP.getIP(line));
                    } catch (Exception e) {
                    }
                }
            }
            writeLock.lock();
            try {
                cloudFlareRanges.clear();
                cloudFlareRanges.addAll(newOnes);
                try (FileWriter fw = new FileWriter(ipListFile)) {
                    fw.write(System.currentTimeMillis() + "\n");
                    for (IP ip : newOnes) {
                        fw.write(ip.toString() + "\n");
                    }
                } catch (Exception e) {
                }
            } finally {
                writeLock.unlock();
            }
        } catch (Exception e) {
        } finally {
            writeLock.lock();
            try {
                lastUpdate = System.currentTimeMillis();
                updatingRanges = false;
            } finally {
                writeLock.unlock();
            }
        }
    }
}
