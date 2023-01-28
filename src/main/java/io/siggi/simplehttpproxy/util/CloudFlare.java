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

    private static final List<IP> localCloudFlareRanges = new ArrayList<>();
    private static final ReentrantReadWriteLock lock = new ReentrantReadWriteLock();
    private static final Lock readLock = lock.readLock();
    private static final Lock writeLock = lock.writeLock();
    private static final List<IP> remoteCloudFlareRanges = new ArrayList<>();
    private static final File ipListFile = new File("cloudflare-ips.txt");
    private static final boolean enabled;
    private static long lastRemoteUpdate = 0L;
    private static boolean updatingRemoteRanges = false;

    static {
        boolean enableCF = false;
        writeLock.lock();
        try {
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(CloudFlare.class.getResourceAsStream("/cloudflare.txt")))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    if (line.equals("")) {
                        continue;
                    }
                    try {
                        localCloudFlareRanges.add(IP.getIP(line));
                    } catch (Exception e) {
                    }
                }
            } catch (Exception e) {
            }
            if (ipListFile.exists()) {
                enableCF = true;
                try (BufferedReader reader = new BufferedReader(new FileReader(ipListFile))) {
                    String line = reader.readLine();
                    lastRemoteUpdate = Long.parseLong(line);
                    while ((line = reader.readLine()) != null) {
                        remoteCloudFlareRanges.add(IP.getIP(line));
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
            a:
            {
                readLock.lock();
                try {
                    if (shouldUpdateRemoteRanges()) {
                        break a;
                    }
                    IP check;
                    try {
                        check = IP.getIP(address);
                    } catch (IllegalArgumentException e) {
                        return false;
                    }
                    if (remoteCloudFlareRanges.isEmpty()) {
                        for (IP ip : localCloudFlareRanges) {
                            if (ip.contains(check)) {
                                return true;
                            }
                        }
                    } else {
                        for (IP ip : remoteCloudFlareRanges) {
                            if (ip.contains(check)) {
                                return true;
                            }
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
        return enabled && !updatingRemoteRanges && (System.currentTimeMillis() - lastRemoteUpdate) > (86400000L * 7L);
    }

    private static void updateRemoteRanges() {
        updatingRemoteRanges = true;
        new Thread(CloudFlare::doUpdateRemoteRanges, "CloudFlare-Update").start();
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
                remoteCloudFlareRanges.clear();
                remoteCloudFlareRanges.addAll(newOnes);
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
                lastRemoteUpdate = System.currentTimeMillis();
                updatingRemoteRanges = false;
            } finally {
                writeLock.unlock();
            }
        }
    }
}
