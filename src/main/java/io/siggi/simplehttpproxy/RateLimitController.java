package io.siggi.simplehttpproxy;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.Set;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantReadWriteLock;

public class RateLimitController {

    private final Set<String> rateLimitSkip = new HashSet<>();
    private final Map<String, RateLimitInfo> rliMap = new HashMap<>();
    private final int rateLimitCount = 10000;
    private final long rateLimitTime = 300000L; // 5 minutes, 2000/minute, or 33/sec
    private final ReentrantReadWriteLock lock = new ReentrantReadWriteLock();
    private final Lock readLock = lock.readLock();
    private final Lock writeLock = lock.writeLock();
    private boolean disableRateLimit = false;
    public RateLimitController(File whitelistFile) {
        try (BufferedReader reader = new BufferedReader(new FileReader(whitelistFile))) {
            String line;
            while ((line = reader.readLine()) != null) {
                int hashPos = line.indexOf("#");
                if (hashPos >= 0) {
                    line = line.substring(0, hashPos);
                }
                line = line.trim();
                if (line.equalsIgnoreCase("disableratelimit")) {
                    disableRateLimit = true;
                    return;
                }
                rateLimitSkip.add(line);
            }
        } catch (Exception e) {
        }
    }

    private boolean shouldSkipRateLimiting(String path, String clientIP) {
        if (rateLimitSkip.contains(clientIP)) {
            return true;
        }
        while (true) {
            if (rateLimitSkip.contains(path)) {
                return true;
            }
            if (path.contains("/")) {
                if (path.endsWith("/")) {
                    path = path.substring(0, path.length() - 1);
                } else {
                    path = path.substring(0, path.lastIndexOf("/") + 1);
                }
            } else {
                return false;
            }
        }
    }

    private RateLimitInfo get(String clientIP) {
        readLock.lock();
        try {
            RateLimitInfo rli = rliMap.get(clientIP);
            if (rli != null) {
                return rli;
            }
        } finally {
            readLock.unlock();
        }
        writeLock.lock();
        try {
            RateLimitInfo rli = rliMap.get(clientIP);
            if (rli != null) {
                return rli;
            }
            long expire = System.currentTimeMillis() - rateLimitTime;
            for (Iterator<Map.Entry<String, RateLimitInfo>> it = rliMap.entrySet().iterator(); it.hasNext(); ) {
                Map.Entry<String, RateLimitInfo> entry = it.next();
                if (entry.getValue().getLatestTime() <= expire) {
                    it.remove();
                }
            }
            rliMap.put(clientIP, rli = new RateLimitInfo());
            return rli;
        } finally {
            writeLock.unlock();
        }
    }

    public boolean shouldRateLimit(String host, String path, String clientIP) {
        if (disableRateLimit) {
            return false;
        }
        if (shouldSkipRateLimiting(host + path, clientIP)) {
            return false;
        }
        RateLimitInfo rli = get(clientIP);
        return rli.hit() > rateLimitCount;
    }

    private class RateLimitInfo {

        private final ReentrantReadWriteLock lk = new ReentrantReadWriteLock();
        private final Lock readLk = lk.readLock();
        private final Lock writeLk = lk.writeLock();

        private final LinkedList<Long> accessTimes = new LinkedList<>();

        public RateLimitInfo() {
        }

        public long getLatestTime() {
            readLk.lock();
            try {
                return accessTimes.getLast();
            } catch (NoSuchElementException nsee) {
                return -1L;
            } finally {
                readLk.unlock();
            }
        }

        public int getCount() {
            readLk.lock();
            try {
                return accessTimes.size();
            } finally {
                readLk.unlock();
            }
        }

        public int hit() {
            long now = System.currentTimeMillis();
            long expire = now - rateLimitTime;
            writeLk.lock();
            try {
                for (Iterator<Long> it = accessTimes.iterator(); it.hasNext(); ) {
                    long time = it.next();
                    if (time <= expire) {
                        it.remove();
                    } else {
                        break;
                    }
                }
                accessTimes.add(now);
                return accessTimes.size();
            } finally {
                writeLk.unlock();
            }
        }
    }
}
