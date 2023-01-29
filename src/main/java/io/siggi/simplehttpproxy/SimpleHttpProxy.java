package io.siggi.simplehttpproxy;

import io.siggi.iphelper.IP;
import io.siggi.iphelper.IPv6;
import io.siggi.processapi.ProcessAPI;
import io.siggi.simplehttpproxy.cache.CacheManager;
import io.siggi.simplehttpproxy.io.IOUtil;
import io.siggi.simplehttpproxy.tls.KeyMaster;
import io.siggi.simplehttpproxy.tls.TlsUtil;
import io.siggi.simplehttpproxy.updater.AutoUpdater;
import io.siggi.simplehttpproxy.util.Logger;
import io.siggi.simplehttpproxy.util.TrustForward;
import io.siggi.simplehttpproxy.util.Util;

import java.net.InetSocketAddress;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantReadWriteLock;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class SimpleHttpProxy {

    private final Object logLock = new Object();
    private final Pattern hstsPattern = Pattern.compile("\\(HSTS([IP]?)=([0-9]{1,})\\)");
    private final List<FileToWatch> filesToWatch = new LinkedList<>();
    private final Map<String, SSLInfo> sslInfo = new HashMap<>();
    private final ReentrantReadWriteLock lock = new ReentrantReadWriteLock();
    private final Lock readLock = lock.readLock();
    private final Lock writeLock = lock.writeLock();
    private final CertPuller certPuller = new CertPuller(this);
    private final byte[] unrecognizedName = new byte[]{
            (byte) 21, // TLS Alert
            (byte) 03, // Version Major
            (byte) 01, // Version Minor
            (byte) 0, // Size most significant
            (byte) 2, // Size least significant
            (byte) 2, // Error: fatal
            (byte) 112 // Error: unrecognized_name
    };
    private final byte[] handshakeFailure = new byte[]{
            (byte) 21, // TLS Alert
            (byte) 03, // Version Major
            (byte) 01, // Version Minor
            (byte) 0, // Size most significant
            (byte) 2, // Size least significant
            (byte) 2, // Error: fatal
            (byte) 40 // Error: handshake_failure
    };
    private final Set<IP> bannedIPs = new HashSet<>();
    private final ReentrantReadWriteLock banLock = new ReentrantReadWriteLock();
    private final Lock banReadLock = banLock.readLock();
    private final Lock banWriteLock = banLock.writeLock();
    private boolean started = false;
    private SimpleDateFormat sdf = null;
    private Logger logger = null;
    private CacheManager cacheManager = null;
    private boolean transparentProxy = false;
    private long lastLoadFactories = 0L;
    private RateLimitController rateLimitController;

    {
        try (BufferedReader reader = new BufferedReader(new FileReader("bannedips.txt"))) {
            String line;
            while ((line = reader.readLine()) != null) {
                try {
                    bannedIPs.add(IP.getIP(line));
                } catch (Exception e) {
                }
            }
        } catch (Exception e) {
        }
    }

    public static void main(String[] args) {
        if (args.length > 0) {
            switch (args[0]) {
                case "password": {
                    try (BufferedReader reader = new BufferedReader(new InputStreamReader(System.in))) {
                        System.err.print("Password: ");
                        String password = reader.readLine();

                        System.err.print("Iterations (min 1, suggested 100000): ");
                        String iterationsStr = reader.readLine();
                        int iterations = 1;
                        try {
                            iterations = Integer.parseInt(iterationsStr);
                        } catch (NumberFormatException nfe) {
                        }

                        String finalHash = BasicAuth.createHash(password.toCharArray(), iterations);
                        System.out.println(finalHash);
                    } catch (IOException ioe) {
                    }
                }
                return;
            }
        }
        SimpleHttpProxy simpleHttpProxy = new SimpleHttpProxy();
        simpleHttpProxy.start();
    }

    private final List<ServerSocket> serverSockets = new ArrayList<>();

    private void start() {
        if (started) {
            return;
        }
        try {
            Runtime.getRuntime().exec(new String[]{new File("setup-perms").getAbsolutePath()}).waitFor();
        } catch (Exception e) {
        }
        rateLimitController = new RateLimitController(new File("ratelimitwhitelist.txt"));
        started = true;
        sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss z");
        logger = new Logger(new File("log"));
        List<Runnable> serverListenerRunnables = new LinkedList<>();
        try (BufferedReader reader = new BufferedReader(new FileReader(new File("ports.txt")))) {
            String line;
            while ((line = reader.readLine()) != null) {
                int pos = line.indexOf("#");
                if (pos != -1) {
                    line = line.substring(0, pos);
                }
                line = line.trim();
                try {
                    boolean secure;
                    if (line.startsWith("s")) {
                        secure = true;
                        line = line.substring(1);
                    } else {
                        secure = false;
                    }
                    ServerSocket ss = new ServerSocket();
                    ss.setReuseAddress(true);
                    ss.bind(new InetSocketAddress((InetAddress) null, Integer.parseInt(line)));
                    serverSockets.add(ss);
                    serverListenerRunnables.add(() -> {
                        try {
                            while (true) {
                                Socket accept = ss.accept();
                                try {
                                    new ProxyHandler(this, secure, accept).start();
                                } catch (Exception e) {
                                }
                            }
                        } catch (Exception e) {
                        }
                    });
                } catch (Exception e) {
                    log(e);
                }
            }
        } catch (Exception e) {
            log(e);
        }
        File dp = new File("dropprivs.txt");
        if (dp.exists()) {
            try (BufferedReader reader = new BufferedReader(new FileReader(dp))) {
                String line = reader.readLine();
                if (line.equals("print")) {
                    System.out.println("uid=" + ProcessAPI.getuid() + ",gid=" + ProcessAPI.getgid());
                } else {
                    String line2 = reader.readLine();
                    int uid = Integer.parseInt(line);
                    int gid = Integer.parseInt(line2);
                    ProcessAPI.setTmpDir();
                    ProcessAPI.setgid(gid);
                    ProcessAPI.setuid(uid);
                }
            } catch (Exception e) {
                log(e);
            }
        }
        logger.start();
        AutoUpdater.start(this::restartForUpdate);
        for (Runnable runnable : serverListenerRunnables) {
            ThreadCreator.createThread(runnable, null, false, false).start();
        }
        cacheManager = new CacheManager(new File("cache"));
        cacheManager.startCleanupThread();
        if (System.getProperty("launcher", "0").equals("1")) {
            ThreadCreator.createThread(() -> {
                try (BufferedReader reader = new BufferedReader(new InputStreamReader(System.in))) {
                    String line;
                    while ((line = reader.readLine()) != null) {
                        switch (line) {
                            case "SIGINT":
                                System.exit(0);
                                break;
                            case "SIGTERM":
                                restartForUpdate();
                                break;
                        }
                    }
                } catch (Exception e) {
                }
            }, null, true, false).start();
        }
    }

    private void closeAllServerSockets() {
        for (ServerSocket serverSocket : serverSockets) {
            try {
                serverSocket.close();
            } catch (Exception e) {
            }
        }
    }

    private void restartForUpdate() {
        logger.stop();
        closeAllServerSockets();
        try {
            Thread.sleep(1000L);
        } catch (Exception e) {
        }
        System.err.println("Launcher-Exit");
    }

    String getAddr(int port, String host) {
        String defaultResult = null;
        try (BufferedReader reader = new BufferedReader(new FileReader(new File("hosts_" + port + ".txt")))) {
            String line;
            while ((line = reader.readLine()) != null) {
                int p = line.indexOf("=");
                if (p == -1) {
                    continue;
                }
                String hostKey = line.substring(0, p);
                String targetAddress = line.substring(p + 1);
                if (hostKey.endsWith("/")) {
                    if (host.startsWith(hostKey)) {
                        return targetAddress;
                    }
                } else if (host.equals(hostKey) || host.startsWith(hostKey + "/")) {
                    return targetAddress;
                }
                if (hostKey.equalsIgnoreCase("default")) {
                    defaultResult = targetAddress;
                }
            }
        } catch (IOException ioe) {
        }
        return defaultResult;
    }

    private List<ForwardingSettings> getSettings(int port) {
        List<ForwardingSettings> settingsList = new ArrayList<>();
        String version = "0";
        String file = port == 0 ? "" : ("hosts_" + port + ".txt");
        try (BufferedReader reader = new BufferedReader(new FileReader(file))) {
            ForwardingSettings currentSettings = null;
            String line;
            while ((line = reader.readLine()) != null) {
                switch (version) {
                    case "0": {
                        int p = line.indexOf("#");
                        if (p != -1) {
                            line = line.substring(0, p);
                        }
                        line = line.trim();
                        p = line.indexOf("=");
                        if (p != -1) {
                            String key = line.substring(0, p).trim();
                            String val = line.substring(p + 1).trim();
                            if (key.equals("version")) {
                                version = val;
                            } else if (key.equalsIgnoreCase("default")) {
                                settingsList.add(parseForwardingSettings(key, port, val));
                            }
                        }
                    }
                    break;
                    case "1": {
                        int p = line.indexOf("#");
                        if (p != -1) {
                            line = line.substring(0, p);
                        }
                        line = line.trim();
                        p = line.indexOf("=");
                        if (p != -1) {
                            String key = line.substring(0, p).trim();
                            String val = line.substring(p + 1).trim();
                            if (currentSettings != null) {
                                switch (key.toLowerCase()) {
                                    case "backend": {
                                        currentSettings.backend = val;
                                        currentSettings.forwardType = ForwardingSettings.ForwardType.NORMAL;
                                    }
                                    break;
                                    case "cache": {
                                        currentSettings.allowCache = Util.parseBoolean(val);
                                    }
                                    break;
                                    case "redirect": {
                                        try {
                                            if (val.indexOf("/", val.indexOf("://") + 3) == -1) {
                                                currentSettings.backend = val;
                                                currentSettings.forwardType = ForwardingSettings.ForwardType.REDIRECT_PREFIX;
                                                break;
                                            }
                                        } catch (Exception e) {
                                        }
                                        currentSettings.backend = val;
                                        currentSettings.forwardType = ForwardingSettings.ForwardType.REDIRECT_EXACT;
                                    }
                                    break;
                                    case "redirectprefix": {
                                        currentSettings.backend = val;
                                        currentSettings.forwardType = ForwardingSettings.ForwardType.REDIRECT_PREFIX;
                                    }
                                    break;
                                    case "redirectexact": {
                                        currentSettings.backend = val;
                                        currentSettings.forwardType = ForwardingSettings.ForwardType.REDIRECT_EXACT;
                                    }
                                    break;
                                    case "hideotherproxies": {
                                        currentSettings.hideOtherProxies = Util.parseBoolean(val);
                                    }
                                    break;
                                    case "alwayscloseconnection": {
                                        currentSettings.alwaysCloseConnection = Util.parseBoolean(val);
                                    }
                                    break;
                                    case "basicauthcondition": {
                                        currentSettings.basicAuthCondition = ForwardingSettings.BasicAuthCondition.valueOf(val.toUpperCase());
                                    }
                                    break;
                                    case "basicauthfile": {
                                        currentSettings.basicAuthFile = val;
                                    }
                                    break;
                                    case "hsts": {
                                        currentSettings.hstsTimeout = Long.parseLong(val);
                                    }
                                    break;
                                    case "hstsincludesubdomains": {
                                        currentSettings.hstsIncludeSubdomains = Util.parseBoolean(val);
                                        if (!currentSettings.hstsIncludeSubdomains) {
                                            currentSettings.hstsPreload = false;
                                        }
                                    }
                                    break;
                                    case "hstspreload": {
                                        currentSettings.hstsPreload = Util.parseBoolean(val);
                                        if (currentSettings.hstsPreload) {
                                            currentSettings.hstsIncludeSubdomains = true;
                                        }
                                    }
                                    break;
                                    case "hostheader": {
                                        currentSettings.hostHeader = val;
                                    }
                                    break;
                                    case "injectheadertoserver": {
                                        currentSettings.injectHeadersToServer.add(val);
                                    }
                                    break;
                                    case "injectheadertoclient": {
                                        currentSettings.injectHeadersToClient.add(val);
                                    }
                                    break;
                                }
                            }
                        } else {
                            if (!line.isEmpty()) {
                                settingsList.add(currentSettings = new ForwardingSettings(line, port));
                            }
                        }
                    }
                    break;
                }
            }
        } catch (IOException ioe) {
        }
        return settingsList;
    }

    ForwardingSettingsMatch getSettings(int port, String host, String path) {
        if (host.contains(":")) {
            int colonPos = host.lastIndexOf(":");
            int checkPort = Integer.parseInt(host.substring(colonPos + 1));
            if (checkPort != port) {
                return null;
            }
            host = host.substring(0, colonPos);
        }
        List<ForwardingSettings> settingsList = getSettings(port);
        for (ForwardingSettings settings : settingsList) {
            ForwardingSettingsMatch match = settings.match(host, path, port);
            if (match != null) {
                return match;
            }
        }
        return null;
    }

    private ForwardingSettings parseForwardingSettings(String key, int port, String val) {
        if (val == null) {
            return null;
        }
        ForwardingSettings settings = new ForwardingSettings(key, port);
        Matcher matcher = hstsPattern.matcher(val);
        if (matcher.find()) {
            if (matcher.start() == 0) {
                try {
                    String includeString = matcher.group(1);
                    String hstsTimeString = matcher.group(2);
                    if (includeString.equals("I")) {
                        settings.hstsIncludeSubdomains = true;
                    } else if (includeString.equals("P")) {
                        settings.hstsIncludeSubdomains = true;
                        settings.hstsPreload = true;
                    }
                    settings.hstsTimeout = Long.parseLong(hstsTimeString);
                } catch (Exception e) {
                    settings.hstsIncludeSubdomains = settings.hstsPreload = false;
                    settings.hstsTimeout = -1L;
                }
                val = val.substring(matcher.end());
            }
        }
        if (val.startsWith("(P)")) { // hide upstream proxies
            settings.hideOtherProxies = true;
            val = val.substring(3);
        }
        if (val.startsWith("@@@")) {
            // Redirect and close connection
            // useful for captive portal redirection
            // prevents original redirection connection from staying open
            // so the browser won't reuse it when the user is granted access
            settings.alwaysCloseConnection = true;
            settings.forwardType = ForwardingSettings.ForwardType.REDIRECT_EXACT;
            val = val.substring(3);
        } else if (val.startsWith("@@")) {
            // Redirect to specific URL
            settings.forwardType = ForwardingSettings.ForwardType.REDIRECT_EXACT;
            val = val.substring(2);
        } else if (val.startsWith("@")) {
            // Redirect prefix only
            settings.forwardType = ForwardingSettings.ForwardType.REDIRECT_PREFIX;
            val = val.substring(1);
        }
        settings.backend = val;
        return settings;
    }

    String getCustom503(int port, String host) {
        String d = null;
        try (BufferedReader reader = new BufferedReader(new FileReader(new File("custom503_" + port + ".txt")))) {
            String line;
            while ((line = reader.readLine()) != null) {
                int p = line.indexOf("=");
                if (p == -1) {
                    continue;
                }
                String h = line.substring(0, p);
                String ad = line.substring(p + 1);
                if (h.endsWith("/")) {
                    if (host.startsWith(h)) {
                        return ad;
                    }
                } else if (host.equals(h) || host.startsWith(h + "/")) {
                    return ad;
                }
                if (h.equalsIgnoreCase("default")) {
                    d = ad;
                }
            }
        } catch (IOException ioe) {
        }
        return d;
    }

    File get429File(String host) {
        File f = new File("error429/" + host + ".html");
        if (!f.exists()) {
            f = new File("error429/default.html");
        }
        return f;
    }

    private void loadSocketFactories() throws IOException {
        long now;
        long check;
        boolean somethingChanged = false;
        boolean updateTimeOnly = false;
        readLock.lock();
        try {
            check = lastLoadFactories;
            now = System.currentTimeMillis();
            somethingChanged = false;
            if (lastLoadFactories == 0L) {
                somethingChanged = true;
            } else if (now - lastLoadFactories > 120000L) {
                updateTimeOnly = true;
                for (FileToWatch w : filesToWatch) {
                    if (w.hasChanged()) {
                        updateTimeOnly = false;
                        somethingChanged = true;
                        break;
                    }
                }
            }
        } finally {
            readLock.unlock();
        }
        if (updateTimeOnly) {
            writeLock.lock();
            try {
                if (check != lastLoadFactories) {
                    return;
                }
                lastLoadFactories = now;
            } finally {
                writeLock.unlock();
            }
        } else if (somethingChanged) {
            writeLock.lock();
            try {
                Map<String, CertPuller.CertPullerInfo> certPullerMap = new HashMap<>();
                if (check != lastLoadFactories) {
                    return;
                }
                lastLoadFactories = now;
                filesToWatch.clear();
                sslInfo.clear();
                File certsDir = new File("certificates");
                if (!certsDir.exists()) {
                    certsDir = new File(".");
                }
                File certs = new File("certificates.txt");
                if (!certs.exists()) {
                    certs = new File(certsDir, "certificates.txt");
                }
                filesToWatch.add(new FileToWatch(certs));
                try (BufferedReader reader = new BufferedReader(new FileReader(certs))) {
                    String line;
                    while ((line = reader.readLine()) != null) {
                        int hashPos = line.indexOf("#");
                        if (hashPos >= 0) {
                            line = line.substring(0, hashPos);
                        }
                        line = line.trim();
                        String[] parts = line.split("\t{1,}+", 4);
                        if (parts[0].equals("transparentproxy")) {
                            transparentProxy = true;
                        }
                        if (parts.length < 2) {
                            continue;
                        }
                        if (parts[0].equals("pull")) {
                            if (parts.length < 4) {
                                continue;
                            }
                            String url = parts[1];
                            String apiKey = parts[2];
                            String file = parts[3];
                            CertPuller.CertPullerInfo cpi = new CertPuller.CertPullerInfo(url, new File(certsDir, file), apiKey);
                            certPullerMap.put(url, cpi);
                        } else {
                            if (parts[1].equalsIgnoreCase("Forward") || parts[1].equalsIgnoreCase("ForwardN")) {
                                if (parts.length < 3) {
                                    continue;
                                }
                                String onlyIPs = null;
                                if (parts.length >= 4) {
                                    onlyIPs = parts[3];
                                }
                                sslInfo.put(parts[0].toLowerCase(), new SSLInfo(parts[2], !parts[1].equals("ForwardN"), onlyIPs));
                            } else {
                                if (parts.length < 4) {
                                    continue;
                                }
                                String keystorePath = parts[2];
                                File keystoreFile = new File(certsDir, keystorePath);
                                filesToWatch.add(new FileToWatch(keystoreFile));
                                if (keystoreFile.exists()) {
                                    KeyStore keystore = KeyMaster.getFromPath(keystoreFile, parts[1], parts[3]);
                                    SSLSocketFactory factory = KeyMaster.getSSLSocketFactory(keystore, parts[3], "TLS");
                                    sslInfo.put(parts[0].toLowerCase(), new SSLInfo(factory));
                                }
                            }
                        }
                    }
                }
                certPuller.set(certPullerMap);
            } finally {
                writeLock.unlock();
            }
        }
    }

    public CacheManager getCacheManager() {
        return cacheManager;
    }

    SSLUpgradeResult upgradeSSL(Socket socket) throws IOException {
        List<String> injectXForwardedFor = new ArrayList<>();
        try {
            loadSocketFactories();
        } catch (Exception e) {
            log("Certificates load error", e);
        }
        InputStream in = socket.getInputStream();
        String clientIp = socket.getInetAddress().getHostAddress();
        byte[] initialBytes = TlsUtil.readTlsPacket(in, 4096);
        if (initialBytes[0] == (byte) 0xff && initialBytes[1] == (byte) 0x7f) {
            int ver = initialBytes[2] & 0xff;
            if (TrustForward.isTrusted(clientIp)) {
                ByteArrayInputStream infoStream = new ByteArrayInputStream(initialBytes, 5, initialBytes.length - 5);
                try {
                    while (infoStream.available() > 0) {
                        int len = IOUtil.read(infoStream);
                        injectXForwardedFor.add(new String(IOUtil.readFully(infoStream, len), StandardCharsets.UTF_8));
                    }
                } catch (Exception e) {
                }
            }
            initialBytes = TlsUtil.readTlsPacket(in, 4096);
        }
        injectXForwardedFor.add(clientIp);
        String sni = TlsUtil.readSNI(initialBytes);
        boolean noSni = false;
        if (sni == null) {
            noSni = true;
            sni = "*";
        }
        SSLInfo info = getSSLInfo(sni);
        if (info == null) {
            if (!noSni && transparentProxy) {
                try {
                    InetAddress byName = InetAddress.getByName(sni);
                    return new SSLUpgradeResult(byName.getHostAddress() + ":" + socket.getLocalPort(), initialBytes, null);
                } catch (Exception e) {
                }
            }
            OutputStream out = socket.getOutputStream();
            out.write(noSni ? handshakeFailure : unrecognizedName);
            return null;
        }
        if (info.factory != null) {
            SSLSocket sslSocket = (SSLSocket) info.factory.createSocket(socket, new ByteArrayInputStream(initialBytes), true);
            sslSocket.setUseClientMode(false);
            sslSocket.startHandshake();
            return new SSLUpgradeResult(sslSocket, initialBytes, info.injectXForwardedFor ? injectXForwardedFor : null);
        } else {
            if (info.onlyIPs != null) {
                if (!info.onlyIPs.isEmpty()) {
                    boolean allowed = false;
                    IP clientIP = IP.getIP(clientIp);
                    for (IP ip : info.onlyIPs) {
                        if (ip.contains(clientIP)) {
                            allowed = true;
                            break;
                        }
                    }
                    if (!allowed) {
                        OutputStream out = socket.getOutputStream();
                        out.write(unrecognizedName);
                        return null;
                    }
                }
            }
            return new SSLUpgradeResult(info.backend, initialBytes, info.injectXForwardedFor ? injectXForwardedFor : null);
        }
    }

    SSLInfo getSSLInfo(String serverName) {
        SSLInfo info = sslInfo.get(serverName);
        while (info == null) {
            if (serverName.equals("*")) {
                break;
            } else if (serverName.startsWith("*.")) {
                serverName = serverName.substring(2);
                if (serverName.contains(".")) {
                    serverName = "*." + serverName.substring(serverName.indexOf(".") + 1);
                } else {
                    serverName = "*";
                }
            } else {
                if (serverName.contains(".")) {
                    serverName = "*." + serverName.substring(serverName.indexOf(".") + 1);
                } else {
                    serverName = "*";
                }
            }
            info = sslInfo.get(serverName);
        }
        return info;
    }

    public void log(String logMessage) {
        logger.log(logMessage, null);
        System.err.println(logMessage);
    }

    public void log(String msg, Throwable t) {
        logger.log(msg, t);
        t.printStackTrace(System.err);
    }

    public void log(Throwable t) {
        logger.log(null, t);
        t.printStackTrace(System.err);
    }

    void ban(String ip) {
        IP i;
        try {
            i = IP.getIP(ip).getNetworkId();
            if (i instanceof IPv6 && i.getPrefixLength() > 64) {
                i = i.adjustPrefix(64).getNetworkId();
            }
        } catch (Exception e) {
            return;
        }
        if (isBanned(ip)) {
            return;
        }
        banWriteLock.lock();
        try {
            if (isBanned(ip)) {
                return;
            }
            bannedIPs.add(i);
            try (FileWriter writer = new FileWriter("bannedips.txt", true)) {
                writer.write(i.toShortString() + "\n");
            }
        } catch (Exception e) {
        } finally {
            banWriteLock.unlock();
        }
    }

    boolean isBanned(String ip) {
        IP i;
        try {
            i = IP.getIP(ip);
        } catch (Exception e) {
            return false;
        }
        banReadLock.lock();
        try {
            while (true) {
                if (bannedIPs.contains(i)) {
                    return true;
                }
                if (i.getPrefixLength() > 0) {
                    i = i.adjustPrefix(i.getPrefixLength() - 1).getNetworkId();
                } else {
                    break;
                }
            }
        } catch (Exception e) {
        } finally {
            banReadLock.unlock();
        }
        return false;
    }

    public RateLimitController getRateLimitController() {
        return rateLimitController;
    }

    public static class SSLUpgradeResult {

        public final SSLSocket socket;
        public final String backend;
        public final byte[] initialBytes;
        public List<String> injectXForwardedFor;

        private SSLUpgradeResult(String backend, byte[] initialBytes, List<String> injectXForwardedFor) {
            this.socket = null;
            this.backend = backend;
            this.initialBytes = initialBytes;
            this.injectXForwardedFor = injectXForwardedFor;
        }

        private SSLUpgradeResult(SSLSocket socket, byte[] initialBytes, List<String> injectXForwardedFor) {
            this.socket = socket;
            this.backend = null;
            this.initialBytes = initialBytes;
            this.injectXForwardedFor = injectXForwardedFor;
        }

        public byte[] getInitialForwardBytes() {
            if (injectXForwardedFor == null || injectXForwardedFor.isEmpty()) {
                return initialBytes;
            }
            try {
                ByteArrayOutputStream out = new ByteArrayOutputStream();
                out.write(0xff);
                out.write(0x7f);
                out.write(0x00);
                ByteArrayOutputStream dataStream = new ByteArrayOutputStream();
                for (String ip : injectXForwardedFor) {
                    byte[] b = ip.getBytes(StandardCharsets.UTF_8);
                    if (b.length > 255) {
                        continue;
                    }
                    dataStream.write(b.length);
                    dataStream.write(b);
                }
                byte[] data = dataStream.toByteArray();
                out.write((data.length >> 8) & 0xff);
                out.write(data.length & 0xff);
                out.write(data);
                out.write(initialBytes);
                return out.toByteArray();
            } catch (IOException e) {
                throw new RuntimeException();
            }
        }
    }

    public class SSLInfo {

        public final String backend;
        public final SSLSocketFactory factory;
        public final boolean injectXForwardedFor;
        public final List<IP> onlyIPs;

        private SSLInfo(String backend, boolean injectXForwardedFor, String onlyIPs) {
            this.factory = null;
            this.backend = backend;
            this.injectXForwardedFor = injectXForwardedFor;
            if (onlyIPs == null || !onlyIPs.trim().isEmpty()) {
                this.onlyIPs = null;
            } else {
                List<IP> result = null;
                try {
                    String[] ips = onlyIPs.split(",");
                    IP[] ipList = new IP[ips.length];
                    for (int i = 0; i < ips.length; i++) {
                        ipList[i] = IP.getIP(ips[i].trim());
                    }
                    result = Collections.unmodifiableList(Arrays.asList(ipList));
                } catch (Exception e) {
                }
                this.onlyIPs = result;
            }
        }

        private SSLInfo(SSLSocketFactory factory) {
            this.factory = factory;
            this.backend = null;
            this.injectXForwardedFor = true;
            this.onlyIPs = null;
        }
    }
}
