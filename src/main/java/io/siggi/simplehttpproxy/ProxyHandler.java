package io.siggi.simplehttpproxy;

import io.siggi.iphelper.IP;
import io.siggi.simplehttpproxy.cache.CacheBuilder;
import io.siggi.simplehttpproxy.cache.CacheManager;
import io.siggi.simplehttpproxy.cache.CacheObject;
import io.siggi.simplehttpproxy.io.ChunkedOutputStream;
import io.siggi.simplehttpproxy.io.SecureBufferedInputStream;
import io.siggi.simplehttpproxy.io.SubInputStream;
import io.siggi.simplehttpproxy.io.TeeOutputStream;
import io.siggi.simplehttpproxy.net.SslProxy;
import io.siggi.simplehttpproxy.util.CaseInsensitiveHashMap;
import io.siggi.simplehttpproxy.util.CloudFlare;
import io.siggi.simplehttpproxy.util.HttpHeader;
import io.siggi.simplehttpproxy.util.TrustForward;
import io.siggi.simplehttpproxy.util.Util;

import javax.net.ssl.SSLException;
import javax.net.ssl.SSLSocket;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.net.SocketException;
import java.net.SocketTimeoutException;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;

public class ProxyHandler {

    private static int nextConnectionId = 0;
    private final SimpleHttpProxy proxyServer;
    private final CacheManager cacheManager;
    private final boolean secure;
    // TODO: make this configurable
    private final boolean allowConnectionReuse = true;
    private Socket clientSocket;
    private SecureBufferedInputStream clientIn;
    private OutputStream clientOut;
    private List<String> injectXForwardedFor = null;
    private String lastHost = null;
    private String lastAddr = null;
    private Socket serverSocket;
    private InputStream serverIn;
    private OutputStream serverOut;
    private boolean keepAlive = true;
    private boolean started = false;
    private ForwardingSettingsMatch settingsMatch = null;
    private ForwardingSettings settings = null;
    public ProxyHandler(SimpleHttpProxy proxyServer, boolean secure, Socket clientSocket) throws IOException {
        this.proxyServer = proxyServer;
        this.cacheManager = proxyServer.getCacheManager();
        this.clientSocket = clientSocket;
        this.secure = secure;
        clientSocket.setSoTimeout(120000); // we announce Keep-Alive timeout=60, but we'll wait up to 2 minutes
    }

    private static synchronized int nextConnectionId() {
        return ++nextConnectionId;
    }

    private static void upgrade(Socket clientSocket, Socket serverSocket) {
        UpgradeProtocolProxy upp = new UpgradeProtocolProxy(clientSocket, serverSocket);
        upp.start();
    }

    private static boolean isSafeMethod(String requestLine) {
        String method;
        if (requestLine.contains(" ")) {
            method = requestLine.substring(0, requestLine.indexOf(" "));
        } else {
            method = requestLine;
        }
        switch (method.toUpperCase()) {
            case "GET":
            case "HEAD":
            case "OPTIONS":
            case "TRACE":
            case "PROPFIND": // WebDAV method
                return true;
            default:
                return false;
        }
    }

    private static boolean isIdempotent(String requestLine) {
        String method;
        if (requestLine.contains(" ")) {
            method = requestLine.substring(0, requestLine.indexOf(" "));
        } else {
            method = requestLine;
        }
        switch (method.toUpperCase()) {
            case "GET":
            case "HEAD":
            case "OPTIONS":
            case "TRACE":
            case "PUT":
            case "DELETE":
            case "PROPFIND": // WebDAV method
                return true;
            default:
                return false;
        }
    }

    public void start() {
        if (started) {
            return;
        }
        started = true;
        new Thread(this::handler).start();
    }

    private void addHstsHeader(HttpHeader header) {
        if (settings == null) {
            return;
        }
        if (settings.hstsTimeout < 0L) {
            header.deleteHeader("Strict-Transport-Security");
        } else {
            String suffix = "";
            if (settings.hstsIncludeSubdomains) {
                suffix += "; includeSubDomains";
            }
            if (settings.hstsPreload) {
                suffix += "; preload";
            }
            header.addHeader("Strict-Transport-Security", "max-age=" + settings.hstsTimeout + suffix);
        }
    }

    private void handler() {
        injectXForwardedFor = null;
        try {
            if (secure) {
                SimpleHttpProxy.SSLUpgradeResult upgradeResult = proxyServer.upgradeSSL(clientSocket);
                if (upgradeResult == null) {
                    try {
                        clientSocket.close();
                    } catch (Exception e) {
                    }
                    return;
                }
                if (upgradeResult.socket == null) {
                    if (upgradeResult.backend == null) {
                        try {
                            clientSocket.close();
                        } catch (Exception e) {
                        }
                        return;
                    }
                    log("Proxying raw SSL connection for " + clientSocket.getInetAddress().getHostAddress() + " to " + upgradeResult.backend);
                    new SslProxy(clientSocket, upgradeResult).start();
                    return;
                }
                SSLSocket ssl = upgradeResult.socket;
                injectXForwardedFor = upgradeResult.injectXForwardedFor;
                clientSocket = ssl;
            }
            clientIn = new SecureBufferedInputStream(clientSocket.getInputStream(), 131072);
            clientOut = clientSocket.getOutputStream();
        } catch (Exception e) {
            try {
                clientSocket.close();
                return;
            } catch (Exception e2) {
            }
            log("Failed to establish connection with client", e);
        }
        boolean doNotClose = false;
        boolean wroteToClient = false;
        boolean receivedRequest = false;
        try {
            int connectionId = nextConnectionId();
            int downstreamId = 0;

            long reuseTimeout = 0L; // expiry time for downstream connection reuse
            int requestsReceived = 0; // on current upstream connection
            int requestsForwarded = 0; // on current downstream connection
            int maxDownstreamRequests = 1;

            String logLine = null;
            InputStream wrappedIn = null;
            HttpHeader downstreamHeaders;
            outerLoop:
            while (keepAlive) {
                String sourceIP = clientSocket.getInetAddress().getHostAddress();
                String clientIP = sourceIP;
                downstreamHeaders = null;
                if (logLine == null) {
                    logLine = "[" + clientSocket.getInetAddress().getHostAddress() + "]: Dropped connection before sending a request on port " + clientSocket.getLocalPort();
                } else {
                    logLine = null;
                }
                this.settingsMatch = null;
                this.settings = null;
                CacheBuilder cacheBuilder = null;
                try {
                    wroteToClient = false;
                    receivedRequest = false;
                    downstreamHeaders = Util.readHeader(clientIn, 16384);
                    receivedRequest = true;
                    if (downstreamHeaders == null) {
                        break;
                    }
                    String method;
                    String httpVer;
                    String path;
                    try {
                        String firstLine = downstreamHeaders.getFirstLine();
                        int firstSpace = firstLine.indexOf(" ");
                        int lastSpace = firstLine.lastIndexOf(" ");
                        method = firstLine.substring(0, firstSpace);
                        path = firstLine.substring(firstSpace + 1, lastSpace);
                        httpVer = firstLine.substring(lastSpace + 1);
                    } catch (Exception e) {
                        return400();
                        continue;
                    }

                    requestsReceived += 1;

                    wrappedIn = downstreamHeaders.wrapInputStream(clientIn);
                    String host = downstreamHeaders.getHeader("Host");
                    if (host == null) {
                        // Host not sent in headers, return a 400 error
                        return400();
                        continue;
                    }
                    downstreamHeaders.setHeader("X-Forwarded-Host", host);
                    String localHostAddr = host + (host.contains(":") ? "" : (":" + clientSocket.getLocalPort()));
                    {
                        // prevent HTTP/2 upgrading
                        String connectionHeader = downstreamHeaders.getHeader("Connection");
                        if (connectionHeader != null && connectionHeader.contains("Upgrade")) {
                            String upgradeHeader = downstreamHeaders.getHeader("Upgrade");
                            if (upgradeHeader != null) {
                                String upgradeHeaderLC = upgradeHeader.toLowerCase();
                                if (upgradeHeaderLC.contains("http/2")
                                        || upgradeHeaderLC.contains("h2c")) {
                                    downstreamHeaders.deleteHeader("Connection");
                                    downstreamHeaders.deleteHeader("Upgrade");
                                }
                            }
                        }
                    }
                    boolean determinedClientIP = false;
                    String viaString = null;
                    String cfRay = downstreamHeaders.getCFRay();
                    String forwardedFor = downstreamHeaders.getHeader("X-Forwarded-For");
                    if (forwardedFor == null || forwardedFor.isEmpty()) {
                        // X-Forwarded-For is not set, set client IP as the only one in the list
                        if (injectXForwardedFor == null || injectXForwardedFor.isEmpty()) {
                            forwardedFor = clientSocket.getInetAddress().getHostAddress();
                        } else {
                            for (String ip : injectXForwardedFor) {
                                forwardedFor = ((forwardedFor == null || forwardedFor.isEmpty()) ? "" : (forwardedFor + ", ")) + ip;
                            }
                        }
                    } else {
                        // X-Forwarded-For is set, append to the list
                        if (CloudFlare.isCloudFlare(clientSocket.getInetAddress())) {
                            String ip = forwardedFor.substring(forwardedFor.lastIndexOf(",") + 1).trim();
                            try {
                                clientIP = IP.getIP(ip).toString();
                                determinedClientIP = true;
                            } catch (Exception e) {
                            }
                            viaString = sourceIP + (cfRay == null ? "" : (", CF-Ray: " + cfRay));
                        }
                        if (injectXForwardedFor == null || injectXForwardedFor.isEmpty()) {
                            forwardedFor += ", " + clientSocket.getInetAddress().getHostAddress();
                        } else {
                            for (String ip : injectXForwardedFor) {
                                forwardedFor += ", " + ip;
                            }
                        }
                    }
                    if (!determinedClientIP && forwardedFor != null && !forwardedFor.isEmpty()) {
                        String[] ips = forwardedFor.replace(" ", "").split(",");
                        clientIP = ips[ips.length - 1];
                        for (int i = ips.length - 1; i >= 1; i--) {
                            if (TrustForward.isTrusted(ips[i]) || CloudFlare.isCloudFlare(ips[i])) {
                                viaString = ips[i] + ((viaString == null || viaString.isEmpty()) ? ("") : (", " + viaString));
                                clientIP = ips[i - 1];
                            }
                        }
                    }
                    if (viaString != null && cfRay != null) {
                        viaString += ", CF-Ray: " + cfRay;
                    }
                    String userAgent = downstreamHeaders.getHeader("User-Agent");
                    downstreamHeaders.setHeader("X-Forwarded-For", forwardedFor);
                    downstreamHeaders.setHeader("X-Forwarded-Proto", clientSocket instanceof SSLSocket ? "https" : "http");
                    {
                        String logIP;
                        if (viaString == null || viaString.isEmpty()) {
                            logIP = clientIP;
                        } else {
                            logIP = clientIP + " (via " + viaString + ")";
                        }
                        logLine = "[" + logIP + "] (" + userAgent + "): " + host + " (" + clientSocket.getLocalPort() + "): " + downstreamHeaders.getFirstLine();
                    }
                    settingsMatch = proxyServer.getSettings(
                            clientSocket.getLocalPort(),
                            localHostAddr.toLowerCase(),
                            path.startsWith("/") ? path : ""
                    );
                    if (settingsMatch != null) {
                        settings = settingsMatch.settings;
                        if (settings.hostHeader != null)
                            downstreamHeaders.setHeader("Host", settings.hostHeader);
                        injectHeaders(settings.injectHeadersToServer, downstreamHeaders);
                    }
                    if (proxyServer.isBanned(clientIP)) {
                        logLine += " -! IP is banned, returning error message";
                        youAreBanned(clientIP);
                        continue;
                    }
                    if (proxyServer.getRateLimitController().shouldRateLimit(host, path, clientIP)) {
                        logLine += " -! Ratelimited";
                        rateLimit(host, path, clientIP);
                        continue;
                    }
                    if (downstreamHeaders.getFirstLine().startsWith("GET ")
                            || downstreamHeaders.getFirstLine().startsWith("HEAD ")) {
                        boolean head = downstreamHeaders.getFirstLine().startsWith("HEAD ");
                        // Direct serve files if they exist
                        if (path.contains("?")) {
                            path = path.substring(0, path.indexOf("?"));
                        }
                        String decode = URLDecoder.decode(path, "UTF-8");
                        if (decode.startsWith("/")) {
                            String chkFile = "directserve/" + clientSocket.getLocalPort() + "/" + host + decode;
                            if (!chkFile.contains("/../") && !chkFile.endsWith("/..")) {
                                File f = new File(chkFile);
                                if (f.exists() && f.isFile()) {
                                    boolean partialContent = false;
                                    long partialStart = 0L;
                                    long partialEnd = 0L;
                                    String rangeHeader = downstreamHeaders.getHeader("Range");
                                    if (rangeHeader != null && !rangeHeader.isEmpty()) {
                                        try {
                                            if (rangeHeader.startsWith("bytes=")) {
                                                rangeHeader = rangeHeader.substring(6).trim();
                                                int pos = rangeHeader.indexOf("-");
                                                if (pos == -1) {
                                                    partialStart = Long.parseLong(rangeHeader);
                                                    partialContent = true;
                                                } else {
                                                    String l = rangeHeader.substring(0, pos);
                                                    String r = rangeHeader.substring(pos + 1);
                                                    partialStart = Long.parseLong(l);
                                                    if (r.isEmpty()) {
                                                        partialEnd = -1L;
                                                    } else {
                                                        partialEnd = Long.parseLong(r);
                                                    }
                                                    if (partialEnd <= f.length() - 1L)
                                                        partialContent = true;
                                                }
                                            }
                                        } catch (Exception e) {
                                        }
                                    }
                                    HttpHeader resultHeader = new HttpHeader(partialContent ? "HTTP/1.1 206 Partial Content" : "HTTP/1.1 200 OK", new CaseInsensitiveHashMap<>());
                                    long amountToWrite = f.length();
                                    if (partialContent) {
                                        if (partialEnd == -1L)
                                            partialEnd = f.length() - 1;
                                        resultHeader.addHeader("Content-Range", "bytes " + partialStart + "-" + partialEnd + "/" + f.length());
                                        amountToWrite = partialEnd - partialStart + 1L;
                                    }
                                    addHstsHeader(resultHeader);
                                    keepAliveHeaders(resultHeader);
                                    resultHeader.setHeader("Content-Length", Long.toString(amountToWrite));
                                    String name = f.getName();
                                    String ext = name.substring(name.lastIndexOf(".") + 1);
                                    if (ext.equals(name)) {
                                        ext = "";
                                    }
                                    resultHeader.setHeader("Content-Type", getContentType(ext));
                                    resultHeader.setHeader("Server", "Siggi-SimpleHttpProxy");
                                    Util.writeHeader(clientOut, resultHeader);
                                    if (!head) {
                                        OutputStream wrapOutputStream = resultHeader.wrapOutputStream(clientOut);
                                        try (FileInputStream fis = new FileInputStream(f)) {
                                            InputStream in;
                                            if (partialContent) {
                                                fis.skip(partialStart);
                                                in = new SubInputStream(fis, amountToWrite);
                                            } else {
                                                in = fis;
                                            }
                                            Util.copy(in, wrapOutputStream);
                                        }
                                    }
                                    continue;
                                }
                            }
                        }
                    }
                    if (settings == null || settings.backend == null) {
                        return404();
                        continue;
                    }
                    if (settings.alwaysCloseConnection) {
                        keepAlive = false;
                    }
                    String backendServer = Util.determineServer(settings.backend);
                    String backendPath = Util.determinePath(settings.backend);
                    if (settings.hideOtherProxies) { // hide upstream proxies
                        downstreamHeaders.setHeader("X-Forwarded-For", clientIP);
                    }
                    if (settings.backend.equals("503")) {
                        String custom503 = proxyServer.getCustom503(clientSocket.getLocalPort(), localHostAddr.toLowerCase() + (path.startsWith("/") ? path : ""));
                        return503(custom503);
                        continue;
                    }
                    if (settings.forwardType == ForwardingSettings.ForwardType.REDIRECT_EXACT) {
                        return302(settings.backend);
                        continue;
                    } else if (settings.forwardType == ForwardingSettings.ForwardType.REDIRECT_PREFIX) {
                        if (path.startsWith("/")) {
                            return302(settings.backend + path);
                        } else {
                            return400();
                        }
                        continue;
                    }
                    switch (settings.basicAuthCondition) {
                        case ALL_EXCEPT_SAFE_AND_POST:
                            if (downstreamHeaders.getFirstLine().toUpperCase().startsWith("POST ")) {
                                break;
                            }
                        case ALL_EXCEPT_SAFE:
                            if (isSafeMethod(downstreamHeaders.getFirstLine())) {
                                break;
                            }
                        case ALL: {
                            BasicAuth basicAuth = settings.getBasicAuth();
                            if (basicAuth.isWhitelisted(clientIP)) {
                                break;
                            }
                            authorization:
                            try {
                                String authorization = downstreamHeaders.getHeader("Authorization");
                                if (authorization == null || !authorization.startsWith("Basic ")) {
                                    break authorization;
                                }
                                String loginDetailsBase64 = authorization.substring(6);
                                String loginDetails = new String(Base64.getDecoder().decode(loginDetailsBase64), StandardCharsets.UTF_8);
                                int pos = loginDetails.indexOf(":");
                                if (pos == -1) {
                                    break authorization;
                                }
                                String username = loginDetails.substring(0, pos);
                                String password = loginDetails.substring(pos + 1);
                                if (basicAuth.checkLogin(username, password)) {
                                    break;
                                }
                            } catch (Exception e) {
                            }
                            return401BasicAuth(basicAuth);
                            continue;
                        }
                    }
                    String downstreamPath = path;
                    if (backendPath != null) {
                        // TODO: Test this to make sure it works properly :D
                        String backendPath0 = backendPath;
                        String prefix = settings.path[settingsMatch.index];
                        if (backendPath0.endsWith("/")) {
                            backendPath0 = backendPath0.substring(0, backendPath0.length() - 1);
                        }
                        if (prefix.endsWith("/")) {
                            prefix = prefix.substring(0, prefix.length() - 1);
                        }
                        String newPath = backendPath0 + path.substring(prefix.length());
                        if (newPath.isEmpty()) {
                            return302(path + "/");
                            continue;
                        }
                        downstreamPath = newPath;
                        downstreamHeaders.setFirstLine(method + " " + newPath + " " + httpVer);
                    }
                    HttpHeader upstreamHeaders = null;
                    HttpHeader forwardedUpstreamHeaders = null;
                    String logLineA = logLine;
                    int tries = -1;
                    String cacheIdentifier = backendServer + downstreamPath;
                    CacheObject cacheObject = null;
                    String expect = downstreamHeaders.getHeader("Expect");
                    boolean expect100Continue = expect != null && expect.equalsIgnoreCase("100-continue");
                    if (!expect100Continue && method.equals("GET") && settings.allowCache) {
                        cacheObject = cacheManager.retrieveCacheObject(cacheIdentifier, downstreamHeaders);
                        if (cacheObject != null) {
                            upstreamHeaders = cacheObject.getResponseHeader();
                            upstreamHeaders.deleteHeader("Transfer-Encoding");
                            upstreamHeaders.deleteHeader("Set-Cookie");
                            upstreamHeaders.setHeader("Content-Length", Long.toString(cacheObject.getContentLength()));
                            upstreamHeaders.setHeader("X-SHP-Cache", "hit");
                        }
                    }
                    while (!wroteToClient) {
                        tries += 1;
                        if (tries != 0) {
                            clientIn.reset();
                        }
                        clientIn.mark(524288); // 512kB
                        logLine = logLineA;
                        boolean reuseConnection = allowConnectionReuse && tries == 0 && isIdempotent(downstreamHeaders.getFirstLine()) && lastHost != null && lastAddr != null && host.equals(lastHost) && backendServer.equals(lastAddr);
                        OutputStream wrappedOut = null;
                        sendReq:
                        if (cacheObject == null) {
                            if (reuseConnection && requestsForwarded < maxDownstreamRequests && System.currentTimeMillis() < reuseTimeout) {
                                try {
                                    Util.writeHeader(serverOut, downstreamHeaders);
                                    wrappedOut = downstreamHeaders.wrapOutputStream(serverOut);
                                    break sendReq;
                                } catch (Exception e) {
                                }
                            }
                            if (serverSocket != null) {
                                try {
                                    serverSocket.close();
                                } catch (Exception e) {
                                }
                            }
                            try {
                                serverSocket = Util.connect(backendServer);
                                requestsForwarded = 0;
                                maxDownstreamRequests = 1;
                                downstreamId += 1;
                            } catch (IOException ioe) {
                                return502();
                                continue outerLoop;
                            }
                            serverIn = serverSocket.getInputStream();
                            serverOut = serverSocket.getOutputStream();
                            Util.writeHeader(serverOut, downstreamHeaders);
                            wrappedOut = downstreamHeaders.wrapOutputStream(serverOut);
                            lastHost = host;
                            lastAddr = backendServer;
                        }
                        requestsForwarded += 1;
                        reuseTimeout = 0L;

                        logLine += " (CID:" + connectionId + ",dCID:" + downstreamId + ",DR:" + requestsForwarded + ")";

                        boolean failed100Continue = false;
                        if (expect100Continue) {
                            upstreamHeaders = Util.readHeader(serverIn, 65536);
                            addHstsHeader(upstreamHeaders);
                            upstreamHeaders.setHeader("Connection", "Keep-Alive");
                            upstreamHeaders.setHeader("Keep-Alive", "timeout=60");
                            Util.writeHeader(clientOut, upstreamHeaders);
                            wroteToClient = true;
                            String firstLine = upstreamHeaders.getFirstLine();
                            if (!firstLine.substring(firstLine.indexOf(" ") + 1).startsWith("100 ")) {
                                logLine += " -> " + firstLine;
                                failed100Continue = true;
                                wrappedIn = null;
                            }
                        }
                        if (!failed100Continue) {
                            if (cacheObject == null && wrappedIn != null && wrappedOut != null) {
                                Util.copy(wrappedIn, wrappedOut);
                                if (wrappedOut instanceof ChunkedOutputStream) {
                                    wrappedOut.close();
                                }
                            }
                            if (cacheObject == null) {
                                upstreamHeaders = Util.readHeader(serverIn, 65536);
                                if (upstreamHeaders == null) {
                                    throw new IOException("End of stream");
                                }
                            }
                            addHstsHeader(upstreamHeaders);
                            String firstLine = upstreamHeaders.getFirstLine();
                            logLine += " -> " + firstLine;
                            if (firstLine.substring(firstLine.indexOf(" ") + 1).startsWith("101 ")) {
                                Util.writeHeader(clientOut, upstreamHeaders);
                                wroteToClient = true;
                                upgrade(clientSocket, serverSocket);
                                doNotClose = true;
                                return;
                            }
                            boolean upstreamKeepAlive = false;
                            {
                                String connectionString = upstreamHeaders.getHeader("Connection");
                                if (connectionString != null && connectionString.equals("Keep-Alive")) {
                                    upstreamKeepAlive = true;
                                    if (maxDownstreamRequests == 1) {
                                        maxDownstreamRequests = Integer.MAX_VALUE;
                                    }
                                    String keepAliveString = upstreamHeaders.getHeader("Keep-Alive");
                                    if (keepAliveString != null) {
                                        String[] keepAliveParts = keepAliveString.split(",");
                                        for (String keepAlivePart : keepAliveParts) {
                                            keepAlivePart = keepAlivePart.trim();
                                            if (keepAlivePart.startsWith("timeout=")) {
                                                try {
                                                    int timeout = Integer.parseInt(keepAlivePart.substring(8));
                                                    long timeoutMillis = (((long) timeout) * 1000L);
                                                    timeoutMillis /= 2L;
                                                    reuseTimeout = System.currentTimeMillis() + timeoutMillis;
                                                } catch (Exception e) {
                                                }
                                            }
                                            if (keepAlivePart.startsWith("max=")) {
                                                try {
                                                    maxDownstreamRequests = Integer.parseInt(keepAlivePart.substring(4));
                                                } catch (Exception e) {
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                            String honeypot = upstreamHeaders.getHeader("X-SimpleHttpProxy-Honeypot");
                            if (honeypot != null) {
                                upstreamHeaders.deleteHeader("X-SimpleHttpProxy-Honeypot");
                                if (honeypot.equalsIgnoreCase("ban")) {
                                    proxyServer.ban(clientIP);
                                }
                            }
                            if (!expect100Continue && method.equals("GET") && settings.allowCache && cacheObject == null) {
                                cacheBuilder = cacheManager.createCache(cacheIdentifier, downstreamHeaders, upstreamHeaders);
                                upstreamHeaders.setHeader("X-SHP-Cache", cacheBuilder == null ? "skipped" : "miss");
                            }
                            injectHeaders(settings.injectHeadersToClient, upstreamHeaders);
                            if (!upstreamKeepAlive && upstreamHeaders.getHeader("Content-Encoding") != null) {
                                // Some webapps report uncompressed Content-Length when sending compressed data
                                // This is incorrect behaviour
                                // They also tend to send Connection: close
                                // We don't know the real Content-Length, so we just convert it to
                                // Transfer-Encoding chunked when forwarding it to the client
                                forwardedUpstreamHeaders = upstreamHeaders.copy();
                                forwardedUpstreamHeaders.deleteHeader("Content-Length");
                                forwardedUpstreamHeaders.setHeader("Transfer-Encoding", "chunked");
                            } else {
                                forwardedUpstreamHeaders = upstreamHeaders;
                            }
                            keepAliveHeaders(forwardedUpstreamHeaders);
                            Util.writeHeader(clientOut, forwardedUpstreamHeaders);
                            wroteToClient = true;
                        }
                    }
                    InputStream upWrapIn = cacheObject != null
                            ? cacheObject.getInputStream()
                            : upstreamHeaders.wrapInputStream(serverIn);
                    OutputStream upWrapOut = forwardedUpstreamHeaders.wrapOutputStream(clientOut);
                    if (upWrapIn != null && upWrapOut != null) {
                        OutputStream outDestination = upWrapOut;
                        if (cacheBuilder != null) {
                            outDestination = new TeeOutputStream(upWrapOut, cacheBuilder);
                        }
                        Util.copy(upWrapIn, outDestination);
                        if (cacheBuilder != null) {
                            cacheBuilder.finished();
                        }
                    }
                    if (upWrapOut instanceof ChunkedOutputStream) {
                        upWrapOut.close();
                    }
                } finally {
                    clientIn.eraseFreeSpace();
                    if (logLine != null) {
                        log(logLine);
                    }
                    boolean setBan = false;
                    String firstLine = downstreamHeaders == null ? null : downstreamHeaders.getFirstLine();
                    if (firstLine != null) {
                        if (firstLine.substring(firstLine.indexOf(" ") + 1).toLowerCase().startsWith("/phpmyadmin")) {
                            setBan = true;
                        }
                    }
                    if (wrappedIn != null) {
                        byte[] b = new byte[4096];
                        int amount = wrappedIn.read(b, 0, b.length);
                        if (amount > 0) {
                            String s = new String(b, 0, amount);
                            if (s.contains("=die(md5(Ch3ck1ng));")) {
                                setBan = true;
                            }
                        }
                    }
                    if (setBan) {
                        proxyServer.ban(clientIP);
                    }
                    if (wrappedIn != null) {
                        Util.copy(wrappedIn, null);
                    }
                    if (cacheBuilder != null) {
                        cacheBuilder.close();
                        cacheBuilder = null;
                    }
                }
            }
        } catch (SocketTimeoutException ste) {
            // we timed out xD
        } catch (SSLException ssle) {
            switch (ssle.getMessage()) {
                case "Socket is closed":
                case "Connection reset":
                    break;
                default:
                    log(ssle);
                    break;
            }
        } catch (Exception e) {
            boolean logException = true;
            if (e instanceof SocketException) {
                String message = e.getMessage();
                if (message != null) switch (message) {
                    case "Socket is closed":
                    case "Connection reset":
                    case "Broken pipe (Write failed)":
                        logException = false;
                        break;
                }
            }
            if (logException)
                log(e);
        } finally {
            if (receivedRequest && !wroteToClient) {
                try {
                    return500();
                } catch (Exception e2) {
                }
            }
            if (!doNotClose) {
                try {
                    clientSocket.close();
                } catch (Exception e) {
                }
                try {
                    serverSocket.close();
                } catch (Exception e) {
                }
            }
        }
    }

    private void injectHeaders(List<String> injectList, HttpHeader headers) {
        for (String string : injectList) {
            int colonPosition = string.indexOf(":");
            if (colonPosition == -1) continue;
            String key = string.substring(0, colonPosition).trim();
            String val = string.substring(colonPosition + 1).trim();
            if (key.startsWith("+")) {
                headers.addHeader(key.substring(1), val);
            } else {
                headers.setHeader(key, val);
            }
        }
    }

    private void keepAliveHeaders(HttpHeader httpHeader) {
        if (keepAlive) {
            httpHeader.setHeader("Connection", "Keep-Alive");
            httpHeader.setHeader("Keep-Alive", "timeout=60");
        } else {
            httpHeader.setHeader("Connection", "close");
        }
    }

    private void return200(String content) throws IOException {
        byte[] bytes = content.getBytes(StandardCharsets.UTF_8);
        if (content.toLowerCase().contains("<html")) {
            return200(bytes, "text/html; charset=utf-8");
        } else {
            return200(bytes, "text/plain; charset=utf-8");
        }
    }

    private void return200(byte[] content, String type) throws IOException {
        HttpHeader httpHeader = new HttpHeader("HTTP/1.1 200 OK", new CaseInsensitiveHashMap<>());
        addHstsHeader(httpHeader);
        httpHeader.setHeader("Server", "Siggi-SimpleHttpProxy");
        httpHeader.setHeader("Content-Length", Integer.toString(content.length));
        httpHeader.setHeader("Cache-Control", "private, max-age=0");
        httpHeader.setHeader("Content-Type", "text/plain; charset=UTF-8");
        keepAliveHeaders(httpHeader);
        Util.writeHeader(clientOut, httpHeader);
        clientOut.write(content);
    }

    private void return302(String target) throws IOException {
        HttpHeader httpHeader = new HttpHeader("HTTP/1.1 302 Found", new CaseInsensitiveHashMap<>());
        addHstsHeader(httpHeader);
        httpHeader.setHeader("Server", "Siggi-SimpleHttpProxy");
        httpHeader.setHeader("Transfer-Encoding", "chunked");
        httpHeader.setHeader("Cache-Control", "private, max-age=0");
        httpHeader.setHeader("Content-Type", "text/plain; charset=UTF-8");
        httpHeader.setHeader("Location", target);
        keepAliveHeaders(httpHeader);
        Util.writeHeader(clientOut, httpHeader);
        try (ChunkedOutputStream out = new ChunkedOutputStream(clientOut)) {
            out.write(("302 Found: " + target).getBytes());
        }
    }

    private void return400() throws IOException {
        HttpHeader httpHeader = new HttpHeader("HTTP/1.1 400 Bad Request", new CaseInsensitiveHashMap<>());
        if (settings != null) {
            addHstsHeader(httpHeader);
        }
        httpHeader.setHeader("Server", "Siggi-SimpleHttpProxy");
        httpHeader.setHeader("Transfer-Encoding", "chunked");
        httpHeader.setHeader("Cache-Control", "private, max-age=0");
        httpHeader.setHeader("Content-Type", "text/plain; charset=UTF-8");
        keepAliveHeaders(httpHeader);
        Util.writeHeader(clientOut, httpHeader);
        try (ChunkedOutputStream out = new ChunkedOutputStream(clientOut)) {
            out.write("400 Bad Request".getBytes());
        }
    }

    private void return401BasicAuth(BasicAuth basicAuth) throws IOException {
        HttpHeader httpHeader = new HttpHeader("HTTP/1.1 401 Unauthorized", new CaseInsensitiveHashMap<>());
        addHstsHeader(httpHeader);
        httpHeader.setHeader("Server", "Siggi-SimpleHttpProxy");
        httpHeader.setHeader("Transfer-Encoding", "chunked");
        httpHeader.setHeader("Cache-Control", "private, max-age=0");
        httpHeader.setHeader("Content-Type", "text/plain; charset=UTF-8");
        httpHeader.setHeader("WWW-Authenticate", "Basic realm=" + basicAuth.getRealm());
        keepAliveHeaders(httpHeader);
        Util.writeHeader(clientOut, httpHeader);
        try (ChunkedOutputStream out = new ChunkedOutputStream(clientOut)) {
            out.write("401 Unauthorized".getBytes());
        }
    }

    private void return404() throws IOException {
        HttpHeader httpHeader = new HttpHeader("HTTP/1.1 404 Not Found", new CaseInsensitiveHashMap<>());
        addHstsHeader(httpHeader);
        httpHeader.setHeader("Server", "Siggi-SimpleHttpProxy");
        httpHeader.setHeader("Transfer-Encoding", "chunked");
        httpHeader.setHeader("Cache-Control", "private, max-age=0");
        httpHeader.setHeader("Content-Type", "text/plain; charset=UTF-8");
        keepAliveHeaders(httpHeader);
        Util.writeHeader(clientOut, httpHeader);
        try (ChunkedOutputStream out = new ChunkedOutputStream(clientOut)) {
            out.write("404 Not Found".getBytes());
        }
    }

    private void return500() throws IOException {
        HttpHeader httpHeader = new HttpHeader("HTTP/1.1 500 Internal Server Error", new CaseInsensitiveHashMap<>());
        addHstsHeader(httpHeader);
        httpHeader.setHeader("Server", "Siggi-SimpleHttpProxy");
        httpHeader.setHeader("Transfer-Encoding", "chunked");
        httpHeader.setHeader("Cache-Control", "private, max-age=15");
        httpHeader.setHeader("Content-Type", "text/plain; charset=UTF-8");
        keepAlive = false;
        keepAliveHeaders(httpHeader);
        Util.writeHeader(clientOut, httpHeader);
        try (ChunkedOutputStream out = new ChunkedOutputStream(clientOut)) {
            out.write("500 Internal Server Error".getBytes());
        }
    }

    private void return502() throws IOException {
        HttpHeader httpHeader = new HttpHeader("HTTP/1.1 502 Bad Gateway", new CaseInsensitiveHashMap<>());
        addHstsHeader(httpHeader);
        httpHeader.setHeader("Server", "Siggi-SimpleHttpProxy");
        httpHeader.setHeader("Transfer-Encoding", "chunked");
        httpHeader.setHeader("Cache-Control", "private, max-age=15");
        httpHeader.setHeader("Content-Type", "text/plain; charset=UTF-8");
        keepAliveHeaders(httpHeader);
        Util.writeHeader(clientOut, httpHeader);
        try (ChunkedOutputStream out = new ChunkedOutputStream(clientOut)) {
            out.write("502 Bad Gateway".getBytes());
        }
    }

    private void return503(String custom503) throws IOException {
        File f = null;
        if (custom503 != null) {
            f = new File(custom503);
            if (!f.exists()) {
                f = null;
            }
        }
        HttpHeader httpHeader = new HttpHeader("HTTP/1.1 503 Service Unavailable", new CaseInsensitiveHashMap<>());
        addHstsHeader(httpHeader);
        httpHeader.setHeader("Server", "Siggi-SimpleHttpProxy");
        if (f != null) {
            httpHeader.setHeader("Content-Length", Long.toString(f.length()));
        } else {
            httpHeader.setHeader("Transfer-Encoding", "chunked");
        }
        httpHeader.setHeader("Cache-Control", "private, max-age=15");
        httpHeader.setHeader("Content-Type", "text/" + (f == null ? "plain" : "html") + "; charset=UTF-8");
        keepAliveHeaders(httpHeader);
        Util.writeHeader(clientOut, httpHeader);
        if (f != null) {
            Util.copy(new FileInputStream(f), clientOut);
        } else {
            try (ChunkedOutputStream out = new ChunkedOutputStream(clientOut)) {
                out.write("503 Service Unavailable".getBytes());
            }
        }
    }

    private void youAreBanned(String ip) throws IOException {
        HttpHeader httpHeader = new HttpHeader("HTTP/1.1 403 Forbidden", new CaseInsensitiveHashMap<>());
        addHstsHeader(httpHeader);
        httpHeader.setHeader("Server", "Siggi-SimpleHttpProxy");
        httpHeader.setHeader("Transfer-Encoding", "chunked");
        httpHeader.setHeader("Cache-Control", "private, max-age=120");
        httpHeader.setHeader("Content-Type", "text/plain; charset=UTF-8");
        keepAliveHeaders(httpHeader);
        Util.writeHeader(clientOut, httpHeader);
        try (ChunkedOutputStream out = new ChunkedOutputStream(clientOut)) {
            out.write(("Your IP address (" + ip + ") is permanently banned from accessing this server.").getBytes());
        }
    }

    private void rateLimit(String host, String path, String ip) throws IOException {
        HttpHeader httpHeader = new HttpHeader("HTTP/1.1 429 Too Many Requests", new CaseInsensitiveHashMap<>());
        addHstsHeader(httpHeader);
        File f = proxyServer.get429File(host);
        int length = (int) f.length();
        httpHeader.setHeader("Server", "Siggi-SimpleHttpProxy");
        httpHeader.setHeader("Cache-Control", "private, max-age=15");
        httpHeader.setHeader("Content-Length", Integer.toString(length));
        httpHeader.setHeader("Content-Type", "text/html; charset=UTF-8");
        keepAliveHeaders(httpHeader);
        Util.writeHeader(clientOut, httpHeader);
        try (FileInputStream in = new FileInputStream(f)) {
            byte[] b = new byte[4096];
            int amountWritten = 0;
            int c;
            while (amountWritten < length) {
                c = in.read(b, 0, Math.min(b.length, length - amountWritten));
                if (c == -1) {
                    break;
                }
                clientOut.write(b, 0, c);
                amountWritten += c;
            }
            while (amountWritten < length) {
                clientOut.write(0);
                amountWritten += 1;
            }
        } catch (Exception e) {
        }
    }

    private void log(String msg) {
        proxyServer.log(msg);
    }

    private void log(String msg, Throwable t) {
        proxyServer.log(msg, t);
    }

    private void log(Throwable t) {
        proxyServer.log(t);
    }

    private String getContentType(String ext) {
        ext = ext.toLowerCase();
        switch (ext) {
            case "html":
                return "text/html; charset=UTF-8";
            case "txt":
                return "text/plain";
            case "png":
                return "image/png";
            case "jpg":
            case "jpeg":
                return "image/jpeg";
            case "gif":
                return "image/gif";
            case "m3u8":
                return "application/x-mpegURL";
            case "ts":
                return "video/MP2T";
            case "mp4":
                return "video/mp4";
            default:
                return "application/x-octet-stream";
        }
    }
}
