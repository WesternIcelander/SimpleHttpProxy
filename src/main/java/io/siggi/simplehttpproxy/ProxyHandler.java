package io.siggi.simplehttpproxy;

import io.siggi.iphelper.IP;
import io.siggi.simplehttpproxy.cache.CacheBuilder;
import io.siggi.simplehttpproxy.cache.CacheManager;
import io.siggi.simplehttpproxy.cache.CacheObject;
import io.siggi.simplehttpproxy.io.ChunkedInputStream;
import io.siggi.simplehttpproxy.io.ChunkedOutputStream;
import io.siggi.simplehttpproxy.io.ResetDetectingInputStream;
import io.siggi.simplehttpproxy.io.SecureBufferedInputStream;
import io.siggi.simplehttpproxy.io.SometimesTimeoutInputStream;
import io.siggi.simplehttpproxy.io.SubInputStream;
import io.siggi.simplehttpproxy.io.TeeOutputStream;
import io.siggi.simplehttpproxy.io.ToggleableBufferedOutputStream;
import io.siggi.simplehttpproxy.net.SslProxy;
import io.siggi.simplehttpproxy.util.CaseInsensitiveHashMap;
import io.siggi.simplehttpproxy.util.CloudFlare;
import io.siggi.simplehttpproxy.util.HttpHeader;
import io.siggi.simplehttpproxy.util.TrustForward;
import io.siggi.simplehttpproxy.util.Util;

import javax.net.ssl.SSLException;
import javax.net.ssl.SSLSocket;
import java.io.ByteArrayOutputStream;
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
import java.nio.file.Files;
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
    // the underlying TCP socket, even if clientSocket gets replaced with a layered SSLSocket
    private final Socket rawClientSocket;
    // set when the backend reset the connection mid-response, so we must reset the client too
    private boolean resetClient = false;
    private SecureBufferedInputStream clientIn;
    private ToggleableBufferedOutputStream clientOut;
    private OutputStream rawClientOut;
    private List<String> injectXForwardedFor = null;
    private String lastHost = null;
    private String lastAddr = null;
    private Socket serverSocket;
    private SometimesTimeoutInputStream serverIn;
    private ToggleableBufferedOutputStream serverOut;
    private OutputStream rawServerOut;
    private boolean head = false;
    private boolean keepAlive = true;
    private boolean started = false;
    private ForwardingSettingsMatch settingsMatch = null;
    private ForwardingSettings settings = null;
    public ProxyHandler(SimpleHttpProxy proxyServer, boolean secure, Socket clientSocket) throws IOException {
        this.proxyServer = proxyServer;
        this.cacheManager = proxyServer.getCacheManager();
        this.clientSocket = clientSocket;
        this.rawClientSocket = clientSocket;
        this.secure = secure;
        clientSocket.setTcpNoDelay(true);
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
        ThreadCreator.createThread(this::handler, null, false, true).start();
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
                ssl.setTcpNoDelay(true);
            }
            clientIn = new SecureBufferedInputStream(clientSocket.getInputStream(), 131072);
            clientOut = new ToggleableBufferedOutputStream(rawClientOut = clientSocket.getOutputStream());
        } catch (Exception e) {
            log("Failed to establish connection with client", e);
            try {
                clientSocket.close();
            } catch (Exception ignored) {
            }
            return;
        }
        boolean doNotClose = false;
        boolean wroteToClient = false;
        boolean receivedRequest = false;
        boolean send408 = false;
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
            Thread downstreamBodyForwarder = null;
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
                    if (downstreamBodyForwarder != null) {
                        downstreamBodyForwarder.join();
                        downstreamBodyForwarder = null;
                        if (!keepAlive) {
                            break;
                        }
                    }
                    wroteToClient = false;
                    receivedRequest = false;
                    send408 = true;
                    downstreamHeaders = Util.readHeader(clientIn, 16384);
                    boolean partialRequestBodyAvailable = clientIn.available() > 0;
                    head = downstreamHeaders.getFirstLine().startsWith("HEAD ");
                    send408 = false;
                    receivedRequest = true;
                    if (downstreamHeaders == null) {
                        break;
                    }
                    String method;
                    String httpVer;
                    String path;
                    String pathWithQueryString;
                    try {
                        String firstLine = downstreamHeaders.getFirstLine();
                        int firstSpace = firstLine.indexOf(" ");
                        int lastSpace = firstLine.lastIndexOf(" ");
                        method = firstLine.substring(0, firstSpace);
                        path = pathWithQueryString = firstLine.substring(firstSpace + 1, lastSpace);
                        httpVer = firstLine.substring(lastSpace + 1);
                    } catch (Exception e) {
                        return400();
                        continue;
                    }

                    boolean isHeadMethod = method.equals("HEAD");

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
                    // Backends may trust CF-Connecting-IP as the client address, but any client can send it.
                    // The client IP is already conveyed through X-Forwarded-For, so never pass it on.
                    downstreamHeaders.deleteHeader("CF-Connecting-IP");
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
                                    clientOut.startBuffering();
                                    Util.writeHeader(clientOut, resultHeader);
                                    clientOut.stopBuffering(!head && amountToWrite > 0L);
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
                        return301(settings.backend);
                        continue;
                    } else if (settings.forwardType == ForwardingSettings.ForwardType.REDIRECT_PREFIX) {
                        if (path.startsWith("/")) {
                            return301(settings.backend + pathWithQueryString);
                        } else {
                            return400();
                        }
                        continue;
                    }
                    if (settings.apiKeyFile != null) {
                        if (!settings.getApiKeys().checkKey(downstreamHeaders.getHeader("X-Api-Key"))) {
                            return403();
                            continue;
                        }
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
                    boolean closeDelimited = false;
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
                        boolean reuseConnection =
                                allowConnectionReuse
                                        && tries == 0
                                        && isIdempotent(downstreamHeaders.getFirstLine())
                                        && lastHost != null
                                        && lastAddr != null
                                        && host.equals(lastHost)
                                        && backendServer.equals(lastAddr)
                                        && serverIn.available() == 0
                                ;
                        OutputStream wrappedOut;
                        sendReq:
                        if (cacheObject == null) {
                            tryReuse:
                            if (reuseConnection && requestsForwarded < maxDownstreamRequests && System.currentTimeMillis() < reuseTimeout) {
                                try {
                                    serverOut.startBuffering();
                                    Util.writeHeader(serverOut, downstreamHeaders);
                                    serverOut.stopBuffering(partialRequestBodyAvailable);
                                } catch (Exception e) {
                                    break tryReuse;
                                }
                                wrappedOut = downstreamHeaders.wrapOutputStream(serverOut);
                                break sendReq;
                            }
                            if (serverSocket != null) {
                                try {
                                    serverSocket.close();
                                } catch (Exception e) {
                                }
                            }
                            try {
                                serverSocket = Util.connect(backendServer);
                                serverSocket.setTcpNoDelay(true);
                                serverSocket.setSoTimeout(300000);
                                requestsForwarded = 0;
                                maxDownstreamRequests = 1;
                                downstreamId += 1;
                            } catch (IOException ioe) {
                                return502();
                                continue outerLoop;
                            }
                            serverIn = new SometimesTimeoutInputStream(serverSocket.getInputStream());
                            serverOut = new ToggleableBufferedOutputStream(rawServerOut = serverSocket.getOutputStream());
                            serverOut.startBuffering();
                            Util.writeHeader(serverOut, downstreamHeaders);
                            serverOut.stopBuffering(partialRequestBodyAvailable);
                            wrappedOut = downstreamHeaders.wrapOutputStream(serverOut);
                            lastHost = host;
                            lastAddr = backendServer;
                        } else {
                            wrappedOut = null;
                        }
                        requestsForwarded += 1;
                        reuseTimeout = 0L;

                        logLine += " (CID:" + connectionId + ",dCID:" + downstreamId + ",DR:" + requestsForwarded + ")";

                        boolean partialResponseBodyAvailable = false;
                        boolean failed100Continue = false;
                        if (expect100Continue) {
                            upstreamHeaders = Util.readHeader(serverIn, 65536);
                            addHstsHeader(upstreamHeaders);
                            upstreamHeaders.setHeader("Connection", "Keep-Alive");
                            upstreamHeaders.setHeader("Keep-Alive", "timeout=60");
                            clientOut.startBuffering();
                            Util.writeHeader(clientOut, upstreamHeaders);
                            clientOut.stopBuffering();
                            wroteToClient = true;
                            String firstLine = upstreamHeaders.getFirstLine();
                            if (!firstLine.substring(firstLine.indexOf(" ") + 1).startsWith("100 ")) {
                                logLine += " -> " + firstLine;
                                failed100Continue = true;
                                wrappedIn = null;
                                partialResponseBodyAvailable = serverIn.available() > 0;
                            }
                        }
                        clientIn.eraseFreeSpace();
                        if (!failed100Continue) {
                            if (cacheObject == null && wrappedIn != null && wrappedOut != null) {
                                InputStream finalWrappedIn = wrappedIn;
                                serverIn.setThrowTimeoutException(false);
                                wrappedIn = null;
                                downstreamBodyForwarder = ThreadCreator.createThread(() -> {
                                    try {
                                        Util.copy(finalWrappedIn, wrappedOut);
                                        if (wrappedOut instanceof ChunkedOutputStream) {
                                            wrappedOut.close();
                                        }
                                    } catch (IOException e) {
                                        keepAlive = false;
                                    } finally {
                                        try {
                                            Util.copy(finalWrappedIn, null);
                                        } catch (IOException ignored) {
                                        }
                                        clientIn.eraseFreeSpace();
                                        serverIn.setThrowTimeoutException(true);
                                    }
                                }, "", false, true);
                                downstreamBodyForwarder.start();
                            }
                            if (cacheObject == null) {
                                upstreamHeaders = Util.readHeader(serverIn, 65536);
                                partialResponseBodyAvailable = serverIn.available() > 0;
                                if (upstreamHeaders == null) {
                                    if (reuseConnection) continue;
                                    throw new IOException("End of stream");
                                }
                            }
                            addHstsHeader(upstreamHeaders);
                            String firstLine = upstreamHeaders.getFirstLine();
                            logLine += " -> " + firstLine;
                            if (firstLine.substring(firstLine.indexOf(" ") + 1).startsWith("101 ")) {
                                // This is a 101 Switching Protocols response, indicating an upgrade
                                clientOut.startBuffering();
                                Util.writeHeader(clientOut, upstreamHeaders);
                                clientOut.stopBuffering();
                                wroteToClient = true;
                                if (downstreamBodyForwarder != null) {
                                    downstreamBodyForwarder.join();
                                    downstreamBodyForwarder = null;
                                }
                                upgrade(clientSocket, serverSocket);
                                doNotClose = true;
                                return;
                            }
                            boolean upstreamKeepAlive = false;
                            {
                                String connectionString = upstreamHeaders.getHeader("Connection");
                                if (connectionString == null) {
                                    // nothing to do
                                } else if (connectionString.equalsIgnoreCase("Keep-Alive")) {
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
                                } else if (connectionString.equalsIgnoreCase("close")) {
                                    keepAlive = false;
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
                            closeDelimited = cacheObject == null && !isHeadMethod && isCloseDelimited(upstreamHeaders);
                            if (closeDelimited) {
                                // The body ends when the backend closes the connection, forward it as is
                                // and close the client connection to mark the end of the response.
                                keepAlive = false;
                                forwardedUpstreamHeaders = upstreamHeaders;
                            } else if (!upstreamKeepAlive && upstreamHeaders.getHeader("Content-Encoding") != null) {
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
                            clientOut.startBuffering();
                            Util.writeHeader(clientOut, forwardedUpstreamHeaders);
                            clientOut.stopBuffering(partialResponseBodyAvailable);
                            wroteToClient = true;
                        }
                    }
                    InputStream upWrapIn = cacheObject != null
                            ? cacheObject.getInputStream()
                            : (isHeadMethod ? null : (closeDelimited ? serverIn : upstreamHeaders.wrapInputStream(serverIn)));
                    OutputStream upWrapOut = isHeadMethod ? null : (closeDelimited ? clientOut : forwardedUpstreamHeaders.wrapOutputStream(clientOut));
                    if (upWrapIn != null && upWrapOut != null) {
                        OutputStream outDestination = upWrapOut;
                        if (cacheBuilder != null) {
                            outDestination = new TeeOutputStream(upWrapOut, cacheBuilder);
                        }
                        // Detect a TCP RST from the backend while reading the body (any framing)
                        ResetDetectingInputStream bodyIn = cacheObject == null ? new ResetDetectingInputStream(upWrapIn) : null;
                        InputStream readFrom = bodyIn != null ? bodyIn : upWrapIn;
                        try {
                            if (upWrapIn instanceof ChunkedInputStream && upWrapOut instanceof ChunkedOutputStream) {
                                ChunkedInputStream chunkedIn = (ChunkedInputStream) upWrapIn;
                                ChunkedOutputStream chunkedOut = (ChunkedOutputStream) upWrapOut;
                                byte[] buffer = new byte[16384];
                                int c;
                                while ((c = readFrom.read(buffer, 0, buffer.length)) != -1) {
                                    if (chunkedIn.didReceiveTerminatorChunk()) chunkedOut.setBuffering(true);
                                    outDestination.write(buffer, 0, c);
                                    if (chunkedIn.didReceiveTerminatorChunk()) chunkedOut.setBuffering(false);
                                }
                            }
                            Util.copy(readFrom, outDestination);
                        } catch (IOException e) {
                            if (bodyIn == null || !bodyIn.wasReset()) throw e;
                            // The backend reset the connection, so the response is incomplete.
                            // Don't cache it, don't finish the chunked stream, and pass the reset on to the client.
                            logLine += " (backend reset connection)";
                            resetClient = true;
                            keepAlive = false;
                            continue;
                        }
                        if (cacheBuilder != null) {
                            cacheBuilder.finished();
                        }
                    }
                    if (closeDelimited) {
                        // the client connection is closed after this to mark the end of the body
                        clientOut.flush();
                    }
                    if (upWrapOut instanceof ChunkedOutputStream) {
                        upWrapOut.close();
                    }
                } finally {
                    if (logLine != null) {
                        log(logLine);
                    }
                    if (wrappedIn != null) {
                        try {
                            Util.copy(wrappedIn, null);
                        } catch (Exception ignored) {
                        }
                    }
                    if (cacheBuilder != null) {
                        cacheBuilder.close();
                        cacheBuilder = null;
                    }
                }
            }
        } catch (SocketTimeoutException ste) {
            // we timed out xD
            if (send408) {
                try {
                    HttpHeader httpHeader = new HttpHeader("HTTP/1.1 408 Request Timeout", new CaseInsensitiveHashMap<>());
                    httpHeader.setHeader("Connection", "close");
                    send(httpHeader, "408 Request Timeout");
                    clientOut.flush();
                } catch (Exception e) {
                }
            }
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
                if (resetClient) {
                    // Mirror the backend's TCP RST: flush what we have, then close the raw TCP socket
                    // with SO_LINGER 0 so the kernel sends RST instead of FIN. We skip the TLS
                    // close_notify on purpose, as it would make the truncated response look complete.
                    try {
                        clientOut.flush();
                    } catch (Exception e) {
                    }
                    try {
                        rawClientSocket.setSoLinger(true, 0);
                        rawClientSocket.close();
                    } catch (Exception e) {
                    }
                }
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

    /**
     * A response whose body is delimited by the backend closing the connection:
     * it may have a body, but has neither Transfer-Encoding: chunked nor Content-Length.
     * The caller must exclude responses to HEAD requests.
     */
    private static boolean isCloseDelimited(HttpHeader responseHeaders) {
        String firstLine = responseHeaders.getFirstLine();
        int space = firstLine.indexOf(" ");
        if (space >= 0) {
            String status = firstLine.substring(space + 1);
            // 1xx, 204 and 304 responses never have a body
            if (status.startsWith("1") || status.startsWith("204") || status.startsWith("304")) {
                return false;
            }
        }
        String transferEncoding = responseHeaders.getHeader("Transfer-Encoding");
        if (transferEncoding != null && transferEncoding.equalsIgnoreCase("chunked")) {
            return false;
        }
        String contentLength = responseHeaders.getHeader("Content-Length");
        if (contentLength != null) {
            try {
                if (Long.parseLong(contentLength) >= 0L) return false;
            } catch (NumberFormatException ignored) {
            }
        }
        return true;
    }

    private void keepAliveHeaders(HttpHeader httpHeader) {
        if (proxyServer.serverShuttingDown()) keepAlive = false;
        if (keepAlive) {
            httpHeader.setHeader("Connection", "Keep-Alive");
            httpHeader.setHeader("Keep-Alive", "timeout=60");
        } else {
            httpHeader.setHeader("Connection", "close");
            httpHeader.deleteHeader("Keep-Alive");
        }
    }

    private void send(HttpHeader httpHeader, String content) throws IOException {
        send(httpHeader, content.getBytes(StandardCharsets.UTF_8));
    }

    private void send(HttpHeader httpHeader, byte[] content) throws IOException {
        if (settings != null) addHstsHeader(httpHeader);
        httpHeader.setHeader("Server", "Siggi-SimpleHttpProxy");
        httpHeader.setHeader("Content-Length", Integer.toString(content.length));
        httpHeader.setHeader("Cache-Control", "private, max-age=0");
        if (httpHeader.getHeader("Content-Type") == null) {
            httpHeader.setHeader("Content-Type", "text/plain; charset=utf-8");
        }
        keepAliveHeaders(httpHeader);
        clientOut.startBuffering();
        Util.writeHeader(clientOut, httpHeader);
        if (head) {
            clientOut.stopBuffering(false);
            return;
        }
        clientOut.stopBuffering(content.length != 0);
        clientOut.write(content);
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
        httpHeader.setHeader("Content-Type", type);
        send(httpHeader, content);
    }

    private void return301(String target) throws IOException {
        HttpHeader httpHeader = new HttpHeader("HTTP/1.1 301 Moved Permanently", new CaseInsensitiveHashMap<>());
        httpHeader.setHeader("Location", target);
        send(httpHeader, "301 Permanently Moved: " + target);
    }

    private void return302(String target) throws IOException {
        HttpHeader httpHeader = new HttpHeader("HTTP/1.1 302 Found", new CaseInsensitiveHashMap<>());
        httpHeader.setHeader("Location", target);
        send(httpHeader, "302 Found: " + target);
    }

    private void return400() throws IOException {
        HttpHeader httpHeader = new HttpHeader("HTTP/1.1 400 Bad Request", new CaseInsensitiveHashMap<>());
        send(httpHeader, "400 Bad Request");
    }

    private void return401BasicAuth(BasicAuth basicAuth) throws IOException {
        HttpHeader httpHeader = new HttpHeader("HTTP/1.1 401 Unauthorized", new CaseInsensitiveHashMap<>());
        httpHeader.setHeader("WWW-Authenticate", "Basic realm=" + basicAuth.getRealm());
        send(httpHeader, "401 Unauthorized");
    }

    private void return403() throws IOException {
        HttpHeader httpHeader = new HttpHeader("HTTP/1.1 403 Forbidden", new CaseInsensitiveHashMap<>());
        send(httpHeader, "403 Forbidden");
    }

    private void return404() throws IOException {
        HttpHeader httpHeader = new HttpHeader("HTTP/1.1 404 Not Found", new CaseInsensitiveHashMap<>());
        send(httpHeader, "404 Not Found");
    }

    private void return500() throws IOException {
        HttpHeader httpHeader = new HttpHeader("HTTP/1.1 500 Internal Server Error", new CaseInsensitiveHashMap<>());
        keepAlive = false;
        send(httpHeader, "500 Internal Server Error");
    }

    private void return502() throws IOException {
        HttpHeader httpHeader = new HttpHeader("HTTP/1.1 502 Bad Gateway", new CaseInsensitiveHashMap<>());
        send(httpHeader, "502 Bad Gateway");
    }

    private void return503(String custom503) throws IOException {
        byte[] custom503Content = null;
        if (custom503 != null) {
            File f = new File(custom503);
            if (f.exists()) {
                try (InputStream in = Files.newInputStream(f.toPath())) {
                    ByteArrayOutputStream out = new ByteArrayOutputStream();
                    Util.copy(in, out);
                    custom503Content = out.toByteArray();
                } catch (IOException ignored) {
                }
            }
        }
        HttpHeader httpHeader = new HttpHeader("HTTP/1.1 503 Service Unavailable", new CaseInsensitiveHashMap<>());
        httpHeader.setHeader("Cache-Control", "private, max-age=15");
        httpHeader.setHeader("Content-Type", "text/" + (custom503Content == null ? "plain" : "html") + "; charset=UTF-8");
        if (custom503Content != null) {
            send(httpHeader, custom503Content);
        } else {
            send(httpHeader, "503 Service Unavailable");
        }
    }

    private void youAreBanned(String ip) throws IOException {
        HttpHeader httpHeader = new HttpHeader("HTTP/1.1 403 Forbidden", new CaseInsensitiveHashMap<>());
        send(httpHeader, "Your IP address (" + ip + ") is permanently banned from accessing this server.");
    }

    private void rateLimit(String host, String path, String ip) throws IOException {
        HttpHeader httpHeader = new HttpHeader("HTTP/1.1 429 Too Many Requests", new CaseInsensitiveHashMap<>());
        File f = proxyServer.get429File(host);
        byte[] pageContent = null;
        String type;
        try (InputStream in = Files.newInputStream(f.toPath())) {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            Util.copy(in, out);
            pageContent = out.toByteArray();
        }
        if (pageContent == null) {
            pageContent = "429 Too Many Requests".getBytes(StandardCharsets.UTF_8);
            type = "text/plain; charset=utf-8";
        } else {
            type = "text/html; charset=utf-8";
        }
        httpHeader.setHeader("Content-Type", type);
        send(httpHeader, pageContent);
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
