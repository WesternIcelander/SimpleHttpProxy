package io.siggi.simplehttpproxy.net;

import io.siggi.simplehttpproxy.SimpleHttpProxy;
import io.siggi.simplehttpproxy.ThreadCreator;
import io.siggi.simplehttpproxy.util.Util;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.net.UnknownHostException;

public class SslProxy {

    private final Socket clientSocket;
    private final SimpleHttpProxy.SSLUpgradeResult upgradeResult;
    private final InetSocketAddress backend;
    private long lastActivity;
    private boolean started = false;
    private Socket serverSocket;

    public SslProxy(Socket clientSocket, SimpleHttpProxy.SSLUpgradeResult upgradeResult) throws IOException {
        this.clientSocket = clientSocket;
        this.upgradeResult = upgradeResult;
        this.backend = parseBackend(upgradeResult.backend);
    }

    public void start() {
        if (started) {
            throw new IllegalStateException();
        }
        started = true;
        lastActivity = System.currentTimeMillis();
        ThreadCreator.createThread(this::serverBound, null, false, true).start();
    }

    public void close() {
        if (!started) {
            throw new IllegalStateException();
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

    private void serverBound() {
        try {
            serverSocket = new Socket(backend.getAddress(), backend.getPort());
            serverSocket.setSoTimeout(120000);
            InputStream in = clientSocket.getInputStream();
            OutputStream out = serverSocket.getOutputStream();
            out.write(upgradeResult.getInitialForwardBytes());
            ThreadCreator.createThread(this::clientBound, null, false, true).start();
            while (true) {
                try {
                    Util.copy(in, out, count -> lastActivity = System.currentTimeMillis());
                    break;
                } catch (SocketTimeoutException e) {
                    if (System.currentTimeMillis() - lastActivity > 120000L) {
                        throw e;
                    }
                }
            }
        } catch (IOException ioe) {
        } finally {
            close();
        }
    }

    private void clientBound() {
        try {
            InputStream in = serverSocket.getInputStream();
            OutputStream out = clientSocket.getOutputStream();
            while (true) {
                try {
                    Util.copy(in, out, count -> lastActivity = System.currentTimeMillis());
                    break;
                } catch (SocketTimeoutException e) {
                    if (System.currentTimeMillis() - lastActivity > 120000L) {
                        throw e;
                    }
                }
            }
        } catch (IOException ioe) {
        } finally {
            close();
        }
    }

    private InetSocketAddress parseBackend(String backend) throws UnknownHostException {
        int pos = backend.lastIndexOf(":");
        int ipv6EndPos = backend.lastIndexOf("]");
        if (ipv6EndPos > pos) {
            pos = -1;
        }
        int port = 443;
        if (pos >= 0) {
            port = Integer.parseInt(backend.substring(pos + 1));
            backend = backend.substring(0, pos);
        }
        return new InetSocketAddress(InetAddress.getByName(backend), port);
    }
}
