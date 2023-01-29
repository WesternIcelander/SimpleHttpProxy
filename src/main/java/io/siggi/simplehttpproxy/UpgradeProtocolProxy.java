package io.siggi.simplehttpproxy;

import io.siggi.simplehttpproxy.util.Util;

import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;

public class UpgradeProtocolProxy {

    private static int nextId = 0;
    private final Socket s1;
    private final Socket s2;
    private final int id;
    private boolean started;

    public UpgradeProtocolProxy(Socket s1, Socket s2) {
        this.s1 = s1;
        this.s2 = s2;
        this.id = id();
    }

    private static synchronized int id() {
        return nextId++;
    }

    public void start() {
        if (started) {
            return;
        }
        started = true;
        ThreadCreator.createThread(this::s1, "UPP-" + id + "-ToServer", false, true).start();
        ThreadCreator.createThread(this::s2, "UPP-" + id + "-ToClient", false, true).start();
    }

    private void s1() {
        r(s1, s2);
    }

    private void s2() {
        r(s2, s1);
    }

    private void r(Socket a, Socket b) {
        try {
            InputStream inputStream = a.getInputStream();
            OutputStream outputStream = b.getOutputStream();
            Util.copy(inputStream, outputStream);
        } catch (Exception e) {
        } finally {
            try {
                a.close();
            } catch (Exception e) {
            }
            try {
                b.close();
            } catch (Exception e) {
            }
        }
    }
}
