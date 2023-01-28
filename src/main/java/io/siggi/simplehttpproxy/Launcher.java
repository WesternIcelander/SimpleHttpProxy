package io.siggi.simplehttpproxy;

import io.siggi.processapi.ProcessAPI;
import io.siggi.processapi.Signal;
import io.siggi.simplehttpproxy.util.Util;
import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;

public class Launcher {
    public static void main(String[] args) throws Exception {
        int uid = -1;
        int gid = -1;
        try (BufferedReader reader = new BufferedReader(new FileReader("dropprivs.txt"))) {
            uid = Integer.parseInt(reader.readLine());
            gid = Integer.parseInt(reader.readLine());
        } catch (Exception e) {
        }
        Process process = Runtime.getRuntime().exec(new String[]{"java", "-Dlauncher=1", "-jar", "SimpleHttpProxy.jar"});
        ProcessAPI.addSignalListener((signal) -> {
            try {
                OutputStream out = process.getOutputStream();
                switch (signal) {
                    case SIGTERM:
                        out.write("SIGTERM\n".getBytes(StandardCharsets.UTF_8));
                        out.flush();
                        break;
                    case SIGINT:
                        out.write("SIGINT\n".getBytes(StandardCharsets.UTF_8));
                        out.flush();
                        break;
                }
            } catch (IOException ioe) {
            }
        });
        ProcessAPI.catchSignal(Signal.SIGTERM);
        ProcessAPI.catchSignal(Signal.SIGINT);
        new Thread(() -> {
            try {
                Util.copy(process.getInputStream(), System.out);
            } catch (Exception e) {
            }
        }).start();
        new Thread(() -> {
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getErrorStream()))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    if (line.equalsIgnoreCase("Launcher-Exit")) {
                        System.err.println("Launcher exiting");
                        System.exit(0);
                    }
                    System.err.println(line);
                }
            } catch (Exception e) {
            }
        }).start();
        if (uid != -1 && gid != -1) {
            ProcessAPI.setgid(gid);
            ProcessAPI.setuid(uid);
        }
    }
}
