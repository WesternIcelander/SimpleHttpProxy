package io.siggi.simplehttpproxy.updater;

import io.siggi.simplehttpproxy.ThreadCreator;
import java.io.File;

public class AutoUpdater {
    private static boolean started = false;
    private static String updaterPath;
    private static Runnable updateCallback;

    public static void start(Runnable callback) {
        if (started) {
            return;
        }
        started = true;
        updateCallback = callback;
        File updaterFile = new File("auto-update");
        updaterPath = updaterFile.getAbsolutePath();
        if (!updaterFile.exists() || !updaterFile.isFile()) {
            System.err.println("AutoUpdater is not running because " + updaterPath + " is missing.");
            return;
        }
        ThreadCreator.createThread(AutoUpdater::updaterThread, null, true, false).start();
    }

    private static void updaterThread() {
        try {
            Thread.sleep(60000L);
        } catch (Exception e) {
        }
        while (true) {
            try {
                if (runUpdater()) {
                    updateCallback.run();
                }
            } catch (Exception e) {
            }
            try {
                Thread.sleep(3600000L);
            } catch (Exception e) {
            }
        }
    }

    private static boolean runUpdater() {
        boolean update = false;
        try {
            Process process = Runtime.getRuntime().exec(new String[]{updaterPath});
            int i = process.waitFor();
            if (i == 10) return true;
        } catch (Exception e) {
        }
        return false;
    }
}
