package io.siggi.simplehttpproxy.updater;

import io.siggi.processapi.ProcessAPI;
import io.siggi.simplehttpproxy.util.Util;
import java.io.File;
import java.net.HttpURLConnection;
import java.util.Map;
import static io.siggi.simplehttpproxy.updater.UpdateUtil.delete;
import static io.siggi.simplehttpproxy.updater.UpdateUtil.download;
import static io.siggi.simplehttpproxy.updater.UpdateUtil.getJavaPath;
import static io.siggi.simplehttpproxy.updater.UpdateUtil.hashFile;
import static io.siggi.simplehttpproxy.updater.UpdateUtil.openConnection;
import static io.siggi.simplehttpproxy.updater.UpdateUtil.readShasums;
import static io.siggi.simplehttpproxy.updater.UpdateUtil.setupPerms;

public class Updater {
    public static void main(String[] args) throws Exception {
        int uid = ProcessAPI.getuid();
        if (uid != 0) {
            System.err.println("Must be run as root");
            System.exit(1);
            return;
        }
        String downloadRoot = "https://siggi.io/code/simplehttpproxy";

        File simpleHttpProxy = new File("SimpleHttpProxy.jar");
        HttpURLConnection connection = openConnection(downloadRoot + "/checksums.txt");
        Map<String, String> shasums = readShasums(connection.getInputStream());
        connection.disconnect();
        String currentHash = hashFile(simpleHttpProxy);
        if (currentHash.equals(shasums.get("SimpleHttpProxy.jar"))) {
            System.err.println("Already up to date");
            System.exit(0);
            return;
        }

        System.err.println("Downloading update");

        File updateDir = new File("shp-update");
        try {
            updateDir.mkdirs();
            File newJar = new File(updateDir, "SimpleHttpProxy.jar");
            File setupPerms = new File("setup-perms");
            File newSetupPerms = new File(updateDir, "setup-perms");
            File run = new File("run");
            File newRun = new File(updateDir, "run");
            download(downloadRoot + "/SimpleHttpProxy.jar", newJar, shasums.get("SimpleHttpProxy.jar"));
            download(downloadRoot + "/setup-perms", newSetupPerms, shasums.get("setup-perms"));
            download(downloadRoot + "/run", newRun, shasums.get("run"));
            setupPerms(newJar);
            setupPerms(newSetupPerms);
            setupPerms(newRun);
            newRun.renameTo(run);
            newSetupPerms.renameTo(setupPerms);
            newJar.renameTo(simpleHttpProxy);
        } finally {
            delete(updateDir);
        }

        System.err.println("Running post update scripts");

        Process proc = Runtime.getRuntime().exec(new String[]{getJavaPath(), "-cp", "SimpleHttpProxy.jar", "io.siggi.simplehttpproxy.updater.PostUpdate"});
        int exitCode = proc.waitFor();
        Util.copy(proc.getInputStream(), System.out);
        Util.copy(proc.getErrorStream(), System.err);
        if (exitCode != 0) {
            System.exit(1);
        }
        System.exit(10);
    }
}
