package io.siggi.simplehttpproxy.updater;

import java.io.File;

public class PostUpdate {
    public static void main(String[] args) throws Exception {
        File postUpdate = new File("post-update");
        if (postUpdate.exists()) {
            Process exec = Runtime.getRuntime().exec(postUpdate.getAbsolutePath());
            exec.waitFor();
        }
    }
}
