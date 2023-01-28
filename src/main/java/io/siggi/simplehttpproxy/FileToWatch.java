package io.siggi.simplehttpproxy;

import java.io.File;

public final class FileToWatch {

    private final File f;
    private final boolean exists;
    private final long l;

    public FileToWatch(File f) {
        this.f = f;
        this.exists = f.exists();
        this.l = exists ? f.lastModified() : 0L;
    }

    public boolean hasChanged() {
        if (exists) {
            return !f.exists() || f.lastModified() != l;
        } else {
            return f.exists();
        }
    }
}
