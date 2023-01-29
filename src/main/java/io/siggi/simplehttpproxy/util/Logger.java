package io.siggi.simplehttpproxy.util;

import io.siggi.simplehttpproxy.ThreadCreator;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.PrintWriter;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.TimeZone;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.zip.GZIPOutputStream;

public class Logger {
    private final File logDirectory;
    private final BlockingQueue<LogItem> queue = new LinkedBlockingQueue<>();
    private Thread thread = null;
    private boolean started = false;
    private boolean stopped = false;

    private long dayNumber = 0L;
    private File currentLogFile;
    private FileOutputStream out;

    public Logger(File logDirectory) {
        this.logDirectory = logDirectory;
    }

    public void start() {
        if (started) return;
        started = true;
        thread = ThreadCreator.createThread(this::run, "Logger", true, false);
        thread.start();
    }

    public void stop() {
        if (!started || stopped) return;
        stopped = true;
        thread.interrupt();
        try {
            out.close();
        } catch (Exception e) {
        }
    }

    public void log(String message, Throwable throwable) {
        queue.offer(new LogItem(message, throwable));
    }

    private void updateLogFile(long time) {
        long day = time / 86400000L;
        if (out == null || day != dayNumber) {
            SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd");
            String date = dateFormat.format(new Date(day * 86400000L));
            File logFile = new File(logDirectory, date + ".log");
            FileOutputStream newOut;
            try {
                newOut = new FileOutputStream(logFile, true);
            } catch (Exception e) {
                return;
            }
            if (out != null) {
                try {
                    out.close();
                } catch (IOException ioe) {
                }
                compress(currentLogFile);
            }
            out = newOut;
            currentLogFile = logFile;
            dayNumber = day;
        }
    }

    private void compress(File file) {
        ThreadCreator.createThread(() -> {
            File compressedFileName = new File(file.getParentFile(), file.getName() + ".gz");
            try (FileInputStream in = new FileInputStream(file); FileOutputStream out = new FileOutputStream(compressedFileName)) {
                GZIPOutputStream gzipOut = new GZIPOutputStream(out);
                Util.copy(in, gzipOut);
                gzipOut.finish();
            } catch (IOException ioe) {
                compressedFileName.delete();
                return;
            }
            file.delete();
        }, null, false, false).start();
    }

    private void writeBytes(long time, byte[] data) {
        updateLogFile(time);
        try {
            out.write(data);
        } catch (IOException ioe) {
        }
    }

    private void run() {
        if (!logDirectory.exists()) {
            logDirectory.mkdirs();
        }
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        PrintWriter writer = new PrintWriter(out);
        SimpleDateFormat timestampFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss z");
        timestampFormat.setTimeZone(TimeZone.getTimeZone("UTC"));
        while (true) {
            LogItem item;
            try {
                item = queue.take();
            } catch (InterruptedException ie) {
                break;
            }
            long time = System.currentTimeMillis();
            String date = timestampFormat.format(new Date(time));
            if (item.message != null) {
                writer.print(date + ": ");
                writer.print(item.message);
                if (item.throwable != null) {
                    writer.print(": ");
                    item.throwable.printStackTrace(writer);
                } else {
                    writer.println();
                }
            } else if (item.throwable != null) {
                writer.print(date + ": ");
                item.throwable.printStackTrace(writer);
            }
            writer.flush();
            byte[] bytes = out.toByteArray();
            out.reset();
            writeBytes(time, bytes);
        }
    }

    private class LogItem {
        private final String message;
        private final Throwable throwable;

        private LogItem(String message, Throwable throwable) {
            this.message = message;
            this.throwable = throwable;
        }
    }
}
