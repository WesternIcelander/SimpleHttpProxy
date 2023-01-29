package io.siggi.simplehttpproxy;

public abstract class ThreadCreator {
    private static final ThreadCreator defaultCreator = new DefaultThreadCreator();
    private static ThreadCreator creator = defaultCreator;

    public static ThreadCreator get() {
        return creator;
    }

    public static void set(ThreadCreator creator) {
        if (creator == null) {
            creator = defaultCreator;
        }
        ThreadCreator.creator = creator;
    }

    public static Thread createThread(Runnable runnable, String name, boolean daemon, boolean handlingClient) {
        return get().createThreadImplementation(runnable, name, daemon, handlingClient);
    }

    protected abstract Thread createThreadImplementation(Runnable runnable, String name, boolean daemon, boolean handlingClient);

    private static class DefaultThreadCreator extends ThreadCreator {
        @Override
        protected Thread createThreadImplementation(Runnable runnable, String name, boolean daemon, boolean handlingClient) {
            if (runnable == null) throw new NullPointerException("runnable");
            Thread thread;
            if (name == null) {
                thread = new Thread(runnable);
            } else {
                thread = new Thread(runnable, name);
            }
            thread.setDaemon(daemon);
            return thread;
        }
    }
}
