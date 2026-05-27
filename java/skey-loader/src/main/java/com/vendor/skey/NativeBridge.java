package com.vendor.skey;

import java.nio.file.Path;
import java.util.concurrent.atomic.AtomicLong;

public final class NativeBridge implements AutoCloseable {
    private final AtomicLong handle;

    private NativeBridge(long handle) {
        this.handle = new AtomicLong(handle);
    }

    public static void load(Path libraryPath) {
        Path absolute = libraryPath.toAbsolutePath().normalize();
        if (!absolute.isAbsolute()) {
            throw new IllegalArgumentException("native library path must be absolute");
        }
        System.setProperty("skey.native.path", absolute.toString());
        System.load(absolute.toString());
    }

    public static NativeBridge init(
            Path appRoot,
            Path payloadPath,
            String entryId,
            String originalPath,
            String[] args,
            String envSession) {
        long handle = initNative(
                appRoot.toAbsolutePath().normalize().toString(),
                payloadPath.toAbsolutePath().normalize().toString(),
                entryId,
                originalPath,
                args,
                envSession);
        return new NativeBridge(handle);
    }

    public synchronized void check(String feature) {
        checkNative(requireHandle(), feature);
    }

    public synchronized byte[] materialize(String entryId) {
        return materializeNative(requireHandle(), entryId);
    }

    public synchronized String createSession() {
        return createSessionNative(requireHandle());
    }

    @Override
    public synchronized void close() {
        long handle = this.handle.getAndSet(0);
        if (handle != 0) {
            freeNative(handle);
        }
    }

    private long requireHandle() {
        long handle = this.handle.get();
        if (handle == 0) {
            throw new IllegalStateException("native bridge is closed");
        }
        return handle;
    }

    private static native long initNative(
            String appRoot,
            String payloadPath,
            String entryId,
            String originalPath,
            String[] args,
            String envSession);

    private static native void checkNative(long handle, String feature);

    private static native byte[] materializeNative(long handle, String entryId);

    private static native String createSessionNative(long handle);

    private static native void freeNative(long handle);

    public static final class SKeyException extends RuntimeException {
        private final int code;

        public SKeyException(int code, String message) {
            super("SKEY[" + code + "]: " + message);
            this.code = code;
        }

        public int code() {
            return code;
        }
    }
}
