package com.vendor.skey;

import java.io.IOException;
import java.net.URISyntaxException;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;
import java.security.SecureRandom;
import java.util.HexFormat;

public final class JarLauncher {
    private static final String PAYLOAD_FILE = "payload.skp";

    private JarLauncher() {
    }

    public static void main(String[] args) throws Exception {
        Path selfJar = locateSelfJar();
        Path productRoot = locateProductRoot(selfJar);
        String originalPath = relativeProductPath(productRoot, selfJar);
        String entryId = "jar:" + originalPath;
        Path nativeLibrary = productRoot.resolve(".secure").resolve("rt").resolve(nativeLibraryName())
                .toAbsolutePath().normalize();
        NativeBridge.load(nativeLibrary);

        int exitCode;
        try (NativeBridge bridge = NativeBridge.init(
                productRoot,
                productRoot.resolve(".secure").resolve(PAYLOAD_FILE),
                entryId,
                originalPath,
                args,
                System.getenv(ProcessRunner.SESSION_ENV))) {
            byte[] jarBytes = bridge.materialize(entryId);
            MaterializedJar materializedJar = materializeJar(productRoot, originalPath, jarBytes);
            try {
                String sessionToken = bridge.createSession();
                exitCode = ProcessRunner.runJar(productRoot, materializedJar.jar(), args, sessionToken, nativeLibrary);
            } finally {
                deleteRecursivelyBestEffort(materializedJar.sessionDir());
            }
        }
        System.exit(exitCode);
    }

    private static Path locateSelfJar() throws URISyntaxException {
        return Path.of(JarLauncher.class.getProtectionDomain().getCodeSource().getLocation().toURI())
                .toAbsolutePath().normalize();
    }

    private static Path locateProductRoot(Path selfJar) {
        for (Path candidate = selfJar.getParent(); candidate != null; candidate = candidate.getParent()) {
            if (Files.isRegularFile(candidate.resolve(".secure").resolve(PAYLOAD_FILE))) {
                return candidate.toAbsolutePath().normalize();
            }
        }
        throw new IllegalStateException("could not locate product .secure payload");
    }

    private static String relativeProductPath(Path productRoot, Path selfJar) {
        Path relative = productRoot.relativize(selfJar.toAbsolutePath().normalize());
        String value = relative.toString().replace('\\', '/');
        if (value.isBlank()) {
            throw new IllegalStateException("loader path has no product-relative location");
        }
        return value;
    }

    private static MaterializedJar materializeJar(Path productRoot, String originalPath, byte[] jarBytes)
            throws IOException {
        Path sessionDir = createSessionDir(productRoot.resolve(".secure").resolve("tmp"));
        try {
            Path safeRelative = safeRelativePath(originalPath);
            Path output = sessionDir.resolve(safeRelative).toAbsolutePath().normalize();
            if (!output.startsWith(sessionDir)) {
                throw new IllegalArgumentException("materialized JAR path escapes session directory");
            }
            Files.createDirectories(output.getParent());
            Files.write(output, jarBytes);
            return new MaterializedJar(output, sessionDir);
        } catch (IOException | RuntimeException error) {
            deleteRecursivelyBestEffort(sessionDir);
            throw error;
        }
    }

    private static void deleteRecursivelyBestEffort(Path root) {
        try {
            Files.walkFileTree(root, new SimpleFileVisitor<>() {
                @Override
                public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) throws IOException {
                    Files.deleteIfExists(file);
                    return FileVisitResult.CONTINUE;
                }

                @Override
                public FileVisitResult postVisitDirectory(Path dir, IOException exc) throws IOException {
                    Files.deleteIfExists(dir);
                    return FileVisitResult.CONTINUE;
                }
            });
        } catch (IOException | RuntimeException ignored) {
            // Cleanup is best effort; the child process exit status must remain authoritative.
        }
    }

    private static Path createSessionDir(Path tmpRoot) throws IOException {
        Files.createDirectories(tmpRoot);
        SecureRandom random = new SecureRandom();
        byte[] token = new byte[16];
        for (int attempt = 0; attempt < 16; attempt++) {
            random.nextBytes(token);
            Path session = tmpRoot.resolve("sess_" + HexFormat.of().formatHex(token));
            try {
                Files.createDirectory(session);
                Files.writeString(session.resolve("active.pid"), Long.toString(ProcessHandle.current().pid()));
                return session.toAbsolutePath().normalize();
            } catch (java.nio.file.FileAlreadyExistsException ignored) {
                // Retry with fresh randomness.
            }
        }
        throw new IOException("could not create unique JAR loader session directory");
    }

    private static Path safeRelativePath(String originalPath) {
        Path path = Path.of(originalPath);
        if (path.isAbsolute()) {
            throw new IllegalArgumentException("materialized JAR path must be relative");
        }
        Path clean = Path.of("");
        for (Path part : path) {
            String value = part.toString();
            if (value.equals(".") || value.isBlank()) {
                continue;
            }
            if (value.equals("..")) {
                throw new IllegalArgumentException("materialized JAR path escapes session directory");
            }
            clean = clean.resolve(part);
        }
        if (clean.toString().isBlank()) {
            throw new IllegalArgumentException("materialized JAR path is empty");
        }
        return clean;
    }

    private static String nativeLibraryName() {
        String os = System.getProperty("os.name", "").toLowerCase();
        if (os.contains("win")) {
            return "skey_jni.dll";
        }
        if (os.contains("mac")) {
            return "libskey_jni.dylib";
        }
        return "libskey_jni.so";
    }

    private record MaterializedJar(Path jar, Path sessionDir) {
    }
}
