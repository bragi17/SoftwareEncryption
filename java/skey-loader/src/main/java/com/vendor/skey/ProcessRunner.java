package com.vendor.skey;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

public final class ProcessRunner {
    public static final String SESSION_ENV = "APP_SKEY_SESSION";
    public static final String ROOT_ENV = "APP_SKEY_ROOT";
    public static final String NATIVE_PATH_ENV = "APP_SKEY_NATIVE_PATH";

    private ProcessRunner() {
    }

    public static int runJar(
            Path productRoot,
            Path materializedJar,
            String[] args,
            String sessionToken,
            Path nativeLibrary) throws IOException, InterruptedException {
        List<String> command = new ArrayList<>();
        command.add(selectJava(productRoot).toString());
        command.add("-jar");
        command.add(materializedJar.toAbsolutePath().normalize().toString());
        for (String arg : args) {
            command.add(arg);
        }

        ProcessBuilder builder = new ProcessBuilder(command);
        builder.inheritIO();
        Map<String, String> environment = builder.environment();
        environment.put(SESSION_ENV, sessionToken);
        environment.put(ROOT_ENV, productRoot.toAbsolutePath().normalize().toString());
        environment.put(NATIVE_PATH_ENV, nativeLibrary.toAbsolutePath().normalize().toString());
        return builder.start().waitFor();
    }

    static Path selectJava(Path productRoot) {
        Path executable = productRoot.resolve("runtime").resolve("java").resolve("bin").resolve(javaBinaryName());
        if (Files.isRegularFile(executable)) {
            return executable.toAbsolutePath().normalize();
        }
        return Path.of("java");
    }

    private static String javaBinaryName() {
        return System.getProperty("os.name", "").toLowerCase().contains("win") ? "java.exe" : "java";
    }
}
