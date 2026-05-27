package com.vendor.skey;

import java.nio.file.Path;

public final class ActivationCli {
    private static final String USAGE = String.join(System.lineSeparator(),
            "usage: ActivationCli check <native-lib> <product-root> <payload> <entry-id> <original-path> <feature>",
            "activation: use `skey-protect activate online` or `skey-protect activate offline ...`");

    private ActivationCli() {
    }

    public static void main(String[] args) {
        String[] checkArgs = args;
        if (args.length == 7 && "check".equals(args[0])) {
            checkArgs = java.util.Arrays.copyOfRange(args, 1, args.length);
        }
        if (checkArgs.length != 6) {
            System.err.println(USAGE);
            System.exit(2);
        }
        Path nativeLibrary = Path.of(checkArgs[0]);
        NativeBridge.load(nativeLibrary);
        try (NativeBridge bridge = NativeBridge.init(
                Path.of(checkArgs[1]),
                Path.of(checkArgs[2]),
                checkArgs[3],
                checkArgs[4],
                new String[0],
                System.getenv(ProcessRunner.SESSION_ENV))) {
            bridge.check(checkArgs[5]);
            System.out.println("ok");
        }
    }
}
