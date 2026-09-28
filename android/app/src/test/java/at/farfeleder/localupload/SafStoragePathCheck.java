package at.farfeleder.localupload;

import java.util.Arrays;

/** Standalone boundary regression: javac with android.jar, then java -ea this class. */
public final class SafStoragePathCheck {
    public static void main(String[] args) {
        check(Arrays.equals(SafStorage.segments("Photos/Grüße 🌍.bin", false),
            new String[] {"Photos", "Grüße 🌍.bin"}), "Unicode path changed");
        check(SafStorage.segments("", true).length == 0, "Root lookup rejected");
        check(SafStorage.segments("..notes", false).length == 1, "Safe filename rejected");
        for (String unsafe : new String[] {
            null, "", "/absolute", "../escape", "folder/../escape", "./file",
            "folder/./file", "folder//file", "folder/", "folder\\file",
            "file\u0000", "file\n", "file\u007f", "\ud800", "\udc00", "\ud800x"
        }) {
            try {
                SafStorage.segments(unsafe, false);
            } catch (IllegalArgumentException expected) {
                continue;
            }
            throw new AssertionError("Unsafe path accepted: " + unsafe);
        }
        System.out.println("SAF path boundary checks passed.");
    }

    private static void check(boolean condition, String message) {
        if (!condition) {
            throw new AssertionError(message);
        }
    }
}
