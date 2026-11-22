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
        check(SafStorage.childId("primary:", "Download").equals("primary:Download"), "Volume root child");
        check(SafStorage.childId("primary:Documents/In", "a b.txt").equals("primary:Documents/In/a b.txt"),
            "Nested child");
        for (String id : new String[] {"primary:", "primary:Download", "1234-ABCD:DCIM/Camera"}) {
            check(SafStorage.pathBasedRoot(id), "Path-based ID rejected: " + id);
        }
        // An opaque ID such as "msf:42" passes this syntax test; the authority whitelist in
        // validate() keeps such providers out, and the per-run listing check is a second line.
        for (String id : new String[] {"", "raw:/storage/x", "primary:/x", "primary:x/",
                "primary:a//b", ":x", "a/b:c", "12345"}) {
            check(!SafStorage.pathBasedRoot(id), "Malformed ID accepted: " + id);
        }
        check(SafStorage.swapAsciiCase(".localupload-Pending-1a2B").equals(".LOCALUPLOAD-pENDING-1A2b"),
            "ASCII case swap");
        check(SafStorage.swapAsciiCase("Grüße.txt").equals("gRüßE.TXT"), "Non-ASCII letters kept");
        check(SafStorage.hasAsciiLetter("2026 ä.x") && !SafStorage.hasAsciiLetter("2026 äö_1"),
            "ASCII letter detection");
        check(SafStorage.caseVariantIds("primary:Docs/CaseProbe.txt", "primary:Docs/caseprobe.TXT"),
            "Case variant in a folder");
        check(SafStorage.caseVariantIds("primary:Target.bin", "primary:target.bin"),
            "Case variant at a volume root");
        for (String[] pair : new String[][] {
            {"primary:Docs/a.txt", "primary:Docs/a.txt"},
            {"primary:Docs/a.txt", "primary:docs/a.txt"},
            {"primary:Docs/a.txt", "primary:Docs/b.txt"},
            {"primary:Docs/a.txt", "primary:Docs/a.txt.bak"},
            {"primary:Docs/a", "primary:Docs/a/A"},
            {"primary:a.txt", "1234-ABCD:A.txt"},
            {"primary:", "PRIMARY:"},
            {"msf:a", "msf:A/x"}
        }) {
            check(!SafStorage.caseVariantIds(pair[0], pair[1]),
                "Different or identical IDs taken for case variants: " + Arrays.toString(pair));
        }
        System.out.println("SAF path boundary checks passed.");
    }

    private static void check(boolean condition, String message) {
        if (!condition) {
            throw new AssertionError(message);
        }
    }
}
