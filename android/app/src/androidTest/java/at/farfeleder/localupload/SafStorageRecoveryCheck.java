package at.farfeleder.localupload;

import android.app.Activity;
import android.app.Instrumentation;
import android.content.ContentResolver;
import android.content.Context;
import android.content.SharedPreferences;
import android.content.UriPermission;
import android.database.Cursor;
import android.net.Uri;
import android.os.Bundle;
import android.provider.DocumentsContract;
import android.provider.DocumentsContract.Document;

import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.UUID;

/** Real-provider crash-window regression; run with am instrument -w after choosing a folder. */
public final class SafStorageRecoveryCheck extends Instrumentation {
    private static final byte[] OLD = "original bytes\u0000\u0001".getBytes(StandardCharsets.UTF_8);
    private static final byte[] NEW = "new upload 🌍\u0000\u0002".getBytes(StandardCharsets.UTF_8);
    private static final byte[] OTHER = "unrelated changed file".getBytes(StandardCharsets.UTF_8);
    private Context context;
    private ContentResolver resolver;
    private SharedPreferences journal;
    private Uri tree;
    private Uri root;

    @Override
    public void onCreate(Bundle arguments) {
        super.onCreate(arguments);
        start();
    }

    @Override
    public void onStart() {
        Bundle result = new Bundle();
        int failures = 0;
        try {
            context = getTargetContext();
            resolver = context.getContentResolver();
            journal = context.getSharedPreferences("saf_upload_transactions", Context.MODE_PRIVATE);
            for (UriPermission permission : resolver.getPersistedUriPermissions()) {
                if (permission.isReadPermission() && permission.isWritePermission()
                        && "com.android.externalstorage.documents".equals(
                            permission.getUri().getAuthority())) {
                    tree = permission.getUri();
                    break;
                }
            }
            require(tree != null, "Choose a local SAF destination in the app before running this check.");
            root = DocumentsContract.buildDocumentUriUsingTree(
                tree, DocumentsContract.getTreeDocumentId(tree));
            for (String scenario : new String[] {
                "pending_restart", "backup_rename_gap", "install_rename_gap",
                "install_recorded_gap", "rollback_pending_gap", "rollback_restore_gap",
                "restore_recorded_gap", "new_file_install_gap", "new_file_recorded_gap",
                "missing_pending_after_rollback", "digest_mismatch_retained",
                "installed_cleanup", "backup_delete_gap"
            }) {
                Bundle receipt = new Bundle();
                receipt.putString("scenario", scenario);
                try {
                    scenario(scenario);
                    receipt.putString("result", "PASS");
                } catch (Exception | AssertionError error) {
                    failures++;
                    receipt.putString("result", "FAIL " + error);
                }
                sendStatus(0, receipt);
            }
            result.putString("stream", "SAF recovery checks: " + failures + " failing scenarios.\n");
        } catch (Exception | AssertionError error) {
            failures++;
            result.putString("stream", "SAF recovery setup failed: " + error + "\n");
        }
        result.putInt("failures", failures);
        finish(failures == 0 ? Activity.RESULT_OK : Activity.RESULT_CANCELED, result);
    }

    private void scenario(String scenario) throws Exception {
        String directoryName = ".localupload-recovery-check-" + UUID.randomUUID();
        Uri parent = create(root, Document.MIME_TYPE_DIR, directoryName);
        String temporaryName = ".localupload-pending-" + UUID.randomUUID();
        String backupName = ".localupload-backup-" + UUID.randomUUID();
        Uri temporary = create(parent, "application/octet-stream", temporaryName);
        String ticket = temporary.toString();
        String key = "tx:" + ticket;
        try {
            write(temporary, NEW);
            boolean newFile = scenario.startsWith("new_file");
            Uri original = newFile ? null : create(parent, "application/octet-stream", "target.bin");
            if (original != null) {
                write(original, OLD);
            }
            Uri recordedTemporary = temporary;
            Uri recordedOld = null;
            String phase = "pending";
            boolean replaced = !newFile && !scenario.equals("pending_restart");
            if (replaced) {
                recordedOld = original;
                original = rename(original, backupName);
                phase = "replacing";
                if (!scenario.equals("backup_rename_gap")) {
                    recordedOld = original;
                }
            }
            boolean installed = scenario.contains("install")
                || scenario.equals("new_file_recorded_gap")
                || scenario.equals("rollback_pending_gap")
                || scenario.equals("digest_mismatch_retained")
                || scenario.equals("missing_pending_after_rollback")
                || scenario.equals("backup_delete_gap");
            if (installed && !scenario.equals("installed_cleanup")
                    && !scenario.equals("backup_delete_gap")) {
                temporary = rename(temporary, "target.bin");
                phase = "installing";
                if (!scenario.equals("install_rename_gap")
                        && !scenario.equals("new_file_install_gap")) {
                    recordedTemporary = temporary;
                }
            }
            if (scenario.equals("rollback_pending_gap")) {
                temporary = rename(temporary, temporaryName);
            } else if (scenario.equals("missing_pending_after_rollback")) {
                require(DocumentsContract.deleteDocument(resolver, temporary), "Delete fixture upload failed.");
            } else if (scenario.equals("rollback_restore_gap")
                    || scenario.equals("restore_recorded_gap")) {
                phase = "restoring";
                original = rename(original, "target.bin");
                if (scenario.equals("restore_recorded_gap")) {
                    recordedOld = original;
                }
            } else if (scenario.equals("digest_mismatch_retained")) {
                write(temporary, OTHER);
            } else if (scenario.equals("installed_cleanup") || scenario.equals("backup_delete_gap")) {
                temporary = rename(temporary, "target.bin");
                recordedTemporary = temporary;
                phase = "installed";
                if (scenario.equals("backup_delete_gap")) {
                    require(DocumentsContract.deleteDocument(resolver, original), "Delete fixture backup failed.");
                }
            }
            JSONObject record = new JSONObject().put("tree", tree.toString()).put("ticket", ticket)
                .put("parent", parent.toString()).put("temporary", recordedTemporary.toString())
                .put("temporaryName", temporaryName).put("relative", directoryName + "/target.bin")
                .put("old", recordedOld == null ? "" : recordedOld.toString())
                .put("backupName", replaced ? backupName : "").put("phase", phase)
                .put("sha256", sha256(NEW));
            require(journal.edit().putString(key, record.toString()).commit(), "Fixture journal write failed.");
            if (scenario.equals("digest_mismatch_retained")) {
                try {
                    new SafStorage(context, tree.toString()).validate();
                    throw new AssertionError("Recovery accepted a different file digest.");
                } catch (IOException expected) {
                    require(Arrays.equals(read(child(parent, backupName)), OLD), "Backup bytes changed.");
                    require(Arrays.equals(read(child(parent, "target.bin")), OTHER), "Unrelated final bytes changed.");
                    require(journal.contains(key), "Ambiguous recovery record was discarded.");
                }
                return;
            }
            new SafStorage(context, tree.toString()).validate();
            Uri destination = child(parent, "target.bin");
            if (newFile) {
                require(destination == null, "Interrupted new-file upload survived rollback.");
            } else {
                byte[] expected = phase.equals("installed") ? NEW : OLD;
                require(destination != null && Arrays.equals(read(destination), expected),
                    "Original/final bytes were lost or changed after " + scenario);
            }
            require(child(parent, temporaryName) == null, "Pending upload was not cleaned up.");
            require(child(parent, backupName) == null, "Backup was not restored or cleaned up.");
            require(!journal.contains(key), "Finished recovery record remained.");
        } finally {
            require(journal.edit().remove(key).commit(), "Fixture journal cleanup failed.");
            require(DocumentsContract.deleteDocument(resolver, parent), "Fixture folder cleanup failed.");
        }
    }

    private Uri child(Uri parent, String name) throws IOException {
        Uri children = DocumentsContract.buildChildDocumentsUriUsingTree(
            tree, DocumentsContract.getDocumentId(parent));
        try (Cursor cursor = resolver.query(children, new String[] {
                Document.COLUMN_DOCUMENT_ID, Document.COLUMN_DISPLAY_NAME}, null, null, null)) {
            require(cursor != null, "Fixture folder query failed.");
            while (cursor.moveToNext()) {
                if (name.equals(cursor.getString(1))) {
                    return DocumentsContract.buildDocumentUriUsingTree(tree, cursor.getString(0));
                }
            }
            return null;
        }
    }

    private Uri create(Uri parent, String mime, String name) throws IOException {
        Uri document = DocumentsContract.createDocument(resolver, parent, mime, name);
        require(document != null, "Fixture creation failed.");
        return document;
    }

    private Uri rename(Uri document, String name) throws IOException {
        Uri changed = DocumentsContract.renameDocument(resolver, document, name);
        require(changed != null, "Fixture rename failed.");
        require(!changed.equals(document), "This test needs the local provider's changing document IDs.");
        return changed;
    }

    private void write(Uri document, byte[] bytes) throws IOException {
        try (OutputStream output = resolver.openOutputStream(document, "wt")) {
            require(output != null, "Fixture stream open failed.");
            output.write(bytes);
        }
    }

    private byte[] read(Uri document) throws IOException {
        require(document != null, "Expected fixture document is missing.");
        try (InputStream input = resolver.openInputStream(document);
                ByteArrayOutputStream output = new ByteArrayOutputStream()) {
            require(input != null, "Fixture read failed.");
            byte[] buffer = new byte[128];
            int count;
            while ((count = input.read(buffer)) != -1) {
                output.write(buffer, 0, count);
            }
            return output.toByteArray();
        }
    }

    private static String sha256(byte[] bytes) throws Exception {
        StringBuilder result = new StringBuilder();
        for (byte value : MessageDigest.getInstance("SHA-256").digest(bytes)) {
            result.append(Character.forDigit((value & 255) >>> 4, 16));
            result.append(Character.forDigit(value & 15, 16));
        }
        return result.toString();
    }

    private static void require(boolean condition, String message) {
        if (!condition) {
            throw new AssertionError(message);
        }
    }
}
