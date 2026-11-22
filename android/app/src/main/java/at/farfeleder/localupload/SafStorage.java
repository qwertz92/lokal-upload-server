package at.farfeleder.localupload;

import android.content.ContentResolver;
import android.content.Context;
import android.content.SharedPreferences;
import android.content.UriPermission;
import android.database.Cursor;
import android.net.Uri;
import android.os.ParcelFileDescriptor;
import android.provider.DocumentsContract;
import android.provider.DocumentsContract.Document;
import android.system.ErrnoException;
import android.system.Os;

import org.json.JSONException;
import org.json.JSONObject;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.FileAlreadyExistsException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

/** Streams upload bytes directly into a user-selected local SAF directory. */
public final class SafStorage {
    // ponytail: one lock serializes metadata changes; upload bytes stream outside this lock.
    private static final Object LOCK = new Object();
    private static final Set<String> ACTIVE = new HashSet<>();
    private static final String[] COLUMNS = {
        Document.COLUMN_DOCUMENT_ID, Document.COLUMN_DISPLAY_NAME,
        Document.COLUMN_MIME_TYPE, Document.COLUMN_FLAGS
    };
    private final ContentResolver resolver;
    private final SharedPreferences journal;
    private final Uri tree;
    private final Uri root;
    private final Map<String, Transaction> pending = new HashMap<>();
    private boolean validated;
    /*
     * True while this tree's document IDs are verified to be "<volume>:<path>" strings, as the
     * Android external-storage provider builds them. A child is then read with one query by its
     * ID instead of listing the whole parent folder, so the cost of a lookup no longer grows with
     * the number of files in the folder. Every answer still comes from the provider at the time
     * of asking; nothing is cached. Any ID that breaks the rule switches this storage back to
     * listing for the rest of the run. Read and written only while holding LOCK.
     */
    private boolean pathIds;
    /** Test-only: skips the direct lookups so that the listing fallback can be exercised. */
    private final boolean listingOnly;

    public SafStorage(Context context, String treeUri) {
        this(context, treeUri, false);
    }

    /**
     * Package-private so that only this app's own code (the instrumentation check) can force the
     * listing fallback; nothing reachable through an intent, the server or the UI selects it.
     */
    SafStorage(Context context, String treeUri, boolean listingOnly) {
        this.listingOnly = listingOnly;
        if (treeUri == null) {
            throw new IllegalArgumentException("Choose a local destination folder first.");
        }
        tree = Uri.parse(treeUri);
        if (!"content".equals(tree.getScheme()) || !DocumentsContract.isTreeUri(tree)) {
            throw new IllegalArgumentException("The destination must be a SAF folder tree URI.");
        }
        root = DocumentsContract.buildDocumentUriUsingTree(
            tree, DocumentsContract.getTreeDocumentId(tree));
        Context app = context.getApplicationContext();
        if (app == null) {
            app = context;
        }
        resolver = app.getContentResolver();
        journal = app.getSharedPreferences("saf_upload_transactions", Context.MODE_PRIVATE);
    }

    public void validate() throws IOException {
        synchronized (LOCK) {
            // This provider covers internal shared storage and removable SD cards.
            // Cloud providers may acknowledge buffered writes before they are durable.
            // This whitelist is also what keeps providers with opaque document IDs away from
            // the direct lookups: direct() cannot catch a provider that simply echoes whatever
            // ID it is asked for, so the path rule is only trusted for this one authority.
            if (!"com.android.externalstorage.documents".equals(tree.getAuthority())) {
                throw new IllegalArgumentException(
                    "Choose an internal-storage or SD-card folder in Android Files. "
                    + "Cloud and other document providers are not supported.");
            }
            boolean permitted = false;
            for (UriPermission grant : resolver.getPersistedUriPermissions()) {
                if (grant.getUri().equals(tree) && grant.isReadPermission()
                        && grant.isWritePermission()) {
                    permitted = true;
                    break;
                }
            }
            if (!permitted) {
                throw new SecurityException(
                    "The saved folder permission is missing. Choose the destination again.");
            }
            Doc directory = require(root);
            if (!directory.directory()
                    || (directory.flags & Document.FLAG_DIR_SUPPORTS_CREATE) == 0) {
                throw new IOException("The selected folder does not support creating files.");
            }
            pathIds = !listingOnly && measureDirectLookups();
            for (Map.Entry<String, ?> entry : journal.getAll().entrySet()) {
                if (!entry.getKey().startsWith("tx:") || !(entry.getValue() instanceof String)) {
                    continue;
                }
                Transaction transaction = Transaction.read((String) entry.getValue());
                if (transaction.tree.equals(tree.toString())
                        && !ACTIVE.contains(transaction.ticket)) {
                    recover(transaction);
                }
            }
            validated = true;
        }
    }

    /** Whether lookups currently go by document ID (true) or by listing the folder (false). */
    public boolean directLookups() {
        synchronized (LOCK) {
            return pathIds;
        }
    }

    public boolean exists(String relative) throws IOException {
        synchronized (LOCK) {
            ready();
            return resolve(segments(relative, true), false) != null;
        }
    }

    public boolean isDirectory(String relative) throws IOException {
        synchronized (LOCK) {
            ready();
            Doc document = resolve(segments(relative, true), false);
            return document != null && document.directory();
        }
    }

    public long availableBytes() {
        // SAF does not expose the selected subtree's filesystem free space. The
        // app's own data volume can differ from an SD card, so do not report it.
        return -1;
    }

    public String begin(String relative) throws IOException {
        synchronized (LOCK) {
            ready();
            String[] path = segments(relative, false);
            Uri parent = parent(path, true);
            Doc existing = child(parent, path[path.length - 1]);
            if (existing != null && (existing.directory()
                    || ACTIVE.contains(existing.uri.toString()))) {
                throw new FileAlreadyExistsException(relative);
            }
            String temporaryName = ".localupload-pending-" + UUID.randomUUID();
            Uri temporary = DocumentsContract.createDocument(
                resolver, parent, "application/octet-stream", temporaryName);
            if (temporary == null) {
                throw new IOException("The destination could not create an upload file.");
            }
            Transaction transaction = new Transaction(
                tree.toString(), temporary.toString(), parent, temporary, temporaryName, relative);
            try {
                exact(parent, temporary, temporaryName);
                writableFile(require(temporary));
                save(transaction);
                pending.put(transaction.ticket, transaction);
                ACTIVE.add(transaction.ticket);
                return transaction.ticket;
            } catch (IOException | RuntimeException error) {
                try {
                    delete(temporary);
                } catch (IOException | RuntimeException cleanup) {
                    error.addSuppressed(cleanup);
                }
                throw error;
            }
        }
    }

    public int openDetachedFd(String ticket) throws IOException {
        synchronized (LOCK) {
            Transaction transaction = ticket(ticket);
            if (transaction.opened || !"pending".equals(transaction.phase)) {
                throw new IllegalArgumentException("This upload ticket was already opened.");
            }
            try (ParcelFileDescriptor descriptor =
                    resolver.openFileDescriptor(transaction.temporary, "rwt")) {
                if (descriptor == null) {
                    throw new IOException("The destination could not open the upload file.");
                }
                int fd = descriptor.detachFd();
                transaction.opened = true;
                return fd;
            }
        }
    }

    /** The caller must flush and close its detached descriptor before committing. */
    public void commit(String ticket, String relative, boolean overwrite, String sha256)
            throws IOException {
        synchronized (LOCK) {
            Transaction transaction = ticket(ticket);
            segments(relative, false);
            if (sha256 == null || !sha256.matches("[0-9a-f]{64}")) {
                throw new IllegalArgumentException("A lowercase SHA-256 upload digest is required.");
            }
            if (!transaction.relative.equals(relative)) {
                throw new IllegalArgumentException("The upload ticket belongs to another path.");
            }
            if (!transaction.opened || !"pending".equals(transaction.phase)) {
                throw new IllegalArgumentException("The upload ticket is not ready to commit.");
            }
            String finalName = finalName(transaction);
            Doc previous = child(transaction.parent, finalName);
            if (previous != null && (previous.directory() || !overwrite
                    || ACTIVE.contains(previous.uri.toString()))) {
                throw new FileAlreadyExistsException(relative);
            }
            transaction.sha256 = sha256;
            try {
                sync(transaction.temporary);
                if (previous != null) {
                    writableFile(previous);
                    transaction.old = previous.uri;
                    transaction.backupName = ".localupload-backup-" + UUID.randomUUID();
                    transaction.phase = "replacing";
                    save(transaction);
                    transaction.old = rename(previous.uri, transaction.backupName);
                    save(transaction);
                    exact(transaction.parent, transaction.old, transaction.backupName);
                }
                transaction.phase = "installing";
                save(transaction);
                transaction.temporary = rename(transaction.temporary, finalName);
                save(transaction);
                exact(transaction.parent, transaction.temporary, finalName);
                transaction.phase = "installed";
                save(transaction);
            } catch (IOException | RuntimeException error) {
                try {
                    rollback(transaction, false);
                } catch (IOException | RuntimeException rollbackError) {
                    error.addSuppressed(rollbackError);
                    throw new IOException(recoveryMessage(transaction), error);
                }
                throw error;
            }
            // Only an installed, verified new document permits removal of old bytes.
            finish(transaction);
        }
    }

    public void abort(String ticket) throws IOException {
        synchronized (LOCK) {
            Transaction transaction = pending.get(ticket);
            if (transaction == null) {
                return;
            }
            if ("installed".equals(transaction.phase)) {
                // A cleanup failure already left the completed final file intact.
                ACTIVE.remove(ticket);
                pending.remove(ticket);
                return;
            }
            try {
                rollback(transaction, false);
                discard(transaction);
            } finally {
                ACTIVE.remove(ticket);
                pending.remove(ticket);
            }
        }
    }

    private void ready() throws IOException {
        if (!validated) {
            validate();
        }
    }

    private Transaction ticket(String ticket) {
        Transaction transaction = pending.get(ticket);
        if (transaction == null) {
            throw new IllegalArgumentException("Unknown or completed upload ticket.");
        }
        return transaction;
    }

    static String[] segments(String relative, boolean rootAllowed) {
        if (relative == null || (relative.isEmpty() && !rootAllowed)) {
            throw new IllegalArgumentException("A relative filename is required.");
        }
        if (relative.isEmpty()) {
            return new String[0];
        }
        String[] parts = relative.split("/", -1);
        for (String part : parts) {
            if (part.isEmpty() || part.equals(".") || part.equals("..")) {
                throw new IllegalArgumentException("Unsafe relative path segment.");
            }
            for (int i = 0; i < part.length(); i++) {
                char character = part.charAt(i);
                if (character == '\\' || character < 32 || character == 127
                        || (Character.isHighSurrogate(character)
                            && (i + 1 == part.length()
                                || !Character.isLowSurrogate(part.charAt(++i))))
                        || Character.isLowSurrogate(character)) {
                    throw new IllegalArgumentException("Unsafe character in relative filename.");
                }
            }
        }
        return parts;
    }

    private Uri parent(String[] path, boolean create) throws IOException {
        String[] directories = new String[path.length - 1];
        System.arraycopy(path, 0, directories, 0, directories.length);
        Doc directory = resolve(directories, create);
        if (directory == null) {
            throw new FileNotFoundException("The destination folder no longer exists.");
        }
        return directory.uri;
    }

    private Doc resolve(String[] path, boolean create) throws IOException {
        Doc current = require(root);
        for (String part : path) {
            if (!current.directory()) {
                throw new FileAlreadyExistsException("A file blocks a destination folder: " + part);
            }
            Doc next = child(current.uri, part);
            if (next == null && create) {
                Uri created = DocumentsContract.createDocument(
                    resolver, current.uri, Document.MIME_TYPE_DIR, part);
                if (created == null) {
                    throw new IOException("Could not create destination folder: " + part);
                }
                exact(current.uri, created, part);
                next = require(created);
            }
            if (next == null) {
                return null;
            }
            current = next;
        }
        if (create && !current.directory()) {
            throw new FileAlreadyExistsException("A file blocks the destination folder.");
        }
        return current;
    }

    private Doc child(Uri parent, String name) throws IOException {
        return child(parent, name, null);
    }

    private Doc child(Uri parent, String name, Uri identity) throws IOException {
        if (pathIds) {
            return identity == null ? direct(parent, name) : directIdentity(parent, identity);
        }
        return listed(parent, name, identity);
    }

    /** The ID a path-based provider gives to {@code name} inside {@code parentId}. */
    static String childId(String parentId, String name) {
        return parentId.endsWith(":") ? parentId + name : parentId + "/" + name;
    }

    static boolean pathBasedRoot(String documentId) {
        // "primary:", "primary:Download" or "1234-ABCD:DCIM/Camera"; no empty or doubled segment.
        int colon = documentId.indexOf(':');
        if (colon <= 0 || documentId.substring(0, colon).indexOf('/') >= 0) {
            return false;
        }
        String path = documentId.substring(colon + 1);
        return path.isEmpty() || !(path.startsWith("/") || path.endsWith("/") || path.contains("//"));
    }

    /** Where the last name segment of a path-based ID starts. */
    private static int nameStart(String documentId) {
        return Math.max(documentId.lastIndexOf('/'), documentId.indexOf(':')) + 1;
    }

    /**
     * Whether two different path-based IDs name the same parent and differ only in the case of
     * their last segment, as sameName() compares it.
     */
    static boolean caseVariantIds(String first, String second) {
        int start = nameStart(first);
        return pathBasedRoot(first) && pathBasedRoot(second) && start > 0
            && start < first.length() && start == nameStart(second)
            && first.regionMatches(0, second, 0, start) && !first.equals(second)
            && sameName(first.substring(start), second.substring(start));
    }

    static boolean hasAsciiLetter(String name) {
        for (int i = 0; i < name.length(); i++) {
            char character = name.charAt(i);
            if ((character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z')) {
                return true;
            }
        }
        return false;
    }

    static String swapAsciiCase(String name) {
        char[] characters = name.toCharArray();
        for (int i = 0; i < characters.length; i++) {
            char character = characters[i];
            if (character >= 'a' && character <= 'z') {
                characters[i] = (char) (character - 'a' + 'A');
            } else if (character >= 'A' && character <= 'Z') {
                characters[i] = (char) (character - 'A' + 'a');
            }
        }
        return new String(characters);
    }

    /**
     * Decides once per run whether direct lookups give the answers listing would give. The IDs
     * must follow the path rule (the root ID looks like one, and every entry of the root folder
     * carries exactly the ID the rule predicts from its name), a name that cannot exist must come
     * back as a clean "missing", and an existing entry must be found under its ASCII-case-swapped
     * spelling, as listing with sameName() would find it. A provider that resolves IDs
     * case-sensitively (reportedly the lower file system on Android 8 to 10) therefore runs on
     * listing, so that skip and overwrite answer the same in both modes and two names that differ
     * only in case are never created side by side. Later lookups and every document this app
     * creates are checked again as they happen.
     */
    private boolean measureDirectLookups() throws IOException {
        String rootId = DocumentsContract.getDocumentId(root);
        if (!pathBasedRoot(rootId)) {
            return false;
        }
        String sample = null;
        Uri children = DocumentsContract.buildChildDocumentsUriUsingTree(tree, rootId);
        try (Cursor cursor = resolver.query(children, COLUMNS, null, null, null)) {
            if (cursor == null || cursor.getExtras().getBoolean(DocumentsContract.EXTRA_LOADING)) {
                return false;
            }
            int idColumn = cursor.getColumnIndexOrThrow(Document.COLUMN_DOCUMENT_ID);
            int nameColumn = cursor.getColumnIndexOrThrow(Document.COLUMN_DISPLAY_NAME);
            while (cursor.moveToNext()) {
                String name = cursor.getString(nameColumn);
                if (name == null || !childId(rootId, name).equals(cursor.getString(idColumn))) {
                    return false;
                }
                if (sample == null && hasAsciiLetter(name)) {
                    sample = name;
                }
            }
        }
        pathIds = true;
        if (lookup(".localupload-absent-" + UUID.randomUUID()) != MISSING) {
            return false;
        }
        if (sample != null) {
            return lookup(swapAsciiCase(sample)) == FOUND;
        }
        // Nothing to compare against: probe with an empty document of this app's own naming and
        // delete exactly the document the provider returned for it.
        String probeName = ".localupload-pending-" + UUID.randomUUID();
        Uri created = DocumentsContract.createDocument(
            resolver, root, "application/octet-stream", probeName);
        if (created == null) {
            throw new IOException("The destination could not create an upload file.");
        }
        try {
            return lookup(swapAsciiCase(probeName)) == FOUND;
        } finally {
            delete(created);
        }
    }

    private static final int FOUND = 1;
    private static final int MISSING = 0;
    private static final int FAILED = -1;

    /** One direct lookup in the root folder during the measurement; any error counts as FAILED. */
    private int lookup(String name) {
        try {
            return direct(root, name) == null ? MISSING : FOUND;
        } catch (IOException | RuntimeException error) {
            return FAILED;
        }
    }

    private void notPathBased() {
        // Fall back for the rest of this run; the current operation fails safely instead.
        pathIds = false;
    }

    /**
     * Reads one child by its predicted ID. Shared storage compares names without regard to case,
     * so this also finds {@code CaseProbe.txt} when asked for {@code caseprobe.txt}; the returned
     * document then carries the requested spelling, which addresses the same file.
     */
    private Doc direct(Uri parent, String name) throws IOException {
        String expected = childId(DocumentsContract.getDocumentId(parent), name);
        Doc document = probe(DocumentsContract.buildDocumentUriUsingTree(tree, expected));
        if (document != null
                && !expected.equals(DocumentsContract.getDocumentId(document.uri))) {
            notPathBased();
            throw new IOException("The provider answered for another document: " + name);
        }
        return document;
    }

    private Doc directIdentity(Uri parent, Uri identity) throws IOException {
        String parentId = DocumentsContract.getDocumentId(parent);
        String id = DocumentsContract.getDocumentId(identity);
        if (!id.startsWith(parentId.endsWith(":") ? parentId : parentId + "/")
                || id.indexOf('/', parentId.length() + 1) >= 0) {
            return null;
        }
        Doc document = probe(identity);
        return document != null && id.equals(DocumentsContract.getDocumentId(document.uri))
            ? document : null;
    }

    /**
     * A document query that reports a missing document as null. For a tree URI the platform's
     * DocumentsProvider first checks that the ID lies inside the tree, and for a file that does
     * not exist that check fails with an IllegalArgumentException whose message carries the
     * provider's FileNotFoundException (measured on Android 17). Any other failure stays an error.
     * A wrong "missing" answer cannot overwrite data: creating or renaming onto an existing name
     * makes the provider pick another name, which exact() then rejects.
     */
    private Doc probe(Uri uri) throws IOException {
        try (Cursor cursor = resolver.query(uri, COLUMNS, null, null, null)) {
            return cursor != null && cursor.moveToFirst() ? row(cursor) : null;
        } catch (IllegalArgumentException error) {
            if (String.valueOf(error.getMessage()).contains("FileNotFoundException")) {
                return null;
            }
            throw new IOException("The destination document is unavailable.", error);
        }
    }

    private static boolean sameName(String requested, String actual) {
        return requested.equals(actual) || requested.toLowerCase(Locale.ROOT)
            .equals(actual == null ? null : actual.toLowerCase(Locale.ROOT));
    }

    private Doc listed(Uri parent, String name, Uri identity) throws IOException {
        Uri children = DocumentsContract.buildChildDocumentsUriUsingTree(
            tree, DocumentsContract.getDocumentId(parent));
        try (Cursor cursor = resolver.query(children, COLUMNS, null, null, null)) {
            if (cursor == null || cursor.getExtras().getBoolean(DocumentsContract.EXTRA_LOADING)) {
                throw new IOException("The destination folder could not be read completely.");
            }
            Doc found = null;
            while (cursor.moveToNext()) {
                Doc document = row(cursor);
                // Shared storage treats names that differ only in case as one file; an identity
                // recorded by a direct lookup can carry another case spelling of the same entry.
                if (identity == null ? sameName(name, document.name)
                        : identity.equals(document.uri) || caseVariant(identity, document.uri)) {
                    if (found != null) {
                        throw new IOException("The provider returned duplicate filename: " + name);
                    }
                    found = document;
                }
            }
            return found;
        }
    }

    /** Whether two URIs of this tree carry case-variant path-based IDs (see caseVariantIds). */
    private boolean caseVariant(Uri first, Uri second) {
        if (first == null || second == null || !tree.getAuthority().equals(first.getAuthority())
                || !tree.getAuthority().equals(second.getAuthority())) {
            return false;
        }
        try {
            String treeId = DocumentsContract.getTreeDocumentId(tree);
            return treeId.equals(DocumentsContract.getTreeDocumentId(first))
                && treeId.equals(DocumentsContract.getTreeDocumentId(second))
                && caseVariantIds(DocumentsContract.getDocumentId(first),
                    DocumentsContract.getDocumentId(second));
        } catch (IllegalArgumentException notTreeDocument) {
            return false;
        }
    }

    /**
     * Whether {@code found}, just looked up in {@code parent}, is the document a journal record
     * calls {@code recorded}. Equal URIs are. A direct lookup returns the requested spelling and
     * listing the spelling on disk, so a record written in one mode and read in the other can
     * name the same entry with another case; that counts only when listing the parent finds
     * exactly one entry under the name in any spelling (listed() rejects two), so two genuinely
     * different documents are never taken for one.
     */
    private boolean sameDocument(Uri parent, Uri found, Uri recorded) throws IOException {
        if (found.equals(recorded)) {
            return true;
        }
        if (!caseVariant(found, recorded)) {
            return false;
        }
        String id = DocumentsContract.getDocumentId(found);
        Doc only = listed(parent, id.substring(nameStart(id)), null);
        return only != null && (only.uri.equals(found) || caseVariant(only.uri, found));
    }

    private Doc read(Uri uri) throws IOException {
        try (Cursor cursor = resolver.query(uri, COLUMNS, null, null, null)) {
            if (cursor == null) {
                throw new IOException("The destination document could not be read.");
            }
            return cursor.moveToFirst() ? row(cursor) : null;
        } catch (IllegalArgumentException error) {
            throw new IOException("The destination document is unavailable.", error);
        }
    }

    private Doc require(Uri uri) throws IOException {
        Doc document = read(uri);
        if (document == null) {
            throw new FileNotFoundException("The destination document no longer exists.");
        }
        return document;
    }

    private Doc row(Cursor cursor) {
        return new Doc(DocumentsContract.buildDocumentUriUsingTree(tree,
            cursor.getString(cursor.getColumnIndexOrThrow(Document.COLUMN_DOCUMENT_ID))),
            cursor.getString(cursor.getColumnIndexOrThrow(Document.COLUMN_DISPLAY_NAME)),
            cursor.getString(cursor.getColumnIndexOrThrow(Document.COLUMN_MIME_TYPE)),
            cursor.getInt(cursor.getColumnIndexOrThrow(Document.COLUMN_FLAGS)));
    }

    private void exact(Uri parent, Uri uri, String name) throws IOException {
        if (pathIds) {
            // A provider that renamed the document (for example to "name (1)") returns an ID
            // with that other name; a path-based ID must be exactly the requested one.
            if (!childId(DocumentsContract.getDocumentId(parent), name)
                    .equals(DocumentsContract.getDocumentId(uri))) {
                if (!DocumentsContract.getDocumentId(uri).startsWith(
                        DocumentsContract.getDocumentId(parent))) {
                    notPathBased();
                }
                throw new IOException("The provider changed the requested filename: " + name);
            }
            require(uri);
            return;
        }
        Doc document = require(uri);
        Doc located = child(parent, name);
        if (!name.equals(document.name) || located == null || !located.uri.equals(uri)) {
            throw new IOException("The provider changed the requested filename: " + name);
        }
    }

    private static void writableFile(Doc document) throws IOException {
        int required = Document.FLAG_SUPPORTS_WRITE | Document.FLAG_SUPPORTS_RENAME
            | Document.FLAG_SUPPORTS_DELETE;
        if (document.directory() || (document.flags & required) != required
                || (document.flags & Document.FLAG_VIRTUAL_DOCUMENT) != 0) {
            throw new IOException("The destination must support writing, renaming and deleting files.");
        }
    }

    private void sync(Uri uri) throws IOException {
        try (ParcelFileDescriptor descriptor = resolver.openFileDescriptor(uri, "rw")) {
            if (descriptor == null) {
                throw new IOException("The completed upload could not be opened for syncing.");
            }
            Os.fsync(descriptor.getFileDescriptor());
        } catch (ErrnoException error) {
            throw new IOException("The completed upload could not be flushed to storage.", error);
        }
    }

    private Uri rename(Uri uri, String name) throws IOException {
        Uri renamed = DocumentsContract.renameDocument(resolver, uri, name);
        if (renamed == null) {
            throw new IOException("The destination could not rename a file to: " + name);
        }
        return renamed;
    }

    private void delete(Uri uri) throws IOException {
        if (!DocumentsContract.deleteDocument(resolver, uri)) {
            throw new IOException("The destination could not delete an upload document.");
        }
    }

    private String finalName(Transaction transaction) {
        String[] path = segments(transaction.relative, false);
        return path[path.length - 1];
    }

    private void rollback(Transaction transaction, boolean recovering) throws IOException {
        if (transaction.old == null) {
            return;
        }
        String name = finalName(transaction);
        Doc backup = child(transaction.parent, transaction.backupName);
        Doc destination = child(transaction.parent, name);
        if (backup != null) {
            if (destination != null) {
                // A crash can precede recording the provider's changed document ID.
                if (recovering && !digestMatches(destination.uri, transaction.sha256)) {
                    throw new IOException(recoveryMessage(transaction));
                }
                if (!destination.uri.equals(transaction.temporary)) {
                    // The lookup mode can switch within a run, so the spelling may differ.
                    if (!recovering && !sameDocument(
                            transaction.parent, destination.uri, transaction.temporary)) {
                        throw new IOException(recoveryMessage(transaction));
                    }
                    transaction.temporary = destination.uri;
                    save(transaction);
                }
                transaction.temporary = rename(transaction.temporary, transaction.temporaryName);
                save(transaction);
                exact(transaction.parent, transaction.temporary, transaction.temporaryName);
            } else if (recovering) {
                reconcilePending(transaction);
            }
            transaction.phase = "restoring";
            save(transaction);
            transaction.old = rename(backup.uri, name);
            save(transaction);
            exact(transaction.parent, transaction.old, name);
        } else if (destination == null || (!(recovering && "restoring".equals(transaction.phase))
                && !sameDocument(transaction.parent, destination.uri, transaction.old))) {
            throw new IOException(recoveryMessage(transaction));
        } else if (recovering) {
            reconcilePending(transaction);
        }
        transaction.old = null;
        transaction.backupName = "";
        transaction.phase = "pending";
        save(transaction);
    }

    private void finish(Transaction transaction) throws IOException {
        exact(transaction.parent, transaction.temporary, finalName(transaction));
        if (transaction.old != null) {
            Doc backup = child(transaction.parent, transaction.backupName);
            if (backup != null) {
                if (!sameDocument(transaction.parent, backup.uri, transaction.old)) {
                    throw new IOException(recoveryMessage(transaction));
                }
                delete(backup.uri);
            }
        }
        forget(transaction);
    }

    private void discard(Transaction transaction) throws IOException {
        Doc temporary = child(transaction.parent, null, transaction.temporary);
        if (temporary != null) {
            if (sameName(finalName(transaction), temporary.name)
                    && !"installing".equals(transaction.phase)) {
                // A reused path-based ID must never turn restored old data into a temp.
                throw new IOException(recoveryMessage(transaction));
            }
            // Delete only the identity returned for this upload, never a name sweep.
            delete(temporary.uri);
        } else if ("installing".equals(transaction.phase)
                && child(transaction.parent, finalName(transaction)) != null) {
            // A rename may have changed its URI before the journal was updated.
            throw new IOException(recoveryMessage(transaction));
        }
        forget(transaction);
    }

    private void recover(Transaction transaction) throws IOException {
        if ("installed".equals(transaction.phase)) {
            finish(transaction);
            return;
        }
        if (transaction.old == null && "installing".equals(transaction.phase)
                && child(transaction.parent, transaction.temporaryName) == null) {
            Doc destination = child(transaction.parent, finalName(transaction));
            if (destination != null) {
                if (!digestMatches(destination.uri, transaction.sha256)) {
                    throw new IOException(recoveryMessage(transaction));
                }
                transaction.temporary = destination.uri;
                save(transaction);
            }
        }
        rollback(transaction, true);
        discard(transaction);
    }

    private void reconcilePending(Transaction transaction) throws IOException {
        Doc temporary = child(transaction.parent, transaction.temporaryName);
        if (temporary == null) {
            // The initially recorded temp ID cannot alias the original destination.
            transaction.temporary = Uri.parse(transaction.ticket);
        } else if (!temporary.uri.equals(transaction.temporary)) {
            if (!temporary.uri.toString().equals(transaction.ticket)
                    && !digestMatches(temporary.uri, transaction.sha256)) {
                throw new IOException(recoveryMessage(transaction));
            }
            transaction.temporary = temporary.uri;
        }
        save(transaction);
    }

    private boolean digestMatches(Uri uri, String expected) throws IOException {
        if (expected.length() != 64) {
            return false;
        }
        try (InputStream input = resolver.openInputStream(uri)) {
            if (input == null) {
                throw new IOException("Could not read the interrupted upload for recovery.");
            }
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] buffer = new byte[65536];
            int count;
            while ((count = input.read(buffer)) != -1) {
                digest.update(buffer, 0, count);
            }
            byte[] actual = digest.digest();
            for (int i = 0; i < actual.length; i++) {
                int value = Character.digit(expected.charAt(2 * i), 16) * 16
                    + Character.digit(expected.charAt(2 * i + 1), 16);
                if ((actual[i] & 255) != value) {
                    return false;
                }
            }
            return true;
        } catch (NoSuchAlgorithmException error) {
            throw new IOException("SHA-256 is unavailable for upload recovery.", error);
        }
    }

    private String recoveryMessage(Transaction transaction) {
        return "An interrupted upload needs recovery in the selected folder. "
            + "Keep the existing files; original backup: " + transaction.backupName
            + "; upload: " + transaction.temporaryName
            + "; intended destination: " + transaction.relative
            + ". Restore the backup to the intended filename after checking both files. "
            + "Then clear this app's saved storage and choose the folder again; "
            + "files in the selected folder are not app-private data.";
    }

    private void save(Transaction transaction) throws IOException {
        if (!journal.edit().putString("tx:" + transaction.ticket, transaction.json()).commit()) {
            throw new IOException("Could not durably record the upload transaction.");
        }
    }

    private void forget(Transaction transaction) throws IOException {
        if (!journal.edit().remove("tx:" + transaction.ticket).commit()) {
            throw new IOException("Could not clear the completed upload transaction.");
        }
        ACTIVE.remove(transaction.ticket);
        pending.remove(transaction.ticket);
    }

    private static final class Doc {
        final Uri uri;
        final String name;
        final String mime;
        final int flags;

        Doc(Uri uri, String name, String mime, int flags) {
            this.uri = uri;
            this.name = name;
            this.mime = mime;
            this.flags = flags;
        }

        boolean directory() {
            return Document.MIME_TYPE_DIR.equals(mime);
        }
    }

    private static final class Transaction {
        final String tree;
        final String ticket;
        final Uri parent;
        Uri temporary;
        final String temporaryName;
        final String relative;
        Uri old;
        String backupName = "";
        String phase = "pending";
        String sha256 = "";
        boolean opened;

        Transaction(String tree, String ticket, Uri parent, Uri temporary,
                String temporaryName, String relative) {
            this.tree = tree;
            this.ticket = ticket;
            this.parent = parent;
            this.temporary = temporary;
            this.temporaryName = temporaryName;
            this.relative = relative;
        }

        String json() throws IOException {
            try {
                return new JSONObject().put("tree", tree).put("ticket", ticket)
                    .put("parent", parent.toString()).put("temporary", temporary.toString())
                    .put("temporaryName", temporaryName).put("relative", relative)
                    .put("old", old == null ? "" : old.toString())
                    .put("backupName", backupName).put("phase", phase)
                    .put("sha256", sha256).toString();
            } catch (JSONException error) {
                throw new IOException("Could not encode the upload transaction.", error);
            }
        }

        static Transaction read(String encoded) throws IOException {
            try {
                JSONObject json = new JSONObject(encoded);
                Transaction transaction = new Transaction(json.getString("tree"),
                    json.getString("ticket"), Uri.parse(json.getString("parent")),
                    Uri.parse(json.getString("temporary")), json.getString("temporaryName"),
                    json.getString("relative"));
                String old = json.getString("old");
                transaction.old = old.isEmpty() ? null : Uri.parse(old);
                transaction.backupName = json.getString("backupName");
                transaction.phase = json.getString("phase");
                transaction.sha256 = json.optString("sha256", "");
                return transaction;
            } catch (JSONException error) {
                throw new IOException("The saved upload recovery record is unreadable.", error);
            }
        }
    }
}
