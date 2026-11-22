package at.farfeleder.localupload;

import android.content.Context;
import android.net.Uri;
import android.os.Build;
import android.os.storage.StorageManager;
import android.os.storage.StorageVolume;
import android.provider.DocumentsContract;
import android.provider.Settings;

/** Human-readable names for the selected folder and this device, for the screen and the page. */
final class Names {
    static final String SEPARATOR = " › ";

    private Names() {
    }

    /**
     * "Internal storage › Documents › Inbox" for the external-storage provider's tree IDs
     * ("primary:Documents/Inbox"), the volume's own name (or "SD card") plus its path for a
     * removable volume, and the raw tree ID only when it cannot be parsed.
     */
    static String folder(Context context, String treeUri) {
        String readable = readableFolder(context, treeUri);
        if (readable != null) return readable;
        try {
            return DocumentsContract.getTreeDocumentId(Uri.parse(treeUri));
        } catch (IllegalArgumentException | NullPointerException error) {
            return "";
        }
    }

    /** For the browser page: the readable name, or nothing; never a raw document ID. */
    static String folderForPage(Context context, String treeUri) {
        String readable = readableFolder(context, treeUri);
        return readable == null ? "" : readable;
    }

    private static String readableFolder(Context context, String treeUri) {
        String id;
        try {
            id = DocumentsContract.getTreeDocumentId(Uri.parse(treeUri));
        } catch (IllegalArgumentException | NullPointerException error) {
            return null;
        }
        int colon = id.indexOf(':');
        if (colon <= 0 || !SafStorage.pathBasedRoot(id)) {
            return null;
        }
        String volumeId = id.substring(0, colon);
        String volume = "primary".equals(volumeId)
            ? context.getString(R.string.storage_internal) : removableName(context, volumeId);
        String path = id.substring(colon + 1);
        return path.isEmpty() ? volume : volume + SEPARATOR + path.replace("/", SEPARATOR);
    }

    private static String removableName(Context context, String volumeId) {
        StorageManager storage = context.getSystemService(StorageManager.class);
        if (storage != null) {
            for (StorageVolume volume : storage.getStorageVolumes()) {
                if (volumeId.equalsIgnoreCase(volume.getUuid())) {
                    // The system's own localized name, for example "SD card" or "USB drive".
                    String description = volume.getDescription(context);
                    if (description != null && !description.trim().isEmpty()) {
                        return description.trim();
                    }
                }
            }
        }
        return context.getString(R.string.storage_sd_card);
    }

    /** The name the user gave the phone in Settings (readable without a permission), else the model. */
    static String device(Context context) {
        String name = Settings.Global.getString(context.getContentResolver(), Settings.Global.DEVICE_NAME);
        if (name == null || name.trim().isEmpty()) {
            name = Build.MODEL;
        }
        return name == null ? "" : name.trim();
    }
}
