# History

## 2026-09-29 — Android activity log

Published `v0.1.2` with its original-key signed APK and checksum; anonymous public downloads match the tested bytes. Added a bounded in-app activity log with a live preview, copy/clear actions and no per-event notifications. Shared server events now distinguish a disconnected response after a successful commit from an aborted upload; a failing log callback cannot interrupt file storage.

The first review/device round reproduced both a reader-position reset and failed bottom-following when log text changed. Scroll checks must compare a retained visible event, not an already-evicted oldest entry; stable control rectangles alone do not prove stable content. Further device checks showed that deferring refreshes during a drag was insufficient while the TextView retained native text selection. Removing that competing selection behavior fixed the unchanged drag/upload reproduction; the explicit Copy button still copies the full log.

## 2026-09-28 — Optional Privacy mode on Android and desktop

Made plain IP/port access the Android default and added an explicit persisted Privacy checkbox; the desktop CLI gets the same optional protection through `--private` and a shared HTTP guard. An in-place 0.1.0-to-0.1.1 upgrade preserves the folder grant and changes the unauthenticated root from 404 to the upload page. Security options must not silently replace the requested simple LAN workflow; verified normal/private uploads, six negative controls and one review round cover this correction. Published `v0.1.1` with its signed APK and checksum; an anonymous download matched the tested bytes.

## 2026-09-28 — Android 0.1.0 publication

Published the signed, tested APK and its SHA-256 checksum with the `v0.1.0` release. A successful local build is separate from a published download; delivery checks must verify the public assets. Moving release signing to another machine requires the existing app key and password properties, plus explicit custody and backup status. An off-machine key backup has not been verified.

## 2026-09-28 — Android implementation and review

Added a native Android launcher/service around the existing Python server, with a persisted local-folder grant, per-run capability URL and externally signed APK. Stream directly into the selected folder; keep the server/browser source shared with desktop.

Review round 1 found a rename/journal crash window in the local Android document provider. Its document IDs change on rename: recovery must identify completed uploads by their existing digest and protect restored originals from stale path-based IDs. A native negative control reproduced six failures in the old APK, including two cases where a stale final-path URI deleted restored original bytes. Regression checks exercise those provider transitions rather than assuming a stable URI.

An upload write-failure regression showed that received-byte accounting must advance before writing to disk, otherwise draining the failed request waits for bytes already consumed. Counterfactual tests also check authorization, active-request shutdown, request bounds, storage initialization and the Java/Python digest handoff.

Round 2 found no remaining P1/P2 in the corrected storage and native app. All 13 recovery scenarios pass on the real provider; old/new APKs used the same runner.

Final device checks confirmed icon start, explicit stop, screen-off transfer and stable control positions. A one-line ScrollView clipping correction keeps large-font scrolled text out of system bars; before/after screenshots provide the negative control.
