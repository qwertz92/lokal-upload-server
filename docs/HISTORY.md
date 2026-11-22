# History

## 2026-11-22 — Stalled connections, a rebuilt page and Android 0.2.0

Published `v0.2.0` with its original-key signed APK and checksum; the anonymous public download matches the tested bytes.

Trigger: 36 files, 1.1 MB in total, sent from a managed Windows laptop to the Android app took 18 minutes and most of them failed. The app's log showed request headers arriving and the bodies not following. The server waited 30 s for each body while the browser gave up after 6 to 9 s, and the browser's own retries were answered `429 busy`, because the abandoned request still held that address's single upload slot. With two retries per file, a stall of a few seconds became a failed file. What stalled the connection (the phone's Wi-Fi power saving with the screen off, or the laptop's proxy client) cannot be decided from that log; the new log lines (`received=X of Y after Zs`, `attempt=N after=reason`) are there to decide it next time.

Lessons:

- A per-address limit must never make a client wait for its own dead request. Each browser tab now names itself (`client=`), its retry replaces its stalled predecessor, and bodies are read in 0.5 s polls so that a replaced or stopped request ends within a second.
- Closing a socket from another thread wakes a blocked `recv` on Linux but not on Windows. Two of the 42 old tests had always errored on Windows for this reason; polling removed the dependency.
- A lost answer is not a failed upload. The page asks `/api/status` before it sends a file again, and the server counts a repeated file once.
- `WIFI_MODE_FULL_HIGH_PERF` is replaced on Android 14 and newer by the low-latency lock, which only works while the app is on screen with the display on (Android reference, read 2026-11-22). A Wi-Fi lock therefore cannot keep a phone with a dark screen responsive; the app holds the lock and additionally keeps the screen on while the server runs, which the user can switch off.
- A transfer rate that is only ever averaged decays towards zero during a stall and turns the remaining time into hundreds of days. No estimate is shown while nothing moves.

Review: round 1 (one breaker on the page, one on the server) confirmed two P2 defects and a dozen smaller ones. Abort did not cancel a status request that was in flight and the file was still sent afterwards; Retry after a cancelled "file exists" dialog overwrote the existing files without asking, which the old page did as well. Round 2 on the fixes found no P1 or P2 and four smaller defects, among them a private-mode path that was parsed a second time without the check added in round 1: a fix that validates input must be applied to every place that parses it again. Round 3 on those fixes found that `A.txt` and `a.txt` only counted as one file on Windows; the server now measures the upload folder at start. The final fresh-context review found no P1 or P2 and eight smaller points, five fixed the same day: a stop or a replacing retry was only noticed while a body read was waiting, never while data kept flowing; files that did not exist when a job was checked were still sent as "overwrite", so a file stored by another device in the meantime was replaced unasked; a user file named like the server's temporary files would have been deleted by the start-up sweep. Checks placed inside a waiting loop are skipped by the busy path: put them where every call passes.

Android: the first 0.2.0 build showed that the log view of 0.1.2 drifted by the font's top padding on every update while older entries were being read; anchoring the top line by its text position instead of subtracting heights fixed it. Building needs a UTF-8 locale (`LC_ALL=C.UTF-8`), because Chaquopy's Python 3.14 environment contains a file with a non-ASCII name. Measuring uploads on the emulator also showed that each one lists the whole destination folder several times (see [open issues](BUGS.md)).

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
