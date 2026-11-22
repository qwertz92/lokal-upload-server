# Open issues

## 2026-09-28 — P3: upstream Chaquopy Gradle deprecations

Location: Chaquopy 17.0.0 Gradle plugin; details in [Android build instructions](../android/README.md#upstream-gradle-diagnostics).

Trigger: any Android build with the default strict Gradle warning gate. Chaquopy
uses four deprecated Gradle API families, including APIs removed in Gradle 10.
The current Gradle 9.8 build succeeds with the documented `--warning-mode all`
exception; application Java warnings and Android lint remain fatal. The signed
APK is unaffected. Upgrading Gradle to 10 before the plugin is fixed would break
building. Recheck on the next Chaquopy upgrade; app-specific patches or a plugin
fork are not justified for these upstream maintenance warnings.

## 2026-11-22 — P3: a re-pointed domain passes the cross-origin check

Location: `SimpleUploadServer._same_origin` in `upload_server.py`.

Trigger: DNS rebinding. A website the user has open is served from a domain that
is afterwards pointed at the server's LAN address. Its requests then carry an
`Origin` equal to the `Host` they are sent to, which is exactly what the check
compares, so they are accepted (reproduced with hand-built headers:
`Host: evil.example:PORT` plus `Origin: http://evil.example:PORT` returns 200; not
attempted with a real browser, where Chrome's private-network rules may stop it).
The effect is an upload into the folder by a site outside the network, in normal
mode only: `--private` and Android's Privacy mode are unaffected because the
secret link is unknown to that site. Closing it means accepting only `Host`
values the server knows as its own, which would also turn away people who reach
it through a router-assigned name such as `phone.fritz.box`; that trade-off is
undecided. Effort: about an hour including an opt-out.

## 2026-11-22 — P4: Android entry point cannot stop idle connections on Windows

Location: `_AndroidHTTPServer.close_clients` in `android/app/src/main/python/android_server.py`.

Trigger: only when the Android module is run on Windows, as the tests do. A
connection that was opened but has sent no request sits in a header read, which
closing the socket from another thread does not interrupt on Windows; `stop()`
then raises "Upload cleanup is still running" after 3 s. Android is Linux, where
the same case stops in under 0.1 s (15 rounds), so no user is affected. A stalled
upload stops cleanly on both systems.

## 2026-11-22 — P2: Android uploads slow down as the destination folder fills

Location: `SafStorage.child()` in `android/app/src/main/java/at/farfeleder/localupload/SafStorage.java`.

Trigger: every upload into a folder that already holds files. Each path lookup
asks the document provider for the complete list of the parent folder and
searches it by name, and one upload makes several lookups. Measured on the
Android 17 emulator with a 15 KB file (median of 8, `artifacts/v0.2.0/timing-receipt.json`):
0.5 s into an empty folder, 1.5 s with 50 files in it, 4.1 s with 200. A job of
100 small files into one folder therefore takes minutes on a perfect network.
Present since 0.1.0; unrelated to the stalled-connection fixes of 0.2.0. A fix
(one listing per upload, or addressing a child directly where the provider's
document ids allow it) changes the storage code, so the 13 recovery scenarios
must be rerun on a device. Effort: one to two hours including that run.

## 2026-11-22 — P3: lint gate fails on a newer Gradle release

Location: `android/gradle/wrapper/gradle-wrapper.properties`.

Trigger: `./gradlew lintRelease`. Its only finding is that Gradle 9.9.2
(released 2026-11-19) is newer than the wrapper's 9.8.0; application code has no
lint finding and Java still compiles with warnings as errors. The 0.2.0 APK was
built with 9.8.0, like 0.1.2. Upgrading needs the new distribution checksum in
the wrapper and one build plus device run, because Chaquopy 17 is untested on
9.9 (see the Chaquopy entry above). Not done on 2026-11-22: the agent session's
permission system refused the wrapper change. Effort: about 30 minutes.

## 2026-11-22 — P3: Android answers 500 for a name that differs only in case

Location: `SafStorage.child()` (exact name comparison) and `android_server.start()`,
which never sets the shared server's case rule.

Trigger: uploading `caseprobe.txt` into a folder that holds `CaseProbe.txt`.
Android's shared storage treats the two as one file, while the app compares
names exactly. Reproduced on the Android 17 emulator with 0.2.0
(`artifacts/v0.2.0/caseprobe-release.json`): the check before the job reports no
conflict, the provider stores the upload as `caseprobe (1).txt`, the app notices
the changed name, removes it again and answers `500 Storage operation failed`,
with `on_exists=skip` and with `overwrite` alike. The existing file keeps its
content and nothing is left behind. The page treats 500 as worth repeating, so
it sends the file up to eight times before listing it as failed with that vague
message. Expected: a conflict the user can decide, as on the desktop. Belongs
with the lookup rework in the P2 entry above.

## 2026-11-22 — P4: a path reservation is released by job, not by request

Location: `_ServerState.reserve_path` and `release_path` in `upload_server.py`.

Trigger (derived, not reproduced): a job's retry arrives from another IP address
(the sender roamed or a VPN reconnected) while its stalled first request is still
open. Both hold the same reservation; when the old request ends, the reservation
of the running one is released with it, so a third job could write the same path
at the same time. Each writer uses its own temporary file and the last complete
one wins, so no partial file can result.

## 2026-11-22 — P4: the Android log repaints unevenly at 500 entries

Location: `LogActivity.render()`.

Trigger: watching the log while many uploads run. With 500 entries and 560
requests in 9.6 s, 47 % of frames were late (median 17 ms, 99th percentile
57 ms); no freeze. The whole text is set again for every change. No measurement
with the earlier limit of 200 exists to compare against.
