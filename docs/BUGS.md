# Open issues

## 2026-09-28 — P3: upstream Chaquopy Gradle deprecations

Location: Chaquopy 17.0.0 Gradle plugin; details in [Android build instructions](../android/README.md#upstream-gradle-diagnostics).

Trigger: any Android build with the default strict Gradle warning gate. Chaquopy
uses four deprecated Gradle API families, including APIs removed in Gradle 10.
The current Gradle 9.9 build succeeds with the documented `--warning-mode all`
exception; application Java warnings and Android lint remain fatal. The signed
APK is unaffected. Upgrading Gradle to 10 before the plugin is fixed would break
building. Recheck on the next Chaquopy upgrade; app-specific patches or a plugin
fork are not justified for these upstream maintenance warnings.

## 2026-11-23 — P3: Android 8 to 10 may distinguish case where the app does not

Location: `SafStorage.listed()`, `recover()` and `rollback()` in
`android/app/src/main/java/at/farfeleder/localupload/SafStorage.java`.

Trigger: unconfirmed, because only Android 17 was run. Two reviews expect from
reading the platform sources that on Android 8 to 10 the document provider
works on a file system that keeps `Report.pdf` and `report.pdf` apart. The
app's start-up measurement would notice (the log then says `Folder lookups: by
listing`) and compare names without regard to case, as intended. What follows
there, if the expectation holds:

- A folder that already holds both spellings (0.2.0 could create such pairs
  there) refuses uploads of either name with "duplicate filename". Nothing is
  lost.
- An upload that crashed while 0.2.0 or 0.2.1 was installing it, in a folder
  with such a pair, can stop the server from starting after the update: the
  recovery finds two candidates, or one whose content does not match. The way
  out is clearing the app's storage; the files stay.
- In one constructed case a user file is deleted: the crashed upload was
  `report.pdf`, the user removed it before the restart, and `Report.pdf` has
  byte-identical content. Recovery then takes `Report.pdf` for the unfinished
  upload and removes it.

Fix: in listing mode prefer the entry with exactly the requested name, and let
recovery adopt a file as "the upload" only under exactly the recorded
spelling (an installed upload always has it). Effort: one to two hours with
the device run, and it should be checked on an Android 9 or 10 system image
(about 1 GB to download), which also settles whether the expectation is true.

## 2026-11-23 — P4: the start-up measurement can fail where uploads would fail anyway

Location: `SafStorage.measureDirectLookups()`.

Trigger: a destination without any entry that has an ASCII letter (empty, or
only names such as `2024`) on storage that cannot create a file (full card, I/O
error). The measurement creates and deletes an empty hidden probe file there;
if that fails, Start reports the storage error. 0.2.0 started and failed at the
first upload instead. A crash exactly between creating and deleting the probe
leaves one empty hidden file `.localupload-pending-…` behind.

## 2026-11-23 — P4: two of the four case-variant recovery scenarios prove little

Location: `SafStorageRecoveryCheck.java`, scenarios `case_backup_rename_gap`
and `case_install_recorded_gap`.

They pass on the 0.2.0 code as well, because their paths never compare the
recorded spelling with the stored one. The two `case_replacing_*` scenarios do
fail without the fix. Not covered by any scenario: the uniqueness check inside
`sameDocument`, the case-variant branch of `listed()` for a recorded identity,
the stricter guard in `discard()`, and the probe-file branch of the start-up
measurement (the test folder is never empty).

## 2026-11-22 — P3: replacing a file under another spelling renames it

Location: `SafStorage.commit()` and `rollback()`.

Trigger: the folder holds `CaseProbe.txt` and a sender replaces it by uploading
`caseprobe.txt`. The stored file is then called `caseprobe.txt`. If that
replacement fails halfway, the original content is restored, but also under the
sender's spelling. No content is lost; a program that expects the old spelling
on a case-sensitive view of the storage would miss the file. The direct lookup
cannot learn the stored spelling, and listing the folder for every replacement
would bring back the slowdown fixed in 0.2.1.

## 2026-11-22 — P3: names that differ in non-ASCII case or Unicode form

Location: `SafStorage.sameName()` (listing fallback) and `_path_key` in
`upload_server.py`.

Trigger (derived from file-system rules, not reproduced): the app and the
server fold case with the full Unicode rule, so `Ärger.txt` and `ärger.txt`
count as one file. FAT and exFAT cards and the storage view of Android 8 to 10
fold ASCII letters only and keep the two apart. In the listing fallback a
sender who ticks "replace" for `ärger.txt` then replaces `Ärger.txt`, and a
folder that already holds both spellings refuses uploads of that name
("duplicate filename"). The opposite gap exists on Android 11 and newer:
spellings that only Unicode normalisation joins (composed and decomposed `é`,
`ß` and `SS`) are two files for the server and one for the storage, so the
second of two such files in one job is refused after its transfer, or replaces
the first when "replace" was ticked. Only the sender's own files are affected
in that second case.

## 2026-11-22 — P3: a folder rule also changes rows hidden by the filter

Location: conflict dialog in `upload_server.py` (`openConflictDialog`, folder rules).

Trigger: more than eight conflicts, a path filter that hides some files of a
folder, then setting that folder's rule to `replace`. The rule ticks every file
of the folder, including the hidden ones. The summary line shows the totals
("Replace 12 · keep 3 · showing 4 of 15"), so the change is visible but easy to
miss. "Replace all shown" respects the filter; the folder rule deliberately
means the whole folder. Making the rule follow the filter would need a third
state for partly visible folders.

## 2026-11-22 — P4: Android entry point cannot stop idle connections on Windows

Location: `_AndroidHTTPServer.close_clients` in `android/app/src/main/python/android_server.py`.

Trigger: only when the Android module is run on Windows, as the tests do. A
connection that was opened but has sent no request sits in a header read, which
closing the socket from another thread does not interrupt on Windows; `stop()`
then raises "Upload cleanup is still running" after 3 s. Android is Linux, where
the same case stops in under 0.1 s (15 rounds), so no user is affected. A stalled
upload stops cleanly on both systems.

## 2026-11-22 — P4: the Android log repaints unevenly at 500 entries

Location: `LogActivity.render()`.

Trigger: watching the log while many uploads run. With 500 entries and 560
requests in 9.6 s, 47 % of frames were late (median 17 ms, 99th percentile
57 ms); no freeze. The whole text is set again for every change. No measurement
with the earlier limit of 200 exists to compare against.

## 2026-11-22 — P4: a job's title counts files that are dropped as duplicates

Location: `filesLabel` and its callers in the page script of `upload_server.py`.

Trigger: selecting files of which some are already in the queue. The job title
("Files: 5 (a.pdf ...)") is built before those are left out, while the line
below it shows the real count. Cosmetic.

## 2026-11-22 — P4: the status call counts a reused job id per check

Location: `_ServerState` session bookkeeping in `upload_server.py`.

Trigger: only a hand-written client that sends several file-list checks for the
same path under one job id; the page never does. `/api/status` then reports
`"done_files": 0` with `"total_files": 1` after the file is stored.
