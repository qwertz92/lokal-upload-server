# Status

Updated: 2026-11-23

Version 0.2.1 removes the slowdown of the Android app in full folders, makes
it ask before replacing a file whose name differs only in case, lets the server
answer only under host names it can trust, and reworks what a person sees: the
page says where files go, speaks German or English and has a shorter conflict
dialog; the app's main screen starts with Start, Stop and the address. The two
unmaintained older server variants are gone. What changed and what it taught:
[history](HISTORY.md).

Published: [release 0.2.1](https://github.com/qwertz92/lokal-upload-server/releases/tag/v0.2.1).
Download: [LocalUpload-0.2.1.apk](https://github.com/qwertz92/lokal-upload-server/releases/download/v0.2.1/LocalUpload-0.2.1.apk),
35,917,641 bytes; also retained at `artifacts/LocalUpload-0.2.1.apk`.
SHA-256: `da55a77fd9082ec94353bc2e6683e4abd70e90fcdf7d4262aca5ed0ace8d4a9a`,
signed with the original release certificate
(`65aa570406522f3ea7ca5920ee45c21392b58573a0597894b202c7f9ea373e5f`).

| Required outcome | Acceptance evidence | State |
| --- | --- | --- |
| Server rules: host names, counted path reservations, byte counter, reserved names, destination text | 92 Python tests (81 in 0.2.0); green on Windows (Python 3.15) and on WSL with 3.14, 3.10 and 3.8 | Passed |
| Android upload time independent of folder size | 15 KB file, median of 8, Android 17 emulator: 0.12 s into an empty folder, 0.13 s with 50 files, 0.14 s with 200, 0.15 s with 1000 (0.2.0: 0.27, 0.80, 2.84 and 11.2 s) | Passed |
| Android lookup mode is measured, not assumed | App log `Folder lookups: direct` on Android 17; the recovery run fails if the device does not choose direct or the forced run does not list | Passed on Android 17 only |
| Interrupted replacement recovery | 17 scenarios (13 from 0.1.0, 4 new with a case-variant name) plus the mode check, each in direct and in forced listing mode: 36 of 36. Without the recovery fix exactly the two cross-mode scenarios failed; the other two new ones pass on the old code too | Passed |
| Names that differ only in case on Android | `caseprobe.txt` into a folder holding `CaseProbe.txt`: the check reports it as existing, `skip` answers 409 and keeps the file, a ticked replacement stores the new content as the only file | Passed |
| Android update keeps configuration | In-place 0.2.0 to 0.2.1 kept the folder grant, the Privacy choice and a switched-off keep-screen-on | Passed |
| Normal and private uploads on the device | 15 checks per mode on the final APK | Passed |
| Page: both languages, destination line, conflict dialog | Real browser at phone and desktop width in German and English; on the device the line reads "... saved in Internal storage › Documents › LocalUploadTest-v020 on sdk_gphone16k_x86_64" and `?lang=de` switches the page | Passed in Chromium |
| App main screen | 32 screenshots: English and German, light and dark, font scale 1.0 and 1.3, running and stopped | Passed on the emulator |
| Release identity | Version 0.2.1/code 5, original certificate, v2 signature, 16 KiB alignment; the server compiled into the APK equals `upload_server.py` of the release commit | Passed |
| Android lint and compile | Gradle 9.9.2: lint "No issues found", Java with warnings as errors | Passed |
| Independent review | Page: one breaker round, no P1 or P2. Android storage: one fresh-context review (no P1, one P2 as a hypothesis for Android 8 to 10, now decided by the start-up measurement) and one breaker check of the fixes (no P1 or P2). Smaller findings are fixed or listed in the [open issues](BUGS.md) | Passed |

Not verified:

- No physical phone and no Android version other than 17. On Android 8 to 10
  the app is expected to choose the slower listing mode; that it does, and that
  names are then handled correctly, is unchecked (see [open issues](BUGS.md)).
- SD cards, ARM64 execution, vendor battery policies and real Wi-Fi power
  saving, as in 0.2.0.
- The page was exercised in Chromium only; Firefox and Safari were not
  available. A browser whose first language is German was simulated with
  `?lang=de`, not with a German browser profile.
- macOS and a sending computer behind a company proxy were not available.
- The incident that started 0.2.0 (36 small files taking 18 minutes) was not
  reproduced; both of its amplifiers on the receiving side, the stalled-request
  handling and the per-file cost in a full folder, are fixed.

Build, device and review receipts are under `artifacts/v0.2.1/` and remain
outside Git. The app still embeds the authoritative Python server; no second
HTTP or browser implementation is maintained. Rebuild and device checks:
[android/README.md](../android/README.md).

The existing app signing key is required for future updates. An off-machine
backup of its keystore and password properties has not been verified; see
[release signing](../android/README.md#release-signing).

Device verification uses an Android 17 x86-64 emulator with a real document
provider and 16 KiB pages.

The lead on this round was Claude Fable 5.2 (server changes, integration,
triage of review findings); the Android changes and the storage reviews ran on
Opus, the page rework, tests and the page breaker on Sonnet. The lead verified
test outputs, receipts, artifact identity and delivery.
