# Status

Updated: 2026-11-22

Version 0.2.0 makes the server and its page survive connections that stall,
reset or lose an answer, and reworks the page. The server file is now
`upload_server.py`; the two older variants moved to `legacy/`. The Android app
additionally holds a Wi-Fi lock, keeps its screen on while the server runs
(optional, on by default) and keeps 500 log entries. What triggered the work and
what it taught: [history](HISTORY.md).

Published: [release 0.2.0](https://github.com/qwertz92/lokal-upload-server/releases/tag/v0.2.0).
Download: [LocalUpload-0.2.0.apk](https://github.com/qwertz92/lokal-upload-server/releases/download/v0.2.0/LocalUpload-0.2.0.apk),
35,900,709 bytes; also retained at `artifacts/LocalUpload-0.2.0.apk`.
SHA-256: `84c4614010f1b9811fb0be97d29d48abe7d8490f0db18322b76ba02e0c757b87`,
signed with the original release certificate
(`65aa570406522f3ea7ca5920ee45c21392b58573a0597894b202c7f9ea373e5f`).
The anonymous public APK and its [checksum file](https://github.com/qwertz92/lokal-upload-server/releases/download/v0.2.0/LocalUpload-0.2.0.apk.sha256)
were downloaded and match the tested artifact byte-for-byte.

| Required outcome | Acceptance evidence | State |
| --- | --- | --- |
| Stalled, flowing and replaced requests, lost answers, status ownership, release order | 81 Python tests (42 before); green on Windows (Python 3.15), WSL (3.14, six runs in a row) and Python 3.8; 75 of them also on 3.10 before the last six were added. Each new test was shown to fail against the previous behaviour | Passed |
| Page under faults | Real browser against a fault-injecting server: lost answer recovered through the status call, stalled request replaced, resets retried, unreachable server waited out, stop after five failures and the order of Retry, Abort in every phase; no page errors | Passed |
| No unasked overwrite | Browser: a file stored by another client between the check and the upload kept its content and was reported as skipped; a ticked file was replaced | Passed |
| Page layout and touch | Measured at 320 and 375 px: no horizontal overflow, every button at least 44 px on a touch device, notes wrap | Passed |
| Android update keeps configuration | In-place 0.1.2 to 0.2.0 kept the folder grant and the Privacy choice; keep-screen-on defaults to on | Passed |
| Wi-Fi lock and keep-screen-on | `dumpsys wifi`: lock held while running, released on Stop; `dumpsys window`: flag follows server state and checkbox in both activities | Passed on the emulator |
| Normal and private uploads on the device | 14 checks per mode on the final APK, including the status call, the cross-origin rule and a stalled upload replaced by its retry | Passed |
| Native log | 500 entries kept; the viewport stays pixel-identical while older entries are read and new ones arrive | Passed on the build before the final one (Java unchanged since) |
| Release identity | Version 0.2.0/code 4, original certificate, v2 signature, 16 KiB alignment; bytecode in the APK equals the compiled working-tree sources | Passed |
| Android lint | One finding: Gradle 9.9.2 exists, the wrapper uses 9.8.0 | Open, see [open issues](BUGS.md) |
| Interrupted replacement recovery | The 13 native scenarios were not rerun; `SafStorage.java` is unchanged since 0.1.2 | Not rerun |
| Independent review | Three breaker rounds and one final fresh-context review; the final state has no known P1 or P2 in the changed code, smaller findings are fixed or listed in the open issues | Passed |

Open: receiving on Android slows down as the destination folder fills (P2,
present since 0.1.0), and a name that differs only in case from an existing file
is answered with 500 there. Both are in [open issues](BUGS.md) with measurements.

Not verified:

- The incident itself was not reproduced. Whether the phone's Wi-Fi power
  saving or the sending laptop's security client stalled the connection is
  unknown; the server-side amplification of such stalls is what was fixed.
- No physical phone: real Wi-Fi power saving, the effect of the Wi-Fi lock with
  the screen off (by Android's documentation none from Android 14 on), vendor
  battery policies, SD cards and ARM64 execution are untested.
- macOS and a sending computer behind a company proxy were not available.
- The status check after a "busy" answer in the page was only checked for
  syntax, not exercised in a browser.

Build, device and review receipts are under `artifacts/v0.2.0/` and remain
outside Git. The app still embeds the authoritative Python server; no second
HTTP or browser implementation is maintained. Rebuild and device checks:
[android/README.md](../android/README.md).

The existing app signing key is required for future updates. An off-machine
backup of its keystore and password properties has not been verified; see
[release signing](../android/README.md#release-signing).

Device verification uses an Android 17 x86-64 emulator with a real document
provider and 16 KiB pages.

The lead on this round was Claude Fable 5.2 (analysis, server and page, fixes,
integration); the Android changes and the final review ran on Opus, tests and
breaker rounds on Sonnet. The lead verified test outputs, receipts, artifact
identity and delivery.
