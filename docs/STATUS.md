# Status

Updated: 2026-09-29

Local Upload 0.1.2 adds native live activity and an in-app log. The latest 200
entries are kept in process memory, with timestamps and Copy/Clear actions.
They survive closing the log and stopping the server, but not process exit.
HTTP requests represent observed activity, not continuously connected clients.
Individual log events do not generate notifications. Normal mode still uses a
plain IP/port URL; Privacy mode remains optional on Android and desktop.

Release candidate: `artifacts/LocalUpload-0.1.2.apk`, 35,883,789 bytes.
SHA-256: `56a4bb38778ce497af1c635e855518406b74b39a905520c6b8dcf243be720c26`.
Local acceptance is complete; public delivery is being verified separately.

| Required outcome | Acceptance evidence | State |
| --- | --- | --- |
| Shared server logging and safe callbacks | 42 Python tests, rerun by the lead and against the staged backend commit; 9 disposable negative controls | Passed |
| Bounded, safe native log | Standalone Java checks plus 7 negative controls for bounds, redaction, sanitization, concurrency and stale-run rejection | Passed |
| Android update preserves configuration | In-place 0.1.1 to 0.1.2 upgrade retained the real folder grant and Privacy choice; corrected APKs also installed in place | Passed |
| Normal and private uploads | 11 HTTP/device checks in each mode, including exact 12 MiB hash, Unicode paths, conflict, overwrite and aborted replacement | Passed |
| Native log scrolling | Real 200-event overflow, retained middle-row comparison and 10-second drag during 8 uploads; original APKs fail and final APK passes | Passed |
| Notification behavior and capability redaction | One foreground notification record before/after traffic; private capability absent from actual log text | Passed |
| Interrupted replacement recovery | All 13 native real-provider scenarios report PASS and failures=0 | Passed |
| Log actions and lifecycle | Actual Copy/paste, empty-state Clear, background return and token-free log text | Passed |
| Background transfer and interface | Exact 4 MiB screen-off upload; German light/dark at 1.3 font scale with stable controls | Passed |
| Browser interaction | Windows Chrome upload/conflict/overwrite, exact device hashes and no JavaScript errors | Passed |
| Release identity | Version 0.1.2/code 3, original release certificate, valid signature and 16 KiB APK alignment | Passed |
| Independent review | Four bounded review rounds; device-reproduced scroll findings fixed, no demonstrated P1/P2 left in the final reviewed code | Passed |

Build, device and negative-control receipts are under `artifacts/v0.1.2/` and
remain outside Git. All 36 native libraries are byte-identical to 0.1.1.
The app still embeds the authoritative Python server; no second HTTP/browser
implementation is maintained. Rebuild and device checks: [android/README.md](../android/README.md).

The existing app signing key is required for future updates. An off-machine
backup of its keystore and password properties has not been verified; see
[release signing](../android/README.md#release-signing).

Java compilation rejects warnings; Android release lint reports no issues.
Gradle 9.8 / AGP 9.4.1 builds with the documented Chaquopy 17 deprecation
exception. The latest stable build-tool versions were checked on 2026-09-29.
See [open findings](BUGS.md).

Device verification uses an Android 17 x86-64 emulator with a real document
provider and 16 KiB pages. Physical ARM64 execution, SD cards, router reachability,
older supported Android versions, long suspend periods and vendor battery
policies have not been tested on physical hardware in this session.

Implementation and the initial build/device checks used Sol; independent reviews
used Luna. Luna continued final device validation after Sol reached model
capacity. The lead verified runtime metadata, test outputs, screenshots, artifact
identity and delivery.
