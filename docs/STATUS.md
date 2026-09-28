# Status

Updated: 2026-09-28

Local Upload 0.1.0 is built as a signed Android APK. Python is included; the app
receives uploads into a user-selected local folder. The desktop server remains
the authoritative HTTP/browser source and works independently.

| Required outcome | Acceptance evidence | State |
| --- | --- | --- |
| Existing desktop server stays functional | 30 Python regression tests, including injected Android storage | Passed |
| Android launch without installing Python | Signed release installed and launched on Android 17, x86-64, 16 KiB pages | Passed |
| One-time folder setup, then launch by icon | Actual system picker, denied/regranted network permission, persisted folder across APK upgrade | Passed |
| Nested files, conflicts, streaming and abort safety | 11 actual HTTP/device checks; exact SHA-256 for a 12 MiB upload | Passed on final APK |
| Native interface | German light/dark and 1.3 font scale; stable running/stopped control bounds; folder/share targets; content clipped outside system bars | Passed |
| Browser interaction | Windows Chrome form upload, duplicate conflict and confirmed overwrite; saved-byte hashes; stable dialog bounds; no JS errors | Passed |
| Interrupted replacement recovery | 13 native real-provider scenarios; old APK fails six, corrected APK passes all 13 | Passed |
| Screen-off operation and explicit stop | 4 MiB upload with screen asleep before/after; app and notification Stop close the listener; Recents does not restart it | Passed |
| Access limited to per-run link | Missing/wrong capability rejected on supported GET/POST endpoints; previous link returns 404 after icon restart | Passed |
| Installable delivery | Release signature and installed/delivery APK SHA-256 match | Passed |
| Independent review | Two rounds with Luna; reviewed fixes have no unresolved P1/P2 findings | Passed |

Delivery: `artifacts/LocalUpload-0.1.0.apk` (35,881,289 bytes), SHA-256
`f75071382453aba310eb7666ae9f986e85c48341274d9c5cce3cfc467b026ab9`.
The APK and raw device/build receipts are generated local artifacts, excluded from
Git. Rebuild instructions and reproducible checks are in [android/README.md](../android/README.md).

Java compilation rejects warnings; Android release lint reports no issues.
Gradle 9.8 / AGP 9.4.1 builds successfully with the explicitly documented
Chaquopy deprecation exception. See [open findings](BUGS.md).

No physical phone is connected. Emulator checks do not establish physical ARM64
execution, SD-card behavior, router reachability, long-duration suspend behavior
or vendor battery policies. The APK includes ARM64 libraries, but that ABI and
older supported Android versions have not been run on a device in this session.
Both bundled ABIs pass 16 KiB ELF and APK alignment checks.

Verification used GPT-6 Sol workers and GPT-6 Luna reviewers; child runtime
metadata was checked. The lead independently reran the Python and final APK
HTTP tests, inspected recovery receipts, signatures, hashes and UI screenshots.

The temporary counterfactual APK `android/build/initial-release.apk`
(35,864,881 bytes) was removed after the old/new recovery check. The final APK,
instrumentation APK and test receipts remain in ignored build/artifact folders.
