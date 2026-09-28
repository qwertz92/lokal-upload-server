# Status

Updated: 2026-09-28

Local Upload 0.1.0 is built as a signed Android APK. Python is included; the app
receives uploads into a user-selected local folder. The desktop server remains
the authoritative HTTP/browser source and works independently.

| Required outcome | Acceptance evidence | State |
| --- | --- | --- |
| Existing desktop server stays functional | 30 Python regression tests, including injected Android storage | Passed |
| Android launch without installing Python | Signed release installed and launched on Android 17, x86-64, 16 KiB pages | Passed |
| One-time folder setup, then launch by icon | Actual system picker, denied/regranted network permission, persisted folder across APK upgrade | Passed setup; lifecycle checks finishing |
| Nested files, conflicts, streaming and abort safety | 11 actual HTTP/device checks; exact SHA-256 for a 12 MiB upload | Passed initial APK; final repeat pending |
| Browser interaction | Windows Chrome form upload, duplicate conflict and confirmed overwrite; saved-byte hashes; stable dialog bounds; no JS errors | Passed |
| Interrupted replacement recovery | 13 native real-provider scenarios; old APK fails six, corrected APK passes all 13 | Passed |
| Screen-off operation and explicit stop | Foreground service/device lifecycle checks | Pending |
| Access limited to per-run link | Missing/wrong capability rejected on supported GET/POST endpoints | Passed; rotation check finishing |
| Installable delivery | Release signature and installed/delivery APK SHA-256 match | Passed |
| Independent review | Two rounds with Luna; reviewed fixes have no unresolved P1/P2 findings | Passed |

Delivery: `artifacts/LocalUpload-0.1.0.apk` (35,881,289 bytes), SHA-256
`458f4a20c1341f6f52ef06853b7fea742429a3bb5d5df9daa79164d05e8bcf3c`.
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
