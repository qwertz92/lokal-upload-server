# Status

Updated: 2026-09-28

Android implementation in progress. The desktop server remains the authoritative
HTTP and browser UI source. Android embeds Python using Chaquopy, exposes a native
start/stop screen and receives files into a user-selected local folder via SAF.

| Required outcome | Acceptance evidence | State |
| --- | --- | --- |
| Existing desktop server stays functional | Complete Python regression suite | Pending |
| Android launch without installing Python | Install and launch signed APK | Pending |
| One-time folder setup, then launch by icon | Real Android picker and persisted grant | Pending |
| Nested files, conflicts, streaming and abort safety | Android HTTP upload plus saved-byte hashes | Pending |
| Screen-off operation and explicit stop | Foreground service/device lifecycle checks | Pending |
| Access limited to per-run link | Unauthorized HTTP requests rejected | Pending |
| Installable delivery | Release signature and APK checksum | Pending |
| Independent review | Concrete failing scenarios; no unresolved P1/P2 | Pending |

No physical phone is currently connected. Emulator checks cannot establish the
behavior of the user's Wi-Fi router, physical phone or vendor battery policies.
