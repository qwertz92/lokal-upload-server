# Status

Updated: 2026-09-28

Local Upload 0.1.1 is built as a signed Android APK. Android and the desktop
server default to plain IP/port access. Privacy mode is explicitly optional:
Android has a persisted checkbox; the desktop CLI accepts `--private`. Both use
the same HTTP authorization code. Python remains bundled in the Android APK.
The latest published download is currently [0.1.0](https://github.com/qwertz92/lokal-upload-server/releases/tag/v0.1.0);
0.1.1 publication is the remaining delivery step.

| Required outcome | Acceptance evidence | State |
| --- | --- | --- |
| Desktop default and optional Privacy mode | 36 Python tests, including real CLI subprocess uploads and multiple private listeners; desktop subset also passes on Windows | Passed |
| Android upgrade and fresh install use a short URL | In-place 0.1.0 to 0.1.1 upgrade keeps the real folder grant; old APK root 404 becomes new APK root 200. Fresh 0.1.1 install also defaults to normal mode with real picker setup | Passed |
| Normal and private upload flows | 11 HTTP/device checks in each mode, including nested Unicode, exact 12 MiB file hash, overwrite, abort and traversal rejection | Passed |
| Optional mode and lifecycle | Checkbox off by default, disabled during an active run, persisted across force-stop and launcher restart; private old links rejected | Passed |
| Native interface | English and German light/dark, 1.3 font scale; stable mode-switch control bounds and reachable controls | Passed |
| Browser interaction | Windows Chrome form upload, conflict and overwrite with exact device hashes; stable dialog bounds and no JS errors | Passed |
| Interrupted replacement recovery | All 13 native real-provider scenarios rerun on 0.1.1 | Passed |
| Background transfer and explicit stop | Normal-mode 4 MiB upload with screen off has exact saved bytes; Stop closes the listener | Passed |
| Release identity | Version 0.1.1/code 2, same certificate as 0.1.0, valid release signature and 16 KiB APK alignment | Passed |
| Independent review | One bounded Luna review of this change; no unresolved P1/P2 findings | Passed |

Local delivery artifact: `artifacts/LocalUpload-0.1.1.apk` (35,881,685 bytes).
SHA-256: `5f2ff229685d2742bbd0a8548c9b70b7b9ab104ff81bd298ea1155dfbcfd4547`.
Build, device, browser and negative-control receipts are under `artifacts/v0.1.1/`;
generated artifacts remain outside Git. The 36 native libraries are byte-identical
to 0.1.0, whose ELF alignment was checked for both bundled ABIs.
Rebuild and device checks: [android/README.md](../android/README.md).

Six negative controls in disposable copies detected disabled shared GET/POST
guards, broken normal mode, disconnected desktop CLI flags and weakened Android
token validation. The native old/new APK comparison separately covers the
reported default-URL regression.

The existing app signing key is required for future updates. An off-machine
backup of its keystore and password properties has not been verified; see
[release signing](../android/README.md#release-signing).

Java compilation rejects warnings; Android release lint reports no issues.
Gradle 9.8 / AGP 9.4.1 builds with the existing documented Chaquopy deprecation
exception. See [open findings](BUGS.md).

Device verification uses an Android 17 x86-64 emulator with a real document
provider and 16 KiB pages. Physical ARM64 execution, SD cards, router reachability,
older supported Android versions, long suspend periods and vendor battery
policies have not been tested on physical hardware in this session.

Implementation and device checks used Sol; the independent review used Luna.
The lead checked runtime metadata, reran the Python suite and inspected build,
signature, browser/device receipts and rendered screenshots.
