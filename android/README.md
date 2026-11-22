# Android development

To install the already signed APK, use the [phone installation instructions](../README.md#android-app).
Building and signing are only needed for development or a new release.

The native Java app embeds CPython 3.14 through Chaquopy 17.0.0. Its Gradle copy
task packages the repository's main Python server, `../upload_server.py`, under the
same name; generated copies belong only in `app/build/`. The Android wrapper
`app/src/main/python/android_server.py` imports it and adds only SAF storage, the
connection limit and the log sink. The app supports Android 8 or newer (API 26),
ARM64 phones and x86-64 emulators, and targets Android 17 (API 37).

## Build

Install JDK 17 or newer, Python 3.14, and Android SDK platform 37 plus build tools
37.0.0. Point `ANDROID_HOME` at the SDK, or put `sdk.dir=/absolute/sdk/path` in
ignored `local.properties`. Gradle 9.8.0 is downloaded by the checksum-verified
wrapper. AGP 9.4.1 is the newest stable release checked on 2026-09-29 and has built
the signed APK successfully. Chaquopy documents compatibility through AGP 9.2;
the newer version is selected based on this project's measured build result.

Run from this directory (fish):

```fish
./check.sh
timeout 1200 ./gradlew --no-daemon --warning-mode all lintDebug assembleDebug
```

The standalone Java checks reject stale start/stop callbacks, duplicate start
commands, unsafe SAF paths, and log-buffer bounds, sanitization, redaction and
concurrency. `check.sh` compiles and runs their `main` methods
with assertions enabled; Gradle's test task does not run these checks. Android lint
and Java compiler warnings fail the build. A debug
APK is for development only; delivered APKs must use the release key.

## Release signing

Keep a signing properties file outside this repository, containing:

```properties
storeFile=/absolute/path/to/local-upload-server.p12
storePassword=your-existing-store-password
keyAlias=your-existing-key-alias
keyPassword=your-existing-key-password
```

Use the existing app-specific PKCS#12 (`.p12`) project key. Do not generate a
replacement when setting up another machine: Android rejects updates signed by
a different key, and losing this key prevents updates to existing installations.
The release build fails if its signing properties are missing or incomplete; it
never falls back to the debug key. The public release certificate's SHA-256 is:

```text
65aa570406522f3ea7ca5920ee45c21392b58573a0597894b202c7f9ea373e5f
```

An off-machine backup has not been verified. Back up both the existing keystore
and its password properties to a secure location outside the build machine.
On another machine, restore both, update `storeFile` for the restored location,
and compare the resulting APK's certificate fingerprint before publishing:

```fish
timeout 30 "$ANDROID_HOME/build-tools/37.0.0/apksigner" verify --print-certs app/build/outputs/apk/release/app-release.apk
```

The reported certificate SHA-256 must match the value above. On HomeBase:

```fish
set -gx JAVA_HOME /usr/lib/jvm/java-21-openjdk
set -gx LC_ALL C.UTF-8
set -gx LOCAL_UPLOAD_SIGNING_PROPERTIES /mnt/c/Users/thoma/.android/keystores/local-upload-server/signing.properties
timeout 1200 ./gradlew --no-daemon --warning-mode all lintRelease assembleRelease
```

Gradle must run under a UTF-8 locale. Chaquopy builds a Python 3.14 virtual
environment whose `bin/` contains the non-ASCII `𝜋thon` link; under the POSIX
locale the JVM's file-name encoding is ASCII and `extractReleasePythonBuildPackages`
fails with "Failed to create MD5 hash for file". The build machine's WSL has only the
`C.UTF-8` locale, so `LC_ALL=C.UTF-8` is set explicitly (measured 2026-11-22).

Alternatively pass `-PlocalUploadSigningProperties=/absolute/signing.properties`.
The signed APK is generated at `app/build/outputs/apk/release/app-release.apk`.

## Upstream Gradle diagnostics

The project keeps Gradle's default gate at `warning.mode=fail`. The explicit
`--warning-mode all` in the artifact commands permits the currently unavoidable
Chaquopy 17 build-plugin deprecations to be reported while app Java warnings and
Android lint still fail the build. Measured on 2026-09-28:

- Multi-string dependency declarations and execution-time `Task.project` access
  are scheduled for removal in Gradle 10.
- `Configuration.setVisible` and configuration-time process execution are
  scheduled for removal in Gradle 11.

Gradle 9.4.1, AGP's older recommended baseline, also fails the default gate on
Chaquopy's dependency declarations, so downgrading does not resolve the finding.
Keep these diagnostics visible and recheck when upgrading Chaquopy; do not move to
Gradle 10 until its plugin has migrated these APIs. No app lint baseline is used.

## Runtime contract

`UploadService` serializes every Python operation on one process-wide executor:

- `android_server.start(SafStorage, token, 8040, logSink)` returns the actual listening port;
  Java `null` / Python `None` selects normal mode, a nonempty token selects Privacy mode.
- `android_server.stop()` closes the listener and finishes active requests.
- `SafStorage(Context, persistedTreeUri).validate()` checks the selected folder.

The optional fourth argument is a per-run Java sink exposing `log(String)`.
HTTP worker threads send events to a bounded in-memory log (500 entries, up to
1024 message characters each); foreground UI listeners coalesce updates. The
capability and URLs are redacted before display/copy. Log callbacks must never
change an HTTP response or interrupt storage work. Logs survive server stop and
activity recreation, but not app-process termination; there is no disk log.

`android_server.py` serves at most `MAX_CONNECTIONS = 24` connections at once and
refuses further ones (logged at most once per 5 seconds). Request bodies use the
desktop server's shared 120-second idle timeout (`BODY_IDLE_TIMEOUT_SEC`); the
former Android-only 30-second body timeout no longer exists.

The service enters the foreground before initializing Python, acquires a timed
CPU wake lock renewed while active, and a non-reference-counted Wi-Fi lock in
`WIFI_MODE_FULL_HIGH_PERF` mode. Both locks are released together on explicit stop,
start failure or destruction. With the screen off, Android may put the Wi-Fi radio
into power-save mode, which can stall transfers for many seconds. The
high-performance mode is the only one documented as effective with the screen off
(API 26-33). Android 14 (API 34) deprecated it and automatically replaces it with
`WIFI_MODE_FULL_LOW_LATENCY`, which is active only while the screen is on and the
app is in the foreground. The deprecated constant is therefore requested in one
helper with a narrow `@SuppressWarnings("deprecation")`.

Because a Wi-Fi lock only helps with the screen on from Android 14, the main screen
has a **Keep screen on while the server runs** checkbox (preference
`keep_screen_on`, default on). While the server is starting or running and the
option is on, the main and log activities set `FLAG_KEEP_SCREEN_ON` on their
window; otherwise they clear it. Unlike Privacy mode, it may be changed while the
server runs and takes effect immediately. The flag affects only the app's own
visible window: it does not keep the screen on after the user leaves the app.
Launching from the app icon starts a previously configured server; an ordinary
activity resume does not restart it. The notification's stop action uses
the same shutdown path. The service is deliberately non-sticky and has no boot
receiver, so Android process termination does not silently reopen access.

Normal mode is the default and publishes `http://IP:port/`, matching the desktop
server. The optional native Privacy mode checkbox persists the user's choice and
is disabled during starting, running and stopping. Stop, change the checkbox,
then Start to use the other mode; changing the preference never restarts the
server. Only Privacy mode generates a fresh token and includes it in the URL.
Both modes use unencrypted HTTP and require a trusted local network.

Network callbacks publish only current Wi-Fi/Ethernet IPv4 addresses; mobile and
VPN interfaces are excluded. Android 17 local-network permission is checked before
starting, and notification permission is requested once on Android 13 or newer.
There are no broad storage permissions. See the root README for phone setup.

## Verified platform references

- [Chaquopy compatibility and Python versions](https://chaquo.com/chaquopy/doc/current/versions.html)
- [Chaquopy Gradle configuration](https://chaquo.com/chaquopy/doc/current/android.html)
- [AGP 9.4 compatibility](https://developer.android.com/build/releases/agp-9-4-0-release-notes)
- [Android local-network permission](https://developer.android.com/privacy-and-security/local-network-permission)
- [Connected-device foreground services](https://developer.android.com/develop/background-work/services/fgs/service-types#connected-device)

## Device regression checks

After installing the signed app, choose a **disposable local folder**, grant the
requested permissions, and start the server. For HTTP checks, run from the
repository root with the phone's complete address and the selected folder's
ADB-visible path:

```fish
timeout 180 python scripts/android_smoke.py --base-url "$UPLOAD_URL" --adb "$ADB" --serial "$DEVICE_SERIAL" --device-dir "$DEVICE_FOLDER"
```

The command above checks normal mode with `http://host:port/`. For Privacy mode,
add `--privacy-mode` and supply the complete `http://host:port/token/` URL; this
also verifies rejection of missing and incorrect tokens on GET and POST routes.

The script checks saved bytes through ADB, including a 12 MiB upload, conflicts,
traversal rejection, unauthorized requests and aborted replacement. It removes
only its own uniquely named test files. With the Windows emulator, run Windows
Python when using `adb.exe forward`; its localhost belongs to Windows, not WSL.

To exercise rename/recovery windows on the real document provider, build and
install the instrumentation APK using the same external signing configuration:

```fish
timeout 1200 ./gradlew --no-daemon --warning-mode all assembleReleaseAndroidTest
timeout 30 "$ADB" -s "$DEVICE_SERIAL" install -r app/build/outputs/apk/androidTest/release/app-release-androidTest.apk
timeout 15 "$ADB" -s "$DEVICE_SERIAL" shell am force-stop at.farfeleder.localupload
timeout 120 "$ADB" -s "$DEVICE_SERIAL" shell am instrument -w -r at.farfeleder.localupload.test/at.farfeleder.localupload.SafStorageRecoveryCheck
```

Run those commands from `android/`. For a Windows `adb.exe` invoked from WSL,
pass the APK's Windows path instead. All 13 scenarios must report `PASS` and the
instrumentation result must contain `failures=0`; `adb`'s exit status alone does
not indicate test success. The runner creates disposable subfolders in the
persisted tree and exercises the installed app's recovery code. It does not
simulate hardware power-loss durability or replace physical-device testing.

For the activity-log UI, first upgrade the previous signed APK in place and check
that its folder grant and Privacy mode setting survive. With **Logs** open, verify
request, upload success, rejection and abort events, then background/reopen the
activity and stop the server: existing entries must remain. Copy must match the
log, Clear must empty it, and individual events must not post notifications.

Fill the log past 500 entries using actual requests. Without touching the view,
it must follow the newest event. Scroll to a middle event that will remain in the
buffer, append a few more events, and compare that same visible event and its
vertical position before/after. Repeat while dragging. Comparing only the fixed
button bounds or an oldest event that was legitimately evicted misses the scroll
regression. Use distinct rows (uploads with different names): identical rows hide a
shift. A pixel comparison of the log viewport, excluding the scrollbar, also catches
small drifts; it found a drift of several pixels per update in the 0.1.2 offset
arithmetic, which subtracted evicted height instead of re-measuring the top line.
Check German/light/dark and large text with the final signed APK.
