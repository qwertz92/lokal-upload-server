# Android development

To install the already signed APK, use the [phone installation instructions](../README.md#android-app).
Building and signing are only needed for development or a new release.

The native Java app embeds CPython 3.14 through Chaquopy 17.0.0. Its Gradle copy
task packages the repository's main Python server as `upload_server.py`; generated
copies belong only in `app/build/`. The app supports Android 8 or newer (API 26),
ARM64 phones and x86-64 emulators, and targets Android 17 (API 37).

## Build

Install JDK 17 or newer, Python 3.14, and Android SDK platform 37 plus build tools
37.0.0. Point `ANDROID_HOME` at the SDK, or put `sdk.dir=/absolute/sdk/path` in
ignored `local.properties`. Gradle 9.8.0 is downloaded by the checksum-verified
wrapper. AGP 9.4.1 is the newest stable release checked on 2026-09-28 and has built
the signed APK successfully. Chaquopy documents compatibility through AGP 9.2;
the newer version is selected based on this project's measured build result.

Run from this directory (fish):

```fish
./check.sh
timeout 1200 ./gradlew --no-daemon --warning-mode all lintDebug assembleDebug
```

The standalone Java checks reject stale start/stop callbacks, duplicate start
commands, and unsafe SAF paths. `check.sh` compiles and runs their `main` methods
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
set -gx LOCAL_UPLOAD_SIGNING_PROPERTIES /mnt/c/Users/thoma/.android/keystores/local-upload-server/signing.properties
timeout 1200 ./gradlew --no-daemon --warning-mode all lintRelease assembleRelease
```

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

- `android_server.start(SafStorage, token, 8040)` returns the actual listening port.
- `android_server.stop()` closes the listener and finishes active requests.
- `SafStorage(Context, persistedTreeUri).validate()` checks the selected folder.

The service enters the foreground before initializing Python, acquires a timed
CPU wake lock renewed while active, and cleans up on explicit stop or destruction.
Launching from the app icon starts a previously configured server; an ordinary
activity resume does not restart it. The notification's stop action uses
the same shutdown path. The service is deliberately non-sticky and has no boot
receiver, so Android process termination does not silently reopen access.

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
