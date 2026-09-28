# lokal-upload-server

A local Python upload server for LAN usage, with queue support, folder structure preservation, conflict handling, and progress tracking.

**Android: [Download the signed Local Upload 0.1.1 APK](https://github.com/qwertz92/lokal-upload-server/releases/download/v0.1.1/LocalUpload-0.1.1.apk)**
· [Installation steps](#android-app)
· [SHA-256 checksum](https://github.com/qwertz92/lokal-upload-server/releases/download/v0.1.1/LocalUpload-0.1.1.apk.sha256)
· [Release page](https://github.com/qwertz92/lokal-upload-server/releases/tag/v0.1.1)

The prebuilt APK is already signed and includes Python. Installing it needs no
build tools or account.

## Desktop Dependency Model

- No external dependencies
- Uses only Python standard library modules
- No `pip install` required
- Nothing is fetched at runtime either: no CDN, no web fonts, no remote assets.
  Every page is self-contained, so the server works on an isolated LAN with no
  internet access at all.

## Features

- Multi-client operation via `ThreadingHTTPServer`
- Browser queue per client (1 active upload, additional jobs queued)
- File and folder uploads (folder root and structure preserved)
- Preflight checks before upload (existing file conflicts + disk space availability)
- Per-file conflict selection (overwrite/skip)
- Advanced conflict modal with:
  - Search scope (`files`, `folders`, `both`)
  - Selection filter toggle (`all`, `selected`, `unselected`)
  - Folder-level rules (`keep`, `overwrite`, automatic `mixed` state)
  - Collapsible file/folder views and larger/compact modal size
- Always-visible overall progress bar (sticky, stays in view no matter how long the queue gets)
- Byte-based progress, smoothed speed, and ETA
- Total upload time counts only time actually spent uploading, not idle gaps
- Scrollable queue list with the running job pinned to the top
- Reorderable queue: drag a waiting job, or use the up/down/`Upload this next` buttons
- Multiple folders per upload: drop several at once, or pick them one after another
- Drag and drop for files and folders, with folder structure preserved
- Upload percentage in the browser tab title
- Abort support for active uploads
- Retry support for transient upload errors (network/timeout/5xx)
- Server logs with client IP, upload start, per-file start/done, and SHA256
- Streaming upload handling (files are written chunk-by-chunk, not fully buffered in RAM)

## Requirements

- Python `>= 3.8`, no pip and no external packages
- Verified on 3.11, 3.12, 3.13, and 3.14 (Windows and Linux)
- Check your interpreter before relying on it:

```bash
python 2025_12_python_upload_webserver.py --selftest
```

  This starts the server on a temporary port, fetches the page once, and exits.
  It catches breakage that a syntax check cannot, such as a standard-library
  module that a newer Python has removed.

## Android app

The Android app requires Android 8 or newer on a 64-bit ARM phone (or an x86-64
emulator) and runs the same upload server on your phone. Python is bundled in
the APK: no terminal, Python installation, account or internet service is needed.
The desktop scripts remain usable independently.

Version 0.1.1 defaults to a simple IP/port address and adds optional Privacy mode.
To update 0.1.0, open the new APK and choose **Update** without uninstalling; the
existing folder selection is retained.

1. [Download LocalUpload-0.1.1.apk](https://github.com/qwertz92/lokal-upload-server/releases/download/v0.1.1/LocalUpload-0.1.1.apk)
   on the phone and open it to install. This prebuilt APK is already signed; you
   do not need to build it or create an account. If Android blocks the
   installation, allow **Install unknown apps** for the browser or file manager
   opening this APK, install it, then disable that permission again.
2. Open **Local Upload**. Select a local reception folder with **Choose folder**
   (German: **Ordner wählen**). Create a `Local Upload` subfolder in Documents or
   Downloads and confirm **Use this folder**. Android does not allow selecting the
   Downloads root itself. Internal storage and SD cards are supported; cloud
   document providers are deliberately excluded.
3. Allow local-network access if Android asks. Allow notifications to keep the
   server's Stop action visible while another app is open.
4. Connect the sender and phone to the same trusted Wi-Fi. Open the address shown
   by the app in the sender's browser. In normal mode, IP and port are enough,
   for example `http://192.168.1.42:8040/`. Use the complete link when Privacy mode
   is enabled. Copy/share the address from the app or type
   the simple IP/port address. Add files or folders to the browser upload queue.
5. Received files appear in your selected folder. Stop the server in the app or
   its notification when finished. After the one-time setup, opening the app from
   its icon starts it again.

The foreground notification keeps the transfer visible while the app is in the
background. In normal mode, any device that can reach the phone's IP and port
can upload into the chosen folder. Optional **Privacy mode** (German:
**Privatmodus**) requires a secret link instead. To change it, stop the server,
set the checkbox, and tap Start; changing the setting does not start a transfer.
In Privacy mode, each start generates a new link and previous links stop working.
Transport remains HTTP without encryption in both modes: use a trusted local
network. Guest Wi-Fi client isolation can prevent devices from reaching each
other even when both show the same Wi-Fi name.

Uploads stream into a temporary document in the destination folder. An existing
file is kept until its replacement has arrived. The app records replacement
steps so an interrupted transfer can be recovered without deleting the original.
SAF does not expose a reliable free-space value for every folder, so the Android
version may detect a full destination during writing rather than during preflight.
Files live in the chosen shared folder and remain there after uninstalling the app.

Developer build and signing instructions: [android/README.md](android/README.md).
Verification coverage and device limits: [docs/STATUS.md](docs/STATUS.md).

## Start (Windows)

```powershell
python .\2025_12_python_upload_webserver.py
```

## Start (Linux)

```bash
python3 ./2025_12_python_upload_webserver.py
```

If your default Python is 3.9+:

```bash
python ./2025_12_python_upload_webserver.py
```

## CLI Options

- `--host`: host/IP to bind with `--port` (repeatable or comma-separated, default: `0.0.0.0`)
- `-p`, `--port`: port used with `--host` (default: `8040`)
- `--listen`: full bind endpoint `HOST:PORT` (repeatable or comma-separated)
- `--per-client-limit`: maximum number of simultaneous upload requests allowed from one client IP at the same time (default: `1`)
- `--retry-count`: automatic retries per file for transient errors (default: `2`)
- `--retry-delay-ms`: base retry delay in ms, with incremental backoff (default: `800`)
- `--upload-timeout-sec`: per-file upload timeout in seconds (default: `0` = disabled)
- `--selftest`: start on a temporary port, fetch the page once, then exit
- `--private`: optionally require a generated secret link; off by default

Examples:

```powershell
python .\2025_12_python_upload_webserver.py --host 192.168.1.50 --port 9000 --per-client-limit 2
```

```bash
python3 ./2025_12_python_upload_webserver.py --host 192.168.1.50 --port 9000 --per-client-limit 2
```

Multiple interfaces with one port:

```bash
python3 ./2025_12_python_upload_webserver.py --host 127.0.0.1 --host 192.168.1.50 --port 8040
```

Multiple independent sockets (host + port pairs):

```bash
python3 ./2025_12_python_upload_webserver.py --listen 127.0.0.1:8040 --listen 192.168.1.50:9000
```

Custom retry and timeout tuning:

```bash
python3 ./2025_12_python_upload_webserver.py --retry-count 3 --retry-delay-ms 1200 --upload-timeout-sec 1800
```

Disable per-file timeout (large files on slow links):

```bash
python3 ./2025_12_python_upload_webserver.py --upload-timeout-sec 0
```

Only localhost:

```bash
python3 ./2025_12_python_upload_webserver.py --host 127.0.0.1
```

## Access

- Local: `http://localhost:8040`
- LAN: `http://<server-ip>:8040`

The default desktop launch keeps these simple IP/port addresses. To explicitly
enable Privacy mode:

```bash
python3 ./2025_12_python_upload_webserver.py --private
```

Use the complete secret link printed by the server. Restarting generates a new
link; previous links stop working. HTTP remains unencrypted in both modes.

## Usage

- Files panel: choose one or more files and click `Add to queue`
- Folders panel: choose a folder, then choose another one. Each pick is added to
  the staging list, and `Add to queue` turns every staged folder into its own
  queue entry.
  - Why pick them one at a time: Chrome, Edge, and Firefox ignore the `multiple`
    attribute as soon as `webkitdirectory` is set, so their folder dialog returns
    exactly one directory. This is a browser limitation, not an OS one -- the
    Windows, macOS, and GTK pickers all support multi-folder selection, and
    Chromium closed the request as WontFix back in 2013.
  - Safari on macOS is the exception: it honours both attributes, so you can
    Cmd-click several folders in one dialog. The staging list handles that too
    and splits the selection into one entry per folder.
- Drag and drop: drop files and folders anywhere on the page. To upload several
  folders at once, select them with `Ctrl` in your file manager and drag them in
  together. Each dropped folder becomes its own queue entry.
- Reordering the queue: waiting jobs can be dragged, moved with the arrow
  buttons, or promoted with `Upload this next`. The running job keeps its place.
- `Clear finished` removes all done, failed, and cancelled entries at once.
- On conflicts: choose per file whether to overwrite or keep
- Conflict modal:
  - `Overwrite all` applies to current search matches (scope + filter)
  - `Selection` toggle filters visible rows (`all`, `selected`, `unselected`)
  - Folder rules can apply overwrite/keep to full folders at once
- Queue jobs run automatically one after another

## Conflict Modal Quick Guide

- Search scope:
  - `files`: search by file path
  - `folders`: search by folder path
  - `both`: match either file or folder
- Selection toggle:
  - `all`: show all matching rows
  - `selected`: show only rows currently marked for overwrite
  - `unselected`: show only rows currently set to keep
- Folder rule colors:
  - green row = full folder overwrite
  - orange row = mixed state in that folder
  - neutral row = keep

## Terms

- `Preflight`: a short check phase before real upload starts. The server validates paths, detects existing/in-progress conflicts, and verifies disk space.
- `Preflight limit` (`MAX_PREFLIGHT_BYTES`): maximum size of the preflight JSON request body. Default is `20 MiB`, and this is metadata only (file paths + file sizes), not file content.
- Practical meaning of `20 MiB`: it limits how much file-list metadata can be sent in one preflight call. In normal usage this is very large and usually enough for many thousands of files, depending on average path length.
- `Per-client limit`: the server-side concurrency cap per source IP address. Example: with `--per-client-limit 4`, one client IP can run up to 4 uploads in parallel.

## Security Notes

- This project is intended for internal networks.
- There is no authentication and no TLS by default. Optional Privacy mode requires
  the secret link, but does not encrypt uploads.
- For internet exposure, add proper hardening first (reverse proxy + HTTPS + auth).

## Streaming Details

- Upload stream chunk size: `8 MiB` (`BUFFER_SIZE = 8 * 1024 * 1024`)
- Preflight request body limit: `20 MiB` (`MAX_PREFLIGHT_BYTES = 20 * 1024 * 1024`)
- Files are streamed directly to disk and are not kept fully in RAM

## Configuration Defaults In Code

- Runtime defaults are centralized at the top of `2025_12_python_upload_webserver.py`.
- You can change defaults there if you want project-wide behavior without passing CLI flags every time.
- Recommended: prefer CLI options for temporary/per-run changes, and edit code defaults only for permanent defaults.

## Troubleshooting

- `Failed to bind ...` or `No server socket could be started`:
  - The selected host/port is invalid, already in use, or blocked by firewall.
  - Try another port, for example `--port 8041`, or check port usage (`netstat -ano | findstr :8040` on Windows).
- HTTP `429` (`Upload already active (use queue)`):
  - The client has reached `--per-client-limit`.
  - Increase limit if needed, for example `--per-client-limit 2`, or wait until one upload finishes.
- Upload timeout:
  - The per-file timeout was reached (`--upload-timeout-sec`, default `0` = disabled).
  - Increase timeout for slow/unstable links, for example `--upload-timeout-sec 1800`.
  - To disable timeout entirely, use `--upload-timeout-sec 0`.
- `in_progress` conflict in preflight:
  - Another active/queued upload is already targeting the same destination path.
  - Wait for the other upload, cancel it, or rename the source file/folder.

## Progress And Timing

- The overall progress bar sits above the queue and sticks to the top of the
  window, so it stays visible while the queue scrolls.
- `upload time` is the time genuinely spent transferring, summed over every job
  in the session. Idle time between uploads is not counted, so adding a job
  hours later does not inherit those hours.
- Speed is smoothed with an exponential moving average, and the ETA is withheld
  for the first few seconds until the measurement is meaningful.
- The bar holds just short of full until the server has acknowledged every file,
  because the browser reports bytes handed to the socket, not bytes written.

## Tests

```bash
python -m unittest discover -s tests
```

Covers path sanitisation, folder-structure uploads, conflict handling, the
request-body rules (`Content-Length`, chunked encoding), and temp-file cleanup.

## Repository Layout

- `2025_12_python_upload_webserver.py`: current main server
- `tests/`: unit tests for the main server and the easy server
- `uploads/`: upload destination folder
- `python_bootstrap_server.py`, `python_latest_easy_server.py`: older variants
