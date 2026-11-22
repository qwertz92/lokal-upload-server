# lokal-upload-server

Send files and whole folders from any browser to another device in the same
network. One Python file, no installation, no internet access needed. An Android
app runs the same server on a phone.

**Android: [Download the signed Local Upload 0.2.0 APK](https://github.com/qwertz92/lokal-upload-server/releases/download/v0.2.0/LocalUpload-0.2.0.apk)**
· [Installation steps](#android-app)
· [SHA-256 checksum](https://github.com/qwertz92/lokal-upload-server/releases/download/v0.2.0/LocalUpload-0.2.0.apk.sha256)
· [Release page](https://github.com/qwertz92/lokal-upload-server/releases/tag/v0.2.0)

The prebuilt APK is already signed and includes Python. Installing it needs no
build tools or account.

## Quick start (desktop)

Copy `upload_server.py` to the machine that should receive the files and run it:

```bash
python upload_server.py
```

(`python3` on most Linux systems.) The server prints the addresses it is
reachable at, for example `http://192.168.1.50:8040`. Open one of them in a
browser on the sending device, choose files or a folder, and they arrive in the
`uploads` folder next to where you started the server. `--upload-dir` selects
another folder.

Until November 2026 the file was called `2025_12_python_upload_webserver.py`;
only the name changed.

## No dependencies

- Python 3.8 or newer and its standard library. No `pip install`.
- Nothing is fetched at runtime either: no CDN, no web fonts, no remote assets.
  The page is self-contained, so the server works on an isolated LAN with no
  internet access at all.
- Check an interpreter before relying on it:

```bash
python upload_server.py --selftest
```

  This starts the server on a temporary port, fetches the page once, and exits.
  It catches breakage that a syntax check cannot, such as a standard-library
  module that a newer Python has removed. The test suite passes on Python 3.8,
  3.10, 3.14 and 3.15 (checked in November 2026).

## What it does

- Files and folders, with the folder structure preserved. Choose them with the
  two buttons or drop them anywhere on the page; choosing is adding, there is
  no second step.
- A queue: jobs upload one after another, can be reordered while they wait, and
  the overall progress stays visible at the top.
- A check before each job: files that already exist on the server are listed,
  and you decide per file or per folder whether to overwrite or keep them. Free
  disk space is checked at the same time.
- Uploads are streamed to disk in 1 MiB pieces, never held in memory, and written
  to a temporary file first. An existing file is only replaced once its
  replacement has arrived completely.
- The server log names every stored file with its size, duration and SHA-256.

### Built for connections that misbehave

A local network is not always as reliable as it looks: a phone's Wi-Fi radio
sleeps when its screen is off, a company security client filters traffic, a
laptop roams between access points. Such a connection often does not fail, it
just goes quiet. The page and the server deal with that on their own:

- **A transfer that stops moving is abandoned and repeated.** After 45 seconds
  without a single byte (`--stall-timeout-sec`) the page gives up on the request
  and sends the file again.
- **A retry replaces the request it gives up on.** The server may not have
  noticed yet that the first attempt is dead. Every request names the browser
  tab it comes from, so the server recognises the retry, stops the stuck
  attempt within about a second and lets the new one through. (Before 0.2.0 the
  retry was turned away with "busy" until the stuck attempt timed out.)
- **A lost answer does not cost a second transfer.** If a file arrived but the
  confirmation got lost, the page asks the server before sending it again.
- **Retries wait longer each time**, three per file by default (`--retry-count`),
  starting at 0.8 s and doubling. A file that still fails gets one more round
  after all others.
- **If the server cannot be reached at all, the queue waits** and checks again
  every few seconds, instead of failing every remaining file. It continues by
  itself when the server is back. Only Abort ends the wait.
- **You see what is happening**: the status line says "Connection lost, retry
  2/3 in 4 s", "No data moving for 12s" or "Server not reachable", and a job
  that ends with failures lists each failed file with its reason. Retry sends
  only those.
- **A file the sending device cannot read is named as such** (moved, deleted,
  locked, or a cloud-only file such as a OneDrive placeholder that is offline),
  instead of surfacing as a vague network error.

## Android app

The Android app requires Android 8 or newer on a 64-bit ARM phone (or an x86-64
emulator) and runs the same upload server on your phone. Python is bundled in
the APK: no terminal, Python installation, account or internet service is needed.

Version 0.2.0 contains the more robust transfer handling described above and
keeps Wi-Fi awake while the server runs. Open the new APK and choose **Update**
without uninstalling; the folder selection and settings are kept.

1. [Download LocalUpload-0.2.0.apk](https://github.com/qwertz92/lokal-upload-server/releases/download/v0.2.0/LocalUpload-0.2.0.apk)
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
   is enabled. Add files or folders in the browser.
5. Received files appear in your selected folder. Stop the server in the app or
   its notification when finished. After the one-time setup, opening the app from
   its icon starts it again.

**Keep the app's screen open during a transfer.** When a phone's screen turns
off, Android saves power on Wi-Fi, and incoming data can then crawl or stall for
half a minute at a time. The app therefore keeps the screen on while the server
runs and its screen is visible; the checkbox on the main screen turns that off.
On Android 8 to 13 the app can additionally keep Wi-Fi fully awake with the
screen off; from Android 14 on, the system only honours that request while the
app is on screen.

Open **Logs** (German: **Protokoll öffnen**) in the app to see stored files,
retries, rejected requests and errors. **Copy** copies the log; **Clear** removes
its entries. The last 500 entries are kept in memory during the app process:
closing the log or stopping the server keeps them, but Android ending the app
process clears them. Individual events do not generate notifications.

In normal mode, any device that can reach the phone's IP and port can upload
into the chosen folder. Optional **Privacy mode** (German: **Privatmodus**)
requires a secret link instead. To change it, stop the server, set the checkbox,
and tap Start. In Privacy mode, each start generates a new link and previous
links stop working. Transport remains HTTP without encryption in both modes: use
a trusted local network. Guest Wi-Fi client isolation can prevent devices from
reaching each other even when both show the same Wi-Fi name.

Uploads stream into a temporary document in the destination folder. An existing
file is kept until its replacement has arrived. The app records replacement
steps so an interrupted transfer can be recovered without deleting the original.
Android does not report free space reliably for every folder, so a full
destination may only be detected during writing. Files live in the chosen shared
folder and remain there after uninstalling the app.

Developer build and signing instructions: [android/README.md](android/README.md).
Verification coverage and device limits: [docs/STATUS.md](docs/STATUS.md).

## Options

| Option | Default | Meaning |
| --- | --- | --- |
| `-d`, `--upload-dir` | `./uploads` | Folder that receives the files |
| `-p`, `--port` | `8040` | Port used with `--host` |
| `--host` | `0.0.0.0` | Address to listen on; repeatable or comma-separated |
| `--listen` | none | Full `HOST:PORT` pair; repeatable, for different ports per address |
| `--private` | off | Require a generated secret link (see [Access](#access)) |
| `--retry-count` | `3` | Automatic retries per file after a connection problem |
| `--retry-delay-ms` | `800` | Delay before the first retry; doubles each time, at most 15 s |
| `--stall-timeout-sec` | `45` | Silence after which the page abandons a request and retries; `0` never |
| `--upload-timeout-sec` | `0` | Hard time limit per file; `0` disables it |
| `--per-client-limit` | `1` | Simultaneous uploads accepted from one IP address |
| `--selftest` | | Start on a temporary port, fetch the page once, exit |

Examples:

```bash
python upload_server.py --upload-dir /srv/incoming --port 9000
python upload_server.py --host 127.0.0.1 --host 192.168.1.50
python upload_server.py --listen 127.0.0.1:8040 --listen 192.168.1.50:9000
```

Defaults live as named constants at the top of `upload_server.py`.

## Access

- Local: `http://localhost:8040`
- LAN: `http://<server-ip>:8040`

To require a secret link instead:

```bash
python upload_server.py --private
```

Use the complete link printed by the server. Restarting generates a new link;
previous links stop working.

## Security

- Intended for networks you trust. There is no login, and transport is plain
  HTTP: anyone on the network who can reach the port can upload, and uploads are
  not encrypted. `--private` hides the address behind a secret link but does not
  encrypt either.
- The server only writes inside its upload folder: paths with `..`, drive
  letters and names Windows cannot store are refused or rewritten.
- Other websites cannot upload through your browser: a request that a foreign
  page makes the browser send is refused (it carries that page's origin, which
  differs from the server's own address). Behind a reverse proxy this requires
  the proxy to pass the `Host` header through unchanged.
- For internet exposure, put it behind a reverse proxy with HTTPS and
  authentication.

## Resolving conflicts

When a job contains files that already exist on the server, a dialog lists them
before anything is sent. `Esc` cancels the job.

- Tick single files to overwrite them, or set a whole folder to `overwrite` or
  `keep` in the folder list (orange marks a folder with both).
- `Overwrite all` applies to the rows currently shown, so it combines with the
  path filter (searching `files`, `folders` or `both`) and the `Selection`
  toggle (`all`, `selected`, `unselected`).
- Files that another upload is writing right now are shown as `in progress`
  and cannot be overwritten.
- Only files you ticked are ever replaced. If another device stores a file
  under the same name after the check, yours is not sent over it; the job
  reports it as `skipped (already on server)`.

Browsers return one folder per folder dialog (only Safari allows several). To
add several folders at once, drop them onto the page together.

## Troubleshooting

- **Uploads are slow, stall, or retry a lot.** The network path between the two
  devices is dropping or delaying data; the status line and the server log say
  what the page did about it. In the log, `Upload aborted: ... reason=timed out
  received=0 B of 14.1 KB after 120.0s` means the request arrived but its
  content never did, and `START ... attempt=2 after=stalled` is the page trying
  again. Things to check, most likely first:
  - Receiving on a phone: keep the app on screen (see [Android app](#android-app)).
  - A company VPN or security client (Zscaler and similar) on the sending
    computer can filter or reroute traffic to local addresses. Try once with it
    paused, or from a device without it.
  - Files in a cloud-synced folder (OneDrive, iCloud Drive) that are not stored
    locally must be downloaded by the sending computer before they can be sent.
    Mark the folder as available offline first.
  - Guest Wi-Fi often blocks devices from reaching each other.
- **Receiving on Android gets slower the fuller the folder is.** The app
  currently needs about half a second per file in an empty reception folder,
  1.5 s with 50 files in it and 4 s with 200 (measured on an emulator,
  [open issue](docs/BUGS.md)). For a job of many files, receive into a new,
  empty subfolder.
- **`Failed to bind ...` or `No server socket could be started`.** The address
  or port is invalid, in use, or blocked. Try `--port 8041`, or look up what
  uses the port (`netstat -ano | findstr :8040` on Windows).
- **"Waiting for another upload from this device".** Another tab or browser on
  the same computer is uploading, and the server accepts one upload per device
  at a time. It continues by itself; `--per-client-limit 2` allows two.
- **`in progress` in the conflict dialog.** Another upload is writing to the same
  target path right now. Wait for it or rename the source.
- **A reverse proxy answers 403 "cross-origin request refused".** The proxy
  rewrites the `Host` header; configure it to pass the original one.

## Tests

```bash
python -m unittest discover -s tests
```

The tests start the real server on a local port and cover exact storage of
uploads, folder structure, conflicts, path rules, stalled and replaced requests,
the status call, the cross-origin rule, Privacy mode and the Android entry point
with a stand-in for its storage.

## Repository layout

- `upload_server.py`: the server and its browser page, in one file on purpose
  (it is the thing you copy to another machine)
- `android/`: the Android app; its build packages `upload_server.py` unchanged
- `tests/`: tests for the server and the Android entry point
- `scripts/android_smoke.py`: end-to-end checks against a running Android app
- `docs/`: [status](docs/STATUS.md), [open issues](docs/BUGS.md),
  [history](docs/HISTORY.md), [ideas for later](docs/ROADMAP.md)
- `legacy/`: two earlier, simpler server variants, kept for reference only
