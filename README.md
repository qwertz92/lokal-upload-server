# lokal-upload-server

A local Python upload server for LAN usage, with queue support, folder structure preservation, conflict handling, and progress tracking.

## Dependency Model

- No external dependencies
- Uses only Python standard library modules
- No `pip install` required

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
- Byte-based progress, speed, and ETA
- Overall progress for the running queue
- Abort support for active uploads
- Retry support for transient upload errors (network/timeout/5xx)
- Server logs with client IP, upload start, per-file start/done, and SHA256
- Streaming upload handling (files are written chunk-by-chunk, not fully buffered in RAM)

## Requirements

- Python `>= 3.9`

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

## Usage

- Files panel: choose one or more files and click `Add to queue`
- Folder panel: choose a folder and click `Add to queue`
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
- There is no authentication and no TLS by default.
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

## Repository Layout

- `2025_12_python_upload_webserver.py`: current main server
- `uploads/`: upload destination folder
- `python_bootstrap_server.py`, `python_latest_easy_server.py`, `python3-8_server.py`: older variants
