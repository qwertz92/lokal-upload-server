# lokal-upload-server

A local Python upload server for LAN usage, with queue support, folder structure preservation, conflict handling, and progress tracking.

## Features

- Multi-client operation via `ThreadingHTTPServer`
- Browser queue per client (1 active upload, additional jobs queued)
- File and folder uploads (folder root and structure preserved)
- Preflight checks before upload:
- Existing file conflicts
- Disk space availability
- Per-file conflict selection (overwrite/skip)
- Byte-based progress, speed, and ETA
- Overall progress for the running queue
- Abort support for active uploads
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

- `-p`, `--port`: choose server port (default: `8040`)
- `--per-client-limit`: max simultaneous uploads per client IP (default: `1`)

Examples:

```powershell
python .\2025_12_python_upload_webserver.py --port 9000 --per-client-limit 2
```

```bash
python3 ./2025_12_python_upload_webserver.py --port 9000 --per-client-limit 2
```

## Access

- Local: `http://localhost:8040`
- LAN: `http://<server-ip>:8040`

## Usage

- Files panel: choose one or more files and click `Add to queue`
- Folder panel: choose a folder and click `Add to queue`
- On conflicts: choose per file whether to overwrite or keep
- Queue jobs run automatically one after another

## Security Notes

- This project is intended for internal networks.
- There is no authentication and no TLS by default.
- For internet exposure, add proper hardening first (reverse proxy + HTTPS + auth).

## Repository Layout

- `2025_12_python_upload_webserver.py`: current main server
- `uploads/`: upload destination folder
- `python_bootstrap_server.py`, `python_latest_easy_server.py`, `python3-8_server.py`: older variants
