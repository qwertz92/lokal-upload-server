from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse
import argparse
import ctypes
import datetime as _dt
import hashlib
import json
import os
import platform
import re
import shutil
import socket
import tempfile
import threading
import time

UPLOAD_ROOT = Path("uploads").resolve()
BUFFER_SIZE = 8 * 1024 * 1024
MAX_PREFLIGHT_BYTES = 20 * 1024 * 1024
DISK_SPACE_FACTOR = 1.1

_INVALID_NAME_RE = re.compile(r'[<>:"|?*\x00-\x1f]')
_RESERVED_NAMES = {
    "CON",
    "PRN",
    "AUX",
    "NUL",
    *(f"COM{i}" for i in range(1, 10)),
    *(f"LPT{i}" for i in range(1, 10)),
}


def _enable_windows_ansi() -> bool:
    if os.name != "nt":
        return True
    try:
        kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
        handle = kernel32.GetStdHandle(-11)  # STD_OUTPUT_HANDLE
        mode = ctypes.c_uint32()
        if kernel32.GetConsoleMode(handle, ctypes.byref(mode)) == 0:
            return False
        ENABLE_VIRTUAL_TERMINAL_PROCESSING = 0x0004
        return (
            kernel32.SetConsoleMode(
                handle, mode.value | ENABLE_VIRTUAL_TERMINAL_PROCESSING
            )
            != 0
        )
    except Exception:
        return False


_ANSI_ENABLED = _enable_windows_ansi() and os.environ.get("NO_COLOR") is None
_ANSI_RESET = "\x1b[0m"
_ANSI_GREEN = "\x1b[32m"
_ANSI_YELLOW = "\x1b[33m"
_ANSI_RED = "\x1b[31m"


def _c(text: str, code: str) -> str:
    if not _ANSI_ENABLED:
        return text
    return f"{code}{text}{_ANSI_RESET}"


def _ts() -> str:
    return _dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def _format_bytes(num: int) -> str:
    value = float(num)
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if value < 1024.0:
            return f"{value:.1f} {unit}"
        value /= 1024.0
    return f"{value:.1f} PB"


def _get_local_ipv4_addresses() -> list[str]:
    addresses: set[str] = set()
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            ip = info[4][0]
            if ip and not ip.startswith("127."):
                addresses.add(ip)
    except Exception:
        pass
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            if ip and not ip.startswith("127."):
                addresses.add(ip)
        finally:
            s.close()
    except Exception:
        pass
    return sorted(addresses)


def _ensure_disk_space(required_bytes: int) -> None:
    free = shutil.disk_usage(UPLOAD_ROOT).free
    required = int(required_bytes * DISK_SPACE_FACTOR)
    if free < required:
        raise ValueError(
            f"Not enough disk space. Required: {_format_bytes(required)}, "
            f"Available: {_format_bytes(free)}"
        )


def _sanitize_name_part(name: str) -> str:
    name = _INVALID_NAME_RE.sub("_", name)
    name = name.rstrip(" .")
    if not name:
        name = "_"
    if name.upper() in _RESERVED_NAMES:
        name = f"_{name}_"
    return name


def _sanitize_rel_path(raw: str) -> str:
    raw = (raw or "").replace("\\", "/").strip()
    raw = raw.lstrip("/")
    raw = re.sub(r"^[A-Za-z]:", "", raw)
    parts: list[str] = []
    for part in raw.split("/"):
        if part in ("", "."):
            continue
        if part == "..":
            raise ValueError("Invalid path (..)")
        parts.append(_sanitize_name_part(part))
    if not parts:
        raise ValueError("Empty file path")
    return "/".join(parts)


def _path_key(rel_path: str) -> str:
    # Windows file system is typically case-insensitive.
    return rel_path.lower() if os.name == "nt" else rel_path


class _ServerState:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._seen_clients: set[str] = set()
        self._sessions: dict[str, dict] = {}
        self._ip_semaphores: dict[str, threading.Semaphore] = {}
        self._reserved_paths: dict[str, str] = {}
        self._per_ip_limit = 1

    def set_per_ip_limit(self, limit: int) -> None:
        safe_limit = max(1, int(limit))
        with self._lock:
            self._per_ip_limit = safe_limit
            # Recreate lazily with the new limit.
            self._ip_semaphores = {}

    def note_client(self, ip: str) -> bool:
        with self._lock:
            is_new = ip not in self._seen_clients
            if is_new:
                self._seen_clients.add(ip)
        return is_new

    def get_ip_semaphore(self, ip: str) -> threading.Semaphore:
        with self._lock:
            sem = self._ip_semaphores.get(ip)
            if sem is None:
                sem = threading.Semaphore(self._per_ip_limit)
                self._ip_semaphores[ip] = sem
            return sem

    def upsert_session(
        self,
        upload_id: str,
        *,
        client_ip: str,
        user_agent: str | None,
        total_files: int,
        total_bytes: int,
    ) -> None:
        with self._lock:
            self._sessions[upload_id] = {
                "upload_id": upload_id,
                "client_ip": client_ip,
                "user_agent": user_agent,
                "total_files": total_files,
                "total_bytes": total_bytes,
                "created_at": time.time(),
                "started_logged": False,
                "files_done": 0,
                "bytes_done": 0,
            }

    def get_session(self, upload_id: str) -> dict | None:
        with self._lock:
            return self._sessions.get(upload_id)

    def mark_started_logged(self, upload_id: str) -> None:
        with self._lock:
            session = self._sessions.get(upload_id)
            if session:
                session["started_logged"] = True

    def bump_done(self, upload_id: str, *, bytes_written: int) -> tuple[int, int, int]:
        with self._lock:
            session = self._sessions.get(upload_id)
            if not session:
                return (0, 0, 0)
            session["files_done"] += 1
            session["bytes_done"] += bytes_written
            return (
                int(session["files_done"]),
                int(session["total_files"]),
                int(session["total_bytes"]),
            )

    def maybe_cleanup(self, upload_id: str) -> None:
        with self._lock:
            session = self._sessions.get(upload_id)
            if not session:
                return
            if int(session.get("files_done", 0)) >= int(session.get("total_files", 0)) > 0:
                self._sessions.pop(upload_id, None)

    def is_path_reserved(self, rel_path: str, *, exclude_upload_id: str | None = None) -> bool:
        key = _path_key(rel_path)
        with self._lock:
            owner = self._reserved_paths.get(key)
            if not owner:
                return False
            if exclude_upload_id and owner == exclude_upload_id:
                return False
            return True

    def reserve_path(self, rel_path: str, upload_id: str) -> bool:
        key = _path_key(rel_path)
        with self._lock:
            owner = self._reserved_paths.get(key)
            if owner and owner != upload_id:
                return False
            self._reserved_paths[key] = upload_id
            return True

    def release_path(self, rel_path: str, upload_id: str) -> None:
        key = _path_key(rel_path)
        with self._lock:
            owner = self._reserved_paths.get(key)
            if owner == upload_id:
                self._reserved_paths.pop(key, None)


STATE = _ServerState()


class SimpleUploadServer(BaseHTTPRequestHandler):
    server_version = "SimpleUploadServer/2026.01"

    def log_message(self, format: str, *args) -> None:  # noqa: A002
        return

    def _log(self, message: str, *, color: str | None = None) -> None:
        prefix = f"[{_ts()}] "
        text = prefix + message
        if color:
            text = _c(text, color)
        print(text, flush=True)

    def _client_ip(self) -> str:
        return (self.client_address[0] if self.client_address else "unknown") or "unknown"

    def _note_client_if_new(self) -> None:
        ip = self._client_ip()
        ua = self.headers.get("User-Agent")
        if STATE.note_client(ip):
            details = f"New client: ip={ip}"
            if ua:
                details += f" ua={ua}"
            self._log(details, color=_ANSI_GREEN)

    def _send_bytes(self, status: int, body: bytes, content_type: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        try:
            self.wfile.write(body)
        except BrokenPipeError:
            pass

    def _send_json(self, status: int, payload: dict) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self._send_bytes(status, body, "application/json; charset=utf-8")

    def _read_body(self, *, max_bytes: int) -> bytes:
        length = int(self.headers.get("Content-Length", "0") or "0")
        if length <= 0:
            return b""
        if length > max_bytes:
            raise ValueError("Request too large")
        data = self.rfile.read(length)
        if len(data) != length:
            raise ConnectionError("Client disconnected")
        return data

    def do_GET(self) -> None:
        self._note_client_if_new()
        if urlparse(self.path).path != "/":
            self._send_json(404, {"ok": False, "error": "not_found"})
            return
        self._send_bytes(200, _HTML.encode("utf-8"), "text/html; charset=utf-8")

    def do_POST(self) -> None:
        self._note_client_if_new()
        path = urlparse(self.path).path
        if path == "/api/preflight":
            self._handle_preflight()
            return
        if path == "/api/upload":
            self._handle_upload()
            return
        self._send_json(404, {"ok": False, "error": "not_found"})

    def _handle_preflight(self) -> None:
        try:
            UPLOAD_ROOT.mkdir(parents=True, exist_ok=True)

            body = self._read_body(max_bytes=MAX_PREFLIGHT_BYTES)
            data = json.loads(body.decode("utf-8")) if body else {}

            upload_id = str(data.get("upload_id") or "").strip()
            items = data.get("items") or []
            if not upload_id or not isinstance(upload_id, str):
                raise ValueError("upload_id fehlt")
            if not re.fullmatch(r"[A-Za-z0-9._-]{6,80}", upload_id):
                raise ValueError("invalid upload_id")
            if not isinstance(items, list) or not items:
                raise ValueError("items fehlt/leer")

            conflicts: list[dict] = []
            total_bytes = 0
            total_files = 0
            seen_paths: set[str] = set()

            for item in items:
                if not isinstance(item, dict):
                    continue
                raw_path = str(item.get("path") or "")
                size = int(item.get("size") or 0)
                rel_path = _sanitize_rel_path(raw_path)
                path_key = _path_key(rel_path)
                if path_key in seen_paths:
                    conflicts.append(
                        {
                            "path": raw_path,
                            "rel_path": rel_path,
                            "reason": "duplicate_in_request",
                        }
                    )
                    continue
                seen_paths.add(path_key)
                total_bytes += max(0, size)
                total_files += 1

                dest_path = (UPLOAD_ROOT / rel_path).resolve()
                if UPLOAD_ROOT not in dest_path.parents and dest_path != UPLOAD_ROOT:
                    raise ValueError("invalid target path")
                if dest_path.exists():
                    conflicts.append(
                        {"path": raw_path, "rel_path": rel_path, "reason": "exists"}
                    )
                elif STATE.is_path_reserved(rel_path, exclude_upload_id=upload_id):
                    conflicts.append(
                        {
                            "path": raw_path,
                            "rel_path": rel_path,
                            "reason": "in_progress",
                        }
                    )

            _ensure_disk_space(total_bytes)

            STATE.upsert_session(
                upload_id,
                client_ip=self._client_ip(),
                user_agent=self.headers.get("User-Agent"),
                total_files=total_files,
                total_bytes=total_bytes,
            )

            self._send_json(
                200,
                {
                    "ok": True,
                    "upload_id": upload_id,
                    "total_files": total_files,
                    "total_bytes": total_bytes,
                    "conflicts": conflicts,
                },
            )
        except Exception as e:
            self._send_json(400, {"ok": False, "error": str(e)})

    def _handle_upload(self) -> None:
        ip = self._client_ip()
        sem = STATE.get_ip_semaphore(ip)
        if not sem.acquire(blocking=False):
            self._send_json(429, {"ok": False, "error": "Upload already active (use queue)"})
            return

        temp_path: Path | None = None
        path_reserved = False
        upload_id = ""
        rel_path = ""
        try:
            parsed = urlparse(self.path)
            qs = parse_qs(parsed.query)

            upload_id = (qs.get("upload_id") or [""])[0].strip()
            raw_path = (qs.get("path") or [""])[0]
            on_exists = ((qs.get("on_exists") or ["skip"])[0] or "skip").strip().lower()
            file_index = int((qs.get("file_index") or ["0"])[0] or 0)

            UPLOAD_ROOT.mkdir(parents=True, exist_ok=True)

            if not upload_id or not re.fullmatch(r"[A-Za-z0-9._-]{6,80}", upload_id):
                raise ValueError("invalid upload_id")
            rel_path = _sanitize_rel_path(raw_path)
            if on_exists not in {"skip", "overwrite"}:
                on_exists = "skip"

            content_length = int(self.headers.get("Content-Length", "0") or "0")
            if content_length < 0:
                raise ValueError("invalid Content-Length")
            _ensure_disk_space(content_length)

            session = STATE.get_session(upload_id)
            if session and not session.get("started_logged"):
                ua = session.get("user_agent")
                ua_part = f" ua={ua}" if ua else ""
                self._log(
                    f"Upload started: id={upload_id} ip={ip} "
                    f"files={session.get('total_files')} total={_format_bytes(int(session.get('total_bytes') or 0))}{ua_part}",
                    color=_ANSI_YELLOW,
                )
                STATE.mark_started_logged(upload_id)

            dest_path = (UPLOAD_ROOT / rel_path).resolve()
            if UPLOAD_ROOT not in dest_path.parents and dest_path != UPLOAD_ROOT:
                raise ValueError("invalid target path")
            dest_path.parent.mkdir(parents=True, exist_ok=True)

            if not STATE.reserve_path(rel_path, upload_id):
                self._send_json(
                    409,
                    {"ok": False, "error": "in_progress", "rel_path": rel_path},
                )
                return
            path_reserved = True

            if dest_path.exists() and dest_path.is_dir():
                raise ValueError("target path is a directory")

            if dest_path.exists() and on_exists == "skip":
                self._send_json(
                    409,
                    {"ok": False, "error": "exists", "rel_path": rel_path},
                )
                return

            self._log(
                f"START id={upload_id} file[{file_index}] ip={ip} path={rel_path} size={_format_bytes(content_length)}"
            )

            fd, tmp = tempfile.mkstemp(prefix=".upload_tmp_", dir=str(dest_path.parent))
            temp_path = Path(tmp)
            hasher = hashlib.sha256()
            bytes_written = 0
            with os.fdopen(fd, "wb") as f:
                remaining = content_length
                while remaining > 0:
                    chunk = self.rfile.read(min(BUFFER_SIZE, remaining))
                    if not chunk:
                        raise ConnectionError("Client disconnected (abort?)")
                    f.write(chunk)
                    hasher.update(chunk)
                    bytes_written += len(chunk)
                    remaining -= len(chunk)

            digest = hasher.hexdigest()
            os.replace(str(temp_path), str(dest_path))
            temp_path = None

            done_files, total_files, total_bytes = STATE.bump_done(
                upload_id, bytes_written=bytes_written
            )
            self._log(
                f"DONE  id={upload_id} file[{file_index}] ip={ip} path={rel_path} "
                f"bytes={_format_bytes(bytes_written)} sha256={digest} ({done_files}/{total_files})"
                if total_files > 0
                else f"DONE  id={upload_id} file[{file_index}] ip={ip} path={rel_path} "
                f"bytes={_format_bytes(bytes_written)} sha256={digest}"
            )

            self._send_json(
                200,
                {
                    "ok": True,
                    "upload_id": upload_id,
                    "rel_path": rel_path,
                    "bytes": bytes_written,
                    "sha256": digest,
                    "done_files": done_files,
                    "total_files": total_files,
                    "total_bytes": total_bytes,
                },
            )
            STATE.maybe_cleanup(upload_id)
        except (ConnectionError, BrokenPipeError) as e:
            if temp_path:
                try:
                    temp_path.unlink(missing_ok=True)  # type: ignore[call-arg]
                except Exception:
                    pass
            reason = str(e) or "Client disconnected"
            self._log(
                f"Upload aborted: id={upload_id or '?'} ip={ip} path={rel_path or '?'} reason={reason}",
                color=_ANSI_YELLOW,
            )
        except Exception as e:
            if temp_path:
                try:
                    temp_path.unlink(missing_ok=True)  # type: ignore[call-arg]
                except Exception:
                    pass
            self._log(f"Upload error: ip={ip} err={e}", color=_ANSI_RED)
            try:
                self._send_json(500, {"ok": False, "error": str(e)})
            except BrokenPipeError:
                pass
        finally:
            if path_reserved and rel_path and upload_id:
                STATE.release_path(rel_path, upload_id)
            try:
                sem.release()
            except ValueError:
                pass


_HTML = r"""<!doctype html>
<html lang="de">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Lokaler Upload Server</title>
  <style>
    :root {
      --bg: #0b1220;
      --panel: #10192b;
      --text: #e8eefc;
      --muted: #aab6d3;
      --border: rgba(255,255,255,.12);
      --green: #22c55e;
      --red: #ef4444;
      --yellow: #f59e0b;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      font-family: system-ui, -apple-system, Segoe UI, Roboto, Arial, sans-serif;
      background: radial-gradient(1200px 700px at 20% 0%, #1b2a57 0%, var(--bg) 55%) fixed;
      color: var(--text);
    }
    .wrap {
      max-width: 980px;
      margin: 0 auto;
      padding: 22px 16px 60px;
    }
    h1 { margin: 0 0 6px; font-size: 26px; }
    h2 { margin: 0 0 10px; font-size: 16px; }
    .hint { color: var(--muted); font-size: 14px; }
    .grid {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 14px;
      margin-top: 18px;
    }
    @media (max-width: 840px) { .grid { grid-template-columns: 1fr; } }
    .card {
      background: rgba(255,255,255,.04);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 14px;
      box-shadow: 0 12px 28px rgba(0,0,0,.25);
    }
    .row { display: flex; gap: 10px; align-items: center; margin-top: 10px; }
    input[type="file"] {
      width: 100%;
      padding: 10px;
      border-radius: 10px;
      border: 1px dashed rgba(255,255,255,.22);
      background: rgba(255,255,255,.04);
      color: var(--text);
    }
    input[type="file"].warn {
      border-color: rgba(245, 158, 11, .9);
      box-shadow: 0 0 0 2px rgba(245, 158, 11, .20);
    }
    .btn {
      appearance: none;
      border: 1px solid rgba(255,255,255,.18);
      background: rgba(34, 197, 94, .12);
      color: var(--text);
      padding: 10px 12px;
      border-radius: 10px;
      cursor: pointer;
      font-weight: 650;
    }
    .btn:hover { background: rgba(34, 197, 94, .18); }
    .btn:disabled { opacity: .55; cursor: not-allowed; }
    .btn.secondary { background: rgba(255,255,255,.06); }
    .btn.secondary:hover { background: rgba(255,255,255,.09); }
    .btn.danger { background: rgba(239, 68, 68, .12); }
    .btn.danger:hover { background: rgba(239, 68, 68, .18); }
    .meta { margin-top: 8px; color: var(--muted); font-size: 13px; min-height: 18px; }
    .meta.warn { color: var(--yellow); }
    .meta.error { color: var(--red); }

    .queue {
      list-style: none;
      padding: 0;
      margin: 10px 0 0;
      display: grid;
      gap: 10px;
      min-width: 0;
    }
    .qitem {
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 10px;
      display: grid;
      grid-template-columns: minmax(0, 1fr) auto;
      align-items: center;
      gap: 10px;
      background: rgba(255,255,255,.03);
      min-width: 0;
      width: 100%;
    }
    .qleft { min-width: 0; overflow: hidden; }
    .qtitle { display: block; max-width: 100%; font-weight: 750; font-size: 14px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
    .qsub { display: block; max-width: 100%; color: var(--muted); font-size: 13px; margin-top: 2px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
    .qactions { display: flex; gap: 8px; align-items: center; justify-content: flex-end; flex: 0 0 auto; }
    @media (max-width: 760px) {
      .qitem { grid-template-columns: 1fr; }
      .qactions { justify-content: flex-start; }
    }
    .badge {
      display: inline-block;
      padding: 2px 8px;
      border-radius: 999px;
      border: 1px solid var(--border);
      color: var(--muted);
      font-size: 12px;
    }
    .badge.ok { color: rgba(34, 197, 94, .95); border-color: rgba(34,197,94,.35); }
    .badge.err { color: rgba(239, 68, 68, .95); border-color: rgba(239,68,68,.35); }
    .badge.run { color: rgba(245, 158, 11, .95); border-color: rgba(245,158,11,.35); }

    .progress {
      width: 100%;
      height: 18px;
      border-radius: 999px;
      border: 1px solid var(--border);
      overflow: hidden;
      background: rgba(255,255,255,.05);
      margin-top: 10px;
    }
    .bar {
      height: 100%;
      width: 0%;
      background: linear-gradient(90deg, rgba(34,197,94,.95), rgba(45,212,191,.95));
      transition: width .12s linear;
    }
    .mono { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }

    .modal {
      position: fixed;
      inset: 0;
      display: none;
      align-items: center;
      justify-content: center;
      background: rgba(0,0,0,.55);
      padding: 14px;
      z-index: 999;
    }
    .modal.show { display: flex; }
    .modalCard {
      width: min(840px, 100%);
      max-height: min(80vh, 760px);
      overflow: hidden;
      border-radius: 14px;
      border: 1px solid var(--border);
      background: rgba(16,25,43,.98);
      box-shadow: 0 18px 60px rgba(0,0,0,.45);
      padding: 14px;
      display: grid;
      grid-template-rows: auto auto 1fr auto;
      gap: 10px;
    }
    .confList {
      border: 1px solid var(--border);
      border-radius: 12px;
      background: rgba(255,255,255,.03);
      overflow: auto;
      padding: 10px;
      font-size: 13px;
      color: var(--muted);
    }
    .confList div { margin: 4px 0; }
    .confRow {
      display: grid;
      grid-template-columns: 18px 1fr auto;
      gap: 8px;
      align-items: center;
      padding: 4px 6px;
      border-radius: 8px;
    }
    .confRow input { margin: 0; }
    .confRow.overwrite { background: rgba(34,197,94,.10); }
    .confRow.skip { background: rgba(255,255,255,.02); }
    .confSummary { color: var(--muted); font-size: 13px; }
  </style>
</head>
<body>
  <div class="wrap">
    <h1>Lokaler Upload Server</h1>
    <div class="hint">Default: 1 active upload per browser. Additional uploads are queued.</div>

    <div class="grid">
      <div class="card">
        <h2>Files (multi-select)</h2>
        <form id="singleFileForm">
          <input type="file" id="singleFile" multiple />
          <div class="row">
            <button class="btn" type="submit">Add to queue</button>
          </div>
          <div class="meta" id="singleFileInfo"></div>
          <div class="meta" id="singleFileWarn"></div>
        </form>
      </div>

      <div class="card">
        <h2>Folder (keep structure)</h2>
        <form id="folderForm">
          <input type="file" id="folderInput" webkitdirectory directory multiple />
          <div class="row">
            <button class="btn" type="submit">Add to queue</button>
          </div>
          <div class="meta" id="folderFileInfo"></div>
          <div class="meta" id="folderWarn"></div>
        </form>
      </div>
    </div>

    <div class="card" style="margin-top:14px;">
      <h2>Queue</h2>
      <div class="hint" id="queueEmpty">No uploads yet.</div>
      <div class="meta error" id="pageError" style="display:none;"></div>
      <ul class="queue" id="queueList"></ul>
    </div>

    <div class="card" style="margin-top:14px;">
      <h2>Active Upload</h2>
      <div class="hint" id="activeHint">No active upload. Session uploaded: <span id="sessionTotal">0 B</span>.</div>
      <div id="activeBox" style="display:none;">
        <div class="qtitle" id="activeTitle"></div>
        <div class="qsub mono" id="activeSub"></div>
        <div class="progress"><div class="bar" id="activeBar"></div></div>
        <div class="qsub mono" id="activeStats" style="margin-top:8px;"></div>
        <div class="progress" style="margin-top:12px;"><div class="bar" id="overallBar"></div></div>
        <div class="qsub mono" id="overallStats" style="margin-top:8px;"></div>
        <div class="row" style="justify-content:flex-end;">
          <button class="btn danger" id="abortBtn" type="button" disabled>Abort</button>
        </div>
      </div>
    </div>
  </div>

  <div class="modal" id="conflictModal" aria-hidden="true">
    <div class="modalCard">
      <div class="qtitle">Existing files detected</div>
      <div class="hint" id="conflictText"></div>
      <div class="row">
        <label class="qsub mono" style="display:flex; align-items:center; gap:8px;">
          <input type="checkbox" id="conflictAll" />
          Overwrite all
        </label>
      </div>
      <div class="confList mono" id="conflictList"></div>
      <div class="confSummary" id="conflictSummary"></div>
      <div class="row">
        <button class="btn" id="conflictOkBtn" type="button">Continue</button>
        <button class="btn danger" id="cancelBtn" type="button">Cancel</button>
      </div>
    </div>
  </div>

  <script>
  (() => {
    'use strict';

    const $ = (id) => document.getElementById(id);
    const queue = [];
    let activeJob = null;
    let activeXhr = null;
    let sessionUploadedBytes = 0;

    function formatBytes(bytes) {
      const n = Number(bytes || 0);
      if (!isFinite(n) || n <= 0) return '0 B';
      const units = ['B', 'KB', 'MB', 'GB', 'TB'];
      let v = n;
      let i = 0;
      while (v >= 1024 && i < units.length - 1) { v /= 1024; i++; }
      return `${v.toFixed(v < 10 && i > 0 ? 2 : 1)} ${units[i]}`;
    }

    function formatSpeed(bps) {
      const v = Number(bps || 0);
      if (!isFinite(v) || v <= 0) return '0 B/s';
      return `${formatBytes(v)}/s`;
    }

    function newId() {
      const c = (typeof window !== 'undefined') ? window.crypto : null;
      if (c && c.randomUUID) return c.randomUUID();
      return `${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 10)}`;
    }

    function showPageError(message) {
      const el = $('pageError');
      if (!el) return;
      el.textContent = message;
      el.style.display = 'block';
      el.className = 'meta error';
    }

    function summarizeSelection(files) {
      if (!files || files.length === 0) return '';
      let total = 0;
      for (const f of files) total += (f.size || 0);
      return `${files.length} file(s), ${formatBytes(total)}`;
    }

    function formatDuration(sec) {
      const s = Math.max(0, Math.floor(sec || 0));
      const h = Math.floor(s / 3600);
      const m = Math.floor((s % 3600) / 60);
      const r = s % 60;
      if (h > 0) return `${h}h ${m}m ${r}s`;
      if (m > 0) return `${m}m ${r}s`;
      return `${r}s`;
    }

    function normPath(p) {
      return (p || '')
        .replace(/\\/g, '/')
        .replace(/^\/+/, '')
        .replace(/\/+/g, '/')
        .trim()
        .toLowerCase();
    }

    function getBusyTargetPaths() {
      const busy = new Set();
      for (const job of queue) {
        if (!['preflight', 'queued', 'uploading'].includes(job.status)) continue;
        for (const item of (job.items || [])) {
          const key = normPath(item.path);
          if (key) busy.add(key);
        }
      }
      return busy;
    }

    function statusBadge(job) {
      const s = job.status;
      if (s === 'done') return '<span class="badge ok">done</span>';
      if (s === 'error') return '<span class="badge err">error</span>';
      if (s === 'canceled') return '<span class="badge err">canceled</span>';
      if (s === 'uploading') return '<span class="badge run">uploading</span>';
      if (s === 'preflight') return '<span class="badge run">preflight</span>';
      return '<span class="badge">queued</span>';
    }

    function renderQueue() {
      const list = $('queueList');
      list.innerHTML = '';
      $('queueEmpty').style.display = queue.length ? 'none' : 'block';

      for (const job of queue) {
        const li = document.createElement('li');
        li.className = 'qitem';

        const left = document.createElement('div');
        left.className = 'qleft';

        const title = document.createElement('div');
        title.className = 'qtitle';
        title.textContent = job.label;

        const sub = document.createElement('div');
        sub.className = 'qsub mono';
        const pct = job.totalBytes > 0 ? Math.floor((job.uploadedBytes / job.totalBytes) * 100) : 0;
        let extra = '';
        if (job.status === 'uploading') extra = ` • ${pct}%`;
        if (job.status === 'preflight') extra = ' • checking...';
        if (job.status === 'error') extra = ` • ${job.error || 'Error'}`;
        if (job.status === 'canceled') extra = ` • ${job.error || 'Canceled'}`;
        if (job.status === 'done' && job.error) extra = ` • ${job.error}`;
        const dur = job.durationSec ? ` • ${formatDuration(job.durationSec)}` : '';
        sub.textContent = `${job.items.length} file(s), ${formatBytes(job.totalBytes)}${extra}${dur}`;

        left.appendChild(title);
        left.appendChild(sub);

        const actions = document.createElement('div');
        actions.className = 'qactions';
        actions.innerHTML = statusBadge(job);

        if (job.status === 'queued') {
          const btn = document.createElement('button');
          btn.className = 'btn danger';
          btn.type = 'button';
          btn.textContent = 'Remove';
          btn.onclick = () => {
            const idx = queue.indexOf(job);
            if (idx >= 0) queue.splice(idx, 1);
            renderQueue();
          };
          actions.appendChild(btn);
        } else if (job.status === 'done' || job.status === 'error' || job.status === 'canceled') {
          const btn = document.createElement('button');
          btn.className = 'btn secondary';
          btn.type = 'button';
          btn.textContent = 'Hide';
          btn.onclick = () => {
            const idx = queue.indexOf(job);
            if (idx >= 0) queue.splice(idx, 1);
            renderQueue();
          };
          actions.appendChild(btn);
        }

        li.appendChild(left);
        li.appendChild(actions);
        list.appendChild(li);
      }
    }

    function setActiveUI(job) {
      if (!job) {
        $('activeHint').style.display = 'block';
        $('activeBox').style.display = 'none';
        $('abortBtn').disabled = true;
        if ($('sessionTotal')) {
          $('sessionTotal').textContent = formatBytes(sessionUploadedBytes);
        }
        return;
      }
      $('activeHint').style.display = 'none';
      $('activeBox').style.display = 'block';
      $('abortBtn').disabled = false;
      $('activeTitle').textContent = job.label;

      const pct = job.totalBytes > 0 ? Math.min(100, (job.uploadedBytes / job.totalBytes) * 100) : 0;
      $('activeBar').style.width = `${pct}%`;
      $('activeSub').textContent = `file ${job.currentIndex || 0}/${job.items.length}: ${job.currentPath || ''}`;
      const elapsed = (performance.now() - job.startedAt) / 1000;
      const remaining = job.speedBps > 0 ? Math.max(0, (job.totalBytes - job.uploadedBytes) / job.speedBps) : 0;
      $('activeStats').textContent =
        `${formatBytes(job.uploadedBytes)} / ${formatBytes(job.totalBytes)} • ${formatSpeed(job.speedBps || 0)} • ` +
        `elapsed ${formatDuration(elapsed)} • eta ${remaining ? formatDuration(remaining) : '--'}`;

      const totals = getOverallTotals();
      const opct = totals.totalBytes > 0 ? Math.min(100, (totals.uploadedBytes / totals.totalBytes) * 100) : 0;
      $('overallBar').style.width = `${opct}%`;
      const oElapsed = totals.startedAt ? (performance.now() - totals.startedAt) / 1000 : 0;
      const oRemaining = totals.speedBps > 0 ? Math.max(0, (totals.totalBytes - totals.uploadedBytes) / totals.speedBps) : 0;
      $('overallStats').textContent =
        `Overall: ${formatBytes(totals.uploadedBytes)} / ${formatBytes(totals.totalBytes)} • ${formatSpeed(totals.speedBps)} • ` +
        `elapsed ${formatDuration(oElapsed)} • eta ${oRemaining ? formatDuration(oRemaining) : '--'}`;
    }

    function showConflictDialog(conflicts) {
      return new Promise((resolve) => {
        const modal = $('conflictModal');
        const list = $('conflictList');
        const text = $('conflictText');
        const allToggle = $('conflictAll');
        const summary = $('conflictSummary');
        list.textContent = '';
        allToggle.checked = false;

        const maxShow = 200;
        const show = conflicts.slice(0, maxShow);
        const entries = [];
        for (const c of show) {
          const row = document.createElement('label');
          row.className = 'confRow skip';
          const cb = document.createElement('input');
          cb.type = 'checkbox';
          cb.checked = false;
          const name = document.createElement('div');
          name.textContent = c.rel_path || c.path || '';
          const tag = document.createElement('div');
          const reason = c.reason || 'exists';
          const locked = reason === 'in_progress' || reason === 'duplicate_in_request';
          tag.textContent = locked ? 'in progress' : 'keep';

          const updateRow = () => {
            const isOn = cb.checked;
            row.className = `confRow ${isOn ? 'overwrite' : 'skip'}`;
            tag.textContent = locked ? 'in progress' : (isOn ? 'overwrite' : 'keep');
            updateSummary();
          };

          if (locked) {
            cb.disabled = true;
            cb.checked = false;
          }
          cb.addEventListener('change', updateRow);
          row.appendChild(cb);
          row.appendChild(name);
          row.appendChild(tag);
          list.appendChild(row);
          entries.push({ cb, path: c.path, rel_path: c.rel_path });
        }
        if (conflicts.length > maxShow) {
          const div = document.createElement('div');
          div.textContent = `... and ${conflicts.length - maxShow} more`;
          list.appendChild(div);
        }

        text.textContent = `${conflicts.length} conflict(s) found. Choose what to do.`;
        modal.classList.add('show');

        const updateSummary = () => {
          let overwrite = 0;
          for (const ent of entries) if (ent.cb.checked) overwrite++;
          const keep = entries.length - overwrite;
          summary.textContent = `Overwrite: ${overwrite} • Keep: ${keep}`;
        };
        updateSummary();

        allToggle.onchange = () => {
          const rows = list.querySelectorAll('input[type="checkbox"]');
          rows.forEach((cb) => {
            if (cb.disabled) return;
            cb.checked = allToggle.checked;
            cb.dispatchEvent(new Event('change'));
          });
        };

        const cleanup = (answer) => {
          modal.classList.remove('show');
          resolve(answer);
        };

        $('conflictOkBtn').onclick = () => {
          const overwriteSet = new Set();
          for (const ent of entries) {
            if (ent.cb.checked) {
              if (ent.path) overwriteSet.add(normPath(ent.path));
              if (ent.rel_path) overwriteSet.add(normPath(ent.rel_path));
            }
          }
          cleanup({ action: 'proceed', overwriteSet });
        };
        $('cancelBtn').onclick = () => cleanup({ action: 'cancel' });
      });
    }

    async function apiPreflight(job) {
      const payload = {
        upload_id: job.id,
        items: job.items.map(it => ({ path: it.path, size: it.file.size || 0 })),
      };
      try {
        const res = await fetch('/api/preflight', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload),
        });
        const data = await res.json().catch(() => null);
        if (!res.ok || !data || !data.ok) {
          return { ok: false, error: (data && data.error) ? data.error : `HTTP ${res.status}` };
        }
        return data;
      } catch (err) {
        const msg = (err && err.message) ? err.message : String(err);
        showPageError(`Preflight failed: ${msg}`);
        return { ok: false, error: msg };
      }
    }

    async function enqueueJob(job) {
      job.status = 'preflight';
      for (const item of job.items) {
        item.onExists = 'overwrite';
      }
      const busy = getBusyTargetPaths();
      let skippedDuplicates = 0;
      const uniqueItems = [];
      for (const item of job.items) {
        const key = normPath(item.path);
        if (!key) continue;
        if (busy.has(key)) {
          skippedDuplicates += 1;
          continue;
        }
        busy.add(key);
        uniqueItems.push(item);
      }
      job.items = uniqueItems;
      job.totalBytes = job.items.reduce((a, it) => a + (it.file.size || 0), 0);
      if (skippedDuplicates > 0) {
        showPageError(`${skippedDuplicates} file(s) skipped: target path already in queue/upload.`);
      }
      if (job.items.length === 0) {
        job.status = 'done';
        job.error = 'Nothing new in queue (duplicates only).';
        queue.push(job);
        renderQueue();
        return;
      }
      queue.push(job);
      renderQueue();

      let preflight = await apiPreflight(job);
      if (!preflight.ok) {
        job.status = 'error';
        job.error = preflight.error;
        renderQueue();
        return;
      }

      let conflicts = preflight.conflicts || [];
      if (conflicts.length) {
        const choice = await showConflictDialog(conflicts);
        if (!choice || choice.action === 'cancel') {
          job.status = 'canceled';
          job.error = 'Canceled (before upload)';
          renderQueue();
          return;
        }

        const conflictSet = new Set();
        for (const c of conflicts || []) {
          if (c.path) conflictSet.add(normPath(c.path));
          if (c.rel_path) conflictSet.add(normPath(c.rel_path));
        }
        const overwriteSet = choice.overwriteSet || new Set();
        for (const item of job.items) {
          const key = normPath(item.path || '');
          if (conflictSet.has(key)) {
            item.onExists = overwriteSet.has(key) ? 'overwrite' : 'skip';
          } else {
            item.onExists = 'overwrite';
          }
        }
        job.items = job.items.filter(it => it.onExists !== 'skip');
        job.totalBytes = job.items.reduce((a, it) => a + (it.file.size || 0), 0);
        if (job.items.length === 0) {
          job.status = 'done';
          job.error = 'All files already exist (nothing to upload)';
          renderQueue();
          return;
        }
        preflight = await apiPreflight(job);
        if (!preflight.ok) {
          job.status = 'error';
          job.error = preflight.error;
          renderQueue();
          return;
        }
      }

      job.status = 'queued';
      renderQueue();
      pumpQueue();
    }

    function uploadFile(job, item, fileIndex) {
      return new Promise((resolve, reject) => {
        const params = new URLSearchParams({
          upload_id: job.id,
          path: item.path,
          file_index: String(fileIndex),
          total_files: String(job.items.length),
          on_exists: item.onExists || 'skip',
        });
        const xhr = new XMLHttpRequest();
        activeXhr = xhr;
        xhr.responseType = 'json';
        xhr.open('POST', `/api/upload?${params.toString()}`, true);
        xhr.setRequestHeader('Content-Type', 'application/octet-stream');

        xhr.upload.onprogress = (e) => {
          if (!e.lengthComputable) return;
          job.currentIndex = fileIndex;
          job.currentPath = item.path;
          const elapsed = (performance.now() - job.startedAt) / 1000;
          job.uploadedBytes = Math.min(job.totalBytes, job.completedBytes + e.loaded);
          job.speedBps = elapsed > 0 ? (job.uploadedBytes / elapsed) : 0;
          const now = performance.now();
          if (!job._lastUi || (now - job._lastUi) > 120 || e.loaded === e.total) {
            job._lastUi = now;
            setActiveUI(job);
            renderQueue();
          }
        };

        xhr.onload = () => {
          const resp = xhr.response || null;
          if (xhr.status === 409 && resp && (resp.error === 'exists' || resp.error === 'in_progress')) {
            resolve({ skipped: true, rel_path: resp.rel_path || item.path });
            return;
          }
          const ok = xhr.status === 200 && resp && resp.ok;
          if (!ok) {
            const msg = (resp && resp.error) ? resp.error : (xhr.responseText || `HTTP ${xhr.status}`);
            reject(new Error(msg));
            return;
          }
          resolve(resp);
        };
        xhr.onerror = () => reject(new Error('Network error during upload'));
        xhr.onabort = () => reject(new Error('Upload canceled'));
        xhr.send(item.file);
      });
    }

    async function runJob(job) {
      job.status = 'uploading';
      job.startedAt = performance.now();
      job._lastUi = 0;
      job.completedBytes = 0;
      job.uploadedBytes = 0;
      job.speedBps = 0;
      job.currentIndex = 0;
      job.currentPath = '';
      setActiveUI(job);
      renderQueue();

      $('abortBtn').disabled = false;
      for (let i = 0; i < job.items.length; i++) {
        if (job.status !== 'uploading') break;
        const item = job.items[i];
        try {
          const res = await uploadFile(job, item, i + 1);
          if (res && res.skipped) {
            item.skipped = true;
          } else {
            item.sha256 = res.sha256 || '';
            sessionUploadedBytes += (item.file.size || 0);
          }
          job.completedBytes += (item.file.size || 0);
          job.uploadedBytes = job.completedBytes;
          setActiveUI(job);
          renderQueue();
        } catch (e) {
          if (job.status === 'canceled') break;
          job.status = 'error';
          job.error = (e && e.message) ? e.message : String(e);
          break;
        }
      }

      $('abortBtn').disabled = true;
      activeXhr = null;
      job.endedAt = performance.now();
      job.durationSec = (job.endedAt - job.startedAt) / 1000;
      if (job.status === 'uploading') job.status = 'done';
      setActiveUI(null);
      renderQueue();
    }

    function getOverallTotals() {
      let totalBytes = 0;
      let uploadedBytes = 0;
      let startedAt = null;
      let speedBps = 0;
      for (const job of queue) {
        totalBytes += (job.totalBytes || 0);
        uploadedBytes += (job.uploadedBytes || 0);
        if (job.startedAt && (startedAt === null || job.startedAt < startedAt)) {
          startedAt = job.startedAt;
        }
        if (job.status === 'uploading') speedBps = job.speedBps || 0;
      }
      return { totalBytes, uploadedBytes, startedAt, speedBps };
    }

    async function pumpQueue() {
      if (activeJob) return;
      const next = queue.find(j => j.status === 'queued');
      if (!next) return;
      activeJob = next;
      try {
        await runJob(next);
      } finally {
        activeJob = null;
        pumpQueue();
      }
    }

    $('abortBtn').addEventListener('click', () => {
      if (!activeJob) return;
      activeJob.status = 'canceled';
      activeJob.error = 'Canceled';
      if (activeXhr) activeXhr.abort();
      setActiveUI(null);
      renderQueue();
    });

    $('singleFile').addEventListener('change', (e) => {
      $('singleFileInfo').textContent = summarizeSelection(e.target.files);
      $('singleFileWarn').textContent = '';
      $('singleFileWarn').className = 'meta';
      e.target.classList.remove('warn');
    });
    $('folderInput').addEventListener('change', (e) => {
      $('folderFileInfo').textContent = summarizeSelection(e.target.files);
      $('folderWarn').textContent = '';
      $('folderWarn').className = 'meta';
      e.target.classList.remove('warn');
    });

    $('singleFileForm').addEventListener('submit', async (e) => {
      e.preventDefault();
      $('pageError').style.display = 'none';
      const input = $('singleFile');
      const files = input.files ? Array.from(input.files) : [];
      if (!files.length) {
        $('singleFileWarn').textContent = 'Please select at least one file first.';
        $('singleFileWarn').className = 'meta warn';
        input.classList.add('warn');
        return;
      }

      const total = files.reduce((a, f) => a + (f.size || 0), 0);
      const label =
        files.length === 1
          ? `File: ${files[0].name}`
          : `Files: ${files.length} (${files[0].name} ...)`;

      const job = {
        id: newId().replace(/[^A-Za-z0-9._-]/g, '').slice(0, 72),
        label,
        kind: 'files',
        items: files.map(f => ({ file: f, path: f.name })),
        totalBytes: total,
        uploadedBytes: 0,
        completedBytes: 0,
        status: 'new',
        error: '',
        onExists: 'skip',
      };
      input.value = '';
      $('singleFileInfo').textContent = '';
      await enqueueJob(job);
    });

    $('folderForm').addEventListener('submit', async (e) => {
      e.preventDefault();
      $('pageError').style.display = 'none';
      const input = $('folderInput');
      const files = input.files ? Array.from(input.files) : [];
      if (!files.length) {
        $('folderWarn').textContent = 'Please select a folder first.';
        $('folderWarn').className = 'meta warn';
        input.classList.add('warn');
        return;
      }

      const root = (files[0].webkitRelativePath || '').split('/')[0] || 'Folder';
      const items = files.map(f => ({ file: f, path: f.webkitRelativePath || f.name }));
      const total = items.reduce((a, it) => a + (it.file.size || 0), 0);

      const job = {
        id: newId().replace(/[^A-Za-z0-9._-]/g, '').slice(0, 72),
        label: `Folder: ${root}`,
        kind: 'folder',
        items,
        totalBytes: total,
        uploadedBytes: 0,
        completedBytes: 0,
        status: 'new',
        error: '',
        onExists: 'skip',
      };
      input.value = '';
      $('folderFileInfo').textContent = '';
      await enqueueJob(job);
    });

    window.addEventListener('error', (e) => {
      showPageError(`JS error: ${e.message || e.type}`);
    });
    window.addEventListener('unhandledrejection', (e) => {
      const reason = e && e.reason ? (e.reason.message || String(e.reason)) : 'unknown';
      showPageError(`JS error: ${reason}`);
    });

    renderQueue();
    setActiveUI(null);
  })();
  </script>
</body>
</html>
"""


def _parse_listen_endpoint(value: str) -> tuple[str, int]:
    item = (value or "").strip()
    if not item:
        raise ValueError("Empty --listen value")
    if ":" not in item:
        raise ValueError(
            f"Invalid --listen value '{value}'. Expected HOST:PORT (example: 0.0.0.0:8040)"
        )
    host_part, port_part = item.rsplit(":", 1)
    host = host_part.strip() or "0.0.0.0"
    try:
        port = int(port_part.strip())
    except ValueError as exc:
        raise ValueError(f"Invalid port in --listen value '{value}'") from exc
    if not (1 <= port <= 65535):
        raise ValueError(f"Port out of range in --listen value '{value}'")
    return (host, port)


def _build_bind_endpoints(
    host_args: list[str], port: int, listen_args: list[str]
) -> list[tuple[str, int]]:
    if not (1 <= int(port) <= 65535):
        raise ValueError(f"--port must be in range 1-65535, got {port}")

    endpoints: list[tuple[str, int]] = []
    if listen_args:
        for raw in listen_args:
            for part in (raw or "").split(","):
                item = part.strip()
                if item:
                    endpoints.append(_parse_listen_endpoint(item))
    else:
        hosts: list[str] = []
        for raw in host_args:
            for part in (raw or "").split(","):
                item = part.strip()
                if item:
                    hosts.append(item)
        if not hosts:
            hosts = ["0.0.0.0"]
        endpoints = [(h, int(port)) for h in hosts]

    unique: list[tuple[str, int]] = []
    seen: set[tuple[str, int]] = set()
    for endpoint in endpoints:
        if endpoint not in seen:
            seen.add(endpoint)
            unique.append(endpoint)

    for host, ep_port in unique:
        try:
            socket.getaddrinfo(host, ep_port, socket.AF_INET, socket.SOCK_STREAM)
        except socket.gaierror as exc:
            raise ValueError(
                f"Invalid/unresolvable bind host '{host}' for port {ep_port}: {exc}"
            ) from exc
    return unique


def run_server(
    endpoints: list[tuple[str, int]], per_client_limit: int = 1
) -> None:
    UPLOAD_ROOT.mkdir(parents=True, exist_ok=True)
    STATE.set_per_ip_limit(per_client_limit)

    local_ips = _get_local_ipv4_addresses()
    primary_ip = local_ips[0] if local_ips else "127.0.0.1"

    print("\n" + "=" * 60)
    print("Upload server started")
    print("=" * 60)
    print(f"Python:         {platform.python_version()}")
    print(f"OS:             {platform.system()}")
    print(f"Primary IP:     {primary_ip}")
    if local_ips:
        print(f"Local IPv4s:    {', '.join(local_ips)}")
    print(f"Per-client limit: {max(1, int(per_client_limit))}")
    print("Bindings:")
    for host, port in endpoints:
        print(f"  - {host}:{port}")
    print("\nAccess URLs:")
    for host, port in endpoints:
        if host in ("", "0.0.0.0"):
            print(f"  Local:    http://localhost:{port}")
            for ip in local_ips[:5]:
                print(f"  Network:  http://{ip}:{port}")
        else:
            print(f"  Host:     http://{host}:{port}")
    print(f"\nStorage path: {UPLOAD_ROOT}")
    print("To stop: Ctrl+C")
    print("=" * 60 + "\n")

    servers: list[ThreadingHTTPServer] = []
    for host, port in endpoints:
        try:
            servers.append(ThreadingHTTPServer((host, port), SimpleUploadServer))
        except OSError as exc:
            print(f"Failed to bind {host}:{port} -> {exc}")

    if not servers:
        raise SystemExit("No server socket could be started. Check host/port values.")

    threads: list[threading.Thread] = []
    for server in servers:
        t = threading.Thread(target=server.serve_forever, daemon=True)
        t.start()
        threads.append(t)

    try:
        while True:
            time.sleep(0.5)
    except KeyboardInterrupt:
        print("\nShutting down server...")
        for server in servers:
            server.shutdown()
            server.server_close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Local upload server (streaming, queue-based, LAN-first)."
    )
    parser.add_argument(
        "--host",
        type=str,
        action="append",
        default=[],
        help="Host/IP to bind with --port. Repeatable or comma-separated (default: 0.0.0.0)",
    )
    parser.add_argument(
        "--listen",
        type=str,
        action="append",
        default=[],
        help="Full bind endpoint HOST:PORT. Repeatable or comma-separated.",
    )
    parser.add_argument(
        "-p",
        "--port",
        type=int,
        default=8040,
        help="TCP port to listen on (default: 8040)",
    )
    parser.add_argument(
        "--per-client-limit",
        type=int,
        default=1,
        help="Max simultaneous uploads per client IP (default: 1)",
    )
    args = parser.parse_args()
    try:
        endpoints = _build_bind_endpoints(args.host, args.port, args.listen)
    except ValueError as exc:
        parser.error(str(exc))
    run_server(
        endpoints=endpoints,
        per_client_limit=max(1, args.per_client_limit),
    )
