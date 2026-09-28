from __future__ import annotations

import sys

# Kept right after the __future__ import (which must stay first) and written in
# syntax old enough to parse on any Python 3, so an outdated interpreter gets
# this message instead of a confusing SyntaxError or ImportError further down.
if sys.version_info < (3, 8):
    sys.stderr.write(
        "ERROR: this server needs Python 3.8 or newer.\n"
        "You are running %s (%s).\n"
        "Tested on 3.8 - 3.14. Install a newer Python and try again.\n"
        % (sys.version.split()[0], sys.executable)
    )
    raise SystemExit(2)

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse
import argparse
import ctypes
import datetime as _dt
import errno
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
STORAGE = None
BUFFER_SIZE = 8 * 1024 * 1024
MAX_PREFLIGHT_BYTES = 20 * 1024 * 1024
DISK_SPACE_FACTOR = 1.1
DEFAULT_BIND_HOST = "0.0.0.0"
DEFAULT_PORT = 8040
DEFAULT_PER_CLIENT_LIMIT = 1
DEFAULT_RETRY_COUNT = 2
DEFAULT_RETRY_DELAY_MS = 800
DEFAULT_UPLOAD_TIMEOUT_SEC = 0
# Idle time allowed on a single socket read before the connection is dropped.
# Generous enough for a slow link, short enough that a dead client frees its
# upload slot on its own.
SOCKET_TIMEOUT_SEC = 300
# Age after which a finished/abandoned upload session is forgotten.
SESSION_TTL_SEC = 12 * 3600
TEMP_PREFIX = ".upload_tmp_"
# Upper bound for draining the body of a rejected request so the client can
# still read the status code. Beyond this the connection is simply closed.
MAX_DISCARD_BYTES = 64 * 1024 * 1024

_INVALID_NAME_RE = re.compile(r'[<>:"|?*\x00-\x1f]')
_RESERVED_NAMES = {
    "CON",
    "PRN",
    "AUX",
    "NUL",
    *(f"COM{i}" for i in range(1, 10)),
    *(f"LPT{i}" for i in range(1, 10)),
}


class _RequestError(Exception):
    """A client-side mistake, carrying the status code to answer with."""

    def __init__(self, message: str, *, status: int = 400) -> None:
        super().__init__(message)
        self.status = status


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


class _LocalStorage:
    def initialize(self) -> None:
        UPLOAD_ROOT.mkdir(parents=True, exist_ok=True)

    def _resolve(self, rel_path: str) -> Path:
        target = (UPLOAD_ROOT / rel_path).resolve()
        if UPLOAD_ROOT not in target.parents and target != UPLOAD_ROOT:
            raise ValueError("invalid target path")
        return target

    def exists(self, rel_path: str) -> bool:
        return self._resolve(rel_path).exists()

    def is_dir(self, rel_path: str) -> bool:
        return self._resolve(rel_path).is_dir()

    def check_space(self, required_bytes: int) -> None:
        _ensure_disk_space(required_bytes)

    def begin(self, rel_path: str):
        target = self._resolve(rel_path)
        target.parent.mkdir(parents=True, exist_ok=True)
        fd, ticket = tempfile.mkstemp(prefix=TEMP_PREFIX, dir=str(target.parent))
        try:
            return os.fdopen(fd, "wb"), Path(ticket)
        except Exception:
            os.close(fd)
            Path(ticket).unlink()
            raise

    def commit(self, ticket, rel_path: str, overwrite: bool, digest: str) -> None:
        target = self._resolve(rel_path)
        if target.is_dir():
            raise ValueError("target path is a directory")
        if target.exists() and not overwrite:
            raise _RequestError("exists", status=409)
        os.replace(str(ticket), str(target))

    def abort(self, ticket) -> None:
        Path(ticket).unlink(missing_ok=True)


_LOCAL_STORAGE = _LocalStorage()


def _sanitize_name_part(name: str) -> str:
    name = _INVALID_NAME_RE.sub("_", name)
    name = name.rstrip(" .")
    if not name:
        name = "_"
    # "con.txt" is just as unwritable on Windows as "con".
    if name.split(".")[0].upper() in _RESERVED_NAMES:
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
            # Sessions are only dropped when every file of a job succeeds, so
            # abandoned tabs and partly failed jobs would accumulate forever on
            # a server that stays up for weeks. Expire them by age here, which
            # is the one place a new session is registered.
            cutoff = time.time() - SESSION_TTL_SEC
            stale = [
                key
                for key, entry in self._sessions.items()
                if float(entry.get("created_at", 0)) < cutoff
            ]
            for key in stale:
                self._sessions.pop(key, None)
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
            if (
                int(session.get("files_done", 0))
                >= int(session.get("total_files", 0))
                > 0
            ):
                self._sessions.pop(upload_id, None)

    def is_path_reserved(
        self, rel_path: str, *, exclude_upload_id: str | None = None
    ) -> bool:
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
_HTML_CONFIG = {
    "max_file_retries": DEFAULT_RETRY_COUNT,
    "retry_delay_ms": DEFAULT_RETRY_DELAY_MS,
    "upload_timeout_ms": DEFAULT_UPLOAD_TIMEOUT_SEC * 1000,
}


def _render_html() -> str:
    html = _HTML_TEMPLATE
    html = html.replace(
        "__MAX_FILE_RETRIES__", str(int(_HTML_CONFIG["max_file_retries"]))
    )
    html = html.replace(
        "__RETRY_BASE_DELAY_MS__", str(int(_HTML_CONFIG["retry_delay_ms"]))
    )
    html = html.replace(
        "__UPLOAD_TIMEOUT_MS__", str(int(_HTML_CONFIG["upload_timeout_ms"]))
    )
    # Whether two paths collide depends on the server's filesystem, not on the
    # browser's, so the client is told rather than left to assume.
    html = html.replace(
        "__CASE_INSENSITIVE_FS__",
        "true" if _path_key("A") == _path_key("a") else "false",
    )
    return html


class SimpleUploadServer(BaseHTTPRequestHandler):
    server_version = "SimpleUploadServer/2026.01"
    # A client that vanishes without closing its TCP connection (laptop asleep,
    # phone out of Wi-Fi range) would otherwise leave the handler blocked in
    # rfile.read() forever, holding this IP's upload slot until the OS keepalive
    # gives up hours later. socketserver applies this to the accepted socket.
    timeout = SOCKET_TIMEOUT_SEC
    # Bytes of the current request body not yet read off the socket.
    _body_remaining: int | None = None

    def setup(self) -> None:
        super().setup()
        self.storage = getattr(self.server, "storage", STORAGE) or _LOCAL_STORAGE
        self.state = getattr(self.server, "state", STATE)

    def handle_one_request(self) -> None:
        try:
            super().handle_one_request()
        except socket.timeout:
            self.close_connection = True

    def log_message(self, format: str, *args) -> None:  # noqa: A002
        return

    def _log(self, message: str, *, color: str | None = None) -> None:
        prefix = f"[{_ts()}] "
        text = prefix + message
        if color:
            text = _c(text, color)
        print(text, flush=True)

    def _client_ip(self) -> str:
        return (
            self.client_address[0] if self.client_address else "unknown"
        ) or "unknown"

    def _note_client_if_new(self) -> None:
        ip = self._client_ip()
        ua = self.headers.get("User-Agent")
        if self.state.note_client(ip):
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

    def _discard_request_body(self) -> None:
        """Read and throw away whatever the client is still sending.

        Answering an upload without consuming its body closes the socket while
        megabytes are still in flight. The client then sees a connection reset
        instead of the status code, and retries a request that was rejected on
        purpose. Draining first makes the reply actually arrive.
        """
        # _body_remaining is what is genuinely still on the wire. Falling back
        # to Content-Length when it is unset is safe; using it after the body
        # was already read would block until the socket times out.
        remaining = self._body_remaining
        if remaining is None:
            remaining = self._declared_length()
        if remaining is None or remaining <= 0:
            self.close_connection = True
            return
        if remaining > MAX_DISCARD_BYTES:
            # Too much to swallow politely; cut the connection instead.
            self.close_connection = True
            return
        try:
            while remaining > 0:
                chunk = self.rfile.read(min(BUFFER_SIZE, remaining))
                if not chunk:
                    break
                remaining -= len(chunk)
                self._body_remaining = remaining
        except (OSError, ValueError):
            self.close_connection = True
        finally:
            self._body_remaining = 0

    def _declared_length(self) -> int | None:
        """Content-Length as an int, or None when it is absent/unusable."""
        if self.headers.get("Transfer-Encoding"):
            return None
        raw = self.headers.get("Content-Length")
        if raw is None:
            return None
        try:
            value = int(raw)
        except ValueError:
            return None
        return value if value >= 0 else None

    def _read_body(self, *, max_bytes: int) -> bytes:
        length = int(self.headers.get("Content-Length", "0") or "0")
        if length <= 0:
            return b""
        if length > max_bytes:
            raise _RequestError("request too large", status=413)
        self._body_remaining = length
        data = self.rfile.read(length)
        self._body_remaining = max(0, length - len(data))
        if len(data) != length:
            raise ConnectionError("Client disconnected")
        return data

    def do_GET(self) -> None:
        self._note_client_if_new()
        if urlparse(self.path).path != "/":
            self._send_json(404, {"ok": False, "error": "not_found"})
            return
        self._send_bytes(
            200, _render_html().encode("utf-8"), "text/html; charset=utf-8"
        )

    def do_POST(self) -> None:
        self._note_client_if_new()
        self._body_remaining: int | None = None
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
            self.storage.initialize()

            body = self._read_body(max_bytes=MAX_PREFLIGHT_BYTES)
            data = json.loads(body.decode("utf-8")) if body else {}

            upload_id = str(data.get("upload_id") or "").strip()
            items = data.get("items") or []
            if not upload_id or not isinstance(upload_id, str):
                raise ValueError("upload_id missing")
            if not re.fullmatch(r"[A-Za-z0-9._-]{6,80}", upload_id):
                raise ValueError("invalid upload_id")
            if not isinstance(items, list) or not items:
                raise ValueError("items missing or empty")

            conflicts: list[dict] = []
            total_bytes = 0
            total_files = 0
            # Only bytes that will really be written count towards the disk
            # check; re-adding an already uploaded folder must not fail with
            # "not enough disk space" when nothing would be transferred.
            incoming_bytes = 0
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

                if self.storage.exists(rel_path):
                    conflicts.append(
                        {"path": raw_path, "rel_path": rel_path, "reason": "exists"}
                    )
                elif self.state.is_path_reserved(rel_path, exclude_upload_id=upload_id):
                    conflicts.append(
                        {
                            "path": raw_path,
                            "rel_path": rel_path,
                            "reason": "in_progress",
                        }
                    )
                else:
                    incoming_bytes += max(0, size)

            self.storage.check_space(incoming_bytes)

            self.state.upsert_session(
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
            status = e.status if isinstance(e, _RequestError) else 400
            self._discard_request_body()
            self._send_json(status, {"ok": False, "error": str(e)})

    def _handle_upload(self) -> None:
        ip = self._client_ip()
        sem = self.state.get_ip_semaphore(ip)
        if not sem.acquire(blocking=False):
            self._discard_request_body()
            self._send_json(
                429, {"ok": False, "error": "Upload already active (use queue)"}
            )
            return

        ticket = None
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

            self.storage.initialize()

            if not upload_id or not re.fullmatch(r"[A-Za-z0-9._-]{6,80}", upload_id):
                raise ValueError("invalid upload_id")
            rel_path = _sanitize_rel_path(raw_path)
            if on_exists not in {"skip", "overwrite"}:
                on_exists = "skip"

            # Without a length the read loop below would write nothing and
            # then replace a perfectly good file with an empty one, while
            # reporting success. Refuse instead of silently destroying data.
            if self.headers.get("Transfer-Encoding"):
                raise _RequestError(
                    "chunked transfer encoding is not supported", status=501
                )
            content_length = self._declared_length()
            if content_length is None:
                raise _RequestError("missing or invalid Content-Length", status=411)
            self.storage.check_space(content_length)

            session = self.state.get_session(upload_id)
            if session and not session.get("started_logged"):
                ua = session.get("user_agent")
                ua_part = f" ua={ua}" if ua else ""
                self._log(
                    f"Upload started: id={upload_id} ip={ip} "
                    f"files={session.get('total_files')} total={_format_bytes(int(session.get('total_bytes') or 0))}{ua_part}",
                    color=_ANSI_YELLOW,
                )
                self.state.mark_started_logged(upload_id)

            if not self.state.reserve_path(rel_path, upload_id):
                self._discard_request_body()
                self._send_json(
                    409,
                    {"ok": False, "error": "in_progress", "rel_path": rel_path},
                )
                return
            path_reserved = True

            if self.storage.is_dir(rel_path):
                raise ValueError("target path is a directory")

            if self.storage.exists(rel_path) and on_exists == "skip":
                self._discard_request_body()
                self._send_json(
                    409,
                    {"ok": False, "error": "exists", "rel_path": rel_path},
                )
                return

            self._log(
                f"START id={upload_id} file[{file_index}] ip={ip} path={rel_path} size={_format_bytes(content_length)}"
            )

            self._body_remaining = content_length
            stream, ticket = self.storage.begin(rel_path)
            hasher = hashlib.sha256()
            bytes_written = 0
            with stream as f:
                remaining = content_length
                while remaining > 0:
                    chunk = self.rfile.read(min(BUFFER_SIZE, remaining))
                    if not chunk:
                        raise ConnectionError("Client disconnected (abort?)")
                    remaining -= len(chunk)
                    self._body_remaining = remaining
                    f.write(chunk)
                    hasher.update(chunk)
                    bytes_written += len(chunk)

            digest = hasher.hexdigest()
            self.storage.commit(ticket, rel_path, on_exists == "overwrite", digest)
            ticket = None

            done_files, total_files, total_bytes = self.state.bump_done(
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
            self.state.maybe_cleanup(upload_id)
        except (ConnectionError, BrokenPipeError, socket.timeout) as e:
            # socket.timeout means the client stopped sending without closing
            # the connection. That is an abandoned upload, not a server fault.
            reason = str(e) or "Client disconnected"
            self._log(
                f"Upload aborted: id={upload_id or '?'} ip={ip} path={rel_path or '?'} reason={reason}",
                color=_ANSI_YELLOW,
            )
        except Exception as e:
            # A bad path or a full disk will fail again on every retry, so it
            # must not be reported as 5xx: the client retries those, re-sending
            # the whole file two more times for nothing.
            if isinstance(e, OSError) and e.errno == errno.ENOSPC:
                e = _RequestError("Not enough disk space", status=400)
            status = e.status if isinstance(e, _RequestError) else (
                400 if isinstance(e, ValueError) else 500
            )
            self._log(
                f"Upload error: ip={ip} status={status} err={e}", color=_ANSI_RED
            )
            try:
                if status != 500:
                    self._discard_request_body()
                self._send_json(status, {"ok": False, "error": str(e)})
            except BrokenPipeError:
                pass
        finally:
            if ticket is not None:
                try:
                    self.storage.abort(ticket)
                except Exception as exc:
                    self._log(f"Temporary upload cleanup failed: {exc}", color=_ANSI_RED)
            if path_reserved and rel_path and upload_id:
                self.state.release_path(rel_path, upload_id)
            try:
                sem.release()
            except ValueError:
                pass


_HTML_TEMPLATE = r"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Local Upload Server</title>
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
    .btn.secondary.mode-selected {
      background: rgba(34, 197, 94, .18);
      border-color: rgba(34, 197, 94, .45);
    }
    .btn.secondary.mode-selected:hover {
      background: rgba(34, 197, 94, .24);
    }
    .btn.secondary.mode-unselected {
      background: rgba(239, 68, 68, .16);
      border-color: rgba(239, 68, 68, .45);
    }
    .btn.secondary.mode-unselected:hover {
      background: rgba(239, 68, 68, .24);
    }
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
      align-content: start;
      /* Long queues scroll inside the card instead of stretching the page,
         so the sticky status bar stays reachable. */
      max-height: min(52vh, 520px);
      overflow-y: auto;
      overscroll-behavior: contain;
      /* Reserve the scrollbar gutter permanently: rows keep their width
         when the list grows past the max-height (no layout shift). */
      scrollbar-gutter: stable;
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
    .qitem.active {
      border-color: rgba(245,158,11,.55);
      /* The running job stays pinned at the top of the scrolled list, so it
         never has to be chased with an auto-scroll. */
      position: sticky;
      top: 0;
      z-index: 1;
      background: #131d33;
    }
    /* Keyboard focus must not land under the sticky status bar. */
    .qitem { scroll-margin-top: 110px; }
    /* Drag state only swaps colours, never sizes, so rows never jump. */
    .qitem.dragging { opacity: .55; }
    .qitem.dropTarget { border-color: rgba(34,197,94,.85); background: rgba(34,197,94,.10); }
    .qleft { min-width: 0; overflow: hidden; }
    .qtitle { display: block; max-width: 100%; font-weight: 750; font-size: 14px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
    .qsub { display: block; max-width: 100%; color: var(--muted); font-size: 13px; margin-top: 2px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
    .qactions { display: flex; gap: 8px; align-items: center; justify-content: flex-end; flex: 0 0 auto; }
    .qbar { height: 4px; margin-top: 6px; border-radius: 999px; }
    .qgrip {
      color: var(--muted);
      cursor: grab;
      user-select: none;
      font-size: 15px;
      line-height: 1;
      padding: 0 2px;
    }
    .qgrip:active { cursor: grabbing; }
    .btn.icon {
      width: 32px;
      height: 32px;
      padding: 0;
      display: inline-flex;
      align-items: center;
      justify-content: center;
      font-size: 13px;
      line-height: 1;
    }
    @media (max-width: 760px) {
      .qitem { grid-template-columns: 1fr; }
      .qactions { justify-content: flex-start; flex-wrap: wrap; }
    }

    /* Always-visible overall progress. Height is constant in every state
       (idle and uploading render the same three rows) so nothing shifts. */
    .statusbar {
      position: sticky;
      top: 0;
      z-index: 20;
      margin-top: 14px;
      padding: 12px 14px;
      border: 1px solid var(--border);
      border-radius: 12px;
      background: rgba(11,18,32,.94);
      backdrop-filter: blur(10px);
      box-shadow: 0 12px 28px rgba(0,0,0,.35);
      display: grid;
      grid-template-columns: minmax(0, 1fr) auto;
      gap: 12px;
      align-items: center;
    }
    .statusMain { min-width: 0; }
    .statusHead {
      display: flex;
      align-items: baseline;
      justify-content: space-between;
      gap: 12px;
      min-width: 0;
    }
    .statusTitle {
      font-weight: 750;
      font-size: 14px;
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
      min-width: 0;
    }
    .statusPct { font-size: 14px; font-weight: 750; flex: 0 0 auto; }
    .statusbar .progress { margin-top: 8px; height: 14px; }
    .statusStats {
      color: var(--muted);
      font-size: 13px;
      margin-top: 8px;
      min-height: 18px;
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
    }
    .statusActions { display: flex; gap: 8px; align-items: center; flex: 0 0 auto; }
    @media (max-width: 620px) {
      .statusbar { grid-template-columns: 1fr; }
      .statusActions { justify-content: flex-end; }
    }

    .dropzone {
      border: 1px dashed rgba(255,255,255,.22);
      border-radius: 12px;
      padding: 12px;
      margin-top: 14px;
      text-align: center;
      color: var(--muted);
      font-size: 13px;
      background: rgba(255,255,255,.02);
      transition: background .12s linear, border-color .12s linear;
    }
    .dropzone.over {
      border-color: rgba(34,197,94,.85);
      background: rgba(34,197,94,.10);
      color: var(--text);
    }
    .staged {
      list-style: none;
      margin: 8px 0 0;
      padding: 0;
      display: grid;
      gap: 6px;
      max-height: 150px;
      overflow-y: auto;
      scrollbar-gutter: stable;
    }
    .stagedRow {
      display: grid;
      grid-template-columns: minmax(0, 1fr) auto;
      gap: 8px;
      align-items: center;
      font-size: 13px;
      color: var(--muted);
      background: rgba(255,255,255,.03);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 4px 8px;
    }
    .stagedName { white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
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
    /* Fixed-width digits keep counters from nudging the text beside them. */
    .mono {
      font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
      font-variant-numeric: tabular-nums;
    }
    .visually-hidden {
      position: absolute;
      width: 1px;
      height: 1px;
      margin: -1px;
      padding: 0;
      overflow: hidden;
      clip-path: inset(50%);
      white-space: nowrap;
      border: 0;
    }
    @media (prefers-reduced-motion: reduce) {
      .bar { transition: none; }
      .dropzone { transition: none; }
    }

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
      height: min(80vh, 760px);
      overflow: hidden;
      border-radius: 14px;
      border: 1px solid var(--border);
      background: rgba(16,25,43,.98);
      box-shadow: 0 18px 60px rgba(0,0,0,.45);
      padding: 14px;
      display: flex;
      flex-direction: column;
      gap: 10px;
    }
    .modalCard.expanded {
      width: min(1120px, 98vw);
      height: min(92vh, 900px);
    }
    #conflictText { min-height: 18px; }
    .confControls {
      display: flex;
      gap: 8px;
      flex-wrap: wrap;
    }
    .btn.small {
      padding: 7px 10px;
      font-size: 12px;
      font-weight: 600;
    }
    .confControls .btn.small {
      min-width: 170px;
      flex: 1 1 170px;
      text-align: center;
      justify-content: center;
    }
    .confControls .btn.small.mode-hidden {
      background: rgba(239, 68, 68, .16);
      border-color: rgba(239, 68, 68, .45);
    }
    .confControls .btn.small.mode-hidden:hover {
      background: rgba(239, 68, 68, .24);
    }
    .confList {
      border: 1px solid var(--border);
      border-radius: 12px;
      background: rgba(255,255,255,.03);
      overflow: auto;
      padding: 10px;
      min-height: 0;
      font-size: 13px;
      color: var(--muted);
    }
    .confList div { margin: 4px 0; }
    .confTools {
      display: grid;
      grid-template-rows: auto auto auto;
      gap: 6px;
      min-height: 0;
    }
    .confScopeRow {
      display: flex;
      align-items: center;
      gap: 8px;
    }
    .confScopeSelect {
      border: 1px solid var(--border);
      border-radius: 8px;
      background: rgba(16,25,43,.98);
      color: var(--text);
      padding: 6px 8px;
    }
    .confSplit {
      flex: 1;
      min-height: 0;
      display: flex;
      flex-direction: column;
      gap: 8px;
    }
    .confFilter {
      width: 100%;
      padding: 9px 10px;
      border-radius: 10px;
      border: 1px solid var(--border);
      background: rgba(255,255,255,.04);
      color: var(--text);
      outline: none;
    }
    .confFilter::placeholder { color: var(--muted); }
    .confFilterMeta {
      color: var(--muted);
      font-size: 12px;
      line-height: 1.35;
      min-height: 16px;
      white-space: normal;
      overflow-wrap: anywhere;
      margin: 0;
    }
    .confFolderSection {
      display: flex;
      flex-direction: column;
      gap: 4px;
      flex: 1;
      min-height: 0;
    }
    .confFolderSection.collapsed { display: none; }
    .confFolderList {
      border: 1px solid var(--border);
      border-radius: 10px;
      background: rgba(255,255,255,.03);
      min-height: 0;
      max-height: none;
      overflow: auto;
      padding: 4px;
      display: grid;
      gap: 3px;
      align-content: start;
      font-size: 13px;
      flex: 1;
    }
    .confFolderRow {
      display: grid;
      grid-template-columns: minmax(0, 1fr) auto;
      gap: 6px;
      align-items: center;
      padding: 2px 4px;
      border-radius: 8px;
      background: rgba(255,255,255,.02);
      border: 1px solid transparent;
    }
    .confFolderRow.state-overwrite {
      background: rgba(34, 197, 94, .12);
      border-color: rgba(34, 197, 94, .40);
    }
    .confFolderRow.state-mixed {
      background: rgba(245, 158, 11, .14);
      border-color: rgba(245, 158, 11, .44);
    }
    .confFolderName {
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
      line-height: 1.2;
    }
    .confFolderSelect {
      border: 1px solid var(--border);
      border-radius: 8px;
      background: rgba(16,25,43,.98) !important;
      color: var(--text);
      padding: 3px 6px;
      line-height: 1.2;
    }
    .confFileSection {
      flex: 1;
      min-height: 0;
      display: flex;
    }
    .confFileSection.collapsed { display: none; }
    .confFileSection .confList {
      width: 100%;
      height: 100%;
    }
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
    <h1>Local Upload Server</h1>
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
        <h2>Folders (keep structure)</h2>
        <form id="folderForm">
          <input type="file" id="folderInput" webkitdirectory directory multiple />
          <div class="row">
            <button class="btn" type="submit">Add to queue</button>
            <button class="btn secondary" id="folderClearBtn" type="button">Clear</button>
          </div>
          <div class="meta" id="folderFileInfo"></div>
          <ul class="staged" id="folderStaged"></ul>
          <div class="meta" id="folderWarn"></div>
        </form>
      </div>
    </div>

    <div class="dropzone" id="dropZone">
      Drop files and folders here. To upload several folders at once, select them
      with <b>Ctrl</b> in your file manager and drag them in together.
    </div>

    <div class="statusbar" id="statusBar">
      <div class="statusMain">
        <div class="statusHead">
          <span class="statusTitle" id="statusTitle">Idle</span>
          <span class="statusPct mono" id="statusPct">0%</span>
        </div>
        <div class="progress" id="overallProgress" role="progressbar"
             aria-valuemin="0" aria-valuemax="100" aria-valuenow="0"
             aria-label="Overall upload progress" aria-describedby="overallStats">
          <div class="bar" id="overallBar"></div>
        </div>
        <div class="statusStats mono" id="overallStats">Nothing queued.</div>
      </div>
      <div class="statusActions">
        <button class="btn danger" id="abortBtn" type="button" disabled>Abort</button>
      </div>
    </div>
    <!-- A progressbar role does not announce its own updates, so milestones
         are pushed through this separate polite region. -->
    <p class="visually-hidden" id="progressAnnounce" role="status"
       aria-live="polite" aria-atomic="true"></p>

    <div class="card" style="margin-top:14px;">
      <div class="row" style="margin-top:0; justify-content:space-between;">
        <h2 style="margin:0;">Queue</h2>
        <button class="btn secondary small" id="clearDoneBtn" type="button">Clear finished</button>
      </div>
      <div class="hint" id="queueEmpty">No uploads yet.</div>
      <div class="meta error" id="pageError" style="display:none;"></div>
      <ul class="queue" id="queueList"></ul>
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
      <div class="confControls">
        <button class="btn secondary small" id="toggleFolderBtn" type="button">Hide folder view</button>
        <button class="btn secondary small" id="toggleFileBtn" type="button">Hide file view</button>
        <button class="btn secondary small" id="selectionFilterBtn" type="button">Selection: all</button>
        <button class="btn secondary small" id="toggleSizeBtn" type="button">Larger size</button>
      </div>
      <div class="confTools">
        <div class="confScopeRow">
          <label class="qsub mono" for="conflictScope">Search scope</label>
          <select class="confScopeSelect mono" id="conflictScope">
            <option value="files" selected>files</option>
            <option value="folders">folders</option>
            <option value="both">both</option>
          </select>
        </div>
        <input class="confFilter mono" id="conflictFilter" type="text" placeholder="Filter by path..." />
        <div class="confFilterMeta mono" id="conflictFilterMeta"></div>
      </div>
      <div class="confSplit">
        <div class="confFolderSection" id="conflictFolderSection">
          <div class="confFilterMeta mono" id="conflictFolderMeta"></div>
          <div class="confFolderList mono" id="conflictFolderList"></div>
        </div>
        <div class="confFileSection" id="conflictFileSection">
          <div class="confList mono" id="conflictList"></div>
        </div>
      </div>
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
    const MAX_FILE_RETRIES = __MAX_FILE_RETRIES__;
    const RETRY_BASE_DELAY_MS = __RETRY_BASE_DELAY_MS__;
    const UPLOAD_TIMEOUT_MS = __UPLOAD_TIMEOUT_MS__;
    const CASE_INSENSITIVE_FS = __CASE_INSENSITIVE_FS__;
    const actionLocks = new Set();
    // Id of the queue row currently being dragged, or null.
    let dragJobId = null;

    // Status bar refreshes on a clock, not on network events. Upload progress
    // events arrive in bursts (and stop completely between files), so deriving
    // the visible timer from them made it freeze and then jump many seconds.
    const TICK_MS = 250;
    // The bar moves every tick, the numbers only once a second.
    const TEXT_REFRESH_MS = 1000;
    // Throughput is smoothed with a time-constant EMA instead of a
    // since-start average, which never recovers from an early slow phase.
    const RATE_TAU_SEC = 5;
    const RATE_MIN_SAMPLE_SEC = 0.4;
    const RATE_WARMUP_MS = 3000;
    // Firefox's download manager weights a falling estimate more than a rising
    // one, so a short hiccup does not make "time left" jump upwards.
    const ETA_FALL_ALPHA = 0.3;
    const ETA_RISE_ALPHA = 0.1;
    const BASE_TITLE = document.title;

    // Time actually spent uploading, summed over every finished run. Idle
    // gaps between uploads are not part of it, so a job added hours later
    // does not inherit those hours.
    const session = { activeMs: 0, uploadedBytes: 0 };

    const rateMeter = { primed: false, startedAt: 0, lastAt: 0, lastBytes: 0, bps: 0 };
    let shownEtaSec = null;

    function smoothEta(rawSec) {
      if (shownEtaSec === null) {
        shownEtaSec = rawSec;
        return rawSec;
      }
      const diff = rawSec - shownEtaSec;
      shownEtaSec += diff * (diff < 0 ? ETA_FALL_ALPHA : ETA_RISE_ALPHA);
      return shownEtaSec;
    }

    function resetRateMeter() {
      shownEtaSec = null;
      rateMeter.primed = false;
      rateMeter.startedAt = performance.now();
      rateMeter.lastAt = 0;
      rateMeter.lastBytes = 0;
      rateMeter.bps = 0;
    }

    function sampleRateMeter(bytes, nowMs) {
      if (!rateMeter.primed) {
        rateMeter.primed = true;
        rateMeter.lastAt = nowMs;
        rateMeter.lastBytes = bytes;
        return;
      }
      const dt = (nowMs - rateMeter.lastAt) / 1000;
      if (dt < RATE_MIN_SAMPLE_SEC) return;
      const delta = bytes - rateMeter.lastBytes;
      rateMeter.lastAt = nowMs;
      rateMeter.lastBytes = bytes;
      if (delta < 0) return;
      const instant = delta / dt;
      // dt-aware alpha keeps the smoothing identical whether samples arrive
      // every 250 ms or every 3 s.
      const alpha = 1 - Math.exp(-dt / RATE_TAU_SEC);
      rateMeter.bps = rateMeter.bps > 0
        ? rateMeter.bps + alpha * (instant - rateMeter.bps)
        : instant;
    }

    // Total time the queue has really been uploading, including the run in
    // progress right now.
    function totalActiveMs() {
      let ms = session.activeMs;
      if (activeJob && activeJob.startedAt) {
        ms += Math.max(0, performance.now() - activeJob.startedAt);
      }
      return ms;
    }

    function setText(el, value) {
      if (el && el.textContent !== value) el.textContent = value;
    }

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

    function makeJob(label, kind, items) {
      return {
        id: newId().replace(/[^A-Za-z0-9._-]/g, '').slice(0, 72),
        label,
        kind,
        items,
        totalBytes: items.reduce((a, it) => a + (it.file.size || 0), 0),
        uploadedBytes: 0,
        completedBytes: 0,
        status: 'new',
        error: '',
        onExists: 'skip',
      };
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

    function sleep(ms) {
      return new Promise((resolve) => setTimeout(resolve, ms));
    }

    function withActionLock(key, fn, lockMs = 280) {
      if (actionLocks.has(key)) return;
      actionLocks.add(key);
      try {
        fn();
      } finally {
        setTimeout(() => actionLocks.delete(key), lockMs);
      }
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
      const cleaned = (p || '')
        .replace(/\\/g, '/')
        .replace(/^\/+/, '')
        .replace(/\/+/g, '/')
        .trim();
      // Folding case on a case-sensitive server would silently drop real
      // files: Makefile and makefile are two different targets on Linux.
      return CASE_INSENSITIVE_FS ? cleaned.toLowerCase() : cleaned;
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

    // Rows may only be reordered while they are still waiting. Everything
    // else (running, finished, failed) keeps its place.
    function queuedPositions() {
      const out = [];
      for (let i = 0; i < queue.length; i++) {
        if (queue[i].status === 'queued') out.push(i);
      }
      return out;
    }

    function moveJobTo(job, targetIndex) {
      const from = queue.indexOf(job);
      if (from < 0 || from === targetIndex) return false;
      queue.splice(from, 1);
      queue.splice(targetIndex, 0, job);
      return true;
    }

    // pumpQueue() always takes the first row with status 'queued', so moving a
    // row to the front of the waiting block is what actually promotes it.
    function moveJobToFront(job) {
      const positions = queuedPositions();
      if (!positions.length) return;
      if (moveJobTo(job, positions[0])) renderQueue();
    }

    function moveJobByStep(job, step) {
      const positions = queuedPositions();
      const at = positions.indexOf(queue.indexOf(job));
      if (at < 0) return;
      const neighbour = positions[at + step];
      if (neighbour === undefined) return;
      if (moveJobTo(job, neighbour)) renderQueue();
    }

    function jobSubText(job) {
      const infoBits = [];
      if (Number.isFinite(job.selectedCount) && job.selectedCount > 0) {
        infoBits.push(`selected ${job.selectedCount}`);
      }
      if (Number.isFinite(job.existsCount) && job.existsCount > 0) {
        infoBits.push(`already on server ${job.existsCount}`);
      }
      if (Number.isFinite(job.inProgressCount) && job.inProgressCount > 0) {
        infoBits.push(`currently uploading ${job.inProgressCount}`);
      }
      if (Number.isFinite(job.queuedDupCount) && job.queuedDupCount > 0) {
        infoBits.push(`already in queue ${job.queuedDupCount}`);
      }
      if (Number.isFinite(job.duplicateInSelectionCount) && job.duplicateInSelectionCount > 0) {
        infoBits.push(`duplicate in selection ${job.duplicateInSelectionCount}`);
      }
      const infoPrefix = infoBits.length ? `${infoBits.join(' • ')} • ` : '';
      const pct = job.totalBytes > 0 ? Math.floor((job.uploadedBytes / job.totalBytes) * 100) : 0;
      let extra = '';
      if (job.status === 'uploading') {
        extra = ` • ${pct}%`;
        if (job.currentPath) {
          extra += ` • file ${job.currentIndex || 0}/${job.items.length}: ${job.currentPath}`;
        }
      }
      if (job.status === 'preflight') extra = ' • checking...';
      if (job.status === 'error') extra = ` • ${job.error || 'Error'}`;
      if (job.status === 'canceled') extra = ` • ${job.error || 'Canceled'}`;
      if (job.status === 'done' && job.error) extra = ` • ${job.error}`;
      if (job.failedCount) extra += ` • failed ${job.failedCount}`;
      const dur = job.durationSec ? ` • ${formatDuration(job.durationSec)}` : '';
      return `${infoPrefix}${job.items.length} file(s), ${formatBytes(job.totalBytes)}${extra}${dur}`;
    }

    function iconButton(label, title, onClick) {
      const btn = document.createElement('button');
      btn.className = 'btn secondary icon';
      btn.type = 'button';
      btn.textContent = label;
      btn.title = title;
      btn.setAttribute('aria-label', title);
      btn.onclick = onClick;
      return btn;
    }

    function renderQueue() {
      // A full rebuild mid-drag would drop the element being dragged.
      if (dragJobId) return;
      const list = $('queueList');
      // Emptying the list resets scrollTop, which would yank the view back to
      // the top on every rebuild once the queue is long enough to scroll.
      const keepScroll = list.scrollTop;
      list.innerHTML = '';
      $('queueEmpty').style.display = queue.length ? 'none' : 'block';
      const positions = queuedPositions();

      for (const job of queue) {
        const li = document.createElement('li');
        li.className = 'qitem';
        if (job.status === 'uploading') li.classList.add('active');
        job._el = li;

        const left = document.createElement('div');
        left.className = 'qleft';

        const title = document.createElement('div');
        title.className = 'qtitle';
        if (job.status === 'queued' && positions.length > 1) {
          const grip = document.createElement('span');
          grip.className = 'qgrip';
          grip.textContent = '⠿ ';
          grip.title = 'Drag to reorder';
          title.appendChild(grip);
        }
        title.appendChild(document.createTextNode(job.label));

        const sub = document.createElement('div');
        sub.className = 'qsub mono';
        sub.textContent = jobSubText(job);
        job._sub = sub;

        left.appendChild(title);
        left.appendChild(sub);

        if (job.status === 'uploading') {
          const track = document.createElement('div');
          track.className = 'progress qbar';
          const bar = document.createElement('div');
          bar.className = 'bar';
          bar.style.width = `${jobPercent(job)}%`;
          track.appendChild(bar);
          left.appendChild(track);
          job._bar = bar;
        } else {
          job._bar = null;
        }

        const actions = document.createElement('div');
        actions.className = 'qactions';
        actions.innerHTML = statusBadge(job);

        if (job.status === 'queued') {
          if (positions.length > 1) {
            const at = positions.indexOf(queue.indexOf(job));
            const top = iconButton('⤒', 'Upload this next', () =>
              withActionLock(`top:${job.id}`, () => moveJobToFront(job)));
            top.disabled = at <= 0;
            const up = iconButton('↑', 'Move up', () =>
              withActionLock(`up:${job.id}`, () => moveJobByStep(job, -1)));
            up.disabled = at <= 0;
            const down = iconButton('↓', 'Move down', () =>
              withActionLock(`down:${job.id}`, () => moveJobByStep(job, 1)));
            down.disabled = at < 0 || at >= positions.length - 1;
            actions.appendChild(top);
            actions.appendChild(up);
            actions.appendChild(down);

            li.draggable = true;
            li.addEventListener('dragstart', (ev) => {
              dragJobId = job.id;
              li.classList.add('dragging');
              if (ev.dataTransfer) {
                ev.dataTransfer.effectAllowed = 'move';
                // Firefox only starts a drag when some data is set.
                ev.dataTransfer.setData('text/plain', job.id);
              }
            });
            li.addEventListener('dragend', () => {
              dragJobId = null;
              li.classList.remove('dragging');
              renderQueue();
            });
            li.addEventListener('dragover', (ev) => {
              if (!dragJobId || dragJobId === job.id) return;
              const dragged = queue.find(j => j.id === dragJobId);
              if (!dragged || dragged.status !== 'queued') return;
              ev.preventDefault();
              if (ev.dataTransfer) ev.dataTransfer.dropEffect = 'move';
              li.classList.add('dropTarget');
            });
            li.addEventListener('dragleave', () => li.classList.remove('dropTarget'));
            li.addEventListener('drop', (ev) => {
              ev.preventDefault();
              li.classList.remove('dropTarget');
              const dragged = queue.find(j => j.id === dragJobId);
              dragJobId = null;
              if (!dragged || dragged === job || dragged.status !== 'queued') return;
              const target = queue.indexOf(job);
              if (target < 0) return;
              moveJobTo(dragged, target);
              renderQueue();
            });
          }

          const btn = document.createElement('button');
          btn.className = 'btn danger';
          btn.type = 'button';
          btn.textContent = 'Remove';
          btn.onclick = (ev) => {
            const target = ev && ev.currentTarget ? ev.currentTarget : null;
            if (target) target.disabled = true;
            withActionLock(`remove:${job.id}`, () => {
              const idx = queue.indexOf(job);
              if (idx >= 0) queue.splice(idx, 1);
              renderQueue();
            });
          };
          actions.appendChild(btn);
        } else if (job.status === 'done' || job.status === 'error' || job.status === 'canceled') {
          if ((job.status === 'error' || job.status === 'canceled') && (job.items || []).some(it => !it.done && !it.skipped)) {
            const retryBtn = document.createElement('button');
            retryBtn.className = 'btn';
            retryBtn.type = 'button';
            retryBtn.textContent = 'Retry';
            retryBtn.onclick = (ev) => {
              const target = ev && ev.currentTarget ? ev.currentTarget : null;
              if (target) target.disabled = true;
              withActionLock(`retry:${job.id}`, () => retryJob(job), 420);
            };
            actions.appendChild(retryBtn);
          }
          const btn = document.createElement('button');
          btn.className = 'btn secondary';
          btn.type = 'button';
          btn.textContent = 'Hide';
          btn.onclick = (ev) => {
            const target = ev && ev.currentTarget ? ev.currentTarget : null;
            if (target) target.disabled = true;
            withActionLock(`hide:${job.id}`, () => {
              const idx = queue.indexOf(job);
              if (idx >= 0) queue.splice(idx, 1);
              renderQueue();
            });
          };
          actions.appendChild(btn);
        }

        li.appendChild(left);
        li.appendChild(actions);
        list.appendChild(li);
      }
      list.scrollTop = keepScroll;
      // The row elements the status bar patches were just replaced, so the
      // summary is refreshed from the new ones straight away.
      renderStatus(true);
    }

    function jobPercent(job) {
      if (!job || !(job.totalBytes > 0)) return 0;
      return Math.min(100, (job.uploadedBytes / job.totalBytes) * 100);
    }

    function getOverallTotals() {
      let totalBytes = 0;
      let uploadedBytes = 0;
      let totalFiles = 0;
      let doneFiles = 0;
      let pendingJobs = 0;
      for (const job of queue) {
        const items = job.items || [];
        if (job.status === 'error' || job.status === 'canceled') {
          // Nothing more will be sent for these, so count only what really
          // went over the wire. Otherwise the bar could never reach 100%.
          const sent = job.uploadedBytes || 0;
          totalBytes += sent;
          uploadedBytes += sent;
          const finished = items.filter(it => it.done || it.skipped).length;
          totalFiles += finished;
          doneFiles += finished;
          continue;
        }
        totalBytes += job.totalBytes || 0;
        uploadedBytes += job.uploadedBytes || 0;
        totalFiles += items.length;
        doneFiles += items.filter(it => it.done || it.skipped).length;
        if (job.status === 'queued' || job.status === 'preflight') pendingJobs += 1;
      }
      return { totalBytes, uploadedBytes, totalFiles, doneFiles, pendingJobs };
    }

    let lastTextAt = 0;
    let lastAnnouncedPct = -1;

    function renderStatus(force) {
      const totals = getOverallTotals();
      const rawPct = totals.totalBytes > 0
        ? Math.min(100, (totals.uploadedBytes / totals.totalBytes) * 100)
        : 0;
      // The browser counts bytes handed to the socket, so the bar can hit 100%
      // while the server is still writing the last file. Holding just short of
      // full until every file is acknowledged avoids a bar that looks finished
      // for minutes.
      const pct = totals.doneFiles < totals.totalFiles ? Math.min(rawPct, 99) : rawPct;
      const pctWhole = Math.floor(pct);

      // The bar follows every tick; the numbers below it do not, so they stay
      // readable instead of flickering four times a second.
      $('overallBar').style.width = `${pct}%`;
      const track = $('overallProgress');
      if (track) track.setAttribute('aria-valuenow', String(pctWhole));
      if (activeJob && activeJob._bar) {
        activeJob._bar.style.width = `${jobPercent(activeJob)}%`;
      }

      const now = performance.now();
      // Sampled here rather than in the ticker: a backgrounded tab has its
      // timers throttled, but per-file renders keep coming, so the meter
      // still gets fed. The interval guard inside it ignores the extras.
      if (activeJob) sampleRateMeter(activeJob.uploadedBytes || 0, now);

      if (!force && now - lastTextAt < TEXT_REFRESH_MS) return;
      lastTextAt = now;

      setText($('statusPct'), `${pctWhole}%`);
      const elapsedText = formatDuration(totalActiveMs() / 1000);

      if (activeJob) {
        setText($('statusTitle'), activeJob.label);
        const remainingBytes = Math.max(0, totals.totalBytes - totals.uploadedBytes);
        // An estimate from the first fraction of a second is noise, so it is
        // withheld until the meter has seen a usable stretch of transfer.
        const warm = rateMeter.bps > 0 && (now - rateMeter.startedAt) >= RATE_WARMUP_MS;
        const eta = warm ? smoothEta(remainingBytes / rateMeter.bps) : 0;
        const bits = [
          `${formatBytes(totals.uploadedBytes)} / ${formatBytes(totals.totalBytes)}`,
          `${totals.doneFiles}/${totals.totalFiles} files`,
          formatSpeed(rateMeter.bps),
          `upload time ${elapsedText}`,
          `eta ${eta > 0 ? formatDuration(eta) : '--'}`,
        ];
        if (totals.pendingJobs > 0) bits.push(`${totals.pendingJobs} waiting`);
        setText($('overallStats'), bits.join(' • '));
        if (track) {
          track.setAttribute('aria-valuetext',
            `${pctWhole} percent, ${totals.doneFiles} of ${totals.totalFiles} files`);
        }
        setTitleProgress(`${pctWhole}%`);
        announceProgress(pctWhole, totals);
      } else {
        const waiting = totals.pendingJobs;
        setText($('statusTitle'), waiting > 0 ? `${waiting} job(s) waiting` : 'Idle');
        setText($('overallStats'),
          `uploaded ${formatBytes(session.uploadedBytes)} • total upload time ${elapsedText}`);
        if (track) track.setAttribute('aria-valuetext', `${pctWhole} percent`);
        setTitleProgress(null);
        lastAnnouncedPct = -1;
      }

      if (activeJob && activeJob._sub) {
        setText(activeJob._sub, jobSubText(activeJob));
      }
    }

    // Announce in 10% steps only; per-percent updates would talk over the user.
    function announceProgress(pctWhole, totals) {
      const step = Math.floor(pctWhole / 10) * 10;
      if (step === lastAnnouncedPct) return;
      lastAnnouncedPct = step;
      setText($('progressAnnounce'),
        `Upload ${step} percent, ${totals.doneFiles} of ${totals.totalFiles} files done.`);
    }

    function setTitleProgress(pctText) {
      document.title = pctText ? `${pctText} • ${BASE_TITLE}` : BASE_TITLE;
    }

    let tickTimer = null;
    function startTicker() {
      if (tickTimer !== null) return;
      tickTimer = setInterval(renderStatus, TICK_MS);
    }

    function stopTicker() {
      if (tickTimer === null) return;
      clearInterval(tickTimer);
      tickTimer = null;
    }

    let conflictChain = Promise.resolve();

    function showConflictDialog(conflicts, summaryInfo = null) {
      const run = conflictChain.then(() => openConflictDialog(conflicts, summaryInfo));
      conflictChain = run.catch(() => {});
      return run;
    }

    function openConflictDialog(conflicts, summaryInfo = null) {
      return new Promise((resolve) => {
        const modal = $('conflictModal');
        const modalCard = modal.querySelector('.modalCard');
        const list = $('conflictList');
        const text = $('conflictText');
        const allToggle = $('conflictAll');
        const summary = $('conflictSummary');
        const scopeSelect = $('conflictScope');
        const filterInput = $('conflictFilter');
        const filterMeta = $('conflictFilterMeta');
        const folderSection = $('conflictFolderSection');
        const folderMeta = $('conflictFolderMeta');
        const folderList = $('conflictFolderList');
        const fileSection = $('conflictFileSection');
        const toggleFolderBtn = $('toggleFolderBtn');
        const toggleFileBtn = $('toggleFileBtn');
        const selectionFilterBtn = $('selectionFilterBtn');
        const toggleSizeBtn = $('toggleSizeBtn');
        list.textContent = '';
        folderList.textContent = '';
        allToggle.checked = false;
        scopeSelect.value = 'files';
        filterInput.value = '';
        let selectionMode = 'all';
        folderSection.classList.remove('collapsed');
        fileSection.classList.remove('collapsed');
        if (modalCard) {
          modalCard.classList.remove('expanded');
        }

        const refreshSectionButtons = () => {
          const folderCollapsed = folderSection.classList.contains('collapsed');
          const fileCollapsed = fileSection.classList.contains('collapsed');
          const expanded = !!(modalCard && modalCard.classList.contains('expanded'));
          toggleFolderBtn.textContent = folderCollapsed ? 'Show folder view' : 'Hide folder view';
          toggleFileBtn.textContent = fileCollapsed ? 'Show file view' : 'Hide file view';
          toggleSizeBtn.textContent = expanded ? 'Compact size' : 'Larger size';
          toggleFolderBtn.classList.toggle('mode-hidden', folderCollapsed);
          toggleFileBtn.classList.toggle('mode-hidden', fileCollapsed);
        };
        const updateSelectionButton = () => {
          const label =
            selectionMode === 'selected'
              ? 'Selection: selected'
              : selectionMode === 'unselected'
                ? 'Selection: unselected'
                : 'Selection: all';
          selectionFilterBtn.textContent = label;
          selectionFilterBtn.classList.remove('mode-selected', 'mode-unselected');
          if (selectionMode === 'selected') {
            selectionFilterBtn.classList.add('mode-selected');
          } else if (selectionMode === 'unselected') {
            selectionFilterBtn.classList.add('mode-unselected');
          }
        };
        toggleFolderBtn.onclick = () => {
          const folderCollapsed = folderSection.classList.contains('collapsed');
          const fileCollapsed = fileSection.classList.contains('collapsed');
          if (folderCollapsed) {
            folderSection.classList.remove('collapsed');
          } else {
            folderSection.classList.add('collapsed');
            if (fileCollapsed) fileSection.classList.remove('collapsed');
          }
          refreshSectionButtons();
        };
        toggleFileBtn.onclick = () => {
          const fileCollapsed = fileSection.classList.contains('collapsed');
          const folderCollapsed = folderSection.classList.contains('collapsed');
          if (fileCollapsed) {
            fileSection.classList.remove('collapsed');
          } else {
            fileSection.classList.add('collapsed');
            if (folderCollapsed) folderSection.classList.remove('collapsed');
          }
          refreshSectionButtons();
        };
        selectionFilterBtn.onclick = () => {
          if (selectionMode === 'all') selectionMode = 'selected';
          else if (selectionMode === 'selected') selectionMode = 'unselected';
          else selectionMode = 'all';
          updateSelectionButton();
          applyFilter();
        };
        toggleSizeBtn.onclick = () => {
          if (modalCard) modalCard.classList.toggle('expanded');
          refreshSectionButtons();
        };
        updateSelectionButton();
        refreshSectionButtons();

        const getFolderKey = (rawPath) => {
          const p = (rawPath || '')
            .replace(/\\/g, '/')
            .replace(/^\/+/, '')
            .replace(/\/+/g, '/')
            .trim();
          if (!p) return '';
          const idx = p.lastIndexOf('/');
          return idx >= 0 ? p.slice(0, idx) : '';
        };

        const refreshEntryVisual = (entry) => {
          const isOn = !!entry.cb.checked;
          entry.row.className = `confRow ${isOn ? 'overwrite' : 'skip'}`;
          entry.tag.textContent = entry.locked
            ? 'in progress'
            : (isOn ? 'overwrite' : 'keep');
        };

        const entries = [];
        const folderControls = new Map();
        const folderRows = new Map();
        const fragment = document.createDocumentFragment();
        for (const c of conflicts) {
          const rawPath = c.rel_path || c.path || '';
          const reason = c.reason || 'exists';
          const locked = reason === 'in_progress' || reason === 'duplicate_in_request';
          const row = document.createElement('label');
          const cb = document.createElement('input');
          cb.type = 'checkbox';
          cb.checked = false;
          const name = document.createElement('div');
          name.textContent = rawPath;
          const tag = document.createElement('div');
          const entry = {
            cb,
            row,
            tag,
            path: c.path,
            rel_path: c.rel_path,
            nameNorm: rawPath.toLowerCase(),
            folderKey: getFolderKey(rawPath),
            locked,
          };

          const updateRow = () => {
            refreshEntryVisual(entry);
            syncFolderControls();
            applyFilter();
          };

          if (locked) {
            cb.disabled = true;
            cb.checked = false;
          }
          cb.addEventListener('change', updateRow);
          row.appendChild(cb);
          row.appendChild(name);
          row.appendChild(tag);
          fragment.appendChild(row);
          refreshEntryVisual(entry);
          entries.push(entry);
        }
        list.appendChild(fragment);

        const folderStats = new Map();
        for (const ent of entries) {
          const key = ent.folderKey;
          const rec = folderStats.get(key) || { count: 0, locked: 0 };
          rec.count += 1;
          if (ent.locked) rec.locked += 1;
          folderStats.set(key, rec);
        }
        const folderKeys = Array.from(folderStats.keys()).sort((a, b) => {
          if (!a) return -1;
          if (!b) return 1;
          return a.localeCompare(b);
        });
        const editableFolders = folderKeys.filter((k) => {
          const rec = folderStats.get(k);
          return !!rec && rec.locked < rec.count;
        }).length;
        folderMeta.textContent = folderKeys.length
          ? `Folder rules: ${editableFolders}/${folderKeys.length} editable folder(s).`
          : 'Folder rules: no folders found.';

        const syncFolderControls = () => {
          const refreshFolderControlVisual = (select) => {
            if (!select) return;
            const row = select.closest('.confFolderRow');
            if (row) row.classList.remove('state-overwrite', 'state-mixed');
            if (select.value === 'overwrite') {
              if (row) row.classList.add('state-overwrite');
            } else if (select.value === 'mixed') {
              if (row) row.classList.add('state-mixed');
            }
          };

          folderControls.forEach((select, folderKey) => {
            const unlocked = entries.filter(ent => ent.folderKey === folderKey && !ent.locked);
            if (unlocked.length === 0) return;
            const checkedCount = unlocked.reduce((n, ent) => n + (ent.cb.checked ? 1 : 0), 0);
            if (checkedCount === 0) {
              select.value = 'keep';
            } else if (checkedCount === unlocked.length) {
              select.value = 'overwrite';
            } else {
              select.value = 'mixed';
            }
            refreshFolderControlVisual(select);
          });
        };

        const applyFolderRule = (folderKey, mode) => {
          const toOverwrite = mode === 'overwrite';
          for (const ent of entries) {
            if (ent.folderKey !== folderKey) continue;
            if (ent.locked) continue;
            ent.cb.checked = toOverwrite;
            refreshEntryVisual(ent);
          }
          syncFolderControls();
          applyFilter();
        };

        const folderFrag = document.createDocumentFragment();
        for (const folderKey of folderKeys) {
          const rec = folderStats.get(folderKey) || { count: 0, locked: 0 };
          const row = document.createElement('div');
          row.className = 'confFolderRow';
          const name = document.createElement('div');
          name.className = 'confFolderName';
          const folderLabel = folderKey || '(root)';
          const suffix = rec.locked > 0 ? ` (${rec.count} files, ${rec.locked} locked)` : ` (${rec.count} files)`;
          name.textContent = `${folderLabel}${suffix}`;

          const select = document.createElement('select');
          select.className = 'confFolderSelect mono';
          const optKeep = document.createElement('option');
          optKeep.value = 'keep';
          optKeep.textContent = 'keep';
          const optOverwrite = document.createElement('option');
          optOverwrite.value = 'overwrite';
          optOverwrite.textContent = 'overwrite';
          const optMixed = document.createElement('option');
          optMixed.value = 'mixed';
          optMixed.textContent = 'mixed';
          optMixed.disabled = true;
          select.appendChild(optKeep);
          select.appendChild(optOverwrite);
          select.appendChild(optMixed);
          select.value = 'keep';
          if (rec.locked >= rec.count) {
            select.disabled = true;
          }
          select.onchange = () => {
            if (select.value === 'mixed') return;
            applyFolderRule(folderKey, select.value);
          };
          folderControls.set(folderKey, select);
          folderRows.set(folderKey, {
            row,
            folderNorm: folderLabel.toLowerCase(),
          });

          row.appendChild(name);
          row.appendChild(select);
          folderFrag.appendChild(row);
        }
        folderList.appendChild(folderFrag);

        const existsCount = conflicts.filter(c => (c.reason || 'exists') === 'exists').length;
        const inProgressCount = conflicts.filter(c => c.reason === 'in_progress').length;
        const dupReqCount = conflicts.filter(c => c.reason === 'duplicate_in_request').length;
        const selectedCount = summaryInfo && Number.isFinite(summaryInfo.selectedCount)
          ? Number(summaryInfo.selectedCount)
          : null;
        const queuedDupCount = summaryInfo && Number.isFinite(summaryInfo.queuedDupCount)
          ? Number(summaryInfo.queuedDupCount)
          : 0;
        const infoParts = [];
        if (selectedCount !== null) infoParts.push(`selected: ${selectedCount}`);
        if (existsCount > 0) infoParts.push(`already on server: ${existsCount}`);
        if (inProgressCount > 0) infoParts.push(`currently uploading: ${inProgressCount}`);
        if (queuedDupCount > 0) infoParts.push(`already in queue: ${queuedDupCount}`);
        if (dupReqCount > 0) infoParts.push(`duplicate in selection: ${dupReqCount}`);
        const summaryText = infoParts.length ? ` (${infoParts.join(' • ')})` : '';
        text.textContent = `${conflicts.length} conflict(s) found${summaryText}. Choose what to do (file-level and folder-level rules available).`;
        modal.classList.add('show');

        const updateSummary = () => {
          let overwrite = 0;
          let visible = 0;
          let visibleOverwrite = 0;
          for (const ent of entries) {
            const isVisible = ent.row.style.display !== 'none';
            if (ent.cb.checked) overwrite++;
            if (isVisible) {
              visible += 1;
              if (ent.cb.checked) visibleOverwrite += 1;
            }
          }
          const keep = entries.length - overwrite;
          const visibleKeep = visible - visibleOverwrite;
          summary.textContent =
            `Overwrite: ${overwrite} • Keep: ${keep} • Visible overwrite: ${visibleOverwrite} • Visible keep: ${visibleKeep}`;
        };

        const syncAllToggleState = () => {
          // Rows hidden by the selection filter are deliberately excluded:
          // one click on "Overwrite all" must never flip rows off screen.
          const targets = entries.filter((ent) => !ent.cb.disabled && !!ent._visibleMatch);
          const selectedAny = entries.some((ent) => !ent.cb.disabled && !!ent.cb.checked);
          if (targets.length === 0) {
            allToggle.checked = false;
            allToggle.indeterminate = selectedAny;
            allToggle.disabled = true;
            return;
          }
          const checkedCount = targets.reduce((n, ent) => n + (ent.cb.checked ? 1 : 0), 0);
          allToggle.disabled = false;
          allToggle.checked = checkedCount === targets.length;
          allToggle.indeterminate =
            (checkedCount > 0 && checkedCount < targets.length)
            || (checkedCount === 0 && selectedAny);
        };

        const applyFilter = () => {
          const q = (filterInput.value || '').trim().toLowerCase();
          const scope = scopeSelect.value || 'files';
          const searchFiles = scope === 'files' || scope === 'both';
          const searchFolders = scope === 'folders' || scope === 'both';
          const folderMatch = new Map();
          folderRows.forEach((meta, key) => {
            if (!q) {
              folderMatch.set(key, true);
              return;
            }
            folderMatch.set(key, searchFolders && meta.folderNorm.includes(q));
          });

          let visible = 0;
          const visibleByFolder = new Map();
          for (const ent of entries) {
            const selectionMatch =
              selectionMode === 'all'
                ? true
                : selectionMode === 'selected'
                  ? !!ent.cb.checked
                  : !ent.cb.checked;
            let searchMatch = true;
            if (q) {
              const fileMatch = searchFiles && ent.nameNorm.includes(q);
              const folderMatched = !!folderMatch.get(ent.folderKey);
              if (scope === 'files') searchMatch = fileMatch;
              else if (scope === 'folders') searchMatch = folderMatched;
              else searchMatch = fileMatch || folderMatched;
            }
            const visibleMatch = searchMatch && selectionMatch;
            ent._visibleMatch = visibleMatch;
            ent.row.style.display = visibleMatch ? '' : 'none';
            if (visibleMatch) {
              visible += 1;
              visibleByFolder.set(ent.folderKey, (visibleByFolder.get(ent.folderKey) || 0) + 1);
            }
          }

          let visibleFolders = 0;
          folderRows.forEach((meta, key) => {
            const hasVisibleFiles = (visibleByFolder.get(key) || 0) > 0;
            const show = hasVisibleFiles;
            meta.row.style.display = show ? '' : 'none';
            if (show) visibleFolders += 1;
          });

          const scopeLabel = scope === 'files' ? 'files' : (scope === 'folders' ? 'folders' : 'both');
          const selLabel =
            selectionMode === 'selected'
              ? 'selected'
              : selectionMode === 'unselected'
                ? 'unselected'
                : 'all';
          filterMeta.textContent = q
            ? `Filter (${scopeLabel}, ${selLabel}): files ${visible}/${entries.length}, folders ${visibleFolders}/${folderRows.size}`
            : `Visible (${scopeLabel}, ${selLabel}): files ${visible}/${entries.length}, folders ${visibleFolders}/${folderRows.size}`;
          updateSummary();
          syncAllToggleState();
        };
        filterInput.oninput = applyFilter;
        scopeSelect.onchange = applyFilter;
        applyFilter();

        allToggle.onchange = () => {
          entries.forEach((ent) => {
            if (ent.cb.disabled) return;
            if (!ent._visibleMatch) return;
            ent.cb.checked = allToggle.checked;
            refreshEntryVisual(ent);
          });
          syncFolderControls();
          applyFilter();
        };

        syncFolderControls();

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
        const res = await fetch('api/preflight', {
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
      const selectedCount = (job.items || []).length;
      job.selectedCount = selectedCount;
      job.queuedDupCount = 0;
      job.existsCount = 0;
      job.inProgressCount = 0;
      job.duplicateInSelectionCount = 0;
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
      job.queuedDupCount = skippedDuplicates;
      job.totalBytes = job.items.reduce((a, it) => a + (it.file.size || 0), 0);
      if (skippedDuplicates > 0) {
        showPageError(
          `Selected ${selectedCount} file(s): ${skippedDuplicates} already queued/in-progress and skipped.`
        );
      }
      if (job.items.length === 0) {
        job.status = 'done';
        job.error = `Nothing new in queue (selected ${selectedCount}, duplicate targets ${skippedDuplicates}).`;
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
        job.existsCount = conflicts.filter(c => (c.reason || 'exists') === 'exists').length;
        job.inProgressCount = conflicts.filter(c => c.reason === 'in_progress').length;
        job.duplicateInSelectionCount = conflicts.filter(c => c.reason === 'duplicate_in_request').length;
        const choice = await showConflictDialog(conflicts, {
          selectedCount,
          queuedDupCount: skippedDuplicates,
        });
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
          const existsCount = (conflicts || []).filter(c => (c.reason || 'exists') === 'exists').length;
          job.error = `Nothing to upload (selected ${selectedCount}, already on server ${existsCount}, skipped ${selectedCount - job.items.length}).`;
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
        xhr.timeout = UPLOAD_TIMEOUT_MS > 0 ? UPLOAD_TIMEOUT_MS : 0;
        xhr.open('POST', `api/upload?${params.toString()}`, true);
        xhr.setRequestHeader('Content-Type', 'application/octet-stream');

        // Progress events only carry data; the ticker owns every redraw.
        xhr.upload.onprogress = (e) => {
          if (!e.lengthComputable) return;
          job.currentIndex = fileIndex;
          job.currentPath = item.path;
          job.uploadedBytes = Math.min(job.totalBytes, job.completedBytes + e.loaded);
        };

        xhr.onload = () => {
          // Anything thrown in here would leave the promise unsettled and the
          // whole queue stuck forever, so the body is wrapped.
          try {
            const resp = xhr.response || null;
            if (xhr.status === 409 && resp && (resp.error === 'exists' || resp.error === 'in_progress')) {
              resolve({ skipped: true, rel_path: resp.rel_path || item.path });
              return;
            }
            const ok = xhr.status === 200 && resp && resp.ok;
            if (!ok) {
              // responseText must not be touched while responseType is 'json':
              // per spec the getter throws InvalidStateError.
              const msg = (resp && resp.error) ? resp.error : `HTTP ${xhr.status}`;
              const err = new Error(msg);
              err.code = xhr.status >= 500 ? 'http_5xx' : 'http_error';
              err.status = xhr.status;
              reject(err);
              return;
            }
            resolve(resp);
          } catch (err) {
            reject(err instanceof Error ? err : new Error(String(err)));
          }
        };
        xhr.onerror = () => {
          const err = new Error('Network error during upload');
          err.code = 'network';
          reject(err);
        };
        xhr.ontimeout = () => {
          const err = new Error('Upload timeout');
          err.code = 'timeout';
          reject(err);
        };
        xhr.onabort = () => {
          const err = new Error('Upload canceled');
          err.code = 'aborted';
          reject(err);
        };
        xhr.send(item.file);
      });
    }

    function isRetriableError(err) {
      if (!err) return false;
      // 429 is the server saying "another upload from this IP is running" —
      // exactly the transient case worth waiting out. Anything else in the 4xx
      // range would fail identically on every attempt.
      return err.code === 'network' || err.code === 'timeout'
        || err.code === 'http_5xx' || err.status === 429;
    }

    async function uploadFileWithRetry(job, item, fileIndex) {
      let attempt = 0;
      while (true) {
        try {
          item.lastError = '';
          return await uploadFile(job, item, fileIndex);
        } catch (err) {
          if (job.status === 'canceled') throw err;
          const canRetry = isRetriableError(err) && attempt < MAX_FILE_RETRIES;
          if (!canRetry) throw err;
          attempt += 1;
          item.lastError = `${err.message || String(err)} (retry ${attempt}/${MAX_FILE_RETRIES})`;
          renderQueue();
          await sleep(RETRY_BASE_DELAY_MS * attempt);
          // Abort during the backoff cannot cancel an XHR that already
          // finished, so without this check the retry would start a fresh
          // upload after the user cancelled.
          if (job.status === 'canceled') throw err;
        }
      }
    }

    function retryJob(job) {
      if (job.status === 'uploading') return;
      for (const item of (job.items || [])) {
        if (item.done || item.skipped) continue;
        item.failed = false;
        item.lastError = '';
      }
      job.status = 'queued';
      job.error = '';
      job.durationSec = 0;
      job.failedCount = 0;
      renderQueue();
      pumpQueue();
    }

    async function runJob(job) {
      job.status = 'uploading';
      job.startedAt = performance.now();
      job.completedBytes = 0;
      for (const item of (job.items || [])) {
        if (item.done || item.skipped) {
          job.completedBytes += (item.file.size || 0);
        }
      }
      job.uploadedBytes = job.completedBytes;
      job.currentIndex = 0;
      job.currentPath = '';
      job.failedCount = 0;
      // A resumed job starts with bytes already on the server. Without this
      // reset the meter would divide them by a fresh clock and report an
      // absurd speed (and an ETA of almost zero).
      resetRateMeter();
      startTicker();
      renderQueue();

      $('abortBtn').disabled = false;
      for (let i = 0; i < job.items.length; i++) {
        if (job.status !== 'uploading') break;
        const item = job.items[i];
        if (item.done || item.skipped) continue;
        try {
          const res = await uploadFileWithRetry(job, item, i + 1);
          if (res && res.skipped) {
            item.skipped = true;
            item.done = true;
          } else {
            item.sha256 = res.sha256 || '';
            item.done = true;
            session.uploadedBytes += (item.file.size || 0);
          }
          item.failed = false;
          item.lastError = '';
          job.completedBytes += (item.file.size || 0);
          job.uploadedBytes = job.completedBytes;
          renderStatus();
        } catch (e) {
          if (job.status === 'canceled') break;
          item.failed = true;
          item.lastError = (e && e.message) ? e.message : String(e);
          job.failedCount += 1;
          renderStatus();
        }
      }

      $('abortBtn').disabled = true;
      activeXhr = null;
      job.endedAt = performance.now();
      job.durationSec = (job.endedAt - job.startedAt) / 1000;
      // Fold this run into the session total, then detach startedAt so the
      // same span cannot be counted twice by totalActiveMs().
      session.activeMs += Math.max(0, job.endedAt - job.startedAt);
      job.startedAt = null;
      stopTicker();
      if (job.status === 'uploading') {
        const remaining = (job.items || []).filter(it => !it.done && !it.skipped);
        if (remaining.length > 0) {
          job.status = 'error';
          job.error = `${remaining.length} file(s) failed. Click Retry to continue remaining files.`;
        } else {
          job.status = 'done';
        }
      }
      renderQueue();
    }

    async function pumpQueue() {
      if (activeJob) return;
      const next = queue.find(j => j.status === 'queued');
      if (!next) {
        stopTicker();
        renderStatus(true);
        return;
      }
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
      renderStatus(true);
    });

    $('clearDoneBtn').addEventListener('click', () => {
      withActionLock('clearDone', () => {
        for (let i = queue.length - 1; i >= 0; i--) {
          const s = queue[i].status;
          if (s === 'done' || s === 'error' || s === 'canceled') queue.splice(i, 1);
        }
        renderQueue();
      });
    });

    // An accidental reload throws away an hour-long queue; browsers only
    // honour this while the tab has actual work in flight.
    window.addEventListener('beforeunload', (e) => {
      const busy = activeJob || queue.some(j => j.status === 'queued' || j.status === 'preflight');
      if (!busy) return;
      e.preventDefault();
      e.returnValue = '';
    });

    $('singleFile').addEventListener('change', (e) => {
      $('singleFileInfo').textContent = summarizeSelection(e.target.files);
      $('singleFileWarn').textContent = '';
      $('singleFileWarn').className = 'meta';
      e.target.classList.remove('warn');
    });
    // The OS folder dialog can only ever return one directory, so several
    // folders are collected across picks (or dropped in together) and each
    // one becomes its own queue entry.
    const stagedFolders = [];

    function renderStaged() {
      const list = $('folderStaged');
      list.innerHTML = '';
      let files = 0;
      let bytes = 0;
      for (const folder of stagedFolders) {
        files += folder.items.length;
        bytes += folder.totalBytes;

        const li = document.createElement('li');
        li.className = 'stagedRow';
        const name = document.createElement('span');
        name.className = 'stagedName';
        name.textContent = `${folder.name} — ${folder.items.length} file(s), ${formatBytes(folder.totalBytes)}`;
        const drop = document.createElement('button');
        drop.className = 'btn secondary icon';
        drop.type = 'button';
        drop.textContent = '✕';
        drop.title = `Remove ${folder.name}`;
        drop.setAttribute('aria-label', `Remove ${folder.name}`);
        drop.onclick = () => {
          const idx = stagedFolders.indexOf(folder);
          if (idx >= 0) stagedFolders.splice(idx, 1);
          renderStaged();
        };
        li.appendChild(name);
        li.appendChild(drop);
        list.appendChild(li);
      }
      $('folderFileInfo').textContent = stagedFolders.length
        ? `${stagedFolders.length} folder(s), ${files} file(s), ${formatBytes(bytes)}`
        : '';
    }

    function stageFolder(name, items) {
      if (!items.length) return;
      const totalBytes = items.reduce((a, it) => a + (it.file.size || 0), 0);
      const existing = stagedFolders.findIndex(f => f.name === name);
      const entry = { name, items, totalBytes };
      if (existing >= 0) stagedFolders[existing] = entry;
      else stagedFolders.push(entry);
    }

    $('folderInput').addEventListener('change', (e) => {
      const files = e.target.files ? Array.from(e.target.files) : [];
      const byRoot = new Map();
      for (const f of files) {
        const rel = f.webkitRelativePath || f.name;
        const root = rel.split('/')[0] || 'Folder';
        if (!byRoot.has(root)) byRoot.set(root, []);
        byRoot.get(root).push({ file: f, path: rel });
      }
      for (const [root, items] of byRoot) stageFolder(root, items);
      // Clearing the value lets the same folder be picked again later.
      e.target.value = '';
      renderStaged();
      $('folderWarn').textContent = '';
      $('folderWarn').className = 'meta';
      e.target.classList.remove('warn');
    });

    $('folderClearBtn').addEventListener('click', () => {
      stagedFolders.length = 0;
      renderStaged();
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

      const label =
        files.length === 1
          ? `File: ${files[0].name}`
          : `Files: ${files.length} (${files[0].name} ...)`;
      const items = files.map(f => ({ file: f, path: f.name }));
      input.value = '';
      $('singleFileInfo').textContent = '';
      await enqueueJob(makeJob(label, 'files', items));
    });

    $('folderForm').addEventListener('submit', async (e) => {
      e.preventDefault();
      $('pageError').style.display = 'none';
      if (!stagedFolders.length) {
        $('folderWarn').textContent = 'Please select at least one folder first.';
        $('folderWarn').className = 'meta warn';
        $('folderInput').classList.add('warn');
        return;
      }
      const pending = stagedFolders.splice(0, stagedFolders.length);
      renderStaged();
      for (const folder of pending) {
        await enqueueJob(makeJob(`Folder: ${folder.name}`, 'folder', folder.items));
      }
    });

    async function collectEntry(entry, prefix, out) {
      if (!entry) return;
      if (entry.isFile) {
        const file = await new Promise((resolve, reject) => entry.file(resolve, reject));
        out.push({ file, path: `${prefix}${entry.name}` });
        return;
      }
      if (!entry.isDirectory) return;
      const reader = entry.createReader();
      const childPrefix = `${prefix}${entry.name}/`;
      // readEntries() hands out at most 100 children per call and signals the
      // end with an empty batch, so it has to be drained in a loop.
      for (;;) {
        const batch = await new Promise((ok, fail) => reader.readEntries(ok, fail));
        if (!batch.length) break;
        for (const child of batch) await collectEntry(child, childPrefix, out);
      }
    }

    const dropZone = $('dropZone');

    function dragHasFiles(ev) {
      // A queue row being reordered must not be mistaken for a file drop.
      if (dragJobId) return false;
      const types = ev.dataTransfer ? ev.dataTransfer.types : null;
      return !!types && Array.prototype.indexOf.call(types, 'Files') >= 0;
    }

    let dragDepth = 0;
    window.addEventListener('dragenter', (ev) => {
      if (!dragHasFiles(ev)) return;
      dragDepth += 1;
      dropZone.classList.add('over');
    });
    window.addEventListener('dragleave', (ev) => {
      if (!dragHasFiles(ev)) return;
      dragDepth = Math.max(0, dragDepth - 1);
      if (dragDepth === 0) dropZone.classList.remove('over');
    });
    window.addEventListener('dragover', (ev) => {
      if (!dragHasFiles(ev)) return;
      // Without this the browser navigates away to the dropped file.
      ev.preventDefault();
      if (ev.dataTransfer) ev.dataTransfer.dropEffect = 'copy';
    });
    window.addEventListener('drop', async (ev) => {
      if (!dragHasFiles(ev)) return;
      ev.preventDefault();
      dragDepth = 0;
      dropZone.classList.remove('over');
      $('pageError').style.display = 'none';

      const dt = ev.dataTransfer;
      // webkitGetAsEntry() has to run before this handler yields; the item
      // list is emptied as soon as the event finishes dispatching.
      const entries = dt && dt.items
        ? Array.from(dt.items)
            .filter(it => it.kind === 'file')
            .map(it => (it.webkitGetAsEntry ? it.webkitGetAsEntry() : null))
            .filter(Boolean)
        : [];

      if (!entries.length) {
        // Browser without the entries API: files only, no folder structure.
        const files = dt && dt.files ? Array.from(dt.files) : [];
        if (!files.length) return;
        const label = files.length === 1
          ? `File: ${files[0].name}`
          : `Files: ${files.length} (${files[0].name} ...)`;
        await enqueueJob(makeJob(label, 'files', files.map(f => ({ file: f, path: f.name }))));
        return;
      }

      const looseFiles = [];
      const folders = [];
      for (const entry of entries) {
        const out = [];
        try {
          await collectEntry(entry, '', out);
        } catch (err) {
          showPageError(`Could not read "${entry.name}": ${(err && err.message) || err}`);
          continue;
        }
        if (!out.length) continue;
        if (entry.isDirectory) folders.push({ name: entry.name, items: out });
        else looseFiles.push(...out);
      }

      if (looseFiles.length) {
        const label = looseFiles.length === 1
          ? `File: ${looseFiles[0].path}`
          : `Files: ${looseFiles.length} (${looseFiles[0].path} ...)`;
        await enqueueJob(makeJob(label, 'files', looseFiles));
      }
      for (const folder of folders) {
        await enqueueJob(makeJob(`Folder: ${folder.name}`, 'folder', folder.items));
      }
    });

    window.addEventListener('error', (e) => {
      showPageError(`JS error: ${e.message || e.type}`);
    });
    window.addEventListener('unhandledrejection', (e) => {
      const reason = e && e.reason ? (e.reason.message || String(e.reason)) : 'unknown';
      showPageError(`JS error: ${reason}`);
    });

    renderStaged();
    renderQueue();
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
            hosts = [DEFAULT_BIND_HOST]
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


class _UploadHTTPServer(ThreadingHTTPServer):
    # On Windows SO_REUSEADDR lets a second process bind a port that is already
    # listening. The duplicate then prints a healthy banner while every request
    # is served by the first instance, so uploads land in the wrong folder.
    allow_reuse_address = os.name != "nt"


def _sweep_stale_temp_files() -> int:
    """Delete leftover .upload_tmp_* files from uploads that never finished.

    Killing the process mid-upload strands the temp file, which can be many
    gigabytes. Only files older than an hour are touched, so a second instance
    sharing this folder is not robbed of a live upload.
    """
    removed = 0
    cutoff = time.time() - 3600
    try:
        candidates = list(UPLOAD_ROOT.rglob(f"{TEMP_PREFIX}*"))
    except OSError:
        return 0
    for path in candidates:
        try:
            if not path.is_file() or path.stat().st_mtime >= cutoff:
                continue
            path.unlink()
            removed += 1
        except OSError:
            continue
    return removed


def run_server(
    endpoints: list[tuple[str, int]],
    per_client_limit: int = DEFAULT_PER_CLIENT_LIMIT,
    retry_count: int = DEFAULT_RETRY_COUNT,
    retry_delay_ms: int = DEFAULT_RETRY_DELAY_MS,
    upload_timeout_sec: int = DEFAULT_UPLOAD_TIMEOUT_SEC,
) -> None:
    # Redirecting stdout to a file switches it to block buffering, which hides
    # the whole banner (including the LAN URL) until the process exits.
    try:
        sys.stdout.reconfigure(line_buffering=True)  # type: ignore[union-attr]
    except (AttributeError, OSError):
        pass
    UPLOAD_ROOT.mkdir(parents=True, exist_ok=True)
    STATE.set_per_ip_limit(per_client_limit)
    _HTML_CONFIG["max_file_retries"] = max(0, int(retry_count))
    _HTML_CONFIG["retry_delay_ms"] = max(0, int(retry_delay_ms))
    _HTML_CONFIG["upload_timeout_ms"] = max(0, int(upload_timeout_sec)) * 1000

    # Bind before announcing anything, so the banner can never advertise a URL
    # that failed to come up.
    servers: list[ThreadingHTTPServer] = []
    bound: list[tuple[str, int]] = []
    for host, port in endpoints:
        try:
            servers.append(_UploadHTTPServer((host, port), SimpleUploadServer))
            bound.append((host, port))
        except OSError as exc:
            print(_c(f"Failed to bind {host}:{port} -> {exc}", _ANSI_RED), flush=True)

    if not servers:
        raise SystemExit("No server socket could be started. Check host/port values.")

    swept = _sweep_stale_temp_files()

    local_ips = _get_local_ipv4_addresses()
    primary_ip = local_ips[0] if local_ips else "127.0.0.1"
    label_w = 28

    def _print_kv(label: str, value: str) -> None:
        print(f"{label + ':':<{label_w}} {value}")

    print("\n" + "=" * 60)
    print("Upload server started")
    print("=" * 60)
    _print_kv("Python", platform.python_version())
    _print_kv("OS", platform.system())
    _print_kv("Primary IP", primary_ip)
    if local_ips:
        _print_kv("Local IPv4 count", str(len(local_ips)))
        if len(local_ips) > 3:
            print("Local IPv4s:")
            for ip in local_ips:
                print(f"  - {ip}")
        else:
            _print_kv("Local IPv4s", ", ".join(local_ips))
    _print_kv(
        "Per-client concurrency",
        f"{max(1, int(per_client_limit))} upload(s) per client IP",
    )
    _print_kv(
        "Automatic retries",
        f"{_HTML_CONFIG['max_file_retries']} (base delay {_HTML_CONFIG['retry_delay_ms']} ms)",
    )
    timeout_ms = int(_HTML_CONFIG["upload_timeout_ms"])
    timeout_text = "disabled" if timeout_ms == 0 else f"{timeout_ms // 1000} s"
    _print_kv("Per-file timeout", timeout_text)
    print("Bindings:")
    for host, port in bound:
        print(f"    - {host}:{port}")
    print("\nAccess URLs:")

    def _print_access(kind: str, url: str) -> None:
        print(f"    - {kind:<8} {url}")

    for host, port in bound:
        if host in ("", "0.0.0.0"):
            _print_access("local", f"http://localhost:{port}")
            for ip in local_ips[:5]:
                _print_access("network", f"http://{ip}:{port}")
        else:
            _print_access("host", f"http://{host}:{port}")
    print()
    _print_kv("Storage path", str(UPLOAD_ROOT))
    if swept:
        _print_kv("Cleaned up", f"{swept} leftover temp file(s)")
    _print_kv("To stop", "Ctrl+C")
    print("=" * 60 + "\n", flush=True)

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


def _run_selftest() -> int:
    """Bind an ephemeral port, fetch the page, and report the result.

    A plain syntax check cannot catch a stdlib module that a newer Python has
    dropped, because that only fails on import. This starts the real server on
    the real interpreter, which is what actually needs to keep working.
    """
    import urllib.request

    httpd = ThreadingHTTPServer(("127.0.0.1", 0), SimpleUploadServer)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        url = f"http://127.0.0.1:{httpd.server_address[1]}/"
        with urllib.request.urlopen(url, timeout=10) as response:
            status = response.status
            body = response.read()
    finally:
        httpd.shutdown()
        httpd.server_close()
        thread.join(timeout=5)

    problems = []
    if status != 200:
        problems.append(f"GET / returned HTTP {status}")
    if not body[:200].lstrip().lower().startswith(b"<!doctype html"):
        problems.append("index page did not start with a HTML doctype")
    for placeholder in (
        "__MAX_FILE_RETRIES__",
        "__RETRY_BASE_DELAY_MS__",
        "__UPLOAD_TIMEOUT_MS__",
        "__CASE_INSENSITIVE_FS__",
    ):
        if placeholder.encode() in body:
            problems.append(f"unreplaced template placeholder {placeholder}")

    if problems:
        for problem in problems:
            print(_c(f"selftest FAILED: {problem}", _ANSI_RED), flush=True)
        return 1
    print(
        _c(
            f"selftest OK on Python {platform.python_version()} "
            f"({len(body)} bytes served)",
            _ANSI_GREEN,
        ),
        flush=True,
    )
    return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Local upload server (streaming, queue-based, LAN-first)."
    )
    parser.add_argument(
        "--selftest",
        action="store_true",
        help="Start on a temporary port, fetch the page once, then exit.",
    )
    parser.add_argument(
        "--host",
        type=str,
        action="append",
        default=[],
        help=(
            "Host/IP to bind with --port. Repeatable or comma-separated "
            f"(default: {DEFAULT_BIND_HOST})"
        ),
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
        default=DEFAULT_PORT,
        help=f"TCP port to listen on (default: {DEFAULT_PORT})",
    )
    parser.add_argument(
        "--per-client-limit",
        type=int,
        default=DEFAULT_PER_CLIENT_LIMIT,
        help=(
            "Max simultaneous uploads per client IP "
            f"(default: {DEFAULT_PER_CLIENT_LIMIT})"
        ),
    )
    parser.add_argument(
        "--retry-count",
        type=int,
        default=DEFAULT_RETRY_COUNT,
        help=(
            "Automatic retries per file for transient errors "
            f"(default: {DEFAULT_RETRY_COUNT})"
        ),
    )
    parser.add_argument(
        "--retry-delay-ms",
        type=int,
        default=DEFAULT_RETRY_DELAY_MS,
        help=(
            "Base backoff delay for automatic retries in milliseconds "
            f"(default: {DEFAULT_RETRY_DELAY_MS})"
        ),
    )
    parser.add_argument(
        "--upload-timeout-sec",
        type=int,
        default=DEFAULT_UPLOAD_TIMEOUT_SEC,
        help=(
            "Per-file upload timeout in seconds "
            f"(default: {DEFAULT_UPLOAD_TIMEOUT_SEC} = disabled)"
        ),
    )
    args = parser.parse_args()
    if args.selftest:
        raise SystemExit(_run_selftest())
    try:
        endpoints = _build_bind_endpoints(args.host, args.port, args.listen)
    except ValueError as exc:
        parser.error(str(exc))
    if args.retry_count < 0:
        parser.error("--retry-count must be >= 0")
    if args.retry_delay_ms < 0:
        parser.error("--retry-delay-ms must be >= 0")
    if args.upload_timeout_sec < 0:
        parser.error("--upload-timeout-sec must be >= 0 (0 disables timeout)")
    run_server(
        endpoints=endpoints,
        per_client_limit=max(1, args.per_client_limit),
        retry_count=args.retry_count,
        retry_delay_ms=args.retry_delay_ms,
        upload_timeout_sec=args.upload_timeout_sec,
    )
