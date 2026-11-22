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

from collections import OrderedDict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse
import argparse
import ctypes
import datetime as _dt
import errno
import hashlib
import hmac
import json
import os
import platform
import re
import secrets
import shutil
import socket
import tempfile
import threading
import time

UPLOAD_ROOT = Path("uploads").resolve()
STORAGE = None
# Size of the one buffer each running upload reads into.
CHUNK_SIZE = 1024 * 1024
MAX_PREFLIGHT_BYTES = 20 * 1024 * 1024
DISK_SPACE_FACTOR = 1.1
DEFAULT_BIND_HOST = "0.0.0.0"
DEFAULT_PORT = 8040
DEFAULT_PER_CLIENT_LIMIT = 1
DEFAULT_RETRY_COUNT = 3
DEFAULT_RETRY_DELAY_MS = 800
DEFAULT_UPLOAD_TIMEOUT_SEC = 0
# The browser gives up on a request that moved no data for this long and tries
# again. Must stay below BODY_IDLE_TIMEOUT_SEC so the browser, which can show
# the user what is going on, notices a dead connection before the server does.
DEFAULT_STALL_TIMEOUT_SEC = 45
# Time allowed for the request line and headers, and for sending the answer.
REQUEST_TIMEOUT_SEC = 30
# Silence tolerated in the middle of an upload before the server drops it.
# A browser may pause this long while its own disk (or a cloud-synced folder
# that still has to fetch the file) delivers the next bytes.
BODY_IDLE_TIMEOUT_SEC = 120
# How often a waiting body read looks for "stop" or "superseded".
BODY_POLL_SEC = 0.5
# A rejected request is only drained while its body keeps flowing.
DISCARD_IDLE_TIMEOUT_SEC = 10
# How long a retry waits for the upload it replaces to let go of its slot.
SUPERSEDE_WAIT_SEC = 5
# Age after which a finished/abandoned upload session is forgotten.
SESSION_TTL_SEC = 12 * 3600
# Stored files remembered for /api/status, across all jobs.
RECENT_DONE_LIMIT = 4096
TEMP_PREFIX = ".upload_tmp_"
# Control characters, including ESC, which starts terminal escape sequences.
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f-\x9f]")
MAX_NAME_BYTES = 255
# Upper bound for draining the body of a rejected request so the client can
# still read the status code. Beyond this the connection is simply closed.
MAX_DISCARD_BYTES = 64 * 1024 * 1024

_ID_RE = re.compile(r"[A-Za-z0-9._-]{6,80}")
_REASON_RE = re.compile(r"[a-z0-9_]{1,24}")
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
    if value < 1024.0:
        return f"{int(value)} B"
    for unit in ["KB", "MB", "GB", "TB"]:
        value /= 1024.0
        if value < 1024.0:
            return f"{value:.1f} {unit}"
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
        part = _sanitize_name_part(part)
        # Names with this prefix are the server's own temporary files, which
        # the start-up sweep deletes; a user's file must not look like one.
        if part.lower().startswith(TEMP_PREFIX):
            part = "_" + part
        # 255 is the limit per name on NTFS (characters) and on ext4, APFS and
        # most others (bytes); checking bytes satisfies both.
        if len(part.encode("utf-8")) > MAX_NAME_BYTES:
            raise ValueError(f"File or folder name too long: {part[:40]}...")
        parts.append(part)
    if not parts:
        raise ValueError("Empty file path")
    return "/".join(parts)


# Whether names that differ only in case are one file in the upload folder.
# Windows is assumed to be that way; run_server() replaces the assumption with
# a measurement, because macOS and mounted Windows or network folders behave
# like that under a system that otherwise does not.
_CASE_INSENSITIVE = os.name == "nt"


def _path_key(rel_path: str) -> str:
    return rel_path.lower() if _CASE_INSENSITIVE else rel_path


def _probe_case_insensitive(folder: Path) -> bool:
    """Measure whether ``folder`` treats ``A`` and ``a`` as the same name."""
    try:
        fd, name = tempfile.mkstemp(prefix=TEMP_PREFIX + "Case", dir=str(folder))
    except OSError:
        return _CASE_INSENSITIVE
    try:
        os.close(fd)
        probe = Path(name)
        return probe.with_name(probe.name.swapcase()).exists()
    finally:
        try:
            os.unlink(name)
        except OSError:
            pass


class _Superseded(Exception):
    """This upload was replaced by a newer request from the same browser tab."""


class _ActiveUpload:
    """One upload request that currently holds one of its IP's slots."""

    __slots__ = ("owner", "upload_id", "seq", "cancel")

    def __init__(self, owner: str | None, upload_id: str, seq: int) -> None:
        self.owner = owner
        self.upload_id = upload_id
        self.seq = seq
        self.cancel = threading.Event()


class _ServerState:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._changed = threading.Condition(self._lock)
        self._seen_clients: set[str] = set()
        self._sessions: dict[str, dict] = {}
        self._active: dict[str, list[_ActiveUpload]] = {}
        self._reserved_paths: dict[str, str] = {}
        self._recent_done: OrderedDict = OrderedDict()
        # Which job stored each remembered path last.
        self._done_owner: dict[str, str] = {}
        # Newest upload request per (ip, tab), by arrival order.
        self._latest: dict[tuple[str, str], int] = {}
        self._next_seq = 0
        self._per_ip_limit = 1
        # Set when the server is shutting down; body reads poll it so a
        # stalled upload ends within one poll interval on every platform.
        self.stopping = threading.Event()

    def set_per_ip_limit(self, limit: int) -> None:
        with self._lock:
            self._per_ip_limit = max(1, int(limit))

    def note_client(self, ip: str) -> bool:
        with self._lock:
            is_new = ip not in self._seen_clients
            if is_new:
                self._seen_clients.add(ip)
        return is_new

    def begin_upload(
        self, ip: str, owner: str | None, upload_id: str, wait_sec: float
    ) -> _ActiveUpload | None:
        """Claim one of this IP's upload slots, or return None when all are busy.

        A browser tab uploads strictly one file at a time and names itself in
        every request (``owner``). A second request from the same tab therefore
        proves that the tab has given up on its previous one, even if the
        server has not noticed yet because the connection died silently. The
        old upload is told to stop, and the new request waits briefly for its
        slot instead of being turned away by its own leftover.
        """
        deadline = time.monotonic() + max(0.0, wait_sec)
        key = (ip, owner) if owner else None
        with self._changed:
            self._next_seq += 1
            seq = self._next_seq
            if key:
                # Requests of one tab that are still waiting here are older
                # retries; they must give way instead of racing this one.
                self._latest[key] = seq
                self._changed.notify_all()
            while True:
                if key and self._latest.get(key) != seq:
                    return None
                entries = self._active.get(ip, [])
                mine = [e for e in entries if owner and e.owner == owner]
                for entry in mine:
                    entry.cancel.set()
                if not mine and len(entries) < self._per_ip_limit:
                    entry = _ActiveUpload(owner, upload_id, seq)
                    self._active.setdefault(ip, []).append(entry)
                    return entry
                remaining = deadline - time.monotonic()
                if not mine or remaining <= 0:
                    if key and self._latest.get(key) == seq:
                        del self._latest[key]
                    return None
                self._changed.wait(remaining)

    def is_busy(self, ip: str, owner: str) -> bool:
        """True when uploads of other tabs fill every slot of this IP."""
        with self._lock:
            others = [e for e in self._active.get(ip, []) if e.owner != owner]
            return len(others) >= self._per_ip_limit

    def end_upload(self, ip: str, entry: _ActiveUpload) -> None:
        with self._changed:
            entries = self._active.get(ip, [])
            if entry in entries:
                entries.remove(entry)
            if not entries:
                self._active.pop(ip, None)
            if entry.owner and self._latest.get((ip, entry.owner)) == entry.seq:
                del self._latest[(ip, entry.owner)]
            self._changed.notify_all()

    def stop(self, wait_sec: float = 0.0) -> None:
        """Ask every request that is still reading a body to give up.

        With ``wait_sec`` the call also waits that long for running uploads to
        remove their temporary files.
        """
        self.stopping.set()
        deadline = time.monotonic() + wait_sec
        with self._changed:
            while self._active:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                self._changed.wait(remaining)

    def upsert_session(
        self,
        upload_id: str,
        *,
        client_ip: str,
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
            previous = self._sessions.get(upload_id) or {}
            self._sessions[upload_id] = {
                "upload_id": upload_id,
                "client_ip": client_ip,
                "total_files": total_files,
                "total_bytes": total_bytes,
                "created_at": time.time(),
                # A second preflight for the same job (after the conflict
                # dialog) must not forget what was already stored.
                "files_done": int(previous.get("files_done", 0)),
                "bytes_done": int(previous.get("bytes_done", 0)),
            }

    def get_session(self, upload_id: str) -> dict | None:
        with self._lock:
            return self._sessions.get(upload_id)

    def bump_done(
        self, upload_id: str, rel_path: str, *, bytes_written: int, digest: str
    ) -> tuple[int, int, int]:
        """Record a stored file; returns (files done, total files, total bytes)."""
        path_key = _path_key(rel_path)
        key = (upload_id, path_key)
        with self._lock:
            # A file is stored again when its first answer got lost on the way
            # back and the browser retried. That must not count twice.
            repeated = key in self._recent_done
            # The job that stored a path last owns what is on disk. An earlier
            # job keeps its entry, so that a repeat of it still counts once,
            # but lookup_done() no longer reports it.
            self._done_owner[path_key] = upload_id
            self._recent_done[key] = (bytes_written, digest)
            self._recent_done.move_to_end(key)
            while len(self._recent_done) > RECENT_DONE_LIMIT:
                (old_id, old_path), _ = self._recent_done.popitem(last=False)
                if self._done_owner.get(old_path) == old_id:
                    del self._done_owner[old_path]
            session = self._sessions.get(upload_id)
            if not session:
                return (0, 0, 0)
            if not repeated:
                session["files_done"] += 1
                session["bytes_done"] += bytes_written
            return (
                int(session["files_done"]),
                int(session["total_files"]),
                int(session["total_bytes"]),
            )

    def lookup_done(self, upload_id: str, rel_path: str) -> tuple[int, str] | None:
        """Size and SHA-256 of a file this job stored recently, if any."""
        path_key = _path_key(rel_path)
        with self._lock:
            if self._done_owner.get(path_key) != upload_id:
                return None
            return self._recent_done.get((upload_id, path_key))

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
    "stall_timeout_ms": DEFAULT_STALL_TIMEOUT_SEC * 1000,
}
_HTML_PLACEHOLDERS = {
    "__MAX_FILE_RETRIES__": "max_file_retries",
    "__RETRY_BASE_DELAY_MS__": "retry_delay_ms",
    "__UPLOAD_TIMEOUT_MS__": "upload_timeout_ms",
    "__STALL_TIMEOUT_MS__": "stall_timeout_ms",
}


def _render_html() -> str:
    html = _HTML_TEMPLATE
    for placeholder, key in _HTML_PLACEHOLDERS.items():
        html = html.replace(placeholder, str(int(_HTML_CONFIG[key])))
    # Whether two paths collide depends on the server's filesystem, not on the
    # browser's, so the client is told rather than left to assume.
    html = html.replace(
        "__CASE_INSENSITIVE_FS__",
        "true" if _path_key("A") == _path_key("a") else "false",
    )
    return html


class SimpleUploadServer(BaseHTTPRequestHandler):
    server_version = "SimpleUploadServer/2026.11"
    # Applies to the request line, the headers and to sending the answer. A
    # connection that was opened but never used (browsers open spare ones)
    # frees its thread after this long.
    timeout = REQUEST_TIMEOUT_SEC
    # Longest silence tolerated in the middle of a request body.
    body_idle_timeout = BODY_IDLE_TIMEOUT_SEC
    # Headers and body leave in one segment instead of two; with Nagle's
    # algorithm the second small write would wait for the client's delayed
    # ACK, which costs up to 200 ms per answered request.
    disable_nagle_algorithm = True
    # Set by a running upload: called once, right before its answer is sent.
    _before_answer = None
    wbufsize = 64 * 1024
    # Bytes of the current request body not yet read off the socket.
    _body_remaining: int | None = None
    # True once nothing of the body is left in rfile's own buffer.
    _rfile_drained = False
    # Set by a newer request from the same tab while this one is uploading.
    _cancel: threading.Event | None = None

    def setup(self) -> None:
        super().setup()
        self.storage = getattr(self.server, "storage", STORAGE) or _LOCAL_STORAGE
        self.state = getattr(self.server, "state", STATE)

    def handle_one_request(self) -> None:
        try:
            super().handle_one_request()
        except (socket.timeout, ConnectionError):
            self.close_connection = True

    def log_message(self, format: str, *args) -> None:  # noqa: A002
        return

    def _log(self, message: str, *, color: str | None = None) -> None:
        prefix = f"[{_ts()}] "
        text = prefix + _CONTROL_RE.sub("?", message)
        if color:
            text = _c(text, color)
        try:
            try:
                print(text, flush=True)
            except UnicodeEncodeError:
                # A redirected stdout with a narrow encoding cannot show every
                # file name.
                print(
                    text.encode("ascii", "backslashreplace").decode("ascii"),
                    flush=True,
                )
        except Exception:
            # A closed or broken stdout loses the line, never the upload.
            pass

    def _client_ip(self) -> str:
        return (
            self.client_address[0] if self.client_address else "unknown"
        ) or "unknown"

    def _note_client(self) -> None:
        ip = self._client_ip()
        if self.state.note_client(ip):
            ua = self.headers.get("User-Agent")
            self._log(
                f"New client: ip={ip}" + (f" ua={ua}" if ua else ""),
                color=_ANSI_GREEN,
            )

    def _send_bytes(
        self,
        status: int,
        body: bytes,
        content_type: str,
        extra_headers: dict | None = None,
    ) -> bool:
        """Send a complete answer; False when the client was already gone."""
        # An upload gives up its slot and its path before the client can read
        # the answer. Releasing afterwards lets the client's next request,
        # sent the moment the answer arrives, find its own slot still taken.
        release, self._before_answer = self._before_answer, None
        if release is not None:
            release()
        try:
            # Reading a body leaves the short poll timeout on the socket.
            self.connection.settimeout(self.timeout)
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            for name, value in (extra_headers or {}).items():
                self.send_header(name, value)
            self.end_headers()
            self.wfile.write(body)
            self.wfile.flush()
        except (ConnectionError, socket.timeout):
            self.close_connection = True
            return False
        return True

    def _send_json(
        self, status: int, payload: dict, extra_headers: dict | None = None
    ) -> bool:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        return self._send_bytes(
            status, body, "application/json; charset=utf-8", extra_headers
        )

    def _recv_into(self, view: memoryview, idle_timeout: float | None = None) -> int:
        """Read some bytes of the request body into ``view``; return how many.

        The body is read from the socket in short polls instead of one long
        blocking call. Between polls the handler checks whether a newer request
        replaced this upload or the server is stopping, so a connection that
        went silent can be given up within half a second. Waking a blocked read
        from another thread is not portable: closing or shutting down the
        socket does not interrupt it on Windows.

        Raises ConnectionError when the client closed the connection,
        socket.timeout after ``idle_timeout`` seconds without a single byte,
        and _Superseded when a newer request took over.
        """
        sock = self.connection
        # Checked on every call, not only while waiting: an upload whose data
        # keeps arriving never reaches the waiting loop below.
        if self._cancel is not None and self._cancel.is_set():
            raise _Superseded()
        if self.state.stopping.is_set():
            raise ConnectionError("Server is stopping")
        if not self._rfile_drained:
            # Parsing the headers may have pulled the start of the body into
            # rfile's buffer. On a non-blocking socket read1() returns exactly
            # those bytes (or whatever has arrived) and never waits.
            sock.settimeout(0)
            try:
                data = self.rfile.read1(len(view))
            finally:
                sock.settimeout(BODY_POLL_SEC)
            if data:
                view[: len(data)] = data
                return len(data)
            self._rfile_drained = True
        limit = self.body_idle_timeout if idle_timeout is None else idle_timeout
        idle_since = time.monotonic()
        sock.settimeout(BODY_POLL_SEC)
        while True:
            if self._cancel is not None and self._cancel.is_set():
                raise _Superseded()
            if self.state.stopping.is_set():
                raise ConnectionError("Server is stopping")
            try:
                count = sock.recv_into(view)
            except socket.timeout:
                if time.monotonic() - idle_since >= limit:
                    raise
                continue
            except InterruptedError:
                continue
            if count == 0:
                raise ConnectionError("Client disconnected")
            return count

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
        view = memoryview(bytearray(min(remaining, 256 * 1024)))
        try:
            while remaining > 0:
                count = self._recv_into(
                    view[: min(len(view), remaining)], DISCARD_IDLE_TIMEOUT_SEC
                )
                remaining -= count
                self._body_remaining = remaining
        except (OSError, ValueError, _Superseded):
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
        length = self._declared_length() or 0
        if length <= 0:
            return b""
        if length > max_bytes:
            raise _RequestError("request too large", status=413)
        self._body_remaining = length
        data = bytearray(length)
        view = memoryview(data)
        received = 0
        while received < length:
            received += self._recv_into(view[received:])
            self._body_remaining = length - received
        return bytes(data)

    def _authorize(self) -> bool:
        token = getattr(self.server, "token", None)
        if token is None:
            return True
        parsed = urlparse(self.path)
        path = parsed.path[1:] if parsed.path.startswith("/") else parsed.path
        segment, separator, tail = path.partition("/")
        if not separator or not hmac.compare_digest(segment.encode("utf-8"), token):
            self.close_connection = True
            self._send_json(404, {"ok": False, "error": "not_found"})
            return False
        self.path = "/" + tail + ("?" + parsed.query if parsed.query else "")
        return self._valid_target()

    def _same_origin(self) -> bool:
        """False when another website made the browser send this request.

        Any page the user has open can POST to an address in the local
        network. Browsers attach the sending page's origin to such a request,
        and only this server's own page has an origin equal to the Host it was
        loaded from. Programs that are not browsers send no Origin at all.
        """
        origin = self.headers.get("Origin")
        if origin is None:
            return True
        host = (self.headers.get("Host") or "").strip().lower()
        try:
            return bool(host) and urlparse(origin).netloc.lower() == host
        except ValueError:
            return False

    def _valid_target(self) -> bool:
        """Answer 400 for a request target that cannot be parsed as a URL."""
        try:
            urlparse(self.path)
        except ValueError:
            self.close_connection = True
            self._send_json(400, {"ok": False, "error": "invalid request target"})
            return False
        return True

    def do_GET(self) -> None:
        if not self._valid_target() or not self._authorize():
            return
        self._note_client()
        parsed = urlparse(self.path)
        if parsed.path == "/":
            self._log(f"Page opened: ip={self._client_ip()}")
            self._send_bytes(
                200, _render_html().encode("utf-8"), "text/html; charset=utf-8"
            )
            return
        if parsed.path == "/api/status":
            self._handle_status(parse_qs(parsed.query))
            return
        self._log(
            f"Request: ip={self._client_ip()} method=GET route=other status=404"
        )
        self._send_json(404, {"ok": False, "error": "not_found"})

    def do_POST(self) -> None:
        if not self._valid_target() or not self._authorize():
            return
        self._note_client()
        self._body_remaining = None
        self._rfile_drained = False
        path = urlparse(self.path).path
        if path not in ("/api/preflight", "/api/upload"):
            self._log(
                f"Request: ip={self._client_ip()} method=POST route=other status=404"
            )
            self._send_json(404, {"ok": False, "error": "not_found"})
            return
        if not self._same_origin():
            self._log(
                f"Request refused: ip={self._client_ip()} status=403 "
                "reason=cross_origin",
                color=_ANSI_YELLOW,
            )
            self._discard_request_body()
            self._send_json(
                403, {"ok": False, "error": "cross-origin request refused"}
            )
            return
        if path == "/api/preflight":
            self._handle_preflight()
        else:
            self._handle_upload()

    def _handle_status(self, qs: dict) -> None:
        """Tell a client whether one file of its job is already stored.

        A browser that lost the answer to an upload cannot tell "never
        arrived" from "stored, but the reply got lost". Asking here first
        saves sending the whole file a second time.
        """
        upload_id = (qs.get("upload_id") or [""])[0].strip()
        try:
            rel_path = _sanitize_rel_path((qs.get("path") or [""])[0])
        except ValueError as exc:
            self._send_json(400, {"ok": False, "error": str(exc)})
            return
        owner = (qs.get("client") or [""])[0].strip()
        payload: dict = {
            "ok": True,
            "done": False,
            "busy": self.state.is_busy(self._client_ip(), owner),
        }
        done = self.state.lookup_done(upload_id, rel_path)
        if done is not None:
            payload.update(done=True, bytes=done[0], sha256=done[1])
        self._send_json(200, payload)

    def _handle_preflight(self) -> None:
        ip = self._client_ip()
        try:
            self.storage.initialize()

            body = self._read_body(max_bytes=MAX_PREFLIGHT_BYTES)
            data = json.loads(body.decode("utf-8")) if body else {}

            upload_id = str(data.get("upload_id") or "").strip()
            items = data.get("items") or []
            if not upload_id or not isinstance(upload_id, str):
                raise ValueError("upload_id missing")
            if not _ID_RE.fullmatch(upload_id):
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
                client_ip=ip,
                total_files=total_files,
                total_bytes=total_bytes,
            )
            self._log(
                f"Preflight: id={upload_id} ip={ip} files={total_files} "
                f"total={_format_bytes(total_bytes)} conflicts={len(conflicts)}",
                color=_ANSI_YELLOW,
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
        except (ConnectionError, socket.timeout) as e:
            # The file list itself did not arrive; there is nobody to answer.
            self.close_connection = True
            self._log(
                f"Preflight aborted: ip={ip} reason={str(e) or 'Client disconnected'}",
                color=_ANSI_YELLOW,
            )
        except Exception as e:
            status = e.status if isinstance(e, _RequestError) else 400
            self._log(
                f"Preflight error: ip={ip} status={status} err={e}",
                color=_ANSI_RED,
            )
            self._discard_request_body()
            self._send_json(status, {"ok": False, "error": str(e)})

    def _handle_upload(self) -> None:
        ip = self._client_ip()
        qs = parse_qs(urlparse(self.path).query)

        def param(name: str, default: str = "") -> str:
            return (qs.get(name) or [default])[0]

        upload_id = param("upload_id").strip()
        owner = param("client").strip()
        entry = self.state.begin_upload(
            ip,
            owner if _ID_RE.fullmatch(owner) else None,
            upload_id,
            SUPERSEDE_WAIT_SEC,
        )
        if entry is None:
            self._log(f"Upload rejected: ip={ip} status=429 reason=busy", color=_ANSI_YELLOW)
            self._discard_request_body()
            self._send_json(
                429,
                {"ok": False, "error": "Another upload from this device is running"},
                {"Retry-After": "2"},
            )
            return

        self._cancel = entry.cancel
        ticket = None
        committed = False
        path_reserved = False
        rel_path = ""
        released = False

        def release() -> None:
            # Order matters for a request that is waiting to take over: the
            # temporary file and the path must be free before the slot is.
            nonlocal released, ticket
            if released:
                return
            released = True
            if ticket is not None:
                try:
                    self.storage.abort(ticket)
                except Exception as exc:
                    self._log(f"Temporary upload cleanup failed: {exc}", color=_ANSI_RED)
                ticket = None
            if path_reserved and rel_path and upload_id:
                self.state.release_path(rel_path, upload_id)
            self._cancel = None
            self.state.end_upload(ip, entry)

        self._before_answer = release
        content_length = 0
        received = 0
        started = time.monotonic()

        def progress() -> str:
            return (
                f"received={_format_bytes(received)} of {_format_bytes(content_length)} "
                f"after {time.monotonic() - started:.1f}s"
            )

        try:
            raw_path = param("path")
            on_exists = (param("on_exists", "skip") or "skip").strip().lower()
            file_index = int(param("file_index", "0") or 0)
            attempt = param("attempt")
            retry_note = ""
            if attempt.isdigit() and 1 < int(attempt) < 1000:
                reason = param("reason")
                retry_note = f" attempt={int(attempt)}" + (
                    f" after={reason}" if _REASON_RE.fullmatch(reason) else ""
                )

            self.storage.initialize()

            if not _ID_RE.fullmatch(upload_id):
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
            declared = self._declared_length()
            if declared is None:
                raise _RequestError("missing or invalid Content-Length", status=411)
            content_length = declared
            self.storage.check_space(content_length)

            if not self.state.reserve_path(rel_path, upload_id):
                self._log(
                    f"Upload rejected: id={upload_id} ip={ip} path={rel_path} status=409 reason=in_progress",
                    color=_ANSI_YELLOW,
                )
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
                self._log(
                    f"Upload rejected: id={upload_id} ip={ip} path={rel_path} status=409 reason=exists",
                    color=_ANSI_YELLOW,
                )
                self._discard_request_body()
                self._send_json(
                    409,
                    {"ok": False, "error": "exists", "rel_path": rel_path},
                )
                return

            self._log(
                f"START id={upload_id} file[{file_index}] ip={ip} path={rel_path} "
                f"size={_format_bytes(content_length)}{retry_note}"
            )

            self._body_remaining = content_length
            stream, ticket = self.storage.begin(rel_path)
            hasher = hashlib.sha256()
            # One reusable buffer: memory per upload stays at CHUNK_SIZE no
            # matter how large the file is.
            buffer = memoryview(bytearray(min(CHUNK_SIZE, max(1, content_length))))
            with stream as f:
                while received < content_length:
                    count = self._recv_into(
                        buffer[: min(len(buffer), content_length - received)]
                    )
                    # Counted before the write: if the disk fails now, the
                    # drain must not wait for bytes that were already read.
                    received += count
                    self._body_remaining = content_length - received
                    chunk = buffer[:count]
                    f.write(chunk)
                    hasher.update(chunk)

            digest = hasher.hexdigest()
            self.storage.commit(ticket, rel_path, on_exists == "overwrite", digest)
            committed = True
            ticket = None

            done_files, total_files, total_bytes = self.state.bump_done(
                upload_id, rel_path, bytes_written=received, digest=digest
            )
            count_note = f" ({done_files}/{total_files})" if total_files > 0 else ""
            self._log(
                f"DONE  id={upload_id} file[{file_index}] ip={ip} path={rel_path} "
                f"bytes={_format_bytes(received)} in {time.monotonic() - started:.1f}s "
                f"sha256={digest}{count_note}"
            )

            delivered = self._send_json(
                200,
                {
                    "ok": True,
                    "upload_id": upload_id,
                    "rel_path": rel_path,
                    "bytes": received,
                    "sha256": digest,
                    "done_files": done_files,
                    "total_files": total_files,
                    "total_bytes": total_bytes,
                },
            )
            if not delivered:
                raise ConnectionError("Client disconnected before the answer")
            self.state.maybe_cleanup(upload_id)
        except _Superseded:
            self.close_connection = True
            self._log(
                f"Upload superseded: id={upload_id or '?'} ip={ip} path={rel_path or '?'} "
                f"{progress()} reason=client retried",
                color=_ANSI_YELLOW,
            )
        except (ConnectionError, socket.timeout) as e:
            # socket.timeout means the client stopped sending without closing
            # the connection. That is an abandoned upload, not a server fault.
            self.close_connection = True
            reason = str(e) or "Client disconnected"
            if committed:
                self._log(
                    f"Upload response disconnected: id={upload_id or '?'} ip={ip} "
                    f"path={rel_path or '?'} reason={reason}",
                    color=_ANSI_YELLOW,
                )
            else:
                self._log(
                    f"Upload aborted: id={upload_id or '?'} ip={ip} path={rel_path or '?'} "
                    f"reason={reason} {progress()}",
                    color=_ANSI_YELLOW,
                )
        except Exception as e:
            # A bad path or a full disk will fail again on every retry, so it
            # must not be reported as 5xx: the client retries those, re-sending
            # the whole file again for nothing.
            if isinstance(e, OSError) and e.errno == errno.ENOSPC:
                e = _RequestError("Not enough disk space", status=400)
            elif isinstance(e, OSError) and (
                e.errno in (errno.ENAMETOOLONG, errno.EINVAL)
                or getattr(e, "winerror", None) in (123, 206)
            ):
                # The whole path is too long or not a valid name here (Windows
                # reports that as error 123 or 206).
                e = _RequestError(
                    "The server's file system cannot store this path", status=400
                )
            status = e.status if isinstance(e, _RequestError) else (
                400 if isinstance(e, ValueError) else 500
            )
            self._log(
                f"Upload error: ip={ip} status={status} err={e}", color=_ANSI_RED
            )
            if status != 500:
                self._discard_request_body()
            self._send_json(status, {"ok": False, "error": str(e)})
        finally:
            # For every way out that sent no answer (a lost connection, a
            # superseded request).
            self._before_answer = None
            release()


_HTML_TEMPLATE = r"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <meta name="color-scheme" content="dark" />
  <!-- An empty icon: without it every visit also requests /favicon.ico. -->
  <link rel="icon" href="data:," />
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
    .card {
      background: rgba(255,255,255,.04);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 14px;
      box-shadow: 0 12px 28px rgba(0,0,0,.25);
    }
    .row { display: flex; gap: 10px; align-items: center; margin-top: 10px; }
    .btn {
      appearance: none;
      border: 1px solid rgba(255,255,255,.18);
      background: rgba(34, 197, 94, .12);
      color: var(--text);
      padding: 10px 12px;
      border-radius: 10px;
      cursor: pointer;
      font-family: inherit;
      font-size: 14px;
      font-weight: 650;
    }
    .btn:disabled { opacity: .55; cursor: not-allowed; }
    .btn.secondary { background: rgba(255,255,255,.06); }
    .btn.danger { background: rgba(239, 68, 68, .12); }
    /* Hover feedback only where a pointer can hover; on touch screens the
       style would stick to the last tapped button. */
    @media (hover: hover) and (pointer: fine) {
      .btn:hover { background: rgba(34, 197, 94, .18); }
      .btn.secondary:hover { background: rgba(255,255,255,.09); }
      .btn.danger:hover { background: rgba(239, 68, 68, .18); }
    }
    /* Fingers need a larger target than a mouse pointer. */
    @media (pointer: coarse) { .btn { min-height: 44px; } }
    :focus-visible { outline: 2px solid #7dd3fc; outline-offset: 2px; }
    .btn.secondary.mode-selected {
      background: rgba(34, 197, 94, .18);
      border-color: rgba(34, 197, 94, .45);
    }
    .btn.secondary.mode-unselected {
      background: rgba(239, 68, 68, .16);
      border-color: rgba(239, 68, 68, .45);
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
    @media (pointer: coarse) { .btn.icon { width: 44px; height: 44px; } }
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
      padding: 16px 12px;
      margin-top: 14px;
      text-align: center;
      color: var(--muted);
      font-size: 13px;
      background: rgba(255,255,255,.02);
      transition: background .12s linear, border-color .12s linear;
    }
    .dropActions { display: flex; gap: 10px; justify-content: center; flex-wrap: wrap; }
    .dropActions .btn { min-width: 150px; font-size: 15px; padding: 12px 16px; }
    .dropHint { margin-top: 10px; }
    /* Dropping needs a mouse; on a touch screen the hint would be noise. */
    @media (pointer: coarse) { .dropHint { display: none; } }
    .statusStats.warn { color: var(--yellow); }
    /* On a phone a note with its countdown does not fit one line. Showing it
       in full is worth the status bar growing by a line while trouble lasts. */
    @media (max-width: 620px) { .statusStats.warn { white-space: normal; } }
    .qfail { margin-top: 6px; font-size: 13px; color: var(--muted); }
    .qfail summary { cursor: pointer; padding: 4px 0; }
    @media (pointer: coarse) { .qfail summary { padding: 14px 0; } }
    /* A finished row has room to say what happened in full; only the running
       row keeps one line, because its text changes every second. */
    .qitem:not(.active) .qsub { white-space: normal; overflow-wrap: anywhere; }
    .qfail ul {
      margin: 4px 0 0;
      padding-left: 18px;
      max-height: 180px;
      overflow-y: auto;
      overflow-wrap: anywhere;
    }
    .dropzone.over {
      border-color: rgba(34,197,94,.85);
      background: rgba(34,197,94,.10);
      color: var(--text);
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
    <div class="hint">Files you add are stored on the device that runs this server.
      They upload one after another, and a lost connection is retried by itself.</div>

    <div class="dropzone" id="dropZone">
      <div class="dropActions">
        <button class="btn" id="pickFilesBtn" type="button">Choose files</button>
        <button class="btn secondary" id="pickFolderBtn" type="button">Choose a folder</button>
      </div>
      <div class="dropHint">or drop files and folders anywhere on this page</div>
      <input class="visually-hidden" type="file" id="singleFile" multiple
             tabindex="-1" aria-hidden="true" />
      <input class="visually-hidden" type="file" id="folderInput" webkitdirectory directory multiple
             tabindex="-1" aria-hidden="true" />
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
      <div class="meta error" id="pageError" role="alert" style="display:none;"></div>
      <ul class="queue" id="queueList"></ul>
    </div>
  </div>

  <div class="modal" id="conflictModal" aria-hidden="true">
    <div class="modalCard" role="dialog" aria-modal="true" aria-labelledby="conflictTitle">
      <div class="qtitle" id="conflictTitle">Existing files detected</div>
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
    // Stops whatever the running job is waiting on (a request or a file read).
    let activeCancel = null;
    const MAX_FILE_RETRIES = __MAX_FILE_RETRIES__;
    const RETRY_BASE_DELAY_MS = __RETRY_BASE_DELAY_MS__;
    const UPLOAD_TIMEOUT_MS = __UPLOAD_TIMEOUT_MS__;
    const STALL_TIMEOUT_MS = __STALL_TIMEOUT_MS__;
    // Retry delays double from RETRY_BASE_DELAY_MS up to this ceiling.
    const RETRY_MAX_DELAY_MS = 15000;
    const PREFLIGHT_ATTEMPTS = 3;
    const PREFLIGHT_TIMEOUT_MS = 60000;
    const STATUS_TIMEOUT_MS = 8000;
    const BUSY_POLL_MS = 2000;
    // From this size on, a busy server is asked first instead of being sent
    // the whole file only to refuse it.
    const BUSY_PRECHECK_BYTES = 32 * 1024 * 1024;
    const SERVER_CHECK_MIN_MS = 3000;
    const SERVER_CHECK_MAX_MS = 30000;
    // Pause before each extra round over files that failed in the first one.
    const SECOND_PASS_DELAYS_MS = [10000];
    const FILE_SLOW_NOTICE_MS = 2000;
    const FILE_READ_LIMIT_MS = 10 * 60 * 1000;
    // Slowest disk assumed while the server flushes a fully received file:
    // 2 MB/s, expressed in bytes per millisecond.
    const FINISH_BYTES_PER_MS = 2 * 1024;
    // Up to this much of a file can sit in the sender's own buffer after the
    // browser reports it as sent; it is given time to drain at 16 KB/s.
    const SEND_BUFFER_BYTES = 1024 * 1024;
    const SLOWEST_LINK_BYTES_PER_MS = 16;
    // A server that answers but fails file after file is not worth walking a
    // whole folder through; the job stops and waits for the user.
    const FAILURES_IN_A_ROW_LIMIT = 5;
    // Beyond this an estimate is noise from a stalled transfer, not a forecast.
    const ETA_MAX_SEC = 99 * 3600;
    const STALL_NOTICE_SEC = 5;
    const FAILED_LIST_LIMIT = 200;
    // Status notes come first in a one-line display that a phone cuts off
    // after about 42 characters, so they are kept shorter than that.
    const BUSY_NOTE = 'Waiting for another upload from this device';
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
    // Names this tab in every request. The server uses it to recognise a retry
    // as "the same uploader trying again" and lets it replace a hung request.
    const CLIENT_ID = newId().replace(/[^A-Za-z0-9._-]/g, '').slice(0, 72);

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
      return `${v.toFixed(i === 0 ? 0 : (v < 10 ? 2 : 1))} ${units[i]}`;
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

    function hidePageNotice() {
      $('pageError').style.display = 'none';
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
      // Only worth a mention when some of the selection was left out.
      if (Number.isFinite(job.selectedCount) && job.selectedCount > job.items.length) {
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
      if (job.status !== 'uploading') {
        const kept = job.items.filter(it => it.skipped).length;
        if (kept) extra += ` • skipped ${kept} (already on server)`;
      }
      if (job.failedCount && job.status === 'uploading') extra += ` • failed ${job.failedCount}`;
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

        // Which files failed, and why, in the words of the last attempt.
        const failed = (job.items || []).filter(it => it.failed && !it.done);
        if (failed.length && job.status !== 'uploading') {
          const details = document.createElement('details');
          details.className = 'qfail';
          details.open = !!job.failOpen;
          details.addEventListener('toggle', () => { job.failOpen = details.open; });
          const summary = document.createElement('summary');
          summary.textContent = `Show ${failed.length} failed file(s)`;
          details.appendChild(summary);
          const ul = document.createElement('ul');
          for (const item of failed.slice(0, FAILED_LIST_LIMIT)) {
            const row = document.createElement('li');
            row.textContent = `${item.path}: ${item.lastError || 'failed'}`;
            ul.appendChild(row);
          }
          if (failed.length > FAILED_LIST_LIMIT) {
            const more = document.createElement('li');
            more.textContent = `and ${failed.length - FAILED_LIST_LIMIT} more`;
            ul.appendChild(more);
          }
          details.appendChild(ul);
          left.appendChild(details);
        }

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
        const idleSec = activeJob.lastProgressAt ? (now - activeJob.lastProgressAt) / 1000 : 0;
        const stuck = !!activeJob.note || idleSec >= STALL_NOTICE_SEC;
        // While nothing moves the measured rate decays towards zero, and
        // "remaining / rate" would climb to days. That is not a forecast, so
        // no estimate is shown, and smoothing restarts once data flows again.
        const rawEta = (warm && !stuck) ? remainingBytes / rateMeter.bps : 0;
        if (!(rawEta > 0 && rawEta < ETA_MAX_SEC)) shownEtaSec = null;
        const eta = shownEtaSec !== null || (rawEta > 0 && rawEta < ETA_MAX_SEC)
          ? smoothEta(rawEta) : 0;
        const bits = [
          `${formatBytes(totals.uploadedBytes)} / ${formatBytes(totals.totalBytes)}`,
          `${totals.doneFiles}/${totals.totalFiles} files`,
        ];
        // What is going wrong goes first: the line is cut off on narrow screens.
        if (activeJob.note) {
          bits.unshift(activeJob.note);
        } else if (stuck) {
          bits.unshift(`No data moving for ${formatDuration(idleSec)}`);
        } else {
          bits.push(formatSpeed(rateMeter.bps));
          bits.push(`eta ${eta > 0 ? formatDuration(eta) : '--'}`);
        }
        bits.push(`upload time ${elapsedText}`);
        if (totals.pendingJobs > 0) bits.push(`${totals.pendingJobs} waiting`);
        setText($('overallStats'), bits.join(' • '));
        $('overallStats').classList.toggle('warn', stuck);
        if (track) {
          track.setAttribute('aria-valuetext',
            `${pctWhole} percent, ${totals.doneFiles} of ${totals.totalFiles} files`);
        }
        setTitleProgress(`${pctWhole}%`);
        announceProgress(pctWhole, totals);
      } else {
        const waiting = totals.pendingJobs;
        const troubled = queue.filter(j => j.status === 'error').length;
        setText($('statusTitle'), waiting > 0 ? `${waiting} job(s) waiting`
          : (troubled > 0 ? `${troubled} job(s) with files not uploaded` : 'Idle'));
        setText($('overallStats'), session.uploadedBytes > 0
          ? `uploaded ${formatBytes(session.uploadedBytes)} • total upload time ${elapsedText}`
          : 'Nothing queued.');
        $('overallStats').classList.remove('warn');
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

        const opener = document.activeElement;
        const onKey = (ev) => {
          if (ev.key === 'Escape') cleanup({ action: 'cancel' });
        };
        const cleanup = (answer) => {
          modal.classList.remove('show');
          modal.setAttribute('aria-hidden', 'true');
          document.removeEventListener('keydown', onKey);
          if (opener && opener.focus) opener.focus();
          resolve(answer);
        };
        document.addEventListener('keydown', onKey);
        modal.setAttribute('aria-hidden', 'false');
        $('conflictOkBtn').focus();

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

    async function enqueueJob(job) {
      job.status = 'preflight';
      const selectedCount = (job.items || []).length;
      job.selectedCount = selectedCount;
      job.queuedDupCount = 0;
      job.existsCount = 0;
      job.inProgressCount = 0;
      job.duplicateInSelectionCount = 0;
      for (const item of job.items) {
        item.onExists = 'create';
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
            // Not on the server when this job was checked. Should another
            // upload store the same path before this one gets there (or
            // before a later Retry), the server keeps that file: nobody was
            // asked whether it may be replaced.
            item.onExists = 'create';
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

      job.checked = true;
      job.status = 'queued';
      renderQueue();
      pumpQueue();
    }

    function makeError(message, code, status) {
      const err = new Error(message);
      err.code = code;
      if (status) err.status = status;
      return err;
    }

    function apiUrl(route, params) {
      return `api/${route}?${new URLSearchParams(params).toString()}`;
    }

    // fetch() that gives up after timeoutMs, so a request whose packets vanish
    // cannot hang the queue. Resolves to parsed JSON, or null on any failure.
    async function fetchJson(url, options, timeoutMs, cancellable) {
      const controller = (typeof AbortController === 'function') ? new AbortController() : null;
      const timer = controller ? setTimeout(() => controller.abort(), timeoutMs) : null;
      const cancel = () => controller.abort();
      if (controller && cancellable) activeCancel = cancel;
      try {
        const res = await fetch(url, Object.assign({ cache: 'no-store' },
          options || {}, controller ? { signal: controller.signal } : {}));
        const data = await res.json().catch(() => null);
        return { status: res.status, data };
      } catch (err) {
        return null;
      } finally {
        if (timer !== null) clearTimeout(timer);
        if (activeCancel === cancel) activeCancel = null;
      }
    }

    // Every await in a running job is followed by this: Abort may have been
    // pressed while the job was waiting, and then nothing more may be sent.
    function ensureNotCanceled(job) {
      if (job.status === 'canceled') throw makeError('Upload canceled', 'aborted');
    }

    // Waits ms, showing a countdown through label(secondsLeft). Rejects as soon
    // as the job is cancelled, so Abort never has to sit out a retry delay.
    function pause(job, ms, label) {
      return new Promise((resolve, reject) => {
        const end = performance.now() + ms;
        const tick = () => {
          if (job.status === 'canceled') {
            reject(makeError('Upload canceled', 'aborted'));
            return;
          }
          const left = end - performance.now();
          if (left <= 0) {
            resolve();
            return;
          }
          if (label) setNote(job, label(Math.max(1, Math.ceil(left / 1000))));
          setTimeout(tick, Math.min(250, left));
        };
        tick();
      });
    }

    function setNote(job, text) {
      if (job.note === text) return;
      job.note = text;
      renderStatus(true);
    }

    async function apiPreflight(job) {
      const body = JSON.stringify({
        upload_id: job.id,
        items: job.items.map(it => ({ path: it.path, size: it.file.size || 0 })),
      });
      let lastError = 'Server not reachable';
      for (let attempt = 1; attempt <= PREFLIGHT_ATTEMPTS; attempt++) {
        const reply = await fetchJson('api/preflight', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body,
        }, PREFLIGHT_TIMEOUT_MS);
        if (reply && reply.status === 200 && reply.data && reply.data.ok) return reply.data;
        if (reply) {
          // The server answered: asking again would get the same answer.
          return { ok: false, error: (reply.data && reply.data.error) || `HTTP ${reply.status}` };
        }
        lastError = 'Server not reachable (the file list did not get through)';
        if (attempt < PREFLIGHT_ATTEMPTS) await sleep(RETRY_BASE_DELAY_MS * attempt);
      }
      return { ok: false, error: lastError };
    }

    // What the server knows about one file of this job: whether it is already
    // stored, and whether this device's upload slot is taken by another tab.
    // null means the server did not answer.
    async function apiStatus(job, item) {
      const reply = await fetchJson(apiUrl('status', {
        upload_id: job.id, client: CLIENT_ID, path: item.path,
      }), null, STATUS_TIMEOUT_MS, true);
      ensureNotCanceled(job);
      return (reply && reply.status === 200 && reply.data && reply.data.ok) ? reply.data : null;
    }

    // Reads the first byte before any network traffic. A file that was moved,
    // deleted or locked fails here with a clear message instead of a vague
    // network error, and a cloud-only file (OneDrive and the like) is fetched
    // by the operating system now, not while the server waits for its body.
    function probeFile(job, item) {
      return new Promise((resolve, reject) => {
        if (!item.file.size || typeof FileReader !== 'function') {
          resolve();
          return;
        }
        const reader = new FileReader();
        let done = false;
        const slow = setTimeout(() => setNote(job,
          'Waiting for the file (still downloading?)'),
          FILE_SLOW_NOTICE_MS);
        const limit = setTimeout(() => finish(makeError(
          'This device did not hand over the file in time', 'file')), FILE_READ_LIMIT_MS);
        function finish(err) {
          if (done) return;
          done = true;
          clearTimeout(slow);
          clearTimeout(limit);
          if (activeCancel === cancel) activeCancel = null;
          if (reader.readyState === 1) reader.abort();
          if (err) reject(err); else resolve();
        }
        function cancel() {
          finish(makeError('Upload canceled', 'aborted'));
        }
        activeCancel = cancel;
        reader.onload = () => finish(null);
        reader.onerror = () => finish(makeError(
          'This device could not read the file (moved, deleted, locked, or cloud-only while offline)',
          'file'));
        reader.readAsArrayBuffer(item.file.slice(0, 1));
      });
    }

    function uploadFile(job, item, fileIndex, attempt, lastCode) {
      return new Promise((resolve, reject) => {
        const params = {
          upload_id: job.id,
          client: CLIENT_ID,
          path: item.path,
          file_index: String(fileIndex),
          total_files: String(job.items.length),
          on_exists: item.onExists === 'overwrite' ? 'overwrite' : 'skip',
        };
        if (attempt > 1) {
          params.attempt = String(attempt);
          if (lastCode) params.reason = lastCode;
        }
        const xhr = new XMLHttpRequest();
        let settled = false;
        let stalled = false;
        let bodySent = false;
        let lastActivity = performance.now();
        let watchdog = null;
        const cancel = () => xhr.abort();
        const settle = (fn, value) => {
          if (settled) return;
          settled = true;
          if (watchdog !== null) clearInterval(watchdog);
          if (activeCancel === cancel) activeCancel = null;
          fn(value);
        };
        activeCancel = cancel;
        job.lastProgressAt = lastActivity;
        xhr.responseType = 'json';
        xhr.timeout = UPLOAD_TIMEOUT_MS > 0 ? UPLOAD_TIMEOUT_MS : 0;
        xhr.open('POST', apiUrl('upload', params), true);
        xhr.setRequestHeader('Content-Type', 'application/octet-stream');

        // Progress events only carry data; the ticker owns every redraw.
        xhr.upload.onprogress = (e) => {
          if (!e.lengthComputable) return;
          lastActivity = performance.now();
          job.lastProgressAt = lastActivity;
          job.currentIndex = fileIndex;
          job.currentPath = item.path;
          job.uploadedBytes = Math.min(job.totalBytes, job.completedBytes + e.loaded);
        };
        xhr.upload.onload = () => {
          bodySent = true;
          lastActivity = performance.now();
        };

        // A connection can die without either side being told (a sleeping
        // Wi-Fi radio, a filtering proxy): nothing fails, nothing moves. The
        // browser has no timeout for that on its own, so the request is
        // abandoned here and retried. Once the whole body is out, the server
        // still has to flush the file to disk, which gets extra time by size.
        // "Out" also only means handed to this computer's send buffer: on a
        // slow link that buffer is still draining, silently, for a while.
        if (STALL_TIMEOUT_MS > 0) {
          const size = item.file.size || 0;
          const afterBody = size / FINISH_BYTES_PER_MS
            + Math.min(size, SEND_BUFFER_BYTES) / SLOWEST_LINK_BYTES_PER_MS;
          watchdog = setInterval(() => {
            const allowance = STALL_TIMEOUT_MS + (bodySent ? afterBody : 0);
            if (performance.now() - lastActivity < allowance) return;
            stalled = true;
            xhr.abort();
          }, 1000);
        }

        xhr.onload = () => {
          // Anything thrown in here would leave the promise unsettled and the
          // whole queue stuck forever, so the body is wrapped.
          try {
            const resp = xhr.response || null;
            if (xhr.status === 409 && resp && resp.error === 'exists') {
              settle(resolve, { skipped: true, rel_path: resp.rel_path || item.path });
              return;
            }
            if (xhr.status === 409 && resp && resp.error === 'in_progress') {
              settle(reject, makeError('Another upload is writing this file right now', 'http_error', 409));
              return;
            }
            const ok = xhr.status === 200 && resp && resp.ok;
            if (!ok) {
              // responseText must not be touched while responseType is 'json':
              // per spec the getter throws InvalidStateError.
              const msg = (resp && resp.error) ? resp.error : `HTTP ${xhr.status}`;
              settle(reject, makeError(msg, xhr.status >= 500 ? 'http_5xx' : 'http_error', xhr.status));
              return;
            }
            settle(resolve, resp);
          } catch (err) {
            settle(reject, err instanceof Error ? err : new Error(String(err)));
          }
        };
        xhr.onerror = () => settle(reject, makeError('Connection lost', 'network'));
        xhr.ontimeout = () => settle(reject, makeError('Per-file time limit hit', 'timeout'));
        xhr.onabort = () => settle(reject, stalled
          ? makeError(`No data moved for ${Math.round(STALL_TIMEOUT_MS / 1000)} s`, 'stalled')
          : makeError('Upload canceled', 'aborted'));
        xhr.send(item.file);
      });
    }

    function isRetriableError(err) {
      // Everything here is a problem of the connection, not of the file: the
      // same request can succeed a moment later. A 4xx answer would repeat.
      return !!err && (err.code === 'network' || err.code === 'timeout'
        || err.code === 'stalled' || err.code === 'http_5xx');
    }

    // Blocks while another tab or browser on this device holds the upload
    // slot. Polling the small status call costs nothing; sending the file just
    // to have it refused would transfer it for nothing.
    async function waitForSlot(job, item) {
      for (;;) {
        const status = await apiStatus(job, item);
        if (!status || !status.busy) return status;
        await pause(job, BUSY_POLL_MS, () => BUSY_NOTE);
      }
    }

    // Returns once the server answers again. Only Abort ends the wait: files
    // that are already stored stay stored, and an unattended queue should
    // continue by itself when the connection comes back.
    async function waitForServer(job, item) {
      let delay = SERVER_CHECK_MIN_MS;
      for (;;) {
        await pause(job, delay, (sec) => `Server not reachable, next check in ${sec} s`);
        setNote(job, 'Checking whether the server answers');
        if (await apiStatus(job, item)) return;
        delay = Math.min(SERVER_CHECK_MAX_MS, delay * 1.5);
      }
    }

    async function uploadFileWithRetry(job, item, fileIndex) {
      let attempt = 1;
      let lastCode = '';
      if ((item.file.size || 0) >= BUSY_PRECHECK_BYTES) await waitForSlot(job, item);
      for (;;) {
        try {
          item.lastError = '';
          await probeFile(job, item);
          ensureNotCanceled(job);
          setNote(job, '');
          return await uploadFile(job, item, fileIndex, attempt, lastCode);
        } catch (err) {
          if (job.status === 'canceled') throw err;
          if (err.status === 429) {
            // Not a failure: the slot is taken. Does not use up a retry.
            job.uploadedBytes = job.completedBytes;
            await pause(job, BUSY_POLL_MS, () => BUSY_NOTE);
            const freed = await waitForSlot(job, item);
            // What held the slot may have been this file's own earlier
            // attempt, finishing late; then there is nothing left to send.
            if (freed && freed.done && freed.bytes === (item.file.size || 0)) {
              return { ok: true, sha256: freed.sha256 || '' };
            }
            continue;
          }
          if (!isRetriableError(err)) throw err;

          // The file may have arrived although its answer did not.
          const status = await apiStatus(job, item);
          if (status && status.done && status.bytes === (item.file.size || 0)) {
            return { ok: true, sha256: status.sha256 || '' };
          }
          if (attempt > MAX_FILE_RETRIES) {
            // The server answers but this file keeps failing: give the other
            // files their turn. If nothing answers, the connection is down and
            // moving on would only fail every remaining file the same way.
            if (status) throw err;
            await waitForServer(job, item);
            attempt = 1;
            lastCode = 'unreachable';
            continue;
          }
          lastCode = err.code || '';
          // Bytes of the failed attempt must not stay in the progress bar.
          job.uploadedBytes = job.completedBytes;
          const delay = Math.min(RETRY_MAX_DELAY_MS, RETRY_BASE_DELAY_MS * Math.pow(2, attempt - 1))
            * (0.75 + Math.random() * 0.5);
          const what = err.message || String(err);
          const nth = attempt;
          item.lastError = what;
          await pause(job, delay, (sec) =>
            `${what}, retry ${nth}/${MAX_FILE_RETRIES} in ${sec} s`);
          attempt += 1;
        }
      }
    }

    function retryJob(job) {
      if (job.status === 'uploading' || job === activeJob) return;
      if (!job.checked) {
        // The existing-files question was never answered for this job (it was
        // cancelled in the dialog, or the check itself failed). Sending now
        // would overwrite files nobody agreed to replace, so it is asked again.
        const idx = queue.indexOf(job);
        if (idx >= 0) queue.splice(idx, 1);
        job.error = '';
        enqueueJob(job);
        return;
      }
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

    // One walk over every file that is not stored yet.
    async function runPass(job) {
      let failuresInARow = 0;
      const count = job.items.length;
      // A pass that was stopped early resumes behind the files that kept
      // failing and wraps around to them at the end; starting at the top
      // again would stop at the same files and never reach the rest.
      const first = (job.resumeAt || 0) % Math.max(1, count);
      job.resumeAt = 0;
      for (let step = 0; step < count; step++) {
        const i = (first + step) % count;
        if (job.status !== 'uploading') break;
        const item = job.items[i];
        // A failed file stays failed until Retry or the second pass clears it.
        if (item.done || item.skipped || item.failed) continue;
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
          failuresInARow = 0;
          job.completedBytes += (item.file.size || 0);
          job.uploadedBytes = job.completedBytes;
          renderStatus();
        } catch (e) {
          if (job.status === 'canceled') break;
          item.failed = true;
          item.retriable = isRetriableError(e);
          failuresInARow = item.retriable ? failuresInARow + 1 : 0;
          if (failuresInARow >= FAILURES_IN_A_ROW_LIMIT) {
            job.stoppedEarly = true;
            job.resumeAt = i + 1;
          }
          item.lastError = (e && e.message) ? e.message : String(e);
          job.failedCount = job.items.filter(it => it.failed && !it.done).length;
          // Bytes of the failed attempt must not stay in the progress bar.
          job.uploadedBytes = job.completedBytes;
          renderStatus();
          if (job.stoppedEarly) break;
        }
      }
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
      job.note = '';
      job.stoppedEarly = false;
      // A resumed job starts with bytes already on the server. Without this
      // reset the meter would divide them by a fresh clock and report an
      // absurd speed (and an ETA of almost zero).
      resetRateMeter();
      startTicker();
      renderQueue();

      $('abortBtn').disabled = false;
      for (let pass = 0; job.status === 'uploading'; pass++) {
        await runPass(job);
        if (job.status !== 'uploading') break;
        const again = job.items.filter(it => it.failed && it.retriable && !it.done);
        if (!again.length || job.stoppedEarly || pass >= SECOND_PASS_DELAYS_MS.length) break;
        // Files that failed while everything around them went through get one
        // more round at the end, after a pause that lets a shaky link settle.
        try {
          await pause(job, SECOND_PASS_DELAYS_MS[pass], (sec) =>
            `${again.length} file(s) failed, trying again in ${sec} s`);
        } catch (e) {
          break;
        }
        for (const item of again) item.failed = false;
        job.failedCount = 0;
      }

      $('abortBtn').disabled = true;
      activeCancel = null;
      job.note = '';
      job.endedAt = performance.now();
      job.durationSec = (job.endedAt - job.startedAt) / 1000;
      // Fold this run into the session total, then detach startedAt so the
      // same span cannot be counted twice by totalActiveMs().
      session.activeMs += Math.max(0, job.endedAt - job.startedAt);
      job.startedAt = null;
      stopTicker();
      job.failedCount = job.items.filter(it => it.failed && !it.done).length;
      if (job.status === 'uploading') {
        const remaining = (job.items || []).filter(it => !it.done && !it.skipped);
        if (remaining.length > 0) {
          job.status = 'error';
          job.error = (job.stoppedEarly
            ? `Stopped after ${FAILURES_IN_A_ROW_LIMIT} files in a row failed. ` : '')
            + `${remaining.length} file(s) not uploaded. Retry sends only those.`;
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
      if (activeCancel) activeCancel();
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

    function filesLabel(files, nameOf) {
      return files.length === 1
        ? `File: ${nameOf(files[0])}`
        : `Files: ${files.length} (${nameOf(files[0])} ...)`;
    }

    $('pickFilesBtn').addEventListener('click', () => $('singleFile').click());
    $('pickFolderBtn').addEventListener('click', () => $('folderInput').click());
    // Phones mostly cannot pick a folder; offering a button that opens a
    // plain file dialog would promise something that does not happen.
    if (!('webkitdirectory' in HTMLInputElement.prototype)) {
      $('pickFolderBtn').hidden = true;
    }

    // Choosing is adding: there is no second "add to queue" step to forget.
    $('singleFile').addEventListener('change', async (e) => {
      const files = e.target.files ? Array.from(e.target.files) : [];
      // Clearing the value lets the same file be picked again later.
      e.target.value = '';
      if (!files.length) return;
      hidePageNotice();
      await enqueueJob(makeJob(filesLabel(files, f => f.name), 'files',
        files.map(f => ({ file: f, path: f.name }))));
    });

    $('folderInput').addEventListener('change', async (e) => {
      const files = e.target.files ? Array.from(e.target.files) : [];
      e.target.value = '';
      hidePageNotice();
      if (!files.length) {
        showPageError('That folder contains no files, so there is nothing to upload.');
        return;
      }
      const byRoot = new Map();
      for (const f of files) {
        const rel = f.webkitRelativePath || f.name;
        const root = rel.split('/')[0] || 'Folder';
        if (!byRoot.has(root)) byRoot.set(root, []);
        byRoot.get(root).push({ file: f, path: rel });
      }
      for (const [root, items] of byRoot) {
        await enqueueJob(makeJob(`Folder: ${root}`, 'folder', items));
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
    # The default backlog of 5 overflows when a browser opens several
    # connections at once; the kernel then drops connection attempts and the
    # client only retries them after a full second.
    request_queue_size = 64

    def handle_error(self, request, client_address) -> None:
        # A client that vanished is routine and already logged by the handler.
        if isinstance(sys.exc_info()[1], (ConnectionError, socket.timeout)):
            return
        super().handle_error(request, client_address)


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
    private_mode: bool = False,
    stall_timeout_sec: int = DEFAULT_STALL_TIMEOUT_SEC,
) -> None:
    # Redirecting stdout to a file switches it to block buffering, which hides
    # the whole banner (including the LAN URL) until the process exits.
    try:
        sys.stdout.reconfigure(line_buffering=True)  # type: ignore[union-attr]
    except (AttributeError, OSError):
        pass
    UPLOAD_ROOT.mkdir(parents=True, exist_ok=True)
    global _CASE_INSENSITIVE
    _CASE_INSENSITIVE = _probe_case_insensitive(UPLOAD_ROOT)
    STATE.set_per_ip_limit(per_client_limit)
    _HTML_CONFIG["max_file_retries"] = max(0, int(retry_count))
    _HTML_CONFIG["retry_delay_ms"] = max(0, int(retry_delay_ms))
    _HTML_CONFIG["upload_timeout_ms"] = max(0, int(upload_timeout_sec)) * 1000
    _HTML_CONFIG["stall_timeout_ms"] = max(0, int(stall_timeout_sec)) * 1000
    token = secrets.token_urlsafe(24) if private_mode else None

    # Bind before announcing anything, so the banner can never advertise a URL
    # that failed to come up.
    servers: list[ThreadingHTTPServer] = []
    bound: list[tuple[str, int]] = []
    for host, port in endpoints:
        try:
            httpd = _UploadHTTPServer((host, port), SimpleUploadServer)
            httpd.token = token.encode("ascii") if token is not None else None
            servers.append(httpd)
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
    stall_ms = int(_HTML_CONFIG["stall_timeout_ms"])
    _print_kv(
        "Stalled-transfer retry",
        "disabled" if stall_ms == 0 else f"after {stall_ms // 1000} s without data",
    )
    print("Bindings:")
    for host, port in bound:
        print(f"    - {host}:{port}")
    print("\nAccess URLs:")

    def _print_access(kind: str, url: str) -> None:
        suffix = f"/{token}/" if token is not None else ""
        print(f"    - {kind:<8} {url}{suffix}")

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
        STATE.stop(wait_sec=2.0)
        for server in servers:
            server.shutdown()
            server.server_close()


def _run_selftest(private_mode: bool = False) -> int:
    """Bind an ephemeral port, fetch the page, and report the result.

    A plain syntax check cannot catch a stdlib module that a newer Python has
    dropped, because that only fails on import. This starts the real server on
    the real interpreter, which is what actually needs to keep working.
    """
    import urllib.request

    httpd = _UploadHTTPServer(("127.0.0.1", 0), SimpleUploadServer)
    token = secrets.token_urlsafe(24) if private_mode else None
    httpd.token = token.encode("ascii") if token is not None else None
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        suffix = f"/{token}/" if token is not None else "/"
        url = f"http://127.0.0.1:{httpd.server_address[1]}{suffix}"
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
    for placeholder in (*_HTML_PLACEHOLDERS, "__CASE_INSENSITIVE_FS__"):
        if placeholder.encode() in body:
            problems.append(f"unreplaced template placeholder {placeholder}")

    if problems:
        for problem in problems:
            print(_c(f"selftest FAILED: {problem}", _ANSI_RED), flush=True)
        return 1
    print(
        _c(
            f"selftest OK on Python {platform.python_version()} "
            f"({len(body)} bytes served{'; private link checked' if private_mode else ''})",
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
        "--private",
        action="store_true",
        help="Optional secret link for access; HTTP remains unencrypted.",
    )
    parser.add_argument(
        "-d",
        "--upload-dir",
        type=str,
        default="uploads",
        help="Folder that receives the files (default: ./uploads)",
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
            "Automatic retries per file for connection problems "
            f"(default: {DEFAULT_RETRY_COUNT})"
        ),
    )
    parser.add_argument(
        "--retry-delay-ms",
        type=int,
        default=DEFAULT_RETRY_DELAY_MS,
        help=(
            "First retry delay in milliseconds; doubles with every retry "
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
    parser.add_argument(
        "--stall-timeout-sec",
        type=int,
        default=DEFAULT_STALL_TIMEOUT_SEC,
        help=(
            "Seconds without any transferred data after which the browser "
            "abandons a request and retries it "
            f"(default: {DEFAULT_STALL_TIMEOUT_SEC}, 0 = never)"
        ),
    )
    args = parser.parse_args()
    if args.selftest:
        raise SystemExit(_run_selftest(private_mode=args.private))
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
    if args.stall_timeout_sec < 0:
        parser.error("--stall-timeout-sec must be >= 0 (0 disables it)")
    UPLOAD_ROOT = Path(args.upload_dir).expanduser().resolve()
    if UPLOAD_ROOT.exists() and not UPLOAD_ROOT.is_dir():
        parser.error(f"--upload-dir is not a folder: {UPLOAD_ROOT}")
    run_server(
        endpoints=endpoints,
        per_client_limit=max(1, args.per_client_limit),
        retry_count=args.retry_count,
        retry_delay_ms=args.retry_delay_ms,
        upload_timeout_sec=args.upload_timeout_sec,
        private_mode=args.private,
        stall_timeout_sec=args.stall_timeout_sec,
    )
