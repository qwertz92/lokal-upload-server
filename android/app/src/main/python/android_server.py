"""Android entry point; the browser UI and upload flow live in upload_server."""

import os
import re
import socket
import sys
import threading
import time

import upload_server


class _SafStorage:
    def __init__(self, storage):
        self.storage = storage
        self._initialized = False

    def _call(self, name, *args):
        try:
            return getattr(self.storage, name)(*args)
        except Exception as exc:
            description = f"{type(exc).__name__}: {exc}"
            if (
                isinstance(exc, FileExistsError)
                or "FileAlreadyExistsException" in description
            ):
                raise upload_server._RequestError("exists", status=409) from exc
            if (
                isinstance(exc, (ValueError, NotADirectoryError, IsADirectoryError))
                or "IllegalArgumentException" in description
            ):
                raise upload_server._RequestError(str(exc), status=400) from exc
            if isinstance(exc, PermissionError) or "SecurityException" in description:
                raise upload_server._RequestError(
                    "Storage permission is unavailable", status=403
                ) from exc
            raise upload_server._RequestError("Storage operation failed", status=500) from exc

    def initialize(self):
        if not self._initialized:
            self._call("validate")
            self._initialized = True

    def exists(self, rel):
        return bool(self._call("exists", rel))

    def is_dir(self, rel):
        return bool(self._call("isDirectory", rel))

    def check_space(self, required):
        available = int(self._call("availableBytes"))
        needed = int(required * upload_server.DISK_SPACE_FACTOR)
        if available >= 0 and available < needed:
            raise ValueError(
                f"Not enough disk space. Required: {upload_server._format_bytes(needed)}, "
                f"Available: {upload_server._format_bytes(available)}"
            )

    def begin(self, rel):
        ticket = str(self._call("begin", rel))
        fd = None
        try:
            fd = int(self._call("openDetachedFd", ticket))
            return os.fdopen(fd, "wb"), ticket
        except Exception:
            if fd is not None:
                os.close(fd)
            self.abort(ticket)
            raise

    def commit(self, ticket, rel, overwrite, digest):
        self._call("commit", ticket, rel, overwrite, digest)

    def abort(self, ticket):
        self._call("abort", ticket)


def _safe_log(message, token):
    if token is not None:
        message = message.replace(token.decode("ascii"), "[hidden]")
    if message.startswith(("New client:", "Upload started:")):
        message = message.partition(" ua=")[0]
    if "invalid literal for int() with base 10:" in message:
        message = message.partition("invalid literal for int() with base 10:")[0] + "invalid numeric parameter"
    message = re.sub(r"[A-Za-z][A-Za-z0-9+.-]*://\S+", "[hidden URI]", message)
    message = "".join(char if char.isprintable() else " " for char in message)
    return message[:1024]


class _Handler(upload_server.SimpleUploadServer):
    timeout = 30

    def _log(self, message, *, color=None):
        # Capability URLs never belong in Android's process logs.
        if self.server.log_sink is not None:
            try:
                self.server.log_sink.log(_safe_log(message, self.server.token))
            except Exception:
                print("Android activity log callback failed", file=sys.stderr, flush=True)
        if message.startswith("Temporary upload cleanup failed:"):
            print("Android temporary upload cleanup failed", file=sys.stderr, flush=True)
        elif message.startswith("Upload error:"):
            print("Android upload failed", file=sys.stderr, flush=True)

class _AndroidHTTPServer(upload_server._UploadHTTPServer):
    daemon_threads = True
    block_on_close = False

    def __init__(self, address, storage, token, log_sink=None):
        self.storage = storage
        self.state = upload_server._ServerState()
        self.token = token.encode("ascii") if token is not None else None
        self.log_sink = log_sink
        self._slots = threading.BoundedSemaphore(8)
        self._clients = set()
        self._clients_changed = threading.Condition()
        super().__init__(address, _Handler)

    def process_request(self, request, client_address):
        if not self._slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        with self._clients_changed:
            self._clients.add(request)
        try:
            super().process_request(request, client_address)
        except Exception:
            self._finished(request)
            raise

    def _finished(self, request):
        with self._clients_changed:
            self._clients.discard(request)
            self._clients_changed.notify_all()
        self._slots.release()

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._finished(request)

    def close_clients(self):
        with self._clients_changed:
            clients = list(self._clients)
        for client in clients:
            try:
                client.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            client.close()
        deadline = time.monotonic() + 3
        with self._clients_changed:
            while self._clients:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise RuntimeError("Upload cleanup is still running; retry Stop before restarting")
                self._clients_changed.wait(remaining)


_server = None
_thread = None
_lifecycle_lock = threading.Lock()


def _stop_locked():
    global _server, _thread
    if _server is None:
        return
    _server.shutdown()
    _server.server_close()
    _thread.join(timeout=2)
    _server.close_clients()
    _server = None
    _thread = None


def start(storage, token, port, log_sink=None):
    """Validate the chosen SAF tree and listen on all LAN interfaces."""
    global _server, _thread
    if token is not None and (
        not isinstance(token, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", token)
    ):
        raise ValueError("Invalid URL token")
    with _lifecycle_lock:
        _stop_locked()
        adapter = _SafStorage(storage)
        adapter.initialize()
        httpd = _AndroidHTTPServer(("0.0.0.0", int(port)), adapter, token, log_sink)
        thread = threading.Thread(
            target=httpd.serve_forever, kwargs={"poll_interval": 0.1}, daemon=True
        )
        _server, _thread = httpd, thread
        try:
            thread.start()
        except Exception:
            httpd.server_close()
            _server = _thread = None
            raise
        return int(httpd.server_address[1])


def stop():
    """Close the listener and active clients, then wait briefly for abort cleanup."""
    with _lifecycle_lock:
        _stop_locked()
