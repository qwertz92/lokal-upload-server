"""Exercise the Android entry point with a file-descriptor SAF stand-in."""

import contextlib
import errno
import hashlib
import http.client
import importlib
import importlib.util
import io
import json
import os
from pathlib import Path
import socket
import sys
import tempfile
import threading
import time
import unittest
from urllib.parse import urlencode

upload_server = importlib.import_module("2025_12_python_upload_webserver")
sys.modules["upload_server"] = upload_server
spec = importlib.util.spec_from_file_location(
    "android_server", Path(__file__).resolve().parents[1]
    / "android/app/src/main/python/android_server.py"
)
android_server = importlib.util.module_from_spec(spec)
spec.loader.exec_module(android_server)


class FakeSafStorage:
    def __init__(self, root):
        self.root = root
        self.validated = False
        self.validation_count = 0
        self.tickets = set()
        self.aborted = threading.Event()
        self.started = threading.Event()
        self.fail_commit = False
        self.commit_digests = []
        self.fail_open = False
        self.available_bytes = -1

    def validate(self):
        self.validated = True
        self.validation_count += 1

    def exists(self, rel):
        return (self.root / rel).exists()

    def isDirectory(self, rel):
        return (self.root / rel).is_dir()

    def availableBytes(self):
        return self.available_bytes  # -1 means the provider cannot expose capacity.

    def begin(self, rel):
        fd, ticket = tempfile.mkstemp(dir=self.root, prefix="pending-")
        os.close(fd)
        self.tickets.add(ticket)
        self.started.set()
        return ticket

    def openDetachedFd(self, ticket):
        if self.fail_open:
            raise OSError("provider cannot open pending document")
        return os.open(ticket, os.O_WRONLY)

    def commit(self, ticket, rel, overwrite, digest):
        if self.fail_commit:
            raise ValueError("provider refused target path")
        target = self.root / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.exists() and not overwrite:
            raise FileExistsError("exists")
        self.commit_digests.append(digest)
        os.replace(ticket, target)
        self.tickets.remove(ticket)

    def abort(self, ticket):
        Path(ticket).unlink(missing_ok=True)
        self.tickets.discard(ticket)
        self.aborted.set()


class AndroidServerTest(unittest.TestCase):
    token = "0123456789abcdef0123456789abcdef"

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name)
        self.storage = FakeSafStorage(self.root)
        self.port = android_server.start(self.storage, self.token, 0)

    def tearDown(self):
        android_server.stop()
        self.directory.cleanup()

    def request(self, method, path, body=None, headers=None):
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        try:
            connection.request(method, path, body=body, headers=headers or {})
            response = connection.getresponse()
            return response.status, response.read()
        finally:
            connection.close()

    def upload(self, path, body, policy="overwrite"):
        query = urlencode({"upload_id": "android-upload", "path": path,
                           "on_exists": policy})
        return self.request("POST", f"/{self.token}/api/upload?{query}", body,
                            {"Content-Type": "application/octet-stream"})

    def preflight(self, items):
        return self.request("POST", f"/{self.token}/api/preflight",
                            json.dumps({"upload_id": "android-upload", "items": items}),
                            {"Content-Type": "application/json"})

    def test_capability_required_before_every_get_and_post(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            for method in ("GET", "POST"):
                for path in ("/", "/api/upload", f"/{self.token}x/", f"/{self.token}"):
                    status, _ = self.request(method, path, b"x" if method == "POST" else None)
                    self.assertEqual(status, 404, (method, path))
        self.assertNotIn(self.token, output.getvalue())
        self.assertFalse(self.storage.tickets)
        status, html = self.request("GET", f"/{self.token}/")
        self.assertEqual(status, 200)
        self.assertIn(b"fetch('api/preflight'", html)
        self.assertIn(b"`api/upload?", html)
        self.assertNotIn(b"fetch('/api", html)

    def test_nested_stream_exact_sha_preflight_skip_and_overwrite(self):
        self.assertTrue(self.storage.validated)
        payload = bytes(range(256)) * 32769  # Cross the server's 8 MiB read boundary.
        status, body = self.upload("outer/inner/data.bin", payload)
        self.assertEqual(status, 200, body)
        self.assertEqual(json.loads(body)["sha256"], hashlib.sha256(payload).hexdigest())
        target = self.root / "outer/inner/data.bin"
        self.assertEqual(target.read_bytes(), payload)
        self.assertEqual(
            self.storage.commit_digests, [hashlib.sha256(payload).hexdigest()]
        )
        status, body = self.preflight([{"path": "outer/inner/data.bin", "size": 999999999}])
        self.assertEqual(status, 200, body)
        self.assertEqual(json.loads(body)["conflicts"][0]["reason"], "exists")
        status, _ = self.upload("outer/inner/data.bin", b"skip me", "skip")
        self.assertEqual(status, 409)
        self.assertEqual(target.read_bytes(), payload)
        status, _ = self.upload("outer/inner/data.bin", b"replacement")
        self.assertEqual(status, 200)
        self.assertEqual(target.read_bytes(), b"replacement")
        self.assertFalse(self.storage.tickets)
        self.assertEqual(self.storage.validation_count, 1)

    def test_commit_error_aborts_ticket_and_preserves_original(self):
        (self.root / "keep.bin").write_bytes(b"original")
        self.storage.fail_commit = True
        status, body = self.upload("keep.bin", b"replacement")
        self.assertEqual(status, 400, body)
        self.assertEqual((self.root / "keep.bin").read_bytes(), b"original")
        self.assertTrue(self.storage.aborted.wait(2))
        self.assertFalse(self.storage.tickets)

    def test_paths_space_and_descriptor_errors_leave_no_pending_upload(self):
        for rel in ("../escape.bin", "folder"):
            if rel == "folder":
                (self.root / rel).mkdir()
            status, _ = self.upload(rel, b"invalid")
            self.assertEqual(status, 400)
        self.storage.available_bytes = 1
        status, body = self.upload("full.bin", b"too much")
        self.assertEqual(status, 400, body)
        self.assertIn("disk space", json.loads(body)["error"])
        self.storage.available_bytes = -1
        self.storage.fail_open = True
        status, body = self.upload("failed.bin", b"contents")
        self.assertEqual(status, 500, body)
        self.assertTrue(self.storage.aborted.wait(2))
        self.assertFalse(self.storage.tickets)

    def test_unknown_capacity_full_disk_is_not_retried_and_preserves_original(self):
        target = self.root / "keep.bin"
        target.write_bytes(b"original")
        adapter = android_server._server.storage
        begin = adapter.begin

        def full_disk_begin(rel):
            stream, ticket = begin(rel)

            class FullStream:
                def __enter__(self):
                    return self

                def __exit__(self, *args):
                    stream.close()

                def write(self, data):
                    raise OSError(errno.ENOSPC, "No space left on device")

            return FullStream(), ticket

        adapter.begin = full_disk_begin
        status, body = self.upload("keep.bin", b"replacement")
        self.assertEqual(status, 400, body)
        self.assertIn("disk space", json.loads(body)["error"])
        self.assertEqual(target.read_bytes(), b"original")
        self.assertTrue(self.storage.aborted.wait(2))
        self.assertFalse(self.storage.tickets)

    def test_stop_aborts_active_socket_then_restart_has_fresh_state(self):
        (self.root / "keep.bin").write_bytes(b"original")
        status, _ = self.preflight([{"path": "keep.bin", "size": 1000000}])
        self.assertEqual(status, 200)
        holder = socket.create_connection(("127.0.0.1", self.port), timeout=5)
        try:
            holder.sendall((f"POST /{self.token}/api/upload?upload_id=android-upload"
                            "&path=keep.bin&on_exists=overwrite HTTP/1.1\r\n"
                            "Host: test\r\nContent-Length: 1000000\r\n\r\n").encode() + b"partial")
            self.assertTrue(self.storage.started.wait(3))
            before = time.monotonic()
            android_server.stop()
            self.assertLess(time.monotonic() - before, 5)
            self.assertTrue(self.storage.aborted.wait(2))
            self.assertFalse(self.storage.tickets)
            self.assertEqual((self.root / "keep.bin").read_bytes(), b"original")
            with self.assertRaises(OSError):
                socket.create_connection(("127.0.0.1", self.port), timeout=1)
        finally:
            holder.close()
        old_token = self.token
        self.token = "fedcba9876543210fedcba9876543210"
        self.port = android_server.start(self.storage, self.token, 0)
        status, _ = self.request("GET", f"/{old_token}/")
        self.assertEqual(status, 404)
        status, body = self.upload("keep.bin", b"after restart", "overwrite")
        self.assertEqual(status, 200, body)
        self.assertEqual(json.loads(body)["total_files"], 0)
        self.assertEqual((self.root / "keep.bin").read_bytes(), b"after restart")

    def test_idle_unauthenticated_connections_cannot_create_unbounded_threads(self):
        holders = []
        try:
            for _ in range(8):
                holders.append(socket.create_connection(("127.0.0.1", self.port), timeout=2))
            deadline = time.monotonic() + 2
            while len(android_server._server._clients) < 8 and time.monotonic() < deadline:
                time.sleep(0.01)
            self.assertEqual(len(android_server._server._clients), 8)
            with socket.create_connection(("127.0.0.1", self.port), timeout=2) as ninth:
                self.assertEqual(ninth.recv(1), b"")
            self.assertEqual(len(android_server._server._clients), 8)
        finally:
            for holder in holders:
                holder.close()

    def test_injected_python_storage_does_not_touch_desktop_root(self):
        class Storage:
            committed = None
            initialize = self.storage.validate
            exists = self.storage.exists
            is_dir = self.storage.isDirectory
            check_space = lambda _, required: None
            begin = lambda _, rel: (io.BytesIO(), "ticket")
            def commit(self, ticket, rel, overwrite, digest):
                self.committed = (ticket, rel, overwrite, digest)

            abort = lambda _, ticket: None
        httpd = upload_server._UploadHTTPServer(("127.0.0.1", 0), upload_server.SimpleUploadServer)
        httpd.storage = Storage()
        httpd.state = upload_server._ServerState()
        thread = threading.Thread(target=httpd.serve_forever, daemon=True)
        thread.start()
        old_port = self.port
        self.port = httpd.server_address[1]
        try:
            status, body = self.request("POST", "/api/upload?upload_id=python-storage&path=a.bin",
                                        b"storage seam")
            self.assertEqual(status, 200, body)
            self.assertEqual(
                httpd.storage.committed,
                ("ticket", "a.bin", False, hashlib.sha256(b"storage seam").hexdigest()),
            )
        finally:
            self.port = old_port
            httpd.shutdown()
            httpd.server_close()
            thread.join(2)


if __name__ == "__main__":
    unittest.main()
