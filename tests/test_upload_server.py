"""Tests for the main upload server.

The point of these is regression cover for the request-handling rules that are
easy to break silently: a body that is not consumed, a length that is missing,
a client mistake reported as a server fault, a retry that is turned away by its
own leftover, a stalled body that is never given up. They also import the
module, which is what catches a stdlib module disappearing under a newer
Python -- a syntax check alone would not.
"""

import errno
import hashlib
import http.client
import io
import json
import os
import random
import socket
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock
from pathlib import Path
from urllib.parse import urlencode

# Make the import independent of the directory the runner was started from.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import upload_server as server  # noqa: E402


def wait_for(predicate, timeout=8.0, interval=0.01):
    """Poll ``predicate`` until it is true; bounded, returns the last answer."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(interval)
    return bool(predicate())


def pattern(size, seed=1):
    """Deterministic, incompressible-looking bytes of exactly ``size``."""
    if size <= 0:
        return b""
    return random.Random(seed).getrandbits(8 * size).to_bytes(size, "big")


def read_response(sock):
    """Read one complete HTTP response from a raw socket."""
    data = b""
    while b"\r\n\r\n" not in data:
        chunk = sock.recv(65536)
        if not chunk:
            break
        data += chunk
    head, _, rest = data.partition(b"\r\n\r\n")
    lines = head.decode("latin-1").split("\r\n")
    status = int(lines[0].split()[1])
    headers = {}
    for line in lines[1:]:
        name, _, value = line.partition(":")
        headers[name.strip().lower()] = value.strip()
    length = int(headers.get("content-length", "0"))
    while len(rest) < length:
        chunk = sock.recv(65536)
        if not chunk:
            break
        rest += chunk
    return status, headers, rest


class UploadServerTestCase(unittest.TestCase):
    def setUp(self):
        self.temp_directory = tempfile.TemporaryDirectory()
        self.upload_root = Path(self.temp_directory.name) / "uploads"
        self.upload_root.mkdir(parents=True, exist_ok=True)
        self._original_root = server.UPLOAD_ROOT
        server.UPLOAD_ROOT = self.upload_root
        self.logs = []
        self.sockets = []

        logs = self.logs

        class RecordingHandler(server.SimpleUploadServer):
            # Short so a deliberately stalled socket in one test cannot linger.
            timeout = 5

            def _log(self, message, *, color=None):
                logs.append(message)

        self.handler_class = RecordingHandler
        # A private state per test: uploads recorded by one test must not be
        # visible to the next one through /api/status or the slot table.
        self.state = server._ServerState()
        self.state.set_per_ip_limit(1)
        self.httpd = server._UploadHTTPServer(("127.0.0.1", 0), RecordingHandler)
        self.httpd.state = self.state
        self.port = self.httpd.server_address[1]
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        for sock in self.sockets:
            try:
                sock.close()
            except OSError:
                pass
        # Body reads poll this flag, so stalled handlers end within a poll.
        self.state.stop()
        wait_for(lambda: not self.temp_files(), timeout=3)
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join(timeout=5)
        server.UPLOAD_ROOT = self._original_root
        try:
            self.temp_directory.cleanup()
        except OSError:
            # Windows keeps a deliberately stalled upload's temp file open
            # until its handler unwinds; the tempdir is disposable anyway.
            pass

    # -- helpers -----------------------------------------------------------

    def temp_files(self):
        return list(self.upload_root.rglob(f"{server.TEMP_PREFIX}*"))

    def log_lines(self, prefix):
        return [m for m in list(self.logs) if m.startswith(prefix)]

    def connect(self):
        sock = socket.create_connection(("127.0.0.1", self.port), timeout=15)
        self.sockets.append(sock)
        return sock

    def request_full(self, method, target, body=None, headers=None):
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=15)
        try:
            connection.request(method, target, body=body, headers=headers or {})
            response = connection.getresponse()
            payload = response.read()
            return (
                response.status,
                {k.lower(): v for k, v in response.getheaders()},
                payload,
            )
        finally:
            connection.close()

    def request(self, method, target, body=None, headers=None):
        status, _, payload = self.request_full(method, target, body, headers)
        return status, payload

    def upload_query(self, name, upload_id, on_exists="overwrite", **extra):
        params = {"upload_id": upload_id, "path": name, "on_exists": on_exists}
        params.update(extra)
        return urlencode(params)

    def upload_full(
        self,
        name,
        payload,
        on_exists="overwrite",
        upload_id="testupload1",
        headers=None,
        **extra,
    ):
        send_headers = {
            "Content-Type": "application/octet-stream",
            "Content-Length": str(len(payload)),
        }
        send_headers.update(headers or {})
        return self.request_full(
            "POST",
            "/api/upload?" + self.upload_query(name, upload_id, on_exists, **extra),
            body=payload,
            headers=send_headers,
        )

    def upload(self, name, payload, on_exists="overwrite", upload_id="testupload1", **extra):
        status, _, body = self.upload_full(name, payload, on_exists, upload_id, **extra)
        return status, body

    def preflight(self, items, upload_id="testupload2", headers=None):
        body = json.dumps({"upload_id": upload_id, "items": items}).encode("utf-8")
        send_headers = {
            "Content-Type": "application/json",
            "Content-Length": str(len(body)),
        }
        send_headers.update(headers or {})
        return self.request("POST", "/api/preflight", body=body, headers=send_headers)

    def upload_head(self, query, length, extra_headers=()):
        lines = [
            f"POST /api/upload?{query} HTTP/1.1",
            f"Host: 127.0.0.1:{self.port}",
            f"Content-Length: {length}",
            "Content-Type: application/octet-stream",
            *extra_headers,
        ]
        return ("\r\n".join(lines) + "\r\n\r\n").encode("ascii")

    def hold(
        self,
        name,
        *,
        client=None,
        upload_id="holdjob001",
        declared=20000,
        sent=5000,
        on_exists="overwrite",
    ):
        """Start an upload on a raw socket and leave its body unfinished.

        Returns once the handler holds its slot and has opened its temporary
        file, so the caller knows the upload is genuinely in flight.
        """
        extra = {"client": client} if client else {}
        query = self.upload_query(name, upload_id, on_exists, **extra)
        sock = self.connect()
        sock.sendall(self.upload_head(query, declared) + pattern(declared)[:sent])
        self.assertTrue(
            wait_for(self.temp_files), "the held upload never opened its temp file"
        )
        return sock

    # -- page --------------------------------------------------------------

    def test_index_page_is_served_with_placeholders_replaced(self):
        status, body = self.request("GET", "/")
        self.assertEqual(status, 200)
        self.assertTrue(body[:200].lstrip().lower().startswith(b"<!doctype html"))
        for placeholder in (
            b"__MAX_FILE_RETRIES__",
            b"__RETRY_BASE_DELAY_MS__",
            b"__UPLOAD_TIMEOUT_MS__",
            b"__STALL_TIMEOUT_MS__",
            b"__CASE_INSENSITIVE_FS__",
        ):
            self.assertNotIn(placeholder, body)

    def test_index_page_has_the_single_picker_buttons_and_relative_api_urls(self):
        status, body = self.request("GET", "/")
        self.assertEqual(status, 200)
        # job.resumeAt: a pass that stopped early continues where it left off.
        for needle in (b'id="pickFilesBtn"', b'id="pickFolderBtn"',
                       b"fetchJson('api/preflight'", b"job.resumeAt"):
            self.assertIn(needle, body)
        for gone in (b"singleFileForm", b"folderForm", b"Folders (keep structure)"):
            self.assertNotIn(gone, body)
        # A leading slash would break the private link, whose prefix is a path.
        self.assertNotIn(b"fetch('/api", body)

    # -- storing -----------------------------------------------------------

    def test_upload_stores_exact_bytes(self):
        payload = os.urandom(4096)
        status, body = self.upload("plain.bin", payload)
        self.assertEqual(status, 200)
        self.assertTrue(json.loads(body)["ok"])
        self.assertEqual((self.upload_root / "plain.bin").read_bytes(), payload)

    def test_upload_preserves_folder_structure(self):
        status, _ = self.upload("outer/inner/deep.bin", b"nested")
        self.assertEqual(status, 200)
        self.assertEqual(
            (self.upload_root / "outer" / "inner" / "deep.bin").read_bytes(), b"nested"
        )

    def test_multi_megabyte_upload_round_trips_exactly(self):
        # Larger than CHUNK_SIZE, so the read loop runs several times.
        payload = pattern(5 * 1024 * 1024, seed=5)
        self.assertGreater(len(payload), server.CHUNK_SIZE)
        status, body = self.upload("big.bin", payload)
        self.assertEqual(status, 200, body)
        reply = json.loads(body)
        self.assertEqual(reply["bytes"], len(payload))
        self.assertEqual(reply["sha256"], hashlib.sha256(payload).hexdigest())
        self.assertEqual((self.upload_root / "big.bin").read_bytes(), payload)

    def test_body_arriving_partly_with_the_headers_and_partly_later_is_exact(self):
        # The start of the body lands in the handler's read buffer together
        # with the headers; the rest comes off the socket. Dropping or
        # duplicating a byte at that seam corrupts the file silently.
        payload = pattern(400 * 1024, seed=11)
        query = self.upload_query("split.bin", "splitjob001")
        sock = self.connect()
        sock.sendall(self.upload_head(query, len(payload)) + payload[:1000])
        self.assertTrue(wait_for(self.temp_files))
        sock.sendall(payload[1000:70000])
        sock.sendall(payload[70000:250000])
        sock.sendall(payload[250000:])
        status, _, body = read_response(sock)
        self.assertEqual(status, 200, body)
        reply = json.loads(body)
        self.assertEqual(reply["bytes"], len(payload))
        self.assertEqual(reply["sha256"], hashlib.sha256(payload).hexdigest())
        self.assertEqual((self.upload_root / "split.bin").read_bytes(), payload)

    def test_parent_directory_traversal_is_rejected_as_client_error(self):
        # Must be 4xx: the client retries 5xx, re-sending the whole file.
        status, body = self.upload("../escape.bin", b"nope")
        self.assertEqual(status, 400)
        self.assertFalse(json.loads(body)["ok"])
        self.assertFalse((self.upload_root.parent / "escape.bin").exists())

    def test_chunked_upload_is_refused_instead_of_writing_an_empty_file(self):
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=15)
        connection.putrequest(
            "POST", "/api/upload?upload_id=testupload1&path=chunked.bin&on_exists=overwrite"
        )
        connection.putheader("Transfer-Encoding", "chunked")
        connection.endheaders()
        connection.send(b"5\r\nhello\r\n0\r\n\r\n")
        response = connection.getresponse()
        status = response.status
        response.read()
        connection.close()

        self.assertEqual(status, 501)
        self.assertFalse((self.upload_root / "chunked.bin").exists())

    def test_upload_without_content_length_does_not_truncate_an_existing_file(self):
        target = self.upload_root / "keep.bin"
        target.write_bytes(b"important")

        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=15)
        connection.putrequest(
            "POST", "/api/upload?upload_id=testupload1&path=keep.bin&on_exists=overwrite"
        )
        connection.endheaders()
        response = connection.getresponse()
        status = response.status
        response.read()
        connection.close()

        self.assertEqual(status, 411)
        self.assertEqual(target.read_bytes(), b"important")

    def test_explicit_zero_length_upload_is_still_allowed(self):
        status, _ = self.upload("empty.bin", b"")
        self.assertEqual(status, 200)
        self.assertTrue((self.upload_root / "empty.bin").exists())
        self.assertEqual((self.upload_root / "empty.bin").stat().st_size, 0)

    def test_skip_leaves_an_existing_file_untouched(self):
        target = self.upload_root / "existing.bin"
        target.write_bytes(b"original")
        status, _ = self.upload("existing.bin", b"replacement", on_exists="skip")
        self.assertEqual(status, 409)
        self.assertEqual(target.read_bytes(), b"original")

    # -- preflight ---------------------------------------------------------

    def test_preflight_reports_existing_files_as_conflicts(self):
        (self.upload_root / "there.bin").write_bytes(b"x")
        status, body = self.preflight([{"path": "there.bin", "size": 1}])
        self.assertEqual(status, 200)
        conflicts = json.loads(body)["conflicts"]
        self.assertEqual([c["reason"] for c in conflicts], ["exists"])

    def test_preflight_ignores_existing_files_in_the_disk_space_check(self):
        # Re-adding an already uploaded folder must not fail with
        # "not enough disk space" -- none of those bytes will be written.
        (self.upload_root / "huge.bin").write_bytes(b"x")
        free = server.shutil.disk_usage(self.upload_root).free
        status, body = self.preflight([{"path": "huge.bin", "size": free * 10}])
        self.assertEqual(status, 200)
        self.assertTrue(json.loads(body)["ok"])

    def test_preflight_still_refuses_genuinely_oversized_uploads(self):
        free = server.shutil.disk_usage(self.upload_root).free
        status, body = self.preflight([{"path": "new_and_huge.bin", "size": free * 10}])
        self.assertEqual(status, 400)
        self.assertIn("disk space", json.loads(body)["error"])

    def test_preflight_whose_body_never_arrives_is_dropped_and_logged(self):
        self.handler_class.body_idle_timeout = 1
        sock = self.connect()
        sock.settimeout(8)
        sock.sendall(
            (
                "POST /api/preflight HTTP/1.1\r\n"
                f"Host: 127.0.0.1:{self.port}\r\n"
                "Content-Type: application/json\r\n"
                "Content-Length: 500\r\n\r\n"
            ).encode("ascii")
            + b'{"upload_id": '
        )
        started = time.monotonic()
        received = b""
        try:
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                received += chunk
        except ConnectionError:
            pass
        elapsed = time.monotonic() - started
        self.assertEqual(received, b"", "an answer was sent for a request without body")
        self.assertLess(elapsed, 6)
        self.assertTrue(wait_for(lambda: self.log_lines("Preflight aborted:")))
        self.assertIn("reason=timed out", self.log_lines("Preflight aborted:")[0])
        self.assertEqual(self.log_lines("Preflight:"), [])

    # -- slots: busy, supersede, idle timeout -------------------------------

    def test_busy_client_receives_the_429_instead_of_a_reset_connection(self):
        # Answering without draining the body closes the socket mid-send, so the
        # client sees a network error instead of the status code.
        payload_size = 8 * 1024 * 1024
        self.hold("hold.bin", upload_id="holdholding", declared=100000000, sent=4096)

        status, headers, body = self.upload_full(
            "second.bin", b"y" * payload_size, upload_id="secondtry01"
        )
        self.assertEqual(status, 429, body)
        self.assertIn("retry-after", headers)

    def _assert_supersede(self, new_path):
        new_payload = pattern(30000, seed=4)
        self.assertNotEqual(pattern(20000)[:5000], new_payload[:5000])
        old = self.hold("target.bin", client="tab-aaaaaa", upload_id="oldjob0001")
        old.settimeout(5)

        started = time.monotonic()
        status, _, body = self.upload_full(
            new_path, new_payload, upload_id="newjob0001", client="tab-aaaaaa"
        )
        elapsed = time.monotonic() - started

        self.assertEqual(status, 200, body)
        # Far below body_idle_timeout (120 s) and SUPERSEDE_WAIT_SEC (5 s): the
        # old request must be told to stop, not waited out.
        self.assertLess(elapsed, 4)
        reply = json.loads(body)
        self.assertEqual(reply["sha256"], hashlib.sha256(new_payload).hexdigest())
        self.assertEqual((self.upload_root / new_path).read_bytes(), new_payload)
        self.assertEqual(self.temp_files(), [])
        if new_path != "target.bin":
            self.assertFalse((self.upload_root / "target.bin").exists())
        lines = self.log_lines("Upload superseded:")
        self.assertEqual(len(lines), 1, self.logs)
        self.assertIn("id=oldjob0001", lines[0])
        self.assertIn("path=target.bin", lines[0])
        self.assertIn("received=4.9 KB of 19.5 KB", lines[0])
        self.assertEqual(self.log_lines("Upload aborted:"), [])
        # The old connection is closed without an answer.
        try:
            data = old.recv(1)
        except ConnectionError:
            data = b""
        self.assertEqual(data, b"")

    def test_same_client_supersedes_a_stalled_upload_of_the_same_path(self):
        self._assert_supersede("target.bin")

    def test_same_client_supersedes_a_stalled_upload_of_another_path(self):
        self._assert_supersede("other.bin")

    def test_other_or_missing_client_is_refused_and_does_not_cancel_the_holder(self):
        payload = pattern(20000)
        holder = self.hold("held.bin", client="tab-aaaaaa", upload_id="heldjob001")
        for label, extra in (
            ("different client", {"client": "tab-bbbbbb"}),
            ("no client", {}),
            # Too short to be an id, so it must not be able to claim anything.
            ("invalid client", {"client": "x"}),
        ):
            with self.subTest(label):
                status, headers, body = self.upload_full(
                    "intruder.bin", b"intruder", upload_id="intruder01", **extra
                )
                self.assertEqual(status, 429, body)
                self.assertTrue(headers.get("retry-after", "").isdigit(), headers)
        self.assertEqual(self.log_lines("Upload superseded:"), [])
        self.assertFalse((self.upload_root / "intruder.bin").exists())
        # The holder was not cancelled: it can still finish and is stored.
        holder.sendall(payload[5000:])
        status, _, body = read_response(holder)
        self.assertEqual(status, 200, body)
        self.assertEqual((self.upload_root / "held.bin").read_bytes(), payload)

    def test_stalled_body_is_aborted_after_the_idle_timeout_and_frees_the_slot(self):
        self.handler_class.body_idle_timeout = 1
        target = self.upload_root / "target.bin"
        target.write_bytes(b"old content")
        started = time.monotonic()
        self.hold("target.bin", upload_id="stalljob001", declared=5000, sent=1000)

        self.assertTrue(wait_for(lambda: self.log_lines("Upload aborted:"), timeout=8))
        self.assertLess(time.monotonic() - started, 6)
        line = self.log_lines("Upload aborted:")[0]
        self.assertIn("reason=timed out", line)
        self.assertIn("received=1000 B of 4.9 KB", line)
        self.assertTrue(wait_for(lambda: not self.temp_files()))
        self.assertEqual(target.read_bytes(), b"old content")
        # The slot is free again: a normal upload from the same IP succeeds.
        status, body = self.upload("fresh.bin", b"abc", upload_id="freshjob001")
        self.assertEqual(status, 200, body)

    # -- /api/status --------------------------------------------------------

    def status_query(self, upload_id, path, client=None):
        params = {"upload_id": upload_id, "path": path}
        if client:
            params["client"] = client
        return self.request("GET", "/api/status?" + urlencode(params))

    def test_status_reports_done_with_size_and_hash_only_for_stored_files(self):
        status, body = self.status_query("statusjob01", "dir/s.bin")
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body)["done"], False)
        self.assertNotIn("sha256", json.loads(body))

        payload = pattern(7777, seed=8)
        self.assertEqual(self.upload("dir/s.bin", payload, upload_id="statusjob01")[0], 200)

        reply = json.loads(self.status_query("statusjob01", "dir/s.bin")[1])
        self.assertTrue(reply["ok"])
        self.assertTrue(reply["done"])
        self.assertEqual(reply["bytes"], len(payload))
        self.assertEqual(reply["sha256"], hashlib.sha256(payload).hexdigest())
        # The answer belongs to one job and one path, not to the file name.
        self.assertFalse(json.loads(self.status_query("otherjob001", "dir/s.bin")[1])["done"])
        self.assertFalse(json.loads(self.status_query("statusjob01", "dir/t.bin")[1])["done"])

    def test_status_busy_flag_is_true_only_for_other_clients(self):
        holder = self.hold("held.bin", client="tab-aaaaaa", upload_id="heldjob002")
        other = json.loads(self.status_query("x" * 8, "a.bin", "tab-bbbbbb")[1])
        anonymous = json.loads(self.status_query("x" * 8, "a.bin")[1])
        own = json.loads(self.status_query("x" * 8, "a.bin", "tab-aaaaaa")[1])
        self.assertTrue(other["busy"])
        self.assertTrue(anonymous["busy"])
        # The holder's own leftover will be superseded, so it is not "busy".
        self.assertFalse(own["busy"])
        holder.close()
        self.assertTrue(
            wait_for(
                lambda: not json.loads(self.status_query("x" * 8, "a.bin", "tab-bbbbbb")[1])["busy"],
                timeout=5,
            ),
            "the slot stayed busy after the holder disconnected",
        )

    def test_status_rejects_invalid_paths_as_client_error(self):
        for path in ("../x.bin", ""):
            with self.subTest(path=path):
                status, body = self.status_query("statusjob01", path)
                self.assertEqual(status, 400)
                self.assertFalse(json.loads(body)["ok"])

    # -- job counting -------------------------------------------------------

    def test_storing_the_same_path_twice_in_one_job_counts_once(self):
        status, body = self.preflight(
            [{"path": "a.bin", "size": 3}, {"path": "b.bin", "size": 3}],
            upload_id="dupjob0001",
        )
        self.assertEqual(status, 200, body)
        self.assertEqual(json.loads(body)["total_files"], 2)

        first = json.loads(self.upload("a.bin", b"one", upload_id="dupjob0001")[1])
        again = json.loads(self.upload("a.bin", b"one", upload_id="dupjob0001")[1])
        self.assertEqual((first["done_files"], first["total_files"]), (1, 2))
        self.assertEqual((again["done_files"], again["total_files"]), (1, 2))
        last = json.loads(self.upload("b.bin", b"two", upload_id="dupjob0001")[1])
        self.assertEqual(last["done_files"], 2)

    # -- cross-origin protection -----------------------------------------------

    def test_cross_origin_upload_and_preflight_are_refused_and_write_nothing(self):
        # Large enough that the answer only arrives if the body is drained.
        payload = pattern(2 * 1024 * 1024, seed=9)
        for origin in ("http://evil.example", "http://127.0.0.1:1"):
            with self.subTest(origin=origin):
                status, _, body = self.upload_full(
                    "evil.bin", payload, upload_id="evil000001", headers={"Origin": origin}
                )
                self.assertEqual(status, 403, body)
                self.assertEqual(
                    json.loads(body)["error"], "cross-origin request refused"
                )
                self.assertFalse((self.upload_root / "evil.bin").exists())
                self.assertEqual(self.temp_files(), [])
                status, body = self.preflight(
                    [{"path": "evil.bin", "size": 1}], headers={"Origin": origin}
                )
                self.assertEqual(status, 403, body)
        self.assertEqual(self.log_lines("Preflight:"), [])
        self.assertEqual(self.log_lines("START"), [])

    def test_same_origin_and_origin_less_requests_are_accepted(self):
        origin = {"Origin": f"http://127.0.0.1:{self.port}"}
        status, _, body = self.upload_full(
            "same.bin", b"same origin", upload_id="origin0001", headers=origin
        )
        self.assertEqual(status, 200, body)
        self.assertEqual((self.upload_root / "same.bin").read_bytes(), b"same origin")
        status, body = self.preflight([{"path": "p.bin", "size": 1}], headers=origin)
        self.assertEqual(status, 200, body)
        # Programs that are not browsers send no Origin at all.
        status, body = self.preflight([{"path": "q.bin", "size": 1}])
        self.assertEqual(status, 200, body)


    # -- name length and file-system limits --------------------------------------

    def test_overlong_name_is_refused_before_anything_is_stored(self):
        long_name = "a" * (server.MAX_NAME_BYTES + 1)
        status, _, body = self.upload_full(f"dir/{long_name}", b"data", upload_id="longname01")
        self.assertEqual(status, 400, body)
        self.assertIn("too long", json.loads(body)["error"])
        self.assertEqual(list(self.upload_root.rglob("*")), [])
        status, body = self.preflight([{"path": f"dir/{long_name}", "size": 4}])
        self.assertEqual(status, 400, body)
        self.assertIn("too long", json.loads(body)["error"])
        self.assertEqual(self.log_lines("Preflight:"), [])

    def test_name_limit_counts_utf8_bytes_per_component(self):
        limit = server.MAX_NAME_BYTES
        self.assertEqual(server._sanitize_rel_path("a" * limit), "a" * limit)
        with self.assertRaises(ValueError):
            server._sanitize_rel_path("a" * (limit + 1))
        # 127 two-byte characters fit, 128 are 256 bytes.
        self.assertEqual(server._sanitize_rel_path("\u00e9" * 127), "\u00e9" * 127)
        with self.assertRaises(ValueError):
            server._sanitize_rel_path("ok/" + "\u00e9" * 128)
        # The limit is per component: a long path of short names is fine.
        self.assertEqual(server._sanitize_rel_path("/".join(["abcdefgh"] * 100)),
                         "/".join(["abcdefgh"] * 100))

    def _storage_failing_with(self, where, error):
        real = server._LOCAL_STORAGE

        class Failing:
            def __getattr__(self, name):
                return getattr(real, name)

        def boom(*args, **kwargs):
            raise error

        storage = Failing()
        setattr(storage, where, boom)
        self.httpd.storage = storage

    def test_file_system_name_errors_are_client_errors_not_server_faults(self):
        windows_style = OSError(errno.EIO, "invalid name")
        windows_style.winerror = 123
        cases = (
            ("begin", OSError(errno.ENAMETOOLONG, "too long")),
            ("begin", OSError(errno.EINVAL, "invalid")),
            ("begin", windows_style),
            ("commit", OSError(errno.ENAMETOOLONG, "too long")),
        )
        for where, error in cases:
            with self.subTest(where=where, error=repr(error)):
                self._storage_failing_with(where, error)
                status, body = self.upload("x.bin", b"data", upload_id="fserror001")
                self.assertEqual(status, 400, body)
                self.assertIn("cannot store this path", json.loads(body)["error"])
                self.assertTrue(wait_for(lambda: not self.temp_files()))
        # Control: any other OS error stays a 500, so the 400 above is specific.
        self._storage_failing_with("begin", OSError(errno.EIO, "disk exploded"))
        status, _ = self.upload("x.bin", b"data", upload_id="fserror001")
        self.assertEqual(status, 500)

    # -- /api/status after another job stored the same path ------------------

    def test_status_of_an_earlier_job_is_invalidated_when_another_job_stores_the_path(self):
        first = pattern(1000, seed=21)
        second = pattern(1500, seed=22)
        self.assertEqual(self.upload("shared.bin", first, upload_id="jobuuuu001")[0], 200)
        self.assertTrue(json.loads(self.status_query("jobuuuu001", "shared.bin")[1])["done"])
        self.assertEqual(self.upload("shared.bin", second, upload_id="jobvvvv001")[0], 200)

        old = json.loads(self.status_query("jobuuuu001", "shared.bin")[1])
        new = json.loads(self.status_query("jobvvvv001", "shared.bin")[1])
        self.assertFalse(old["done"])
        self.assertNotIn("sha256", old)
        self.assertTrue(new["done"])
        self.assertEqual(new["bytes"], len(second))
        self.assertEqual(new["sha256"], hashlib.sha256(second).hexdigest())

    # -- privacy mode: malformed remainder after the secret prefix ---------------

    def test_private_mode_bad_remainder_after_the_prefix_gets_a_clean_400(self):
        errors = []
        self.httpd.handle_error = lambda request, address: errors.append(address)
        self.httpd.token = b"privatetoken"
        try:
            for target in ("/privatetoken//[x", "/privatetoken//[::1/x"):
                for method in ("GET", "POST"):
                    with self.subTest(method=method, target=target):
                        sock = self.connect()
                        sock.settimeout(8)
                        sock.sendall(
                            (
                                f"{method} {target} HTTP/1.1\r\nHost: h\r\n"
                                "Content-Length: 0\r\n\r\n"
                            ).encode("ascii")
                        )
                        status, _, body = read_response(sock)
                        self.assertEqual(status, 400, body)
                        self.assertEqual(
                            json.loads(body),
                            {"ok": False, "error": "invalid request target"},
                        )
        finally:
            self.httpd.token = None
        self.assertEqual(errors, [], "a handler raised instead of answering")

    # -- a broken stdout never decides an upload ---------------------------------

    def test_closed_stdout_does_not_fail_the_upload(self):
        class RealLogHandler(server.SimpleUploadServer):
            timeout = 5

        httpd = server._UploadHTTPServer(("127.0.0.1", 0), RealLogHandler)
        httpd.state = server._ServerState()
        thread = threading.Thread(target=httpd.serve_forever, daemon=True)
        thread.start()
        closed = io.StringIO()
        closed.close()  # every write now raises ValueError
        original = sys.stdout
        self.addCleanup(setattr, sys, "stdout", original)
        sys.stdout = closed
        payload = pattern(3000, seed=41)
        try:
            connection = http.client.HTTPConnection(
                "127.0.0.1", httpd.server_address[1], timeout=15
            )
            query = self.upload_query("quiet.bin", "closedout01")
            connection.request("POST", "/api/upload?" + query, body=payload,
                               headers={"Content-Length": str(len(payload))})
            response = connection.getresponse()
            status, body = response.status, response.read()
            connection.close()
        finally:
            sys.stdout = original
            httpd.shutdown()
            httpd.server_close()
            thread.join(5)
        self.assertEqual(status, 200, body)
        self.assertEqual(json.loads(body)["sha256"], hashlib.sha256(payload).hexdigest())
        self.assertEqual((self.upload_root / "quiet.bin").read_bytes(), payload)

    # -- overwrite by another job, then a resend of the first ----------------------

    def test_overwrite_by_another_job_then_resend_counts_once_and_moves_ownership(self):
        for job in ("jobvvvvv01", "jobuuuuu01"):
            status, body = self.preflight(
                [{"path": "p.bin", "size": 3}, {"path": "q.bin", "size": 3}],
                upload_id=job,
            )
            self.assertEqual(status, 200, body)
        v_data, u_data = pattern(1200, seed=51), pattern(1700, seed=52)

        first = json.loads(self.upload("p.bin", v_data, upload_id="jobvvvvv01")[1])
        self.assertEqual(first["done_files"], 1)
        self.assertEqual(
            json.loads(self.upload("p.bin", u_data, upload_id="jobuuuuu01")[1])["done_files"], 1
        )

        # Ownership: the job that stored the path last is the only one "done".
        v_status = json.loads(self.status_query("jobvvvvv01", "p.bin")[1])
        u_status = json.loads(self.status_query("jobuuuuu01", "p.bin")[1])
        self.assertFalse(v_status["done"])
        self.assertTrue(u_status["done"])
        self.assertEqual(u_status["bytes"], len(u_data))
        self.assertEqual(u_status["sha256"], hashlib.sha256(u_data).hexdigest())

        # V's first answer "got lost" and it sends P again: still one file.
        again = json.loads(self.upload("p.bin", v_data, upload_id="jobvvvvv01")[1])
        self.assertEqual((again["done_files"], again["total_files"]), (1, 2))
        v_status = json.loads(self.status_query("jobvvvvv01", "p.bin")[1])
        u_status = json.loads(self.status_query("jobuuuuu01", "p.bin")[1])
        self.assertTrue(v_status["done"])
        self.assertEqual(v_status["bytes"], len(v_data))
        self.assertEqual(v_status["sha256"], hashlib.sha256(v_data).hexdigest())
        self.assertFalse(u_status["done"])

    # -- stop and supersede reach an upload whose data keeps flowing --------------

    def _slow_storage(self, written):
        """Storage whose writes take 50 ms, so the socket buffer never empties."""
        real = server._LOCAL_STORAGE

        class SlowStream:
            def __init__(self, stream):
                self.stream = stream

            def __enter__(self):
                return self

            def __exit__(self, *args):
                self.stream.close()

            def write(self, data):
                time.sleep(0.05)
                written.append(len(data))
                return self.stream.write(data)

        class SlowStorage:
            def __getattr__(self, name):
                return getattr(real, name)

            def begin(self, rel):
                stream, ticket = real.begin(rel)
                return SlowStream(stream), ticket

        self.httpd.storage = SlowStorage()

    def _start_flowing_upload(self, written, client=None):
        """Declare a huge body and keep sending it until told to stop."""
        extra = {"client": client} if client else {}
        query = self.upload_query("flow.bin", "flowjob001", **extra)
        sock = self.connect()
        halt = threading.Event()

        def sender():
            chunk = b"f" * 256 * 1024
            try:
                sock.sendall(self.upload_head(query, 500 * 1024 * 1024))
                while not halt.is_set():
                    sock.sendall(chunk)
            except OSError:
                pass

        thread = threading.Thread(target=sender, daemon=True)
        thread.start()
        self.addCleanup(thread.join, 5)
        self.addCleanup(halt.set)
        self.assertTrue(
            wait_for(lambda: sum(written) >= 512 * 1024),
            "the flowing upload never got going",
        )
        return sock

    def test_slot_and_path_are_free_before_the_answer_goes_out(self):
        # A client sends its next file the moment an answer arrives. Whatever
        # that answer is, the slot must no longer belong to the finished
        # request, or the next file is turned away as "busy" now and then.
        seen = []
        state = self.state
        original = self.handler_class.send_response

        def recording(handler, code, message=None):
            if handler.path.startswith("/api/upload"):
                seen.append((code, bool(state._active), bool(state._reserved_paths)))
            return original(handler, code, message)

        self.handler_class.send_response = recording
        self.assertEqual(self.upload("slot.txt", b"one")[0], 200)
        self.assertEqual(self.upload("slot.txt", b"two", on_exists="skip")[0], 409)
        self.assertEqual(self.upload("../slot.txt", b"bad")[0], 400)
        self.assertEqual(
            seen, [(200, False, False), (409, False, False), (400, False, False)]
        )
        self.assertEqual((self.upload_root / "slot.txt").read_bytes(), b"one")

    def test_stop_ends_an_upload_whose_data_keeps_flowing(self):
        written = []
        self._slow_storage(written)
        self._start_flowing_upload(written)
        started = time.monotonic()
        self.state.stop(wait_sec=6)
        elapsed = time.monotonic() - started
        self.assertLess(elapsed, 2)
        self.assertEqual(self.state._active, {})
        self.assertEqual(self.temp_files(), [])
        self.assertTrue(self.log_lines("Upload aborted:"), self.logs)

    def test_new_request_of_the_same_client_supersedes_a_flowing_upload(self):
        written = []
        self._slow_storage(written)
        self._start_flowing_upload(written, client="tab-aaaaaa")
        # The replacement is small and must not wait for the 500 MB to end.
        self.httpd.storage = server._LOCAL_STORAGE
        started = time.monotonic()
        status, _, body = self.upload_full(
            "new.bin", b"replacement", upload_id="flowjob002", client="tab-aaaaaa"
        )
        self.assertEqual(status, 200, body)
        self.assertLess(time.monotonic() - started, 4)
        self.assertEqual((self.upload_root / "new.bin").read_bytes(), b"replacement")
        self.assertTrue(wait_for(lambda: self.log_lines("Upload superseded:")), self.logs)
        self.assertTrue(wait_for(lambda: not self.temp_files()))
        self.assertFalse((self.upload_root / "flow.bin").exists())

    def test_recv_into_honours_stop_and_cancel_even_with_buffered_data(self):
        # Unit level: the start of a body already sits in rfile's buffer, so
        # no wait ever happens and only a check on entry can notice the flag.
        left, right = socket.socketpair()
        self.addCleanup(left.close)
        self.addCleanup(right.close)
        for flag in ("stop", "cancel"):
            with self.subTest(flag):
                handler = object.__new__(self.handler_class)
                handler.connection = left
                handler.rfile = io.BufferedReader(io.BytesIO(b"buffered body"))
                handler.state = server._ServerState()
                handler._rfile_drained = False
                handler._cancel = threading.Event()
                if flag == "stop":
                    handler.state.stop()
                    expected = ConnectionError
                else:
                    handler._cancel.set()
                    expected = server._Superseded
                with self.assertRaises(expected):
                    handler._recv_into(memoryview(bytearray(64)))

    # -- names that look like the server's temporary files --------------------------

    def test_user_file_never_carries_the_temporary_name_pattern(self):
        cases = (
            (".upload_tmp_evil.bin", "_.upload_tmp_evil.bin"),
            (".UPLOAD_TMP_Upper.bin", "_.UPLOAD_TMP_Upper.bin"),
            (".Upload_Tmp_dir/inner.bin", "_.Upload_Tmp_dir/inner.bin"),
        )
        old = time.time() - 7200
        for name, expected in cases:
            with self.subTest(name=name):
                status, body = self.upload(name, name.encode(), upload_id="tmpname001")
                self.assertEqual(status, 200, body)
                self.assertEqual(json.loads(body)["rel_path"], expected)
                stored = self.upload_root / expected
                self.assertEqual(stored.read_bytes(), name.encode())
                os.utime(stored, (old, old))
        self.assertEqual(server._sweep_stale_temp_files(), 0)
        for _, expected in cases:
            self.assertTrue((self.upload_root / expected).exists(), expected)

    # -- control characters never reach the log ---------------------------------------

    def test_control_characters_in_headers_are_replaced_in_the_log(self):
        class RealLogHandler(server.SimpleUploadServer):
            timeout = 5

        httpd = server._UploadHTTPServer(("127.0.0.1", 0), RealLogHandler)
        httpd.state = server._ServerState()
        thread = threading.Thread(target=httpd.serve_forever, daemon=True)
        thread.start()
        captured = io.StringIO()
        original = sys.stdout
        self.addCleanup(setattr, sys, "stdout", original)
        sys.stdout = captured
        try:
            sock = socket.create_connection(("127.0.0.1", httpd.server_address[1]), timeout=10)
            try:
                sock.sendall(
                    b"GET / HTTP/1.1\r\nHost: h\r\n"
                    b"User-Agent: x\x1b[31mred\x07bell\r\n\r\n"
                )
                self.assertEqual(read_response(sock)[0], 200)
            finally:
                sock.close()
        finally:
            sys.stdout = original
            httpd.shutdown()
            httpd.server_close()
            thread.join(5)
        text = captured.getvalue()
        self.assertIn("ua=x?[31mred?bell", text)
        self.assertNotIn("\x07", text)
        self.assertNotIn("\x1b[31m", text)

    # -- several retries of one tab ------------------------------------------

    def test_only_the_newest_of_several_retries_takes_over_a_stalled_upload(self):
        self.hold("target.bin", client="tab-aaaaaa", upload_id="oldjob0001")
        results = {}
        payloads = {"r2.bin": pattern(30000, seed=31), "r3.bin": pattern(40000, seed=32)}

        def send(name, upload_id):
            try:
                results[name] = self.upload_full(
                    name, payloads[name], upload_id=upload_id, client="tab-aaaaaa"
                )
            except Exception as exc:  # noqa: BLE001 - recorded for the assertion
                results[name] = exc

        second = threading.Thread(target=send, args=("r2.bin", "retry00002"))
        third = threading.Thread(target=send, args=("r3.bin", "retry00003"))
        second.start()
        time.sleep(0.05)
        third.start()
        second.join(15)
        third.join(15)

        self.assertEqual(results["r3.bin"][0], 200, results)
        self.assertEqual((self.upload_root / "r3.bin").read_bytes(), payloads["r3.bin"])
        self.assertEqual(results["r2.bin"][0], 429, results)
        self.assertFalse((self.upload_root / "r2.bin").exists())
        self.assertFalse((self.upload_root / "target.bin").exists())

    # -- malformed targets and headers ----------------------------------------

    def test_unparsable_request_targets_and_origins_get_a_clean_answer(self):
        errors = []
        self.httpd.handle_error = lambda request, address: errors.append(address)
        origin_post = (
            "POST /api/upload?upload_id=badorigin1&path=a.bin HTTP/1.1\r\n"
            f"Host: 127.0.0.1:{self.port}\r\nOrigin: http://[::1\r\n"
            "Content-Length: 0\r\n\r\n"
        )
        cases = (
            ("GET http://[x/ HTTP/1.1\r\nHost: h\r\n\r\n", 400),
            ("POST http://[x/api/upload HTTP/1.1\r\nHost: h\r\nContent-Length: 0\r\n\r\n", 400),
            (origin_post, 403),
        )
        # Private mode must answer 400 too: the target is checked before the
        # secret prefix is, and the prefix check parses the target itself.
        attempts = [(None, raw, code) for raw, code in cases]
        attempts += [(b"privatetoken", raw, 400) for raw, _ in cases[:2]]
        for token, raw, expected in attempts:
            self.httpd.token = token
            with self.subTest(raw=raw.split("\r\n")[0], private=token is not None):
                sock = self.connect()
                sock.settimeout(8)
                sock.sendall(raw.encode("ascii"))
                status, _, body = read_response(sock)
                self.assertEqual(status, expected, body)
                self.assertFalse(json.loads(body)["ok"])
        self.httpd.token = None
        self.assertEqual(errors, [], "a handler raised instead of answering")
        self.assertFalse((self.upload_root / "a.bin").exists())
        self.assertEqual(self.request("GET", "/")[0], 200)

    # -- logging must not change the outcome ------------------------------------

    def test_log_line_that_stdout_cannot_encode_does_not_fail_the_upload(self):
        class RealLogHandler(server.SimpleUploadServer):
            timeout = 5

        httpd = server._UploadHTTPServer(("127.0.0.1", 0), RealLogHandler)
        httpd.state = server._ServerState()
        thread = threading.Thread(target=httpd.serve_forever, daemon=True)
        thread.start()
        captured = io.BytesIO()
        narrow = io.TextIOWrapper(captured, encoding="cp1252", errors="strict")
        original = sys.stdout
        sys.stdout = narrow
        try:
            connection = http.client.HTTPConnection(
                "127.0.0.1", httpd.server_address[1], timeout=15
            )
            query = self.upload_query("\u00fcber\u65e5.txt", "unicode0001")
            connection.request("POST", "/api/upload?" + query, body=b"hello",
                               headers={"Content-Length": "5"})
            response = connection.getresponse()
            status, body = response.status, response.read()
            connection.close()
            narrow.flush()
            log_bytes = captured.getvalue()
        finally:
            sys.stdout = original
            httpd.shutdown()
            httpd.server_close()
            thread.join(5)
        self.assertEqual(status, 200, body)
        self.assertEqual(json.loads(body)["bytes"], 5)
        self.assertEqual((self.upload_root / "\u00fcber\u65e5.txt").read_bytes(), b"hello")
        self.assertIn(b"\\xfcber\\u65e5.txt", log_bytes)

    # -- stopping ---------------------------------------------------------------

    def test_stop_with_wait_returns_after_the_stalled_upload_cleaned_up(self):
        self.hold("target.bin", client="tab-aaaaaa", upload_id="stopjob001")
        started = time.monotonic()
        self.state.stop(wait_sec=3)
        elapsed = time.monotonic() - started
        # Checked immediately, without polling: stop() itself must have waited.
        self.assertEqual(self.temp_files(), [])
        self.assertLess(elapsed, 2.5)

    # -- logging ------------------------------------------------------------

    def test_log_lines_describe_the_request_lifecycle(self):
        self.assertEqual(self.request("GET", "/")[0], 200)
        self.assertEqual(self.request("GET", "/nothing-here")[0], 404)
        self.assertEqual(
            self.upload("log.bin", b"hello", upload_id="logjob0001")[0], 200
        )
        self.assertEqual(
            self.upload(
                "log2.bin", b"hello", upload_id="logjob0001", attempt="2", reason="stalled"
            )[0],
            200,
        )
        self.assertEqual(
            self.upload(
                "log3.bin", b"hello", upload_id="logjob0001", attempt="3", reason="Bad Reason!"
            )[0],
            200,
        )
        self.assertEqual(
            self.upload("log4.bin", b"hello", upload_id="logjob0001", attempt="1")[0], 200
        )

        self.assertEqual(len(self.log_lines("New client:")), 1)
        self.assertEqual(len(self.log_lines("Page opened:")), 1)
        self.assertIn(
            "method=GET route=other status=404", self.log_lines("Request:")[0]
        )
        starts = self.log_lines("START")
        self.assertEqual(len(starts), 4)
        self.assertNotIn("attempt=", starts[0])
        self.assertTrue(starts[1].endswith(" attempt=2 after=stalled"), starts[1])
        self.assertTrue(starts[2].endswith(" attempt=3"), starts[2])
        self.assertNotIn("attempt=", starts[3])
        done = self.log_lines("DONE")
        self.assertEqual(len(done), 4)
        self.assertIn("bytes=5 B", done[0])
        self.assertIn(hashlib.sha256(b"hello").hexdigest(), done[0])
        # Lines of earlier versions that must not come back.
        self.assertEqual(self.log_lines("Upload started:"), [])
        self.assertFalse([m for m in self.logs if m.startswith("Client request:")])

    def test_successful_preflight_is_logged_with_counts(self):
        (self.upload_root / "there.bin").write_bytes(b"x")
        status, _ = self.preflight(
            [{"path": "there.bin", "size": 1}, {"path": "new.bin", "size": 2048}],
            upload_id="prejob0001",
        )
        self.assertEqual(status, 200)
        line = self.log_lines("Preflight:")[0]
        for part in ("id=prejob0001", "files=2", "total=2.0 KB", "conflicts=1"):
            self.assertIn(part, line)

    def test_format_bytes(self):
        self.assertEqual(server._format_bytes(0), "0 B")
        self.assertEqual(server._format_bytes(1023), "1023 B")
        self.assertEqual(server._format_bytes(1024), "1.0 KB")
        self.assertEqual(server._format_bytes(1536), "1.5 KB")


class ServerStateTestCase(unittest.TestCase):
    def test_older_waiting_retry_gives_way_to_the_newest_one(self):
        state = server._ServerState()
        active = state.begin_upload("10.0.0.1", "tab-aaaaaa", "active0001", 0)
        self.assertIsNotNone(active)
        results = {}

        def waiter(name):
            results[name] = state.begin_upload("10.0.0.1", "tab-aaaaaa", name, 5)

        first = threading.Thread(target=waiter, args=("waiter0001",))
        first.start()
        self.assertTrue(wait_for(active.cancel.is_set), "waiter A never started waiting")
        second = threading.Thread(target=waiter, args=("waiter0002",))
        second.start()
        # A is told to give way as soon as B exists, before the slot frees up.
        first.join(3)
        self.assertFalse(first.is_alive(), "the older waiter kept waiting")
        self.assertIsNone(results["waiter0001"])
        state.end_upload("10.0.0.1", active)
        second.join(3)
        self.assertFalse(second.is_alive())
        winner = results["waiter0002"]
        self.assertIsNotNone(winner)
        self.assertEqual(winner.upload_id, "waiter0002")
        state.end_upload("10.0.0.1", winner)
        self.assertEqual(state._latest, {})

    def test_owner_less_requests_never_cancel_or_supersede(self):
        state = server._ServerState()
        active = state.begin_upload("10.0.0.1", "tab-aaaaaa", "active0001", 0)
        self.assertIsNone(state.begin_upload("10.0.0.1", None, "anon000001", 0.2))
        self.assertIsNone(state.begin_upload("10.0.0.1", "tab-bbbbbb", "other00001", 0.2))
        self.assertFalse(active.cancel.is_set())
        state.end_upload("10.0.0.1", active)
        self.assertEqual(state._latest, {})

    def test_recent_done_eviction_keeps_both_structures_consistent(self):
        state = server._ServerState()
        with mock.patch.object(server, "RECENT_DONE_LIMIT", 2):
            state.bump_done("jobaaaaaa1", "a.bin", bytes_written=1, digest="d1")
            state.bump_done("jobbbbbbb2", "a.bin", bytes_written=2, digest="d2")
            state.bump_done("jobccccc03", "b.bin", bytes_written=3, digest="d3")
            state.bump_done("jobddddd04", "c.bin", bytes_written=4, digest="d4")
        self.assertIsNone(state.lookup_done("jobaaaaaa1", "a.bin"))
        self.assertIsNone(state.lookup_done("jobbbbbbb2", "a.bin"))
        self.assertEqual(state.lookup_done("jobccccc03", "b.bin"), (3, "d3"))
        self.assertEqual(state.lookup_done("jobddddd04", "c.bin"), (4, "d4"))
        recent = {(job, path) for job, path in state._recent_done}
        owners = {(job, path) for path, job in state._done_owner.items()}
        self.assertEqual(owners, recent)


class TempFileSweepTestCase(unittest.TestCase):
    def setUp(self):
        self.temp_directory = tempfile.TemporaryDirectory()
        self.upload_root = Path(self.temp_directory.name) / "uploads"
        (self.upload_root / "sub").mkdir(parents=True, exist_ok=True)
        self._original_root = server.UPLOAD_ROOT
        server.UPLOAD_ROOT = self.upload_root

    def tearDown(self):
        server.UPLOAD_ROOT = self._original_root
        self.temp_directory.cleanup()

    def test_only_stale_temp_files_are_removed(self):
        stale = self.upload_root / "sub" / f"{server.TEMP_PREFIX}stale"
        fresh = self.upload_root / f"{server.TEMP_PREFIX}fresh"
        real = self.upload_root / "real_upload.bin"
        for path in (stale, fresh, real):
            path.write_bytes(b"x" * 16)
        old = time.time() - 7200
        os.utime(stale, (old, old))

        removed = server._sweep_stale_temp_files()

        self.assertEqual(removed, 1)
        self.assertFalse(stale.exists())
        self.assertTrue(fresh.exists())
        self.assertTrue(real.exists())


class PathSanitizationTestCase(unittest.TestCase):
    def test_parent_segments_are_refused(self):
        for bad in ("../x", "a/../../x", "..\\x"):
            with self.assertRaises(ValueError):
                server._sanitize_rel_path(bad)

    def test_drive_letters_and_leading_slashes_are_stripped(self):
        self.assertEqual(server._sanitize_rel_path("C:\\dir\\file.bin"), "dir/file.bin")
        self.assertEqual(server._sanitize_rel_path("/etc/passwd"), "etc/passwd")

    def test_windows_reserved_names_are_escaped(self):
        self.assertEqual(server._sanitize_rel_path("nul"), "_nul_")
        self.assertEqual(server._sanitize_rel_path("a/con.txt/b"), "a/_con.txt_/b")

    def test_illegal_characters_are_replaced(self):
        self.assertEqual(server._sanitize_rel_path('a<b>c.bin'), "a_b_c.bin")
        # A colon would otherwise open an alternate data stream on Windows.
        self.assertEqual(server._sanitize_rel_path("file.txt:stream"), "file.txt_stream")

    def test_empty_paths_are_refused(self):
        with self.assertRaises(ValueError):
            server._sanitize_rel_path("")


class CaseSensitivityTestCase(unittest.TestCase):
    def test_probe_measures_the_folder_and_leaves_nothing_behind(self):
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp)
            (folder / "Marker.txt").write_bytes(b"x")
            expected = (folder / "mARKER.TXT").exists()
            # The unmeasured fallback is set to the opposite of the truth, so
            # only a real measurement can return the expected answer.
            with mock.patch.object(server, "_CASE_INSENSITIVE", not expected):
                self.assertEqual(server._probe_case_insensitive(folder), expected)
            self.assertEqual([p.name for p in folder.iterdir()], ["Marker.txt"])

    def test_measured_case_rule_decides_path_keys_and_the_page(self):
        for flag, needle in ((True, "= true;"), (False, "= false;")):
            with mock.patch.object(server, "_CASE_INSENSITIVE", flag):
                same = server._path_key("Dir/A.TXT") == server._path_key("dir/a.txt")
                self.assertEqual(same, flag)
                self.assertIn(
                    "const CASE_INSENSITIVE_FS " + needle, server._render_html()
                )


if __name__ == "__main__":
    unittest.main()
