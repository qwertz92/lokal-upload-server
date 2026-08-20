"""Tests for the main upload server.

The point of these is regression cover for the request-handling rules that are
easy to break silently: a body that is not consumed, a length that is missing,
a client mistake reported as a server fault. They also import the module, which
is what catches a stdlib module disappearing under a newer Python -- a syntax
check alone would not.
"""

import http.client
import importlib
import json
import os
import socket
import tempfile
import threading
import time
import unittest
from pathlib import Path

# The module name starts with a digit, so it cannot be imported with `import`.
server = importlib.import_module("2025_12_python_upload_webserver")


class QuietUploadServer(server.SimpleUploadServer):
    # Short so a deliberately stalled socket in one test cannot linger.
    timeout = 5

    def _log(self, message, *, color=None):
        pass


class UploadServerTestCase(unittest.TestCase):
    def setUp(self):
        self.temp_directory = tempfile.TemporaryDirectory()
        self.upload_root = Path(self.temp_directory.name) / "uploads"
        self.upload_root.mkdir(parents=True, exist_ok=True)
        self._original_root = server.UPLOAD_ROOT
        server.UPLOAD_ROOT = self.upload_root
        server.STATE.set_per_ip_limit(1)

        self.httpd = server._UploadHTTPServer(("127.0.0.1", 0), QuietUploadServer)
        self.port = self.httpd.server_address[1]
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
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

    def request(self, method, target, body=None, headers=None):
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=15)
        connection.request(method, target, body=body, headers=headers or {})
        response = connection.getresponse()
        payload = response.read()
        connection.close()
        return response.status, payload

    def upload(self, name, payload, on_exists="overwrite", upload_id="testupload1"):
        return self.request(
            "POST",
            f"/api/upload?upload_id={upload_id}&path={name}&on_exists={on_exists}",
            body=payload,
            headers={
                "Content-Type": "application/octet-stream",
                "Content-Length": str(len(payload)),
            },
        )

    def preflight(self, items, upload_id="testupload2"):
        body = json.dumps({"upload_id": upload_id, "items": items}).encode("utf-8")
        return self.request(
            "POST",
            "/api/preflight",
            body=body,
            headers={
                "Content-Type": "application/json",
                "Content-Length": str(len(body)),
            },
        )

    def test_index_page_is_served_with_placeholders_replaced(self):
        status, body = self.request("GET", "/")
        self.assertEqual(status, 200)
        self.assertTrue(body[:200].lstrip().lower().startswith(b"<!doctype html"))
        for placeholder in (
            b"__MAX_FILE_RETRIES__",
            b"__RETRY_BASE_DELAY_MS__",
            b"__UPLOAD_TIMEOUT_MS__",
            b"__CASE_INSENSITIVE_FS__",
        ):
            self.assertNotIn(placeholder, body)

    def test_upload_stores_exact_bytes(self):
        payload = os.urandom(4096)
        status, body = self.upload("plain.bin", payload)
        self.assertEqual(status, 200)
        self.assertTrue(json.loads(body)["ok"])
        self.assertEqual((self.upload_root / "plain.bin").read_bytes(), payload)

    def test_upload_preserves_folder_structure(self):
        status, _ = self.upload("outer%2Finner%2Fdeep.bin", b"nested")
        self.assertEqual(status, 200)
        self.assertEqual(
            (self.upload_root / "outer" / "inner" / "deep.bin").read_bytes(), b"nested"
        )

    def test_parent_directory_traversal_is_rejected_as_client_error(self):
        # Must be 4xx: the client retries 5xx, re-sending the whole file.
        status, body = self.upload("..%2Fescape.bin", b"nope")
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

    def test_busy_client_receives_the_429_instead_of_a_reset_connection(self):
        # Answering without draining the body closes the socket mid-send, so the
        # client sees a network error instead of the status code.
        payload_size = 8 * 1024 * 1024
        holder = socket.create_connection(("127.0.0.1", self.port), timeout=20)
        holder.sendall(
            b"POST /api/upload?upload_id=holdholding&path=hold.bin&on_exists=overwrite"
            b" HTTP/1.1\r\nHost: t\r\nContent-Length: 100000000\r\n\r\n" + b"z" * 4096
        )
        time.sleep(0.5)

        result = {}

        def attempt():
            try:
                result["status"], _ = self.upload(
                    "second.bin", b"y" * payload_size, upload_id="secondtry01"
                )
            except Exception as exc:  # noqa: BLE001 - recorded for the assertion
                result["error"] = f"{type(exc).__name__}: {exc}"

        worker = threading.Thread(target=attempt)
        worker.start()
        worker.join(timeout=40)
        # Let the stalled handler unwind before the temp dir is removed.
        holder.close()
        time.sleep(0.5)

        self.assertNotIn("error", result, msg=result.get("error"))
        self.assertEqual(result.get("status"), 429)


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


if __name__ == "__main__":
    unittest.main()
