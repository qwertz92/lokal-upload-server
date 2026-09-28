"""Run the real desktop CLI to verify normal and private access URLs."""

import contextlib
import hashlib
import http.client
import json
from pathlib import Path
import re
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from urllib.parse import urlencode, urlparse

SCRIPT = Path(__file__).resolve().parents[1] / "2025_12_python_upload_webserver.py"


class DesktopPrivacyTest(unittest.TestCase):
    @contextlib.contextmanager
    def running_cli(self, private=False, listeners=1):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            sockets = [socket.socket() for _ in range(listeners)]
            try:
                for item in sockets:
                    item.bind(("127.0.0.1", 0))
                ports = [item.getsockname()[1] for item in sockets]
            finally:
                for item in sockets:
                    item.close()
            args = [sys.executable, str(SCRIPT)]
            if listeners == 1:
                args += ["--host", "127.0.0.1", "--port", str(ports[0])]
            else:
                for port in ports:
                    args += ["--listen", f"127.0.0.1:{port}"]
            if private:
                args.append("--private")
            log = root / "server.log"
            with log.open("w") as output:
                process = subprocess.Popen(args, cwd=root, stdout=output, stderr=output)
                watchdog = threading.Timer(20, process.kill)
                watchdog.daemon = True
                watchdog.start()
                try:
                    deadline = time.monotonic() + 8
                    while time.monotonic() < deadline:
                        text = log.read_text()
                        if "Storage path:" in text:
                            break
                        if process.poll() is not None:
                            self.fail(f"Server exited before startup: {text}")
                        time.sleep(0.02)
                    else:
                        self.fail(f"Server startup timed out: {log.read_text()}")
                    urls = re.findall(r"http://127\.0\.0\.1:\d+(?:/[A-Za-z0-9_-]+/)?", text)
                    self.assertEqual(len(urls), listeners, text)
                    yield root, urls
                finally:
                    watchdog.cancel()
                    if process.poll() is None:
                        process.terminate()
                    try:
                        process.wait(timeout=3)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=3)

    def request(self, url, method="GET", target=None, body=None):
        parsed = urlparse(url)
        connection = http.client.HTTPConnection(parsed.hostname, parsed.port, timeout=3)
        try:
            connection.request(method, target or parsed.path or "/", body=body)
            response = connection.getresponse()
            return response.status, response.read()
        finally:
            connection.close()

    def test_default_cli_plain_root_preflight_and_nested_upload(self):
        with self.running_cli() as (root, urls):
            url = urls[0]
            self.assertEqual(urlparse(url).path, "")
            status, html = self.request(url)
            self.assertEqual(status, 200)
            self.assertIn(b"fetch('api/preflight'", html)
            payload = bytes(range(256)) * 17
            body = json.dumps({"upload_id": "desktop-normal", "items": [
                {"path": "folder/plain.bin", "size": len(payload)}
            ]}).encode()
            status, body = self.request(url, "POST", "/api/preflight", body)
            self.assertEqual(status, 200, body)
            query = urlencode({"upload_id": "desktop-normal", "path": "folder/plain.bin"})
            status, body = self.request(url, "POST", f"/api/upload?{query}", payload)
            self.assertEqual(status, 200, body)
            self.assertEqual((root / "uploads/folder/plain.bin").read_bytes(), payload)

    def test_private_cli_same_secret_link_on_all_listeners_and_routes(self):
        with self.running_cli(private=True, listeners=2) as (root, urls):
            paths = {urlparse(url).path for url in urls}
            self.assertEqual(len(paths), 1)
            prefix = paths.pop()
            self.assertRegex(prefix, r"^/[A-Za-z0-9_-]{24,}/$")
            for url in urls:
                for method, target, body in (
                    ("GET", "/", None),
                    ("POST", "/api/preflight", b'{}'),
                    ("POST", "/api/upload?upload_id=blocked-upload&path=blocked.bin", b"blocked"),
                ):
                    status, _ = self.request(url, method, target, body)
                    self.assertEqual(status, 404, (url, method, target))
                status, _ = self.request(url)
                self.assertEqual(status, 200)
            self.assertFalse((root / "uploads/blocked.bin").exists())
            payload = bytes(range(256)) * 19
            body = json.dumps({"upload_id": "desktop-private", "items": [
                {"path": "folder/private.bin", "size": len(payload)}
            ]}).encode()
            status, body = self.request(urls[0], "POST", prefix + "api/preflight", body)
            self.assertEqual(status, 200, body)
            query = urlencode({"upload_id": "desktop-private", "path": "folder/private.bin"})
            status, body = self.request(urls[0], "POST", prefix + f"api/upload?{query}", payload)
            self.assertEqual(status, 200, body)
            self.assertEqual(json.loads(body)["sha256"], hashlib.sha256(payload).hexdigest())
            self.assertEqual((root / "uploads/folder/private.bin").read_bytes(), payload)

    def test_private_cli_selftest_checks_private_link(self):
        result = subprocess.run(
            [sys.executable, str(SCRIPT), "--private", "--selftest"],
            capture_output=True, text=True, timeout=15,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("private link checked", result.stdout)


if __name__ == "__main__":
    unittest.main()
