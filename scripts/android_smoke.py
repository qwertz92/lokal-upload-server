#!/usr/bin/env python3
"""Exercise the running Android server and verify its SAF files using ADB.

Select --device-dir in the app first and pass its current URL. Add --privacy-mode
when the app requires the complete capability URL instead of plain IP:port.
The script does not install, start, stop, or configure the app or ADB forwarding.
"""

import argparse
from datetime import datetime, timezone
import hashlib
import http.client
import json
from pathlib import Path, PurePosixPath
import re
import secrets
import shlex
import socket
import subprocess
import tempfile
import time
from urllib.parse import urlencode, urlsplit


class Smoke:
    def __init__(self, args):
        self.args = args
        self.url = urlsplit(args.base_url)
        valid_path = (re.fullmatch(r"/[A-Za-z0-9_-]{1,128}/", self.url.path)
                      if args.privacy_mode else self.url.path == "/")
        if (self.url.scheme != "http" or not self.url.hostname
                or self.url.username or self.url.password or self.url.query
                or self.url.fragment
                or not valid_path):
            expected = "http://host:port/token/" if args.privacy_mode else "http://host:port/"
            raise ValueError("--base-url must be " + expected + " for the selected mode")
        root = PurePosixPath(args.device_dir)
        if not root.is_absolute() or ".." in root.parts or "\n" in args.device_dir:
            raise ValueError("--device-dir must be an absolute Android directory without '..'")
        self.root = str(root)
        self.run = "android-smoke-" + secrets.token_hex(8)
        self.files = {}
        self.checks = []
        self.owns_namespace = False

    def adb(self, command):
        result = subprocess.run(
            [self.args.adb, "-s", self.args.serial, "shell", command],
            capture_output=True, timeout=self.args.timeout, check=False,
        )
        if result.returncode:
            raise RuntimeError(f"ADB failed ({result.returncode}): "
                               + result.stderr.decode("utf-8", "replace").strip())
        return result.stdout.decode("utf-8", "replace").strip()

    def device_path(self, rel):
        return str(PurePosixPath(self.root) / rel)

    def request(self, method, suffix="", body=None, base=None, headers=None):
        connection = http.client.HTTPConnection(
            self.url.hostname, self.url.port or 80, timeout=self.args.timeout,
        )
        try:
            connection.request(method, (self.url.path if base is None else base) + suffix,
                               body=body, headers=headers or {})
            response = connection.getresponse()
            data = response.read(2 * 1024 * 1024 + 1)
            if len(data) > 2 * 1024 * 1024:
                raise RuntimeError("Server response exceeds the smoke test's 2 MiB limit")
            return response.status, data
        finally:
            connection.close()

    def preflight(self, rel, size):
        body = json.dumps({"upload_id": self.run, "items": [{"path": rel, "size": size}]})
        status, data = self.request("POST", "api/preflight", body.encode(),
                                    headers={"Content-Type": "application/json"})
        self.require(status == 200, f"preflight status {status}: {data!r}")
        payload = json.loads(data)
        self.require(payload.get("ok") is True, f"preflight failed: {payload}")
        return payload

    def upload(self, rel, body, policy="overwrite", client=None, headers=None):
        params = {"upload_id": self.run, "path": rel, "on_exists": policy}
        if client is not None:
            params["client"] = client
        query = urlencode(params)
        if isinstance(body, bytes):
            size = len(body)
        else:
            size = body.seek(0, 2)
            body.seek(0)
        return self.request("POST", "api/upload?" + query, body,
                            headers={"Content-Type": "application/octet-stream",
                                     "Content-Length": str(size), **(headers or {})})

    def status(self, rel, client=None, base=None):
        params = {"upload_id": self.run, "path": rel}
        if client is not None:
            params["client"] = client
        status, data = self.request("GET", "api/status?" + urlencode(params), base=base)
        return status, (json.loads(data) if status == 200 else data)

    def hung_upload(self, rel, client, size=4 * 1024 * 1024):
        """Open an upload that sends part of its body and then goes silent."""
        query = urlencode({"upload_id": self.run, "path": rel, "on_exists": "overwrite",
                           "client": client})
        connection = socket.create_connection((self.url.hostname, self.url.port or 80),
                                              timeout=self.args.timeout)
        connection.settimeout(self.args.timeout)
        header = (f"POST {self.url.path}api/upload?{query} HTTP/1.1\r\nHost: smoke\r\n"
                  f"Content-Length: {size}\r\nContent-Type: application/octet-stream\r\n\r\n")
        connection.sendall(header.encode("ascii") + b"hung" * 16384)
        return connection

    @staticmethod
    def require(condition, message):
        if not condition:
            raise AssertionError(message)

    def passed(self, name, **evidence):
        self.checks.append({"check": name, "passed": True, **evidence})
        print("PASS " + name, flush=True)

    def verify(self, rel, size, digest):
        path = shlex.quote(self.device_path(rel))
        output = self.adb("sha256sum " + path)
        actual = output.split(maxsplit=1)[0] if output else ""
        self.require(actual == digest, f"Device SHA-256 differs for {rel}: {actual}")
        actual_size = int(self.adb("wc -c < " + path))
        self.require(actual_size == size, f"Device size differs for {rel}: {actual_size}")
        self.files[rel] = {"bytes": size, "sha256": digest}

    def put(self, rel, data, wait=0):
        self.files.setdefault(rel, {})  # Track attempted writes for exact cleanup on failure.
        self.preflight(rel, len(data))
        deadline = time.monotonic() + wait
        retries = 0
        while True:
            status, body = self.upload(rel, data)
            if status != 429 or time.monotonic() >= deadline:
                break
            retries += 1
            time.sleep(0.1)
        digest = hashlib.sha256(data).hexdigest()
        self.require(status == 200, f"upload status {status}: {body!r}")
        result = json.loads(body)
        self.require(result.get("ok") is True and result.get("bytes") == len(data)
                     and result.get("sha256") == digest, f"upload receipt differs: {result}")
        self.verify(rel, len(data), digest)
        return retries

    def listing(self):
        path = shlex.quote(self.device_path(self.run))
        output = self.adb("find " + path + " -type f")
        return set(output.splitlines()) if output else set()

    def no_temporary_files(self, wait=0):
        expected = {self.device_path(rel) for rel in self.files}
        deadline = time.monotonic() + wait
        while True:
            actual = self.listing()
            if actual == expected:
                return
            if time.monotonic() >= deadline:
                self.require(False, f"Unexpected/missing smoke files: {sorted(actual ^ expected)}")
            time.sleep(0.1)

    def execute(self):
        self.require(self.adb("test -d " + shlex.quote(self.root) + " && printf yes") == "yes",
                     "Selected device folder is unavailable over ADB")
        self.adb("test ! -e " + shlex.quote(self.device_path(self.run)))
        self.owns_namespace = True
        self.passed("device folder accessible", serial=self.args.serial, directory=self.root)

        unauthorized = self.run + "/unauthorized.bin"
        self.files[unauthorized] = {}
        query = urlencode({"upload_id": self.run, "path": unauthorized, "on_exists": "skip"})
        rejected_bases = ["/wrong-" + secrets.token_hex(8) + "/"]
        if self.args.privacy_mode:
            rejected_bases.append("/")
        for base in rejected_bases:
            status_query = urlencode({"upload_id": self.run, "path": unauthorized})
            for method, suffix in (("GET", ""), ("GET", "api/status?" + status_query),
                                   ("POST", "api/preflight"), ("POST", "api/upload?" + query)):
                status, _ = self.request(method, suffix, b"" if method == "POST" else None,
                                         base=base)
                self.require(status == 404, f"Rejected prefix accepted: {method} {suffix} returned {status}")
        self.files.pop(unauthorized)
        self.passed("missing and wrong capability rejected on every endpoint" if self.args.privacy_mode
                    else "unrecognized URL prefix rejected on every endpoint")

        status, body = self.request("GET")
        html = body.decode("utf-8")
        self.require(status == 200 and "<!doctype html>" in html.lower(), "Browser page did not load")
        self.require("'api/preflight'" in html and "`api/${route}?" in html
                     and "apiUrl('upload'" in html and "apiUrl('status'" in html
                     and not re.search(r"['\"`]/api/", html),
                     "Browser JavaScript does not use relative upload endpoints")
        # An inline data: URL (the empty favicon) loads nothing from elsewhere.
        self.require(not re.search(r"<(?:script|link|img)\b[^>]*(?:src|href)\s*=\s*(?!['\"]?data:)",
                                   html, re.IGNORECASE)
                     and not re.search(r"@import\b|url\(\s*['\"]?https?://", html, re.IGNORECASE),
                     "Browser page depends on external resources")
        self.passed("self-contained browser page and relative upload endpoints", html_bytes=len(body))

        rel = self.run + "/nested/Grüße-東京.bin"
        original = bytes(range(256)) * 513 + "Grüße 東京".encode()
        self.put(rel, original)
        self.passed("nested binary and Unicode upload", **self.files[rel])
        self.put(self.run + "/empty.bin", b"")
        self.passed("zero-byte upload")

        status, payload = self.status(rel, client="smoke-status")
        self.require(status == 200 and payload.get("done") is True
                     and payload.get("bytes") == self.files[rel]["bytes"]
                     and payload.get("sha256") == self.files[rel]["sha256"],
                     f"Status does not report the stored file: {status}, {payload}")
        status, payload = self.status(self.run + "/never-sent.bin")
        self.require(status == 200 and payload.get("done") is False,
                     f"Status reports an unsent file as stored: {status}, {payload}")
        self.passed("status reports stored and unsent files", **self.files[rel])

        # Shared storage treats names that differ only in case as one file; so must the app.
        upper = self.run + "/case/CaseProbe.txt"
        lower = self.run + "/case/caseprobe.txt"
        self.put(upper, b"one")
        conflict = self.preflight(lower, 3)
        self.require(any(item.get("reason") == "exists" for item in conflict.get("conflicts", [])),
                     f"Case-only clash absent from preflight: {conflict}")
        status, body = self.upload(lower, b"two", "skip")
        self.require(status == 409 and json.loads(body).get("error") == "exists",
                     f"Case-only clash with skip: {status}, {body!r}")
        self.verify(upper, 3, hashlib.sha256(b"one").hexdigest())
        status, body = self.upload(lower, b"two", "overwrite")
        self.require(status == 200, f"Case-only clash with overwrite: {status}, {body!r}")
        names = self.adb("ls " + shlex.quote(self.device_path(self.run + "/case"))).split()
        self.require(len(names) == 1 and names[0].lower() == "caseprobe.txt",
                     f"Case-only overwrite left these files: {names}")
        self.files.pop(upper)
        self.files.pop(lower, None)
        # Track the spelling that is actually on disk, for exact listing checks and cleanup.
        self.verify(self.run + "/case/" + names[0], 3, hashlib.sha256(b"two").hexdigest())
        self.passed("case-only name clash: conflict, skip 409, overwrite replaces one file",
                    spelling_after_overwrite=names[0])

        cross = self.run + "/cross-origin.bin"
        self.files[cross] = {}
        foreign = {"Origin": "http://attacker.example"}
        body = json.dumps({"upload_id": self.run, "items": [{"path": cross, "size": 1}]}).encode()
        status, _ = self.request("POST", "api/preflight", body,
                                 headers={"Content-Type": "application/json", **foreign})
        self.require(status == 403, f"Cross-origin preflight returned {status}")
        status, _ = self.upload(cross, b"x", headers=foreign)
        self.require(status == 403, f"Cross-origin upload returned {status}")
        self.require(self.device_path(cross) not in self.listing(), "Cross-origin upload was stored")
        self.files.pop(cross)
        own = {"Origin": f"http://{self.url.netloc}"}
        status, _ = self.request("POST", "api/preflight", body,
                                 headers={"Content-Type": "application/json", **own})
        self.require(status == 200, f"Same-origin preflight returned {status}")
        self.passed("cross-origin POST refused, same-origin POST accepted")

        conflict = self.preflight(rel, 7)
        self.require(any(item.get("rel_path") == rel and item.get("reason") == "exists"
                         for item in conflict.get("conflicts", [])), "Existing file absent from preflight")
        status, body = self.upload(rel, b"skip me", "skip")
        self.require(status == 409 and json.loads(body).get("error") == "exists",
                     f"Skip did not report the existing file: {status}, {body!r}")
        self.verify(rel, len(original), hashlib.sha256(original).hexdigest())
        self.passed("conflict and skip preserve saved bytes")
        replacement = b"exact replacement\x00\xff"
        self.put(rel, replacement)
        self.no_temporary_files()
        self.passed("overwrite stores exact replacement without temporary siblings")

        # The rejected traversal stays in our namespace even if a server regresses.
        traversal = self.run + "/nested/../traversal.bin"
        candidate = self.run + "/traversal.bin"
        self.files[candidate] = {}
        data = json.dumps({"upload_id": self.run, "items": [{"path": traversal, "size": 1}]}).encode()
        status, _ = self.request("POST", "api/preflight", data,
                                 headers={"Content-Type": "application/json"})
        self.require(status == 400, f"Preflight accepted traversal: {status}")
        status, _ = self.upload(traversal, b"x")
        self.require(status == 400, f"Upload accepted traversal: {status}")
        self.files.pop(candidate)
        self.no_temporary_files()
        self.passed("preflight and upload reject path traversal")

        self.preflight(rel, 8 * 1024 * 1024)
        query = urlencode({"upload_id": self.run, "path": rel, "on_exists": "overwrite"})
        target = self.url.path + "api/upload?" + query
        with socket.create_connection((self.url.hostname, self.url.port or 80),
                                      timeout=self.args.timeout) as connection:
            connection.settimeout(self.args.timeout)
            header = (f"POST {target} HTTP/1.1\r\nHost: smoke\r\n"
                      "Content-Length: 8388608\r\nContent-Type: application/octet-stream\r\n\r\n")
            connection.sendall(header.encode("ascii") + b"partial" * 32768)
            connection.shutdown(socket.SHUT_WR)
            # EOF proves the handler finished instead of merely observing unchanged old bytes.
            while connection.recv(4096):
                pass
        self.verify(rel, len(replacement), hashlib.sha256(replacement).hexdigest())
        self.no_temporary_files(wait=5)
        self.passed("socket abort preserves old file and removes pending siblings")

        retries = self.put(self.run + "/after-failure.txt", b"server remains usable\n", wait=5)
        self.passed("server accepts uploads after rejected and aborted requests", busy_retries=retries)

        # A browser tab whose upload hung retries with the same client id.
        hung_rel = self.run + "/superseded.bin"
        self.files[hung_rel] = {}
        self.preflight(hung_rel, 4 * 1024 * 1024)
        hung = self.hung_upload(hung_rel, "smoke-tab-one")
        try:
            time.sleep(1)
            other = self.run + "/other-tab.bin"
            self.files[other] = {}
            status, body = self.upload(other, b"other tab", client="smoke-tab-two")
            self.require(status == 429, f"Another client's upload was not held back: {status}, {body!r}")
            self.files.pop(other)
            fresh = b"retried after a hung request\n"
            started = time.monotonic()
            status, body = self.upload(hung_rel, fresh, client="smoke-tab-one")
            took = round(time.monotonic() - started, 3)
            self.require(status == 200, f"Same-client retry did not supersede: {status}, {body!r}")
            # EOF proves the server ended the superseded request instead of leaving it waiting.
            while hung.recv(4096):
                pass
        finally:
            hung.close()
        self.verify(hung_rel, len(fresh), hashlib.sha256(fresh).hexdigest())
        self.no_temporary_files(wait=5)
        self.passed("same-client retry supersedes a hung upload; another client gets 429",
                    retry_seconds=took)
        large_rel = self.run + "/large.bin"
        self.files[large_rel] = {}
        size = self.args.large_mib * 1024 * 1024
        digest = hashlib.sha256()
        block = bytes(range(256)) * 256
        with tempfile.TemporaryFile() as fixture:
            for _ in range(size // len(block)):
                fixture.write(block)
                digest.update(block)
            fixture.seek(0)
            self.preflight(large_rel, size)
            status, body = self.upload(large_rel, fixture)
        self.require(status == 200, f"Stream upload status {status}: {body!r}")
        receipt = json.loads(body)
        self.require(receipt.get("bytes") == size and receipt.get("sha256") == digest.hexdigest(),
                     f"Stream receipt differs: {receipt}")
        self.verify(large_rel, size, digest.hexdigest())
        self.no_temporary_files()
        self.passed("large streamed upload saved with exact device hash", **self.files[large_rel])

    def cleanup(self):
        # Delete only the exact files this run tried to write; leave unknown files as evidence.
        if not self.owns_namespace:
            return
        for rel in self.files:
            self.adb("rm -f " + shlex.quote(self.device_path(rel)))
        directories = {self.run}
        for rel in self.files:
            parent = PurePosixPath(rel).parent
            while str(parent) != ".":
                directories.add(str(parent))
                parent = parent.parent
        for rel in sorted(directories, key=lambda value: value.count("/"), reverse=True):
            path = shlex.quote(self.device_path(rel))
            self.adb("if test -d " + path + "; then rmdir " + path + "; fi")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", required=True, help="Current http://host:port/ or private capability URL")
    parser.add_argument("--privacy-mode", action="store_true", help="Require the token URL and verify unauthenticated endpoints are denied")
    parser.add_argument("--adb", default="adb", help="ADB executable; a Windows adb.exe path also works")
    parser.add_argument("--serial", default="emulator-5554")
    parser.add_argument("--device-dir", required=True, help="ADB path of the folder selected in the app")
    parser.add_argument("--large-mib", type=int, choices=range(8, 17), default=12)
    parser.add_argument("--timeout", type=float, default=30, help="Each socket/ADB timeout in seconds")
    parser.add_argument("--keep", action="store_true", help="Keep this run's fixture files for inspection")
    parser.add_argument("--evidence", type=Path, help="Write the result and device hashes to JSON")
    args = parser.parse_args()
    if args.timeout <= 0:
        parser.error("--timeout must be positive")
    smoke = None
    result = {"started_utc": datetime.now(timezone.utc).isoformat(), "passed": False}
    started = time.monotonic()
    try:
        smoke = Smoke(args)
        result.update(serial=args.serial, device_dir=smoke.root, run_prefix=smoke.run,
                      origin=f"http://{smoke.url.netloc}", privacy_mode=args.privacy_mode)
        smoke.execute()
        result["passed"] = True
    except (AssertionError, ValueError, RuntimeError, OSError, http.client.HTTPException,
            subprocess.SubprocessError) as error:
        result["error"] = str(error)
        print("FAIL " + str(error), flush=True)
    finally:
        if smoke is not None:
            result.update(checks=smoke.checks, files=smoke.files)
            if not args.keep:
                try:
                    smoke.cleanup()
                    result["cleaned_up"] = True
                except (OSError, subprocess.SubprocessError, RuntimeError) as error:
                    result["cleaned_up"] = False
                    result["cleanup_error"] = str(error)
                    result["passed"] = False
                    print("FAIL cleanup: " + str(error), flush=True)
            else:
                result["cleaned_up"] = False
                print("Kept device fixtures: " + smoke.device_path(smoke.run), flush=True)
        result["elapsed_seconds"] = round(time.monotonic() - started, 3)
        if args.evidence:
            args.evidence.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
