import http.client
from pathlib import Path
import tempfile
import threading
import unittest
from urllib.parse import quote

from python_latest_easy_server import HTTPServer, SimpleUploadServer


class QuietUploadServer(SimpleUploadServer):
    def log_message(self, format, *args):  # noqa: A002
        pass


class UploadServerTest(unittest.TestCase):
    def setUp(self):
        self.temp_directory = tempfile.TemporaryDirectory()
        self.upload_directory = Path(self.temp_directory.name) / 'uploads'
        QuietUploadServer.upload_directory = self.upload_directory

        self.server = HTTPServer(('127.0.0.1', 0), QuietUploadServer)
        self.server_thread = threading.Thread(target=self.server.serve_forever)
        self.server_thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.server_thread.join()
        self.temp_directory.cleanup()

    def request(self, method, target, body=None, headers=None):
        connection = http.client.HTTPConnection(
            '127.0.0.1', self.server.server_port, timeout=5
        )
        connection.request(method, target, body=body, headers=headers or {})
        response = connection.getresponse()
        response_body = response.read()
        connection.close()
        return response.status, response_body

    def upload(self, relative_path, content):
        encoded_path = quote(relative_path, safe='')
        return self.request(
            'POST',
            f'/upload?path={encoded_path}',
            body=content,
            headers={'Content-Type': 'application/octet-stream'},
        )

    def test_upload_saves_exact_file_content(self):
        content = b'content with multipart-looking bytes\r\n--boundary--\r\n'

        status, response = self.upload('probe.txt', content)

        self.assertEqual(status, 200, response.decode())
        self.assertEqual(
            (self.upload_directory / 'probe.txt').read_bytes(), content
        )

    def test_upload_preserves_folder_structure(self):
        status, response = self.upload('folder/subfolder/probe.txt', b'folder file')

        self.assertEqual(status, 200, response.decode())
        self.assertEqual(
            (self.upload_directory / 'folder/subfolder/probe.txt').read_bytes(),
            b'folder file',
        )

    def test_upload_rejects_parent_directory_traversal(self):
        status, _ = self.upload('../outside.txt', b'must not be written')

        self.assertEqual(status, 400)
        self.assertFalse((Path(self.temp_directory.name) / 'outside.txt').exists())


if __name__ == '__main__':
    unittest.main()
