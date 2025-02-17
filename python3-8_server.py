import os
from http.server import HTTPServer, BaseHTTPRequestHandler
import cgi

UPLOAD_DIRECTORY = "uploads"
if not os.path.exists(UPLOAD_DIRECTORY):
    os.makedirs(UPLOAD_DIRECTORY)

class SimpleHTTPRequestHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        self.wfile.write(b'''
            <!doctype html>
            <html>
            <body>
            <h1>Datei hochladen</h1>
            <form enctype="multipart/form-data" method="post">
            <input type="file" name="file">
            <input type="submit" value="Hochladen">
            </form>
            </body>
            </html>
        ''')

    def do_POST(self):
        ctype, pdict = cgi.parse_header(self.headers['content-type'])
        if ctype == 'multipart/form-data':
            fs = cgi.FieldStorage(fp=self.rfile, headers=self.headers, environ={'REQUEST_METHOD': 'POST'})
            if 'file' in fs:
                file_item = fs['file']
                filename = os.path.basename(file_item.filename)
                filepath = os.path.join(UPLOAD_DIRECTORY, filename)
                with open(filepath, 'wb') as f:
                    f.write(file_item.file.read())
                self.send_response(200)
                self.end_headers()
                self.wfile.write(f'Datei {filename} erfolgreich hochgeladen.'.encode())
        else:
            self.send_response(400)
            self.end_headers()

def run(server_class=HTTPServer, handler_class=SimpleHTTPRequestHandler, port=8080):
    server_address = ('', port)
    httpd = server_class(server_address, handler_class)
    print(f'Server läuft auf Port {port}')
    httpd.serve_forever()

if __name__ == '__main__':
    run(port=8040)
