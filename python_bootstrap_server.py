from http.server import HTTPServer, BaseHTTPRequestHandler
import os
import logging
from typing import Optional
import secrets

class UploadServer(BaseHTTPRequestHandler):
    # Konfigurationsvariablen
    UPLOAD_DIR = "uploads"
    MAX_FILE_SIZE = 50 * 1024 * 1024  # 50MB limit
    ALLOWED_EXTENSIONS = {'.txt', '.pdf', '.png', '.jpg', '.jpeg', '.gif'}
    
    def __init__(self, *args, **kwargs):
        # Stelle sicher dass Upload-Verzeichnis existiert
        os.makedirs(self.UPLOAD_DIR, exist_ok=True)
        super().__init__(*args, **kwargs)

    def do_GET(self):
        """Zeige Upload-Formular mit Bootstrap Styling"""
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        
        html = '''
        <!DOCTYPE html>
        <html>
        <head>
            <title>File Upload</title>
            <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
            <style>
                .upload-form { max-width: 500px; margin: 50px auto; padding: 20px; }
            </style>
        </head>
        <body>
            <div class="container">
                <div class="upload-form">
                    <h2 class="mb-4">Datei hochladen</h2>
                    <form enctype="multipart/form-data" method="post">
                        <div class="mb-3">
                            <input class="form-control" type="file" name="file" required>
                        </div>
                        <button class="btn btn-primary" type="submit">Hochladen</button>
                    </form>
                </div>
            </div>
        </body>
        </html>
        '''
        self.wfile.write(html.encode())

    def do_POST(self):
        """Handle file upload with improved error handling and security"""
        try:
            # Parse Content-Type header
            content_type = self.headers.get('Content-Type', '')
            if not content_type.startswith('multipart/form-data'):
                raise ValueError("Falscher Content-Type")

            # Check file size
            content_length = int(self.headers.get('Content-Length', 0))
            if content_length > self.MAX_FILE_SIZE:
                raise ValueError(f"Datei zu groß. Maximum ist {self.MAX_FILE_SIZE/1024/1024}MB")

            # Parse boundary
            boundary = content_type.split('=')[1].encode()
            
            # Read POST data
            post_data = self.rfile.read(content_length)
            
            # Find file data boundaries
            file_start = post_data.find(b'\r\n\r\n') + 4
            file_end = post_data.rfind(b'\r\n--' + boundary + b'--')
            
            # Extract filename
            filename = self._extract_filename(post_data[:file_start].decode())
            if not filename:
                raise ValueError("Kein Dateiname gefunden")

            # Validate file extension
            if not self._is_allowed_file(filename):
                raise ValueError(f"Dateityp nicht erlaubt. Erlaubt sind: {', '.join(self.ALLOWED_EXTENSIONS)}")

            # Generate secure filename
            secure_filename = self._generate_secure_filename(filename)
            
            # Save file
            filepath = os.path.join(self.UPLOAD_DIR, secure_filename)
            with open(filepath, 'wb') as f:
                f.write(post_data[file_start:file_end])

            # Log success
            logging.info(f"Datei erfolgreich hochgeladen: {secure_filename}")
            
            # Send success response
            self._send_response("Datei erfolgreich hochgeladen!", "success")

        except Exception as e:
            logging.error(f"Upload-Fehler: {str(e)}")
            self._send_response(f"Fehler beim Upload: {str(e)}", "danger")

    def _extract_filename(self, header: str) -> Optional[str]:
        """Extrahiere sicher den Dateinamen aus dem Header"""
        for line in header.split('\n'):
            if 'filename=' in line:
                return line.split('filename=')[1].strip('"')
        return None

    def _is_allowed_file(self, filename: str) -> bool:
        """Prüfe ob die Dateiendung erlaubt ist"""
        return os.path.splitext(filename)[1].lower() in self.ALLOWED_EXTENSIONS

    def _generate_secure_filename(self, filename: str) -> str:
        """Generiere einen sicheren Dateinamen mit zufälligem Prefix"""
        random_prefix = secrets.token_hex(8)
        _, ext = os.path.splitext(filename)
        return f"{random_prefix}{ext}"

    def _send_response(self, message: str, status: str):
        """Sende formatierte Response"""
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        
        response = f'''
        <!DOCTYPE html>
        <html>
        <head>
            <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
        </head>
        <body>
            <div class="container mt-5">
                <div class="alert alert-{status}">{message}</div>
                <a href="/" class="btn btn-primary">Zurück</a>
            </div>
        </body>
        </html>
        '''
        self.wfile.write(response.encode())

def run_server(port: int = 8040):
    """Starte den Server mit Logging"""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )
    
    server_address = ('', port)
    httpd = HTTPServer(server_address, UploadServer)
    logging.info(f'Server läuft auf Port {port}')
    
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        logging.info('Server wird beendet...')
        httpd.server_close()

if __name__ == '__main__':
    run_server()