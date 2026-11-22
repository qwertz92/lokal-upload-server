from http.server import HTTPServer, BaseHTTPRequestHandler
import os
from pathlib import Path
import tempfile
from urllib.parse import parse_qs, urlsplit


BUFFER_SIZE = 8 * 1024 * 1024


def _safe_relative_path(raw_path):
    """Validiert einen vom Browser übermittelten relativen Dateipfad."""
    normalized = (raw_path or '').replace('\\', '/').strip()
    if not normalized or normalized.startswith('/'):
        raise ValueError("Ungültiger Dateipfad")

    parts = normalized.split('/')
    if any(part in ('', '.', '..') for part in parts):
        raise ValueError("Ungültiger Dateipfad")
    if ':' in parts[0]:
        raise ValueError("Ungültiger Dateipfad")

    return Path(*parts)


class SimpleUploadServer(BaseHTTPRequestHandler):
    upload_directory = Path('uploads')

    def _send_text(self, status, message):
        body = message.encode('utf-8')
        self.send_response(status)
        self.send_header('Content-type', 'text/plain; charset=utf-8')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        """Zeigt die Upload-Seite mit den zwei Upload-Optionen an."""
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        
        html = '''
        <!DOCTYPE html>
        <html lang="de">
        <head>
            <meta charset="utf-8">
            <meta name="viewport" content="width=device-width, initial-scale=1">
            <title>Datei-Upload</title>
            <style>
                body { 
                    font-family: Arial, sans-serif;
                    max-width: 800px;
                    margin: 0 auto;
                    padding: 20px;
                }
                .upload-section {
                    background: #f5f5f5;
                    padding: 20px;
                    margin: 20px 0;
                    border-radius: 8px;
                }
                .progress {
                    width: 100%;
                    height: 20px;
                    background-color: #f0f0f0;
                    border-radius: 10px;
                    margin: 20px 0;
                    display: none;
                }
                .progress-bar {
                    width: 0%;
                    height: 100%;
                    background-color: #4CAF50;
                    border-radius: 10px;
                    transition: width 0.3s ease;
                }
                .button {
                    background: #4CAF50;
                    color: white;
                    padding: 10px 20px;
                    border: none;
                    border-radius: 4px;
                    cursor: pointer;
                }
                .button:hover {
                    background: #45a049;
                }
            </style>
        </head>
        <body>
            <h1>Datei-Upload</h1>
            
            <!-- Datei-Upload -->
            <div class="upload-section">
                <h2>Eine oder mehrere Dateien hochladen</h2>
                <form id="singleFileForm">
                    <input type="file" name="files" multiple required>
                    <br><br>
                    <input type="submit" value="Hochladen" class="button">
                </form>
                <div class="progress" id="singleProgress">
                    <div class="progress-bar" id="singleProgressBar"></div>
                </div>
                <div id="singleStatus"></div>
            </div>

            <!-- Ordner-Upload -->
            <div class="upload-section">
                <h2>Ordner hochladen</h2>
                <form id="folderForm" enctype="multipart/form-data" method="post">
                    <input type="file" name="files[]" webkitdirectory directory multiple>
                    <br><br>
                    <input type="submit" value="Hochladen" class="button">
                </form>
                <div class="progress" id="folderProgress">
                    <div class="progress-bar" id="folderProgressBar"></div>
                </div>
                <div id="folderStatus"></div>
            </div>

            <script>
                // Funktion für den Upload einer oder mehrerer Dateien
                document.getElementById('singleFileForm').onsubmit = async function(e) {
                    e.preventDefault();
                    const form = e.target;
                    const files = Array.from(form.querySelector('input[type="file"]').files);
                    if (files.length === 0) {
                        alert('Bitte wählen Sie mindestens eine Datei aus');
                        return;
                    }

                    const progress = document.getElementById('singleProgress');
                    const progressBar = document.getElementById('singleProgressBar');
                    const status = document.getElementById('singleStatus');
                    
                    progress.style.display = 'block';
                    progressBar.style.width = '0%';
                    let uploadedCount = 0;

                    for (const file of files) {
                        try {
                            status.textContent = `Lade ${file.name} hoch (${uploadedCount + 1}/${files.length})...`;
                            const response = await fetch(`/upload?path=${encodeURIComponent(file.name)}`, {
                                method: 'POST',
                                headers: {'Content-Type': 'application/octet-stream'},
                                body: file
                            });

                            if (!response.ok) {
                                const errorText = await response.text();
                                throw new Error(errorText);
                            }

                            uploadedCount++;
                            progressBar.style.width = (uploadedCount / files.length * 100) + '%';
                        } catch (error) {
                            status.textContent = `Fehler beim Upload von ${file.name}: ${error.message}`;
                            console.error('Upload error:', error);
                            return;
                        }
                    }

                    status.textContent = files.length === 1
                        ? `${files[0].name} wurde erfolgreich hochgeladen!`
                        : `Alle ${uploadedCount} Dateien wurden erfolgreich hochgeladen!`;
                };

                // Funktion für den Ordner-Upload
                document.getElementById('folderForm').onsubmit = async function(e) {
                    e.preventDefault();
                    const form = e.target;
                    const files = form.querySelector('input[type="file"]').files;
                    if (files.length === 0) {
                        alert('Bitte wählen Sie einen Ordner aus');
                        return;
                    }

                    const progress = document.getElementById('folderProgress');
                    const progressBar = document.getElementById('folderProgressBar');
                    const status = document.getElementById('folderStatus');
                    
                    progress.style.display = 'block';
                    let uploadedCount = 0;

                    for (let file of files) {
                        try {
                            status.textContent = `Lade hoch: ${file.webkitRelativePath}`;
                            const uploadPath = file.webkitRelativePath || file.name;
                            const response = await fetch(`/upload?path=${encodeURIComponent(uploadPath)}`, {
                                method: 'POST',
                                headers: {'Content-Type': 'application/octet-stream'},
                                body: file
                            });
                            
                            if (!response.ok) {
                                const errorText = await response.text();
                                throw new Error(errorText);
                            }
                            
                            uploadedCount++;
                            progressBar.style.width = (uploadedCount / files.length * 100) + '%';
                        } catch (error) {
                            status.textContent = `Fehler beim Upload von ${file.webkitRelativePath}: ${error.message}`;
                            console.error('Upload error:', error);
                            return;
                        }
                    }
                    
                    status.textContent = `Alle ${uploadedCount} Dateien wurden erfolgreich hochgeladen!`;
                };
            </script>
        </body>
        </html>
        '''
        self.wfile.write(html.encode())

    def do_POST(self):
        """Speichert eine Datei als Stream, ohne sie komplett in RAM zu laden."""
        temp_path = None
        try:
            parsed_url = urlsplit(self.path)
            if parsed_url.path != '/upload':
                self._send_text(404, "Nicht gefunden")
                return

            query = parse_qs(parsed_url.query)
            relative_path = _safe_relative_path((query.get('path') or [''])[0])

            content_length_header = self.headers.get('Content-Length')
            if content_length_header is None:
                self._send_text(411, "Content-Length fehlt")
                return
            content_length = int(content_length_header)
            if content_length < 0:
                raise ValueError("Ungültige Content-Length")

            upload_root = self.upload_directory.resolve()
            destination = (upload_root / relative_path).resolve()
            if upload_root not in destination.parents:
                raise ValueError("Ungültiger Dateipfad")

            destination.parent.mkdir(parents=True, exist_ok=True)
            file_descriptor, temp_name = tempfile.mkstemp(
                prefix='.upload-', dir=str(destination.parent)
            )
            temp_path = Path(temp_name)

            with os.fdopen(file_descriptor, 'wb') as temp_file:
                remaining = content_length
                while remaining:
                    chunk = self.rfile.read(min(BUFFER_SIZE, remaining))
                    if not chunk:
                        raise ConnectionError("Upload wurde vorzeitig unterbrochen")
                    temp_file.write(chunk)
                    remaining -= len(chunk)

            os.replace(temp_path, destination)
            temp_path = None
            self._send_text(200, f"Datei {relative_path.as_posix()} erfolgreich hochgeladen")
        except (ValueError, OSError) as error:
            print(f"Fehler beim Upload: {error}")
            self._send_text(400, str(error))
        finally:
            if temp_path is not None:
                temp_path.unlink(missing_ok=True)

# def run_server(port=8040):
#     """Startet den Server auf dem angegebenen Port."""
#     os.makedirs('uploads', exist_ok=True)
#     server = HTTPServer(('', port), SimpleUploadServer)
#     print(f'Server läuft auf http://localhost:{port}')
#     print(f'Dateien werden im Ordner "uploads" gespeichert')
#     print(f'Zum Beenden Strg+C drücken')
#     try:
#         server.serve_forever()
#     except KeyboardInterrupt:
#         print('\nServer wird beendet...')
#         server.server_close()

def run_server(port=8040):
    """Startet den Server und zeigt die IP-Adresse des Systems an."""
    import socket
    import platform

    # Erstelle den Upload-Ordner, falls er nicht existiert
    os.makedirs('uploads', exist_ok=True)

    # Ermittle das Betriebssystem
    system = platform.system().lower()
    
    # Hole die IP-Adresse des Systems
    # Wir erstellen eine temporäre Socket-Verbindung zu einem öffentlichen DNS,
    # um die richtige Netzwerk-Interface-IP zu ermitteln
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # Wir verbinden uns nicht wirklich - dies dient nur dazu, das richtige Interface zu finden
        s.connect(("8.8.8.8", 80))
        ip_address = s.getsockname()[0]
    except Exception:
        # Falls die Methode oben fehlschlägt, nutzen wir einen Fallback
        ip_address = socket.gethostbyname(socket.gethostname())
    finally:
        s.close()

    # Starte den Server
    server = HTTPServer(('', port), SimpleUploadServer)
    
    # Zeige die Server-Informationen an
    print(f'\nServer-Informationen:')
    print(f'-------------------')
    print(f'Betriebssystem: {platform.system()}')
    print(f'IP-Adresse: {ip_address}')
    print(f'Port: {port}')
    print(f'URLs zum Zugriff:')
    print(f'  - Lokal: http://localhost:{port}')
    print(f'  - Netzwerk: http://{ip_address}:{port}')
    print(f'Dateien werden im Ordner "uploads" gespeichert')
    print(f'Zum Beenden Strg+C drücken')
    print(f'-------------------\n')

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print('\nServer wird beendet...')
        server.server_close()


if __name__ == '__main__':
    run_server()
