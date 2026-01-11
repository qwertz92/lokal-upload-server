from http.server import HTTPServer, BaseHTTPRequestHandler
import os
import socket
import platform
import shutil


class SimpleUploadServer(BaseHTTPRequestHandler):
    # Puffer-Größe für Streaming: 8MB
    BUFFER_SIZE = 8 * 1024 * 1024

    def log_message(self, format, *args):
        """Überschreibe die Standard-Logging-Methode für sauberere Ausgabe."""
        print(f"[{self.log_date_time_string()}] {format % args}")

    def do_GET(self):
        """Zeigt die Upload-Seite mit zwei Upload-Optionen an."""
        self.send_response(200)
        self.send_header("Content-type", "text/html; charset=utf-8")
        self.end_headers()

        html = """
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="utf-8">
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
                    height: 30px;
                    background-color: #e0e0e0;
                    border-radius: 15px;
                    margin: 20px 0;
                    display: none;
                    overflow: hidden;
                }
                .progress-bar {
                    width: 0%;
                    height: 100%;
                    background: linear-gradient(90deg, #4CAF50, #45a049);
                    border-radius: 15px;
                    transition: width 0.3s ease;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    color: white;
                    font-weight: bold;
                }
                .button {
                    background: #4CAF50;
                    color: white;
                    padding: 10px 20px;
                    border: none;
                    border-radius: 4px;
                    cursor: pointer;
                    font-size: 16px;
                }
                .button:hover {
                    background: #45a049;
                }
                .button:disabled {
                    background: #cccccc;
                    cursor: not-allowed;
                }
                .status {
                    margin-top: 10px;
                    padding: 10px;
                    border-radius: 4px;
                }
                .status.success {
                    background: #d4edda;
                    color: #155724;
                }
                .status.error {
                    background: #f8d7da;
                    color: #721c24;
                }
                .file-info {
                    font-size: 14px;
                    color: #666;
                    margin-top: 10px;
                }
            </style>
        </head>
        <body>
            <h1>📁 Datei-Upload Server</h1>
            
            <!-- Einzeldatei-Upload -->
            <div class="upload-section">
                <h2>📄 Einzelne Datei hochladen</h2>
                <form id="singleFileForm">
                    <input type="file" name="file" id="singleFile">
                    <div class="file-info" id="singleFileInfo"></div>
                    <br><br>
                    <button type="submit" class="button" id="singleUploadBtn">Hochladen</button>
                </form>
                <div class="progress" id="singleProgress">
                    <div class="progress-bar" id="singleProgressBar">0%</div>
                </div>
                <div id="singleStatus"></div>
            </div>

            <!-- Ordner-Upload -->
            <div class="upload-section">
                <h2>📂 Ordner hochladen</h2>
                <form id="folderForm">
                    <input type="file" name="files[]" id="folderInput" webkitdirectory directory multiple>
                    <div class="file-info" id="folderFileInfo"></div>
                    <br><br>
                    <button type="submit" class="button" id="folderUploadBtn">Hochladen</button>
                </form>
                <div class="progress" id="folderProgress">
                    <div class="progress-bar" id="folderProgressBar">0%</div>
                </div>
                <div id="folderStatus"></div>
            </div>

            <script>
                // Hilfsfunktion zur Formatierung von Dateigrößen
                function formatFileSize(bytes) {
                    if (bytes === 0) return '0 Bytes';
                    const k = 1024;
                    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
                    const i = Math.floor(Math.log(bytes) / Math.log(k));
                    return Math.round(bytes / Math.pow(k, i) * 100) / 100 + ' ' + sizes[i];
                }

                // Zeige Dateiinformationen für Einzeldatei
                document.getElementById('singleFile').onchange = function(e) {
                    const file = e.target.files[0];
                    if (file) {
                        document.getElementById('singleFileInfo').textContent = 
                            `Ausgewählt: ${file.name} (${formatFileSize(file.size)})`;
                    }
                };

                // Zeige Dateiinformationen für Ordner
                document.getElementById('folderInput').onchange = function(e) {
                    const files = e.target.files;
                    if (files.length > 0) {
                        let totalSize = 0;
                        for (let file of files) {
                            totalSize += file.size;
                        }
                        document.getElementById('folderFileInfo').textContent = 
                            `Ausgewählt: ${files.length} Dateien (${formatFileSize(totalSize)})`;
                    }
                };

                // Einzeldatei-Upload
                document.getElementById('singleFileForm').onsubmit = async function(e) {
                    e.preventDefault();
                    
                    const fileInput = document.getElementById('singleFile');
                    const file = fileInput.files[0];
                    if (!file) {
                        alert('Bitte wählen Sie eine Datei aus');
                        return;
                    }

                    const progress = document.getElementById('singleProgress');
                    const progressBar = document.getElementById('singleProgressBar');
                    const status = document.getElementById('singleStatus');
                    const uploadBtn = document.getElementById('singleUploadBtn');
                    
                    uploadBtn.disabled = true;
                    progress.style.display = 'block';
                    status.textContent = '';
                    status.className = '';
                    
                    const formData = new FormData();
                    formData.append('file', file);
                    formData.append('filename', file.name);
                    
                    try {
                        const xhr = new XMLHttpRequest();
                        
                        xhr.upload.onprogress = function(e) {
                            if (e.lengthComputable) {
                                const percent = Math.round((e.loaded / e.total) * 100);
                                progressBar.style.width = percent + '%';
                                progressBar.textContent = percent + '%';
                            }
                        };
                        
                        xhr.onload = function() {
                            if (xhr.status === 200) {
                                status.textContent = `✓ ${file.name} wurde erfolgreich hochgeladen!`;
                                status.className = 'status success';
                                fileInput.value = '';
                                document.getElementById('singleFileInfo').textContent = '';
                            } else {
                                throw new Error(xhr.responseText || 'Upload fehlgeschlagen');
                            }
                            uploadBtn.disabled = false;
                        };
                        
                        xhr.onerror = function() {
                            throw new Error('Netzwerkfehler beim Upload');
                        };
                        
                        xhr.open('POST', '/', true);
                        xhr.send(formData);
                        
                    } catch (error) {
                        status.textContent = `✗ Fehler: ${error.message}`;
                        status.className = 'status error';
                        console.error('Upload error:', error);
                        uploadBtn.disabled = false;
                    }
                };

                // Ordner-Upload
                document.getElementById('folderForm').onsubmit = async function(e) {
                    e.preventDefault();
                    
                    const fileInput = document.getElementById('folderInput');
                    const files = fileInput.files;
                    if (files.length === 0) {
                        alert('Bitte wählen Sie einen Ordner aus');
                        return;
                    }

                    const progress = document.getElementById('folderProgress');
                    const progressBar = document.getElementById('folderProgressBar');
                    const status = document.getElementById('folderStatus');
                    const uploadBtn = document.getElementById('folderUploadBtn');
                    
                    uploadBtn.disabled = true;
                    progress.style.display = 'block';
                    status.textContent = '';
                    status.className = '';
                    
                    let uploadedCount = 0;
                    let failedFiles = [];

                    for (let file of files) {
                        const formData = new FormData();
                        formData.append('file', file);
                        formData.append('filepath', file.webkitRelativePath);
                        
                        try {
                            status.textContent = `Lade hoch (${uploadedCount + 1}/${files.length}): ${file.webkitRelativePath}`;
                            
                            const response = await fetch('/', {
                                method: 'POST',
                                body: formData
                            });
                            
                            if (!response.ok) {
                                throw new Error(`HTTP ${response.status}`);
                            }
                            
                            uploadedCount++;
                            const percent = Math.round((uploadedCount / files.length) * 100);
                            progressBar.style.width = percent + '%';
                            progressBar.textContent = percent + '%';
                            
                        } catch (error) {
                            console.error('Upload error:', error);
                            failedFiles.push(file.webkitRelativePath);
                        }
                    }
                    
                    if (failedFiles.length === 0) {
                        status.textContent = `✓ Alle ${uploadedCount} Dateien wurden erfolgreich hochgeladen!`;
                        status.className = 'status success';
                    } else {
                        status.textContent = `⚠ ${uploadedCount} von ${files.length} Dateien hochgeladen. Fehler bei: ${failedFiles.join(', ')}`;
                        status.className = 'status error';
                    }
                    
                    fileInput.value = '';
                    document.getElementById('folderFileInfo').textContent = '';
                    uploadBtn.disabled = false;
                };
            </script>
        </body>
        </html>
        """
        self.wfile.write(html.encode("utf-8"))

    def do_POST(self):
        """Verarbeitet Datei-Uploads mit Streaming für effiziente Speichernutzung."""
        import tempfile

        temp_file = None
        try:
            # Lese Content-Type und Content-Length
            content_type = self.headers.get("Content-Type", "")
            content_length = int(self.headers.get("Content-Length", 0))

            if not content_type.startswith("multipart/form-data"):
                raise ValueError("Falscher Content-Type")

            # Prüfe verfügbaren Speicherplatz
            self._check_disk_space(content_length)

            # Extrahiere boundary
            boundary = content_type.split("boundary=")[1].encode()

            # Erstelle temporäre Datei
            temp_file = tempfile.NamedTemporaryFile(delete=False, dir="uploads")

            # Variablen für das Parsen
            buffer = b""
            filename = None
            filepath = None
            in_file_data = False
            bytes_written = 0
            bytes_read = 0

            # Lese und verarbeite Daten in Chunks
            while bytes_read < content_length:
                chunk_size = min(self.BUFFER_SIZE, content_length - bytes_read)
                chunk = self.rfile.read(chunk_size)
                if not chunk:
                    break

                bytes_read += len(chunk)
                buffer += chunk

                # Suche nach Datei-Header
                if not in_file_data and b"filename=" in buffer:
                    # Extrahiere Dateiinformationen
                    header_str = buffer.decode("utf-8", "ignore")

                    # Finde Dateinamen
                    if 'filename="' in header_str:
                        start = header_str.index('filename="') + 10
                        end = header_str.index('"', start)
                        filename = header_str[start:end]

                    # Finde optionalen Pfad
                    if 'name="filepath"' in header_str:
                        path_start = header_str.index('name="filepath"')
                        path_data = header_str[path_start:]
                        if "\r\n\r\n" in path_data:
                            path_start = path_data.index("\r\n\r\n") + 4
                            path_end = path_data.index("\r\n", path_start)
                            filepath = path_data[path_start:path_end]

                    # Finde Start der Dateidaten
                    data_start = buffer.find(b"\r\n\r\n") + 4
                    if data_start > 3:
                        buffer = buffer[data_start:]
                        in_file_data = True

                # Schreibe Dateidaten
                if in_file_data:
                    # Prüfe auf Ende-Marker
                    end_marker = b"\r\n--" + boundary
                    if end_marker in buffer:
                        # Schreibe bis zum Ende-Marker
                        end_pos = buffer.index(end_marker)
                        temp_file.write(buffer[:end_pos])
                        bytes_written += end_pos
                        break
                    else:
                        # Behalte etwas Puffer für den End-Marker
                        if len(buffer) > len(end_marker):
                            write_size = len(buffer) - len(end_marker)
                            temp_file.write(buffer[:write_size])
                            bytes_written += write_size
                            buffer = buffer[write_size:]

            temp_file.close()

            if not filename:
                raise ValueError("Kein Dateiname gefunden")

            # Bereinige Dateinamen
            filename = self._sanitize_filename(filename)

            # Bestimme finalen Pfad
            if filepath:
                filepath = filepath.replace("\\", "/").strip()
                save_path = os.path.join("uploads", filepath)
            else:
                save_path = os.path.join("uploads", filename)

            save_path = os.path.normpath(save_path)

            # Erstelle Verzeichnisse
            os.makedirs(os.path.dirname(save_path), exist_ok=True)

            # Verschiebe temporäre Datei
            shutil.move(temp_file.name, save_path)

            print(
                f"✓ Datei gespeichert: {save_path} ({self._format_size(bytes_written)})"
            )

            # Sende Erfolgsantwort
            self.send_response(200)
            self.send_header("Content-type", "text/plain; charset=utf-8")
            self.end_headers()
            self.wfile.write(
                f"Datei {filename} erfolgreich hochgeladen".encode("utf-8")
            )

        except Exception as e:
            # Cleanup bei Fehler
            if temp_file:
                try:
                    temp_file.close()
                    if os.path.exists(temp_file.name):
                        os.unlink(temp_file.name)
                except:
                    pass

            print(f"✗ Upload-Fehler: {str(e)}")
            self.send_response(500)
            self.send_header("Content-type", "text/plain; charset=utf-8")
            self.end_headers()
            self.wfile.write(f"Fehler: {str(e)}".encode("utf-8"))

    def _check_disk_space(self, required_bytes):
        """Prüft ob genug Speicherplatz verfügbar ist."""
        total, used, free = shutil.disk_usage("uploads")
        # Füge 10% Puffer hinzu
        required = required_bytes * 1.1
        if free < required:
            raise ValueError(
                f"Nicht genug Speicherplatz. "
                f"Benötigt: {self._format_size(required)}, "
                f"Verfügbar: {self._format_size(free)}"
            )

    def _sanitize_filename(self, filename):
        """Entfernt unsichere Zeichen aus Dateinamen."""
        import re

        # Verwende nur den Basisnamen (keine Pfade)
        filename = os.path.basename(filename)
        # Entferne problematische Zeichen, aber behalte Leerzeichen und Punkte
        filename = re.sub(r'[<>:"|?*\x00-\x1f]', "_", filename)
        return filename

    def _format_size(self, bytes):
        """Formatiert Byte-Größen in lesbare Form."""
        for unit in ["B", "KB", "MB", "GB"]:
            if bytes < 1024.0:
                return f"{bytes:.1f} {unit}"
            bytes /= 1024.0
        return f"{bytes:.1f} TB"


def run_server(port=8040):
    """Startet den Server und zeigt die Netzwerkinformationen an."""
    # Erstelle Upload-Verzeichnis
    os.makedirs("uploads", exist_ok=True)

    # Ermittle IP-Adresse
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        ip_address = s.getsockname()[0]
    except Exception:
        ip_address = socket.gethostbyname(socket.gethostname())
    finally:
        s.close()

    # Zeige Server-Informationen
    print("\n" + "=" * 50)
    print("🚀 Upload-Server gestartet")
    print("=" * 50)
    print(f"Betriebssystem: {platform.system()}")
    print(f"IP-Adresse:     {ip_address}")
    print(f"Port:           {port}")
    print(f"\n📍 Zugriffs-URLs:")
    print(f"   Lokal:       http://localhost:{port}")
    print(f"   Netzwerk:    http://{ip_address}:{port}")
    print(f"\n📁 Speicherort: {os.path.abspath('uploads')}")
    print(f"\n⌨  Zum Beenden: Strg+C drücken")
    print("=" * 50 + "\n")

    # Starte Server
    server = HTTPServer(("", port), SimpleUploadServer)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n\n🛑 Server wird beendet...")
        server.server_close()
        print("✓ Server beendet\n")


if __name__ == "__main__":
    run_server()
