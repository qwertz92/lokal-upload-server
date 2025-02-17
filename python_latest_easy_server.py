from http.server import HTTPServer, BaseHTTPRequestHandler
import os
import re  # Fügen wir das re (Regular Expression) Modul hinzu

class SimpleUploadServer(BaseHTTPRequestHandler):
    def do_GET(self):
        """Zeigt die Upload-Seite mit den zwei Upload-Optionen an."""
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        
        html = '''
        <!DOCTYPE html>
        <html>
        <head>
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
            
            <!-- Einzeldatei-Upload -->
            <div class="upload-section">
                <h2>Einzelne Datei hochladen</h2>
                <form id="singleFileForm" enctype="multipart/form-data" method="post">
                    <input type="file" name="file">
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
                // Funktion für den Upload einer einzelnen Datei
                document.getElementById('singleFileForm').onsubmit = async function(e) {
                    e.preventDefault();
                    const form = e.target;
                    const file = form.querySelector('input[type="file"]').files[0];
                    if (!file) {
                        alert('Bitte wählen Sie eine Datei aus');
                        return;
                    }

                    const progress = document.getElementById('singleProgress');
                    const progressBar = document.getElementById('singleProgressBar');
                    const status = document.getElementById('singleStatus');
                    
                    progress.style.display = 'block';
                    const formData = new FormData();
                    formData.append('file', file);
                    
                    try {
                        status.textContent = `Lade ${file.name} hoch...`;
                        const response = await fetch('/', {
                            method: 'POST',
                            body: formData
                        });
                        
                        if (!response.ok) {
                            const errorText = await response.text();
                            throw new Error(errorText);
                        }
                        
                        progressBar.style.width = '100%';
                        status.textContent = `${file.name} wurde erfolgreich hochgeladen!`;
                    } catch (error) {
                        status.textContent = `Fehler beim Upload: ${error.message}`;
                        console.error('Upload error:', error);
                    }
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
                        const formData = new FormData();
                        formData.append('file', file);
                        formData.append('path', file.webkitRelativePath);
                        
                        try {
                            status.textContent = `Lade hoch: ${file.webkitRelativePath}`;
                            const response = await fetch('/', {
                                method: 'POST',
                                body: formData
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
        """Verarbeitet den Datei-Upload mit verbesserter Fehlerbehandlung."""
        try:
            # Lese die Content-Length und den Content-Type
            content_length = int(self.headers.get('Content-Length', 0))
            content_type = self.headers.get('Content-Type', '')
            
            # Hole die boundary aus dem Content-Type
            boundary = content_type.split('=')[1].encode()
            
            # Lese die POST-Daten
            post_data = self.rfile.read(content_length)
            
            # Teile die Daten in Teile auf der Basis der boundary
            parts = post_data.split(b'--' + boundary)
            
            # Iteriere durch die Teile, um die Datei zu finden
            for part in parts:
                if b'filename=' in part:
                    # Extrahiere den Header-Teil
                    header_end = part.find(b'\r\n\r\n')
                    if header_end == -1:
                        continue
                        
                    header = part[:header_end].decode('utf-8', 'ignore')
                    body = part[header_end + 4:]
                    
                    # Finde den Dateinamen
                    filename_match = re.search(r'filename="(.+?)"', header)
                    if not filename_match:
                        continue
                    
                    # Extrahiere und bereinige den Dateinamen
                    filename = filename_match.group(1)
                    filename = filename.replace('\\', '/').strip()  # Normalisiere Pfadtrenner
                    filename = re.sub(r'[\r\n"]', '', filename)    # Entferne ungültige Zeichen
                    
                    # Finde den Pfad (für Ordner-Upload)
                    path_match = re.search(r'name="path"\r\n\r\n(.+?)(?:\r\n|$)', header)
                    if path_match:
                        filepath = path_match.group(1).strip()
                        save_path = os.path.join('uploads', filepath)
                    else:
                        save_path = os.path.join('uploads', filename)
                    
                    # Normalisiere den Pfad und erstelle Verzeichnisse
                    save_path = os.path.normpath(save_path)
                    os.makedirs(os.path.dirname(save_path), exist_ok=True)
                    
                    # Finde das Ende der Dateidaten
                    if body.endswith(b'\r\n'):
                        body = body[:-2]
                    
                    # Speichere die Datei
                    with open(save_path, 'wb') as f:
                        f.write(body)
                    
                    print(f"Datei erfolgreich gespeichert: {save_path}")  # Logging
                    
                    # Sende Erfolgsmeldung
                    self.send_response(200)
                    self.send_header('Content-type', 'text/plain')
                    self.end_headers()
                    self.wfile.write(f"Datei {os.path.basename(save_path)} erfolgreich hochgeladen".encode())
                    return
            
            # Wenn keine Datei gefunden wurde
            raise ValueError("Keine Datei im Upload gefunden")
            
        except Exception as e:
            print(f"Fehler beim Upload: {str(e)}")  # Server-seitige Logging
            self.send_response(500)
            self.send_header('Content-type', 'text/plain')
            self.end_headers()
            self.wfile.write(str(e).encode())

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