# Repository instructions

This repository contains a dependency-free desktop Python upload server and an
Android app which embeds that same server. Keep documentation and code comments
in English. The existing MIT license remains authoritative.

- Main server: `2025_12_python_upload_webserver.py`; older variants are retained.
- Android: `android/`; its build generates `upload_server.py` from the main script.
  Never maintain a second copy of the browser UI or HTTP implementation.
- Run `python -m unittest discover -s tests` after server changes.
- Run Android compilation, lint and device checks before shipping an APK; keep
  warnings as errors and explain any narrow suppressions beside their use.
- Uploads must stream with bounded memory. An aborted/failed replacement must
  preserve the previous file, and temporary-file cleanup must not delete user data.
- Android uses a persisted Storage Access Framework tree grant, not broad storage
  permissions. Require the per-run capability URL on every Android HTTP endpoint.
- Keep keys, signing passwords, received files, SDKs and generated artifacts out of
  Git. A delivered APK must use the project's release key, never a debug key.
- Work on `main`, commit signed logical changes and push after local checks pass.

Current coverage and outstanding device checks: [docs/STATUS.md](docs/STATUS.md).
Open findings: [docs/BUGS.md](docs/BUGS.md).
Implementation and review lessons: [docs/HISTORY.md](docs/HISTORY.md).
