# Repository instructions

This repository contains a dependency-free desktop Python upload server and an
Android app which embeds that same server. Keep documentation and code comments
in English. The existing MIT license remains authoritative.

- Main server: `upload_server.py`, one file holding the server and its browser
  page so that it can be copied to any machine with Python. Keep it free of
  third-party imports and of anything fetched at runtime.
- Android: `android/`; its build generates `upload_server.py` from the main script.
  Never maintain a second copy of the browser UI or HTTP implementation.
- Run `python -m unittest discover -s tests` after server changes.
- Run Android compilation, lint and device checks before shipping an APK; keep
  warnings as errors and explain any narrow suppressions beside their use.
- Request bodies are read through `SimpleUploadServer._recv_into`, which polls
  so that a stalled upload can be replaced or stopped; never read a body with a
  blocking `rfile.read`. A browser tab names itself with `client=` and its retry
  supersedes its own stuck request; do not let one client's retry cancel another's.
  An upload frees its slot and path before its answer is sent (`_before_answer`),
  because the client's next request follows the answer at once.
- The page sends `on_exists=overwrite` only for files the user ticked in the
  conflict dialog; everything else is sent as `skip`, so a file stored by someone
  else in the meantime is never replaced unasked.
- Uploads must stream with bounded memory. An aborted/failed replacement must
  preserve the previous file, and temporary-file cleanup must not delete user data.
- Android uses a persisted Storage Access Framework tree grant, not broad storage
  permissions. Desktop and Android default to the plain IP/port URL. Privacy mode
  is explicitly optional; when enabled, require its per-run capability on every
  supported GET/POST endpoint through the shared handler. Changing the Android
  mode requires a stopped server.
- Keep keys, signing passwords, received files, SDKs and generated artifacts out of
  Git. A delivered APK must use the project's release key, never a debug key.
- Work on `main`, commit signed logical changes and push after local checks pass.

Current coverage and outstanding device checks: [docs/STATUS.md](docs/STATUS.md).
Open findings: [docs/BUGS.md](docs/BUGS.md).
Implementation and review lessons: [docs/HISTORY.md](docs/HISTORY.md).
Ideas kept for later: [docs/ROADMAP.md](docs/ROADMAP.md).
