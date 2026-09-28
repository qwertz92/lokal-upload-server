# History

## 2026-09-28 — Android implementation and review

Added a native Android launcher/service around the existing Python server, with a persisted local-folder grant, per-run capability URL and externally signed APK. Stream directly into the selected folder; keep the server/browser source shared with desktop.

Review round 1 found a rename/journal crash window in the local Android document provider. Its document IDs change on rename: recovery must identify completed uploads by their existing digest and protect restored originals from stale path-based IDs. A native negative control reproduced six failures in the old APK, including two cases where a stale final-path URI deleted restored original bytes. Regression checks exercise those provider transitions rather than assuming a stable URI.

An upload write-failure regression showed that received-byte accounting must advance before writing to disk, otherwise draining the failed request waits for bytes already consumed. Counterfactual tests also check authorization, active-request shutdown, request bounds, storage initialization and the Java/Python digest handoff.

Round 2 found no remaining P1/P2 in the corrected storage and native app. All 13 recovery scenarios pass on the real provider; old/new APKs used the same runner.

Final device checks confirmed icon start, explicit stop, screen-off transfer and stable control positions. A one-line ScrollView clipping correction keeps large-font scrolled text out of system bars; before/after screenshots provide the negative control.
