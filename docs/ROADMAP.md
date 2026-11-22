# Roadmap

Ideas deliberately kept for later. Defects belong in [BUGS.md](BUGS.md).

## 2026-11-22 — Resume a partly sent file

Today a file whose transfer breaks is sent again from its first byte. Keeping
the partial temporary file and letting the page continue at the received offset
would save most of a multi-gigabyte upload on an unreliable connection. It
waits because the Android storage layer journals every temporary document and
its 13 recovery scenarios only run on a device; a resumable ticket changes that
contract and needs its own design and device round. Small and medium files gain
nothing from it.

## 2026-11-22 — Several small files at once

Each file costs one connection and, on Android, several slow storage calls, so
a folder with thousands of small files is limited by per-file overhead rather
than by the network. Two or three parallel requests for small files would
shorten such jobs. It waits because the server recognises a retry by "this tab
uploads one file at a time"; parallel requests need a per-slot identity first.

## 2026-11-22 — Checksum comparison in the browser

The server logs a SHA-256 for every stored file, but the page cannot compute
one to compare: browsers only offer their hashing API on HTTPS pages, and this
server is plain HTTP. A JavaScript implementation would work at reduced speed.
It waits because TCP already protects the transfer and the declared length is
enforced; the benefit would be detecting a file that changed on the sending
disk during the upload.

## 2026-11-22 — Address as a QR code

The desktop server prints its address as text; a QR code in the terminal would
save typing it on a phone. It waits because a QR encoder without dependencies
is a few hundred lines for a convenience.
