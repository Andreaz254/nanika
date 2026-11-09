#!/usr/bin/env python3
"""
Nanika update server.

Run this from ~/nanika-updates:

    python3 server.py

Then point a cloudflared tunnel at it so the public hostname is updates.freessh.indevs.in, e.g.:

    cloudflared tunnel --url http://127.0.0.1:8787

(or a named tunnel with that hostname routed to http://127.0.0.1:8787 in its config). Cloudflare terminates
TLS, so the app always reaches this over https:// - this script itself only needs to speak plain HTTP on
localhost.

Drop release files into ./releases, named exactly   nanika-v<version>.apk   for example:

    releases/nanika-v1.17.apk

The highest version found (compared numerically, part by part: 1.9 < 1.17) is advertised automatically:

    GET /                                    -> {"version":"1.17","file":"nanika-v1.17.apk",
                                                   "url":"/downloads/nanika-v1.17.apk","sha256":"...","size":...}
    GET /downloads/nanika-v1.17.apk          -> the file

No third-party packages needed (just Python 3's standard library). To keep it running, use systemd, tmux,
screen, or `nohup python3 server.py &`.
"""
import hashlib
import html
import json
import os
import re
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HOST = "127.0.0.1"
PORT = 8788
RELEASES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "releases")
NAME_RE = re.compile(r"^nanika-v([0-9]+(?:\.[0-9]+)*)\.apk$", re.IGNORECASE)

_cache_lock = threading.Lock()
_cache = {"key": None, "data": None}


def version_key(v):
    return tuple(int(p) for p in v.split("."))


def scan_releases():
    """Finds the newest nanika-v<version>.apk in RELEASES_DIR. Returns (version, filename, path) or None."""
    best = None
    if not os.path.isdir(RELEASES_DIR):
        return None
    for name in os.listdir(RELEASES_DIR):
        m = NAME_RE.match(name)
        if not m:
            continue
        path = os.path.join(RELEASES_DIR, name)
        if not os.path.isfile(path):
            continue
        try:
            key = version_key(m.group(1))
        except ValueError:
            continue
        if best is None or key > best[0]:
            best = (key, m.group(1), name, path)
    return None if best is None else (best[1], best[2], best[3])


def sha256_of(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def latest_info():
    """Cached by (filename, mtime), so the hash is only recomputed when the release file actually changes."""
    found = scan_releases()
    if found is None:
        return None
    version, filename, path = found
    key = (filename, os.path.getmtime(path))
    with _cache_lock:
        if _cache["key"] == key and _cache["data"]:
            return _cache["data"]
    data = {
        "version": version,
        "file": filename,
        "url": "/downloads/" + filename,
        "sha256": sha256_of(path),
        "size": os.path.getsize(path),
    }
    with _cache_lock:
        _cache["key"] = key
        _cache["data"] = data
    return data


class Handler(BaseHTTPRequestHandler):
    server_version = "NanikaUpdates/1.0"

    def log_message(self, fmt, *args):
        print("%s - %s" % (self.address_string(), fmt % args))

    def _json(self, code, obj):
        body = json.dumps(obj).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path = self.path.split("?", 1)[0]

        if path in ("", "/"):
            info = latest_info()
            if info is None:
                self._json(404, {"error": "no release available"})
                return
            self._json(200, info)
            return

        if path.startswith("/downloads/"):
            requested = html.unescape(os.path.basename(path[len("/downloads/"):]))
            if not NAME_RE.match(requested):
                self._json(404, {"error": "not found"})
                return
            full = os.path.join(RELEASES_DIR, requested)
            if not os.path.isfile(full):
                self._json(404, {"error": "not found"})
                return
            size = os.path.getsize(full)
            self.send_response(200)
            self.send_header("Content-Type", "application/vnd.android.package-archive")
            self.send_header("Content-Length", str(size))
            self.send_header("Content-Disposition", 'attachment; filename="%s"' % requested)
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            with open(full, "rb") as f:
                while True:
                    chunk = f.read(1 << 16)
                    if not chunk:
                        break
                    try:
                        self.wfile.write(chunk)
                    except (BrokenPipeError, ConnectionResetError):
                        return
            return

        self._json(404, {"error": "not found"})


def main():
    os.makedirs(RELEASES_DIR, exist_ok=True)
    srv = ThreadingHTTPServer((HOST, PORT), Handler)
    print("Nanika update server on http://%s:%s" % (HOST, PORT))
    print("Releases directory:", RELEASES_DIR)
    print("Point your cloudflared tunnel at this port (updates.freessh.indevs.in -> http://%s:%s)." % (HOST, PORT))
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
