"""Small HTTP service used to exercise the hardened image.

GET /healthz returns 200 with {"status": "ok"}. Any other path returns 404.

The service takes its settings from the environment. If DB_PASSWORD_FILE
points to a mounted secret file, the service reads it at start and logs that
it did. It never logs or returns the value.
"""

import json
import os
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

PORT = int(os.environ.get("PORT", "8080"))


def load_secret(path):
    if not path:
        print("DB_PASSWORD_FILE is not set", file=sys.stderr)
        return None
    try:
        with open(path, encoding="utf-8") as handle:
            value = handle.read().strip()
    except OSError as exc:
        print(f"cannot read DB_PASSWORD_FILE: {exc.strerror}", file=sys.stderr)
        return None
    print("DB_PASSWORD_FILE was read", file=sys.stderr)
    return value


# Held in memory only. This demo does not use it.
DB_PASSWORD = load_secret(os.environ.get("DB_PASSWORD_FILE"))


class Handler(BaseHTTPRequestHandler):
    server_version = "app"
    sys_version = ""

    def do_GET(self):
        if urlsplit(self.path).path != "/healthz":
            self.send_error(404)
            return
        body = json.dumps({"status": "ok"}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()  # nosec B104
