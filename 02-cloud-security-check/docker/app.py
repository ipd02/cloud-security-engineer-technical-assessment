"""Small HTTP service used to exercise the hardened image.

GET /healthz returns 200 with a short JSON body.
Any other path returns 404.

Configuration comes from the environment at run time. Secrets are never
baked into the image. If DB_PASSWORD_FILE points to a file (for example a
mounted secret), the service reads it at start and only reports whether a
value is present. It never logs or returns the value.
"""

import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT = int(os.environ.get("PORT", "8080"))


def load_secret(path):
    if not path:
        return None
    try:
        with open(path, encoding="utf-8") as handle:
            return handle.read().strip() or None
    except OSError:
        return None


DB_PASSWORD = load_secret(os.environ.get("DB_PASSWORD_FILE"))


class Handler(BaseHTTPRequestHandler):
    server_version = "app"
    sys_version = ""

    def do_GET(self):
        if self.path != "/healthz":
            self.send_error(404)
            return
        body = json.dumps({"status": "ok", "db_secret_present": DB_PASSWORD is not None}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()  # nosec B104
