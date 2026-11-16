"""A tiny real HTTP server on 127.0.0.1 for tests. Real sockets, so the
executor's pinning, timeouts, redirects and headers are exercised for real."""
from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


def reply(handler, status=200, body=b"", headers=None):
    if isinstance(body, (dict, list)):
        body = json.dumps(body).encode()
        headers = {"Content-Type": "application/json", **(headers or {})}
    handler.send_response(status)
    for key, value in (headers or {}).items():
        handler.send_header(key, value)
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)


class LocalServer:
    """`app(handler)` answers each request (use reply()). Every request seen is
    kept in `.log` as {method, path, headers: [(name, value), ...]}."""

    def __init__(self, app):
        self.app = app
        self.log: list[dict] = []
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def _handle(self):
                outer.log.append({"method": self.command, "path": self.path, "headers": list(self.headers.items())})
                try:
                    outer.app(self)
                except (BrokenPipeError, ConnectionResetError, OSError):
                    pass

            do_GET = do_POST = do_PUT = do_DELETE = do_HEAD = _handle

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.httpd.daemon_threads = True
        self.port = self.httpd.server_address[1]
        self.origin = f"http://127.0.0.1:{self.port}"
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *exc):
        self.httpd.shutdown()
        self.httpd.server_close()

    def header_values(self, name: str, index: int = -1) -> list[str]:
        """All values of a header on one logged request, case-insensitive."""
        headers = self.log[index]["headers"]
        return [v for k, v in headers if k.lower() == name.lower()]
