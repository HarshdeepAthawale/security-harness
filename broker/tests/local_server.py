import gzip
import ssl
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Thread


class LocalHandler(BaseHTTPRequestHandler):
    """Tiny real-TCP target. Routes:
    /          200 text
    /host      200, echoes the Host header it received
    /redirect  302 to the cloud metadata address
    /gzip      200 with Content-Encoding: gzip
    /big       200, 10,000-byte body
    """

    def _send(self, status, body=b"", headers=()):
        self.send_response(status)
        for k, v in headers:
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def do_GET(self):
        path = self.path.split("?", 1)[0]
        if path == "/host":
            self._send(200, (self.headers.get("Host") or "").encode(),
                       [("Content-Type", "text/plain")])
        elif path == "/redirect":
            self._send(302, b"", [("Location", "http://169.254.169.254/latest/meta-data/")])
        elif path == "/gzip":
            self._send(200, gzip.compress(b"hello"), [("Content-Encoding", "gzip")])
        elif path == "/big":
            self._send(200, b"x" * 10_000, [("Content-Type", "text/plain")])
        else:
            self._send(200, b"Hello from the real TCP server!",
                       [("Content-Type", "text/plain")])

    def log_message(self, format, *args):
        pass


def start_server(use_https=False):
    server = ThreadingHTTPServer(("127.0.0.1", 0), LocalHandler)
    protocol = "http"

    if use_https:
        cert_dir = Path(__file__).parent / "certs"
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(
            certfile=str(cert_dir / "localhost-cert.pem"),
            keyfile=str(cert_dir / "localhost-key.pem"),
        )
        server.socket = context.wrap_socket(server.socket, server_side=True)
        protocol = "https"

    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    port = server.server_address[1]
    return server, thread, f"{protocol}://localhost:{port}"


def stop_server(server, thread):
    server.shutdown()
    server.server_close()
    thread.join()
