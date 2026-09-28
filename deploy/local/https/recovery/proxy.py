"""Private loopback-only HTTPS routing for the isolated recovery rehearsal."""

import http.client
import http.server
import ssl
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path("/proof")


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, _format, *_arguments):
        pass  # Paths/query strings may carry OAuth state or authorization codes.

    def handle_request(self):
        hostname = self.headers.get("Host", "")
        route = urlsplit(self.path).path
        if hostname == "auth.fleet.test:8443":
            port = 4444
        elif hostname == "recall.fleet.test:8443":
            port = 8081
        elif hostname == "login.fleet.test:8443":
            port = 4433 if route.startswith(("/self-service/", "/sessions/", "/schemas/")) else 3000
        else:
            self.send_error(404)
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if not 0 <= length <= 4 * 1024 * 1024 or self.headers.get("Transfer-Encoding"):
                self.send_error(413)
                return
            body = self.rfile.read(length) if length else None
            blocked = {"connection", "transfer-encoding", "x-forwarded-for", "x-forwarded-host", "x-forwarded-proto", "forwarded"}
            headers = {key: value for key, value in self.headers.items() if key.lower() not in blocked}
            headers.update({"X-Forwarded-Proto": "https", "X-Forwarded-Host": hostname, "X-Forwarded-For": "127.0.0.1"})
            connection = http.client.HTTPConnection("127.0.0.1", port, timeout=45)
            try:
                connection.request(self.command, self.path, body, headers)
                response = connection.getresponse()
                payload = response.read(16 * 1024 * 1024 + 1)
                if len(payload) > 16 * 1024 * 1024:
                    self.send_error(502)
                    return
                self.send_response(response.status)
                for key, value in response.getheaders():
                    if key.lower() not in {"transfer-encoding", "connection", "content-length"}:
                        self.send_header(key, value)
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)
            finally:
                connection.close()
        except (OSError, ValueError, http.client.HTTPException):
            self.send_error(502)

    do_GET = handle_request
    do_POST = handle_request
    do_PUT = handle_request
    do_DELETE = handle_request


if __name__ == "__main__":
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 8443), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(ROOT / "tls/chain.pem", ROOT / "tls/leaf.key")
    server.socket = context.wrap_socket(server.socket, server_side=True)
    server.serve_forever()
