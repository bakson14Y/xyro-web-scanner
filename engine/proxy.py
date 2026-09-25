"""A loopback proxy restricting native crawlers to the selected host and port.

HTTPS remains end-to-end encrypted. Rates for HTTPS are set in each tool;
CONNECT filtering controls destinations, not requests inside TLS tunnels.
"""
import http.client
import select
import socket
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

def start(scope):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        def log_message(self, *args): pass
        def do_CONNECT(self):
            p = urlsplit("https://" + self.path)
            if (p.hostname, p.port or 443) != scope.origin[1:]:
                self.send_error(403, "Outside scope")
                return
            try:
                upstream = socket.create_connection((p.hostname, p.port or 443), timeout=10)
                self.send_response(200)
                self.end_headers()
                self.connection.settimeout(15)
                with upstream:
                    while True:
                        readable, _, _ = select.select([self.connection, upstream], [], [], 15)
                        if not readable: break
                        for source in readable:
                            data = source.recv(65536)
                            if not data: return
                            (upstream if source is self.connection else self.connection).sendall(data)
            except (OSError, ValueError):
                return
            finally:
                self.close_connection = True

        def do_GET(self): self.forward()
        def do_POST(self): self.forward()
        def do_HEAD(self): self.forward()
        def forward(self):
            if not scope.contains(self.path):
                self.send_error(403, "Outside scope")
                return
            p = urlsplit(self.path)
            length = int(self.headers.get("Content-Length", 0))
            if length > 1024 * 1024 or self.headers.get("Transfer-Encoding"):
                self.send_error(413)
                return
            body = self.rfile.read(length) if length else None
            connection = http.client.HTTPConnection(p.hostname, p.port, timeout=10)
            try:
                headers = {k: v for k, v in self.headers.items()
                           if k.lower() not in ("host", "connection", "proxy-authorization", "proxy-connection")}
                connection.request(self.command, p.path + ("?" + p.query if p.query else ""), body, headers)
                response = connection.getresponse()
                data = response.read(4 * 1024 * 1024)
                self.send_response(response.status)
                for k, v in response.getheaders():
                    if k.lower() not in ("content-length", "transfer-encoding", "connection"):
                        self.send_header(k, v)
                self.send_header("Content-Length", str(len(data)))
                self.send_header("Connection", "close")
                self.end_headers()
                if self.command != "HEAD": self.wfile.write(data)
            except OSError:
                self.close_connection = True
            finally:
                connection.close()
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.daemon_threads = True
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, f"http://127.0.0.1:{server.server_port}"
