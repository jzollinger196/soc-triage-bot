"""A tiny fake HTTP service for tests: routes map (method, path-prefix) -> (status, body)."""
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer


class FakeService:
    def __init__(self):
        self.routes = {}
        self.requests = []
        service = self

        class Handler(BaseHTTPRequestHandler):
            def _handle(self):
                length = int(self.headers.get("Content-Length") or 0)
                raw = self.rfile.read(length) if length else b""
                try:
                    body = json.loads(raw) if raw else None
                except json.JSONDecodeError:
                    body = raw.decode()
                service.requests.append({"method": self.command, "path": self.path,
                                         "headers": dict(self.headers), "body": body})
                status, reply = 404, {"error": "no route"}
                for (method, prefix), result in service.routes.items():
                    if method == self.command and self.path.startswith(prefix):
                        status, reply = result(self.path, body) if callable(result) else result
                        break
                data = b"" if reply is None else (reply.encode() if isinstance(reply, str)
                                                  else json.dumps(reply).encode())
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                if self.command != "HEAD":
                    self.wfile.write(data)

            do_GET = do_POST = do_PUT = do_HEAD = do_DELETE = _handle

            def log_message(self, *args):
                pass

        self.server = HTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def route(self, method, prefix, result):
        self.routes[(method, prefix)] = result

    def calls(self, method=None, prefix=""):
        return [r for r in self.requests
                if (method is None or r["method"] == method) and r["path"].startswith(prefix)]

    def close(self):
        self.server.shutdown()
        self.server.server_close()
