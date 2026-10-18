"""Applicazione integrata loopback: riusa sessioni/SQLite/canary della fixture precedente."""
import json
import socket
import threading
import time
from html import escape
from http.server import ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit, urlencode
from urllib.request import build_opener, ProxyHandler

from test_controlled import ControlledServerTests


class Laboratory:
    def __enter__(self):
        base = ControlledServerTests
        base.setUpClass()
        base.revoked, base.logout_effective = False, True
        parent = base.server.RequestHandlerClass
        base.server.shutdown()
        base.server.server_close()
        base.thread.join(2)
        lab = self
        self.callback_events = None
        self.counts = {}
        self.duplicate_callbacks = False
        self.wrong_nonce = False
        class Handler(parent):
            def handle(self):
                try:
                    super().handle()
                except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
                    pass  # expected when the timeout fixture closes its client socket

            def send(self, body, mime="text/html", status=200, headers=None):
                self.send_response(status)
                self.send_header("Content-Type", mime)
                for key, value in (headers or {}).items():
                    self.send_header(key, value)
                raw = body.encode()
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                try:
                    self.wfile.write(raw)
                except OSError:
                    pass

            def do_POST(self):
                raw = self.rfile.read(min(65536, int(self.headers.get("Content-Length", "0"))))
                fields = json.loads(raw) if "json" in self.headers.get("Content-Type", "") else {key: values[0] for key, values in parse_qs(raw.decode()).items()}
                self.path += "?" + urlencode(fields)
                self.do_GET()

            def do_OPTIONS(self):
                origin = self.headers.get("Origin", "")
                headers = {"Access-Control-Allow-Origin": origin, "Access-Control-Allow-Credentials": "true",
                           "Access-Control-Allow-Methods": "GET", "Vary": "Origin"} if "vulnerable" in self.path else {}
                self.send("", status=204, headers=headers)

            def do_GET(self):
                parsed = urlsplit(self.path)
                path, query = parsed.path, parse_qs(parsed.query, keep_blank_values=True)
                lab.counts[path] = lab.counts.get(path, 0) + 1
                if path.endswith("/drop"):
                    self.connection.shutdown(socket.SHUT_RDWR)
                    self.connection.close()
                    return
                if path.endswith("/slow"):
                    time.sleep(.5)
                if path == "/":
                    self.send('<html><a href="/item?q=lab">query</a><a href="/api.json">api</a><a href="/spa">spa</a><script src="/app.js"></script><form method="POST" action="/xitool-lab/sql-vulnerable"><input name="id"></form><a href="https://outside.invalid/">outside</a></html>')
                elif path == "/app.js":
                    self.send('const base="/api";const endpoint=base+"/items";const request=fetch;request(endpoint);axios.get(`/api/info`);const xhr=new XMLHttpRequest();xhr.open("GET","/api/xhr");', "application/javascript")
                elif path == "/spa":
                    self.send('<html><div id="app"></div><script>document.getElementById("app").innerHTML="<a href=\'/dynamic?q=spa\'>SPA</a>";fetch("/api/network");</script></html>')
                elif path.startswith("/api") or path == "/graphql":
                    doc = {"openapi": "3.0.0", "paths": {"/api/items": {"get": {"parameters": [{"in": "query", "name": "id"}]}, "post": {"parameters": [{"in": "query", "name": "id"}]}}}} if path == "/api.json" else {"data": {"name": "synthetic"}}
                    self.send(json.dumps(doc), "application/json")
                elif path == "/redirect":
                    self.send("", status=302, headers={"Location": "/item?q=redirect"})
                elif "/xss-" in path:
                    text = query.get("q", [""])[0]
                    self.send(escape(text) if path.endswith("safe") else text, headers={"Content-Security-Policy": "script-src 'none'"} if path.endswith("csp") else {})
                elif "/dom-" in path:
                    sink = "textContent" if path.endswith("safe") else "innerHTML"
                    self.send('<html><div id="r"></div><script>document.getElementById("r").' + sink + '=decodeURIComponent(location.hash.slice(1))</script></html>')
                elif "/cors-" in path:
                    origin = self.headers.get("Origin", "")
                    headers = {"Access-Control-Allow-Origin": origin, "Access-Control-Allow-Credentials": "true", "Vary": "Origin"} if path.endswith("vulnerable") and origin else {}
                    if path.endswith("public"):
                        headers = {"Access-Control-Allow-Origin": "*"}
                    self.send(base.owner_canary if self.headers.get("Cookie") == "lab=synthetic" and not path.endswith("public") else "public", headers=headers)
                elif "/ssrf-" in path:
                    callback = query.get("url", [""])[0]
                    if path.endswith("vulnerable"):
                        target = urlsplit(callback)
                        # The fixture itself refuses all but its own bound callback origin.
                        if target.scheme == "http" and target.netloc == urlsplit(lab.origin).netloc and target.path.startswith("/xitool-callback/"):
                            with build_opener(ProxyHandler({})).open(callback, timeout=2) as response:
                                response.read()
                    self.send("processed")
                elif path.startswith("/xitool-callback/"):
                    from xitool.storage import utcnow
                    if lab.callback_events:
                        with lab.callback_events.open("a", encoding="utf-8") as stream:
                            event = json.dumps({"id": "0" * 32 if lab.wrong_nonce else path.rsplit("/", 1)[-1], "received_at": utcnow(), "source_ip": self.client_address[0]}) + "\n"
                            stream.write(event * (2 if lab.duplicate_callbacks else 1))
                    self.send("", status=204)
                elif path == "/xitool-lab/secret-positive":
                    token = "ghp_" + "Ab9x" * 10
                    self.send(token + " " + token, "text/plain")
                elif path == "/xitool-lab/secret-safe":
                    self.send("ghp_" + "X" * 40, "text/plain")
                elif path == "/xitool-lab/headers-safe":
                    self.send("<html>safe</html>", headers={"Content-Security-Policy": "default-src 'none'", "X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer", "Permissions-Policy": "camera=()"})
                elif path == "/xitool-lab/missing":
                    self.send("missing", status=404)
                elif path == "/xitool-lab/denied":
                    self.send("denied", status=403)
                elif path == "/xitool-lab/unstable":
                    self.send("baseline " + str(lab.counts[path]), "text/plain")
                elif path == "/xitool-lab/sql-unstable":
                    self.send(base.owner_canary + str(lab.counts[path]), "text/plain")
                else:
                    super().do_GET()
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.origin = f"http://127.0.0.1:{self.server.server_port}"
        self.caller = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.caller_thread = threading.Thread(target=self.caller.serve_forever, daemon=True)
        self.caller_thread.start()
        self.caller_origin = f"http://127.0.0.1:{self.caller.server_port}"
        return self

    def __exit__(self, *args):
        for server, thread in ((self.server, self.thread), (self.caller, self.caller_thread)):
            server.shutdown()
            server.server_close()
            thread.join(2)
        ControlledServerTests.fixture_directory.cleanup()
