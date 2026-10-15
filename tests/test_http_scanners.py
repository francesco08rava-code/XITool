"""HTTP e scanner verificati senza richieste verso target pubblici."""
import copy
from pathlib import Path
import socket
import threading
import tempfile
import time
import unittest
from unittest.mock import Mock, patch
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

from xitool.http import HTTPClient, NetworkError, RateLimiter, Response
from xitool.scope import Scope, ScopeViolation
from xitool.scanners import MODULES
from xitool.scanners import classify, discover, safe_url, scan, smart
from xitool.storage import DEFAULTS, DataError


def configuration():
    config = copy.deepcopy(DEFAULTS)
    config["http"].update(max_retries=0, requests_per_second=20)
    return config


class HTTPTests(unittest.TestCase):
    def setUp(self):
        self.client = HTTPClient(Scope(["example.com"], []), configuration())
        self.client.limiter.wait = Mock()

    def test_reject_before_transport(self):
        with patch.object(self.client, "_request") as transport:
            with self.assertRaises(ScopeViolation):
                self.client.get("https://evil.org/")
            transport.assert_not_called()

    def test_redirect_out_of_scope(self):
        with patch.object(self.client, "_request", return_value=Response("https://example.com/", 302, {"location": "https://evil.org/"}, "")) as transport:
            with self.assertRaises(ScopeViolation):
                self.client.get("https://example.com/")
            self.assertEqual(transport.call_count, 1)

    def test_redirect_each_hop_and_loop(self):
        responses = [Response("https://example.com/", 302, {"location": "/next"}, ""), Response("https://example.com/next", 200, {}, "ok")]
        with patch.object(self.client, "_request", side_effect=responses) as transport:
            result = self.client.get("https://example.com/")
            self.assertEqual(result.body, "ok")
            self.assertEqual(transport.call_args_list[1].args[0], "https://example.com/next")
        self.client.cache.clear()
        with patch.object(self.client, "_request", return_value=Response("https://example.com/", 302, {"location": "/"}, "")):
            with self.assertRaises(NetworkError):
                self.client.get("https://example.com/")

    def test_dns_private_blocked_before_socket(self):
        addresses = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 443))]
        with patch("xitool.http.socket.getaddrinfo", return_value=addresses), patch("xitool.http.socket.socket") as create:
            with self.assertRaises(ScopeViolation):
                self.client._request("https://example.com/", {})
            create.assert_not_called()

    def test_dns_not_reresolved_during_connect(self):
        addresses = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 80))]
        stream = Mock()
        stream.getpeername.return_value = ("8.8.8.8", 80)
        reply = Mock(status=200)
        reply.getheaders.return_value = [("Content-Type", "text/plain")]
        reply.read1.side_effect = [b"ok", b""]
        with patch("xitool.http.socket.getaddrinfo", return_value=addresses) as dns, patch("xitool.http.socket.socket", return_value=stream), patch("xitool.http.http.client.HTTPConnection") as connection:
            connection.return_value.getresponse.return_value = reply
            response = self.client._request("http://example.com/", {})
            dns.assert_called_once()
            stream.connect.assert_called_once_with(("8.8.8.8", 80))
            self.assertEqual(response.body, "ok")

    def test_peer_mismatch(self):
        addresses = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 80))]
        stream = Mock()
        stream.getpeername.return_value = ("127.0.0.1", 80)
        with patch("xitool.http.socket.getaddrinfo", return_value=addresses), patch("xitool.http.socket.socket", return_value=stream):
            with self.assertRaises(ScopeViolation):
                self.client._request("http://example.com/", {})

    def test_stalled_dns_is_bounded_and_does_not_accumulate_threads(self):
        self.client.config["http"]["timeout_seconds"] = 0.02
        release = threading.Event()
        def resolver(*args, **kwargs):
            release.wait(timeout=2)
            return []
        try:
            with patch("xitool.http.socket.getaddrinfo", side_effect=resolver) as dns:
                with self.assertRaises(TimeoutError):
                    self.client._resolve("example.com", 443)
                with self.assertRaises(NetworkError):
                    self.client._resolve("other.com", 443)
                self.assertEqual(dns.call_count, 1)
        finally:
            release.set()
            self.client._dns_thread.join(timeout=2)

    def test_cache_ttl_and_no_store(self):
        with patch.object(self.client, "_request", return_value=Response("https://example.com/", 200, {}, "ok")) as transport:
            self.client.get("https://example.com/")
            self.client.get("https://example.com/")
            self.assertEqual(transport.call_count, 1)
            self.assertEqual(self.client.stats["cache_hits"], 1)
            self.client.cache = {k: (0, v[1]) for k, v in self.client.cache.items()}
            self.client.get("https://example.com/")
            self.assertEqual(transport.call_count, 2)
        self.client.cache.clear()
        with patch.object(self.client, "_request", return_value=Response("https://example.com/", 200, {"set-cookie": "session=secret"}, "ok")):
            self.client.get("https://example.com/")
            self.assertFalse(self.client.cache)

    def test_origin_separate_cache(self):
        with patch.object(self.client, "_request", return_value=Response("https://example.com/", 200, {}, "ok")) as transport:
            self.client.get("https://example.com/")
            self.client.get("https://example.com/", {"Origin": "https://xitool.invalid"})
            self.assertEqual(transport.call_count, 2)

    def test_timeout_retry(self):
        self.client.config["http"]["max_retries"] = 1
        with patch.object(self.client, "_request", side_effect=[TimeoutError(), Response("https://example.com/", 200, {}, "ok")]):
            self.assertEqual(self.client.get("https://example.com/").status, 200)
        self.assertEqual(self.client.stats["timeouts"], 1)
        self.assertLess(self.client.limiter.current, self.client.limiter.maximum)

    def test_limiter_spacing_and_retry_after(self):
        limiter = RateLimiter(2)
        with patch("xitool.http.time.monotonic", return_value=100), patch("xitool.http.time.sleep") as sleep:
            limiter.wait()
            limiter.wait()
            self.assertEqual(sleep.call_args.args[0], 0.5)
            limiter.feedback(429, "12")
            self.assertEqual(limiter.current, 1)
            self.assertGreaterEqual(limiter.next_at, 112)
            for _ in range(100):
                limiter.feedback(200)
            self.assertEqual(limiter.current, 2)

    def test_429_bounded_retries(self):
        self.client.config["http"]["max_retries"] = 2
        with patch.object(self.client, "_request", return_value=Response("https://example.com/", 429, {"retry-after": "1"}, "")) as transport:
            self.assertEqual(self.client.get("https://example.com/").status, 429)
            self.assertEqual(transport.call_count, 3)


class ScannerTests(unittest.TestCase):
    def setUp(self):
        self.scope = Scope(["example.com", "*.example.com"], ["admin.example.com"])

    def test_html_discovery_and_forms(self):
        html = '''<a href="/search?q=test">search</a><a href="https://admin.example.com/?id=1">deny</a>
        <form action="/upload" method="post"><input name="document" type="file"><input name="password" type="password"></form>
        <script src="/app.js"></script><a href="/logout">logout</a>'''
        inputs, links = discover(self.scope, Response("https://example.com/", 200, {"content-type": "text/html"}, html))
        self.assertEqual({i["parameter"] for i in inputs}, {"q", "document", "password"})
        self.assertTrue(all("admin" not in url and "logout" not in url for url in links))
        self.assertEqual(next(i for i in inputs if i["parameter"] == "document")["method"], "POST")
        self.assertTrue(all("value" not in entry for entry in inputs))

    def test_javascript_static_references(self):
        inputs, links = discover(self.scope, Response("https://example.com/app.js", 200, {"content-type": "application/javascript"}, '''fetch('/api/user?user_id=2'); const x="https://evil.org/";'''))
        self.assertEqual(links, ["https://example.com/api/user?user_id=2"])
        self.assertEqual(inputs[0]["input_type"], "identifier")

    def test_classifier(self):
        for name, kind in (("redirect_url", "url"), ("file", "file"), ("user_id", "identifier"), ("q", "text"), ("access_token", "authentication")):
            self.assertEqual(classify(name), kind)

    def test_sensitive_and_mutative_urls_rejected(self):
        for url in ("https://example.com/?token=secret", "https://example.com/logout"):
            with self.assertRaises(DataError):
                safe_url(self.scope, url)

    def test_xss_reflection_never_verified(self):
        client = HTTPClient(self.scope, configuration())
        def reply(url, **kwargs):
            value = parse_qs(urlsplit(url).query)["q"][0]
            return Response(url, 200, {"content-type": "text/html"}, f"<p>{value}</p>")
        with patch.object(client, "get", side_effect=reply):
            result = scan("xss", {"url": "https://example.com/?q=hello", "method": "GET", "parameter": "q", "source": "query"}, client)[0]
        self.assertEqual(result["status"], "POTENTIAL")
        self.assertNotIn("xitool_", json_text(result))

    def test_encoded_reflection_not_vulnerability(self):
        import html
        client = HTTPClient(self.scope, configuration())
        def reply(url, **kwargs):
            return Response(url, 200, {"content-type": "text/html"}, html.escape(parse_qs(urlsplit(url).query)["q"][0]))
        with patch.object(client, "get", side_effect=reply):
            result = scan("xss", {"url": "https://example.com/?q=x", "method": "GET", "parameter": "q"}, client)[0]
        self.assertEqual(result["status"], "OBSERVED")
        self.assertTrue(result["evidence"]["reflected"])

    def test_idor_only_classifies_no_request(self):
        client = HTTPClient(self.scope, configuration())
        with patch.object(client, "get") as get:
            result = scan("idor", {"url": "https://example.com/?id=1", "parameter": "id", "input_type": "identifier"}, client)
            get.assert_not_called()
        self.assertEqual(result[0]["status"], "MANUAL_REVIEW")

    def test_cookie_values_never_stored(self):
        client = HTTPClient(self.scope, configuration())
        with patch.object(client, "get", return_value=Response("https://example.com/", 200, {"set-cookie": "session=VERYSECRET; Secure; HttpOnly; SameSite=Lax"}, "")):
            result = scan("authentication", {"url": "https://example.com/"}, client)
        self.assertNotIn("VERYSECRET", json_text(result))
        self.assertTrue(result[0]["evidence"]["cookies"][0]["secure"])

    def test_secret_values_masked(self):
        client = HTTPClient(self.scope, configuration())
        secret = "AKIA" + "A" * 16
        with patch.object(client, "get", return_value=Response("https://example.com/", 200, {}, secret)):
            result = scan("sensitive", {"url": "https://example.com/"}, client)
        self.assertNotIn(secret, json_text(result))
        self.assertEqual(result[0]["status"], "MANUAL_REVIEW")

    def test_cors_wildcard_not_vulnerability(self):
        client = HTTPClient(self.scope, configuration())
        with patch.object(client, "get", return_value=Response("https://example.com/", 200, {"access-control-allow-origin": "*"}, "")):
            result = scan("cors", {"url": "https://example.com/"}, client)
        self.assertEqual(result[0]["status"], "OBSERVED")

    def test_smart_filters_post_xss(self):
        proposals = smart([{"input_type": "text", "method": "POST"}, {"input_type": "identifier", "method": "GET"}], [])
        self.assertNotIn("xss", proposals)
        self.assertEqual(proposals["idor"], 1)


def json_text(value):
    import json
    return json.dumps(value)


class LocalLabTests(unittest.TestCase):
    def test_actual_http_loopback_requires_explicit_cidr(self):
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.end_headers()
                self.wfile.write(b'<a href="/?q=lab">fixture</a>')
            def log_message(self, *args):
                pass
        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            port = server.server_address[1]
            config = configuration()
            config["http"]["allowed_ports"] = [port]
            url = f"http://127.0.0.1:{port}/"
            blocked = HTTPClient(Scope(["127.0.0.1"], []), config)
            with self.assertRaises(ScopeViolation):
                blocked.get(url)
            client = HTTPClient(Scope(["127.0.0.1"], [], ["127.0.0.1/32"]), config)
            result = client.get(url)
            self.assertEqual(result.status, 200)
            self.assertEqual(discover(client.scope, result)[0][0]["parameter"], "q")
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

    def test_local_workflow_discovery_checks_and_reports(self):
        from xitool.execution import Engine, build_tasks, latest_discovery
        from xitool.storage import Projects, read_json, save_json
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                query = parse_qs(urlsplit(self.path).query)
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Set-Cookie", "fixture=NEVER_PERSIST_THIS_COOKIE; HttpOnly; SameSite=Lax")
                origin = self.headers.get("Origin")
                if origin:
                    self.send_header("Access-Control-Allow-Origin", origin)
                    self.send_header("Access-Control-Allow-Credentials", "true")
                self.end_headers()
                body = '<a href="/search?q=lab">search</a><a href="/user?id=1">user</a>'
                body += '<form action="/submit" method="post"><input name="file"></form>'
                body += query.get("q", [""])[0]
                self.wfile.write(body.encode())
            def log_message(self, *args):
                pass
        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with tempfile.TemporaryDirectory() as temporary:
                projects = Projects(Path(temporary) / "targets")
                project = projects.create("LocalLab", ["127.0.0.1"], [])
                data = read_json(project / "scope.json")
                data["allowed_ip_ranges"] = ["127.0.0.1/32"]
                save_json(project / "scope.json", data)
                _, scope = projects.load("LocalLab")
                config = configuration()
                port = server.server_address[1]
                config["http"]["allowed_ports"] = [port]
                discovery = Engine(project, scope, config, "subfinding", tasks=[{"url": f"http://127.0.0.1:{port}/", "depth": 0}])
                self.assertEqual(discovery.execute()["status"], "COMPLETED")
                inputs, urls = latest_discovery(project, scope)
                self.assertTrue(inputs)
                for module in ("xss", "idor", "traversal", "misconfiguration", "authentication", "cors", "sensitive"):
                    tasks = build_tasks(module, scope, inputs, urls)
                    self.assertTrue(tasks, module)
                    engine = Engine(project, scope, config, module, tasks=tasks)
                    state = engine.execute()
                    self.assertEqual(state["status"], "COMPLETED")
                    self.assertEqual(state["errors"], [], module)
                    self.assertNotIn("VERIFIED", {r["status"] for r in state["results"]})
                    report = (engine.directory / "report.json").read_text(encoding="utf-8")
                    self.assertNotIn("NEVER_PERSIST_THIS_COOKIE", report)
                    if module == "xss":
                        self.assertIn("POTENTIAL", {r["status"] for r in state["results"]})
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)
