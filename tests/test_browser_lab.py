"""Browser facoltativo: fixture reali, profilo effimero e rete pagina interamente bloccata."""
import copy
import html
import importlib.util
import os
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit, urlencode
import json

from xitool.controlled import tasks
from xitool.execution import Engine
from xitool.http import HTTPClient
from xitool.dynamic import render
from xitool.scope import Scope
from xitool.storage import DEFAULTS, Projects, save_json


@unittest.skipUnless(os.environ.get("XITOOL_BROWSER_TESTS") == "1" and importlib.util.find_spec("playwright"),
                     "Browser opzionale: installare requirements-browser.txt e impostare XITOOL_BROWSER_TESTS=1")
class BrowserLabTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                body = self.rfile.read(int(self.headers.get("Content-Length", 0))).decode()
                fields = json.loads(body) if self.headers.get("Content-Type") == "application/json" else {key: values[0] for key, values in parse_qs(body).items()}
                self.path = urlsplit(self.path).path + "?" + urlencode(fields)
                self.do_GET()

            def do_GET(self):
                parsed = urlsplit(self.path)
                value = parse_qs(parsed.query).get("q", [""])[0]
                if parsed.path == "/xitool-lab/dynamic":
                    value = "<script>const a=document.createElement('a'); a.href='/xitool-lab/generated?id=1'; document.body.appendChild(a); fetch('https://outside.invalid/data').catch(()=>{});</script>"
                if parsed.path.startswith("/xitool-lab/cors-"):
                    value = "BROWSER_CORS_CANARY_721b69a2" if self.headers.get("Cookie") == "fixture=PRIVATE_BROWSER_TEST" else "anonymous"
                if parsed.path.endswith("safe"):
                    value = html.escape(value)
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                if parsed.path.endswith("csp"):
                    self.send_header("Content-Security-Policy", "script-src 'none'")
                if parsed.path.startswith("/xitool-lab/cors-"):
                    self.send_header("Access-Control-Allow-Credentials", "true")
                    self.send_header("Access-Control-Allow-Origin", self.headers.get("Origin", "https://safe.invalid") if parsed.path.endswith("open") else "https://safe.invalid")
                self.end_headers()
                self.wfile.write(("<html><body>" + value + "</body></html>").encode())
            def log_message(self, *args):
                pass
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.caller_server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        cls.caller_thread = threading.Thread(target=cls.caller_server.serve_forever, daemon=True)
        cls.caller_thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=2)
        cls.caller_server.shutdown()
        cls.caller_server.server_close()
        cls.caller_thread.join(timeout=2)

    def run_case(self, path, content_type=None):
        with tempfile.TemporaryDirectory() as directory:
            project = Projects(Path(directory)).create("BrowserLab", ["127.0.0.1"], [])
            scope = Scope(["127.0.0.1"], [], ["127.0.0.1/32"])
            config = copy.deepcopy(DEFAULTS)
            port = self.server.server_address[1]
            config["http"].update(allowed_ports=[port], requests_per_second=20, max_retries=0)
            url = f"http://127.0.0.1:{port}/xitool-lab/{path}?q=baseline"
            case = {"id": "browser-proof", "module": "xss", "url": url, "operator_owned": True, "parameter": "q", "fixture_only": True}
            if content_type:
                case["url"] = url.split("?")[0]
                case["request"] = {"method": "POST", "content_type": content_type, "fields": {"q": "baseline"}, "authorized": True}
            save_json(project / "controlled_checks.json", {"version": 1, "checks": [case]})
            engine = Engine(project, scope, config, "xss", target="127.0.0.1", tasks=tasks(project, scope, "xss"))
            engine.execute()
            self.assertEqual(engine.state["errors"], [])
            result = engine.state["results"][0]
            self.assertNotEqual(result["status"], "UNSUPPORTED", result)
            return result

    def test_real_browser_confirms_execution_only_for_unescaped_lab_html(self):
        result = self.run_case("vulnerable")
        self.assertEqual(result["status"], "VERIFIED")
        self.assertTrue(result["evidence"]["probe_executed"])
        self.assertFalse(result["evidence"]["baseline_executed"])

    def test_real_browser_does_not_verify_encoded_reflection(self):
        self.assertEqual(self.run_case("safe")["status"], "NO_ISSUES_OBSERVED")

    def test_real_browser_respects_content_security_policy(self):
        self.assertEqual(self.run_case("csp")["status"], "NO_ISSUES_OBSERVED")

    def test_real_browser_confirms_explicit_json_fixture_twice(self):
        result = self.run_case("vulnerable", "application/json")
        self.assertEqual(result["status"], "VERIFIED")
        self.assertTrue(result["evidence"]["repeat_executed"])
        self.assertEqual(result["http_method"], "POST")

    def test_real_browser_rejects_escaped_json_fixture(self):
        self.assertEqual(self.run_case("safe", "application/json")["status"], "NO_ISSUES_OBSERVED")

    def test_real_browser_confirms_explicit_form_fixture(self):
        self.assertEqual(self.run_case("vulnerable", "application/x-www-form-urlencoded")["status"], "VERIFIED")

    def cors_case(self, path):
        with tempfile.TemporaryDirectory() as directory:
            project = Projects(Path(directory)).create("CorsBrowser", ["127.0.0.1"], [])
            scope = Scope(["127.0.0.1"], [], ["127.0.0.1/32"])
            config = copy.deepcopy(DEFAULTS)
            port = self.server.server_address[1]
            caller_port = self.caller_server.server_address[1]
            config["http"].update(allowed_ports=[port, caller_port], requests_per_second=20, max_retries=0)
            origin = f"http://127.0.0.1:{port}"
            save_json(project / "session_profiles.json", {"version": 1, "profiles": {"cookie": {
                "origin": origin, "header_env": {"Cookie": "XITOOL_CORS_COOKIE"}}}})
            save_json(project / "controlled_checks.json", {"version": 1, "checks": [{
                "id": "browser-cors", "module": "cors", "url": origin + "/xitool-lab/" + path,
                "operator_owned": True, "fixture_only": True, "proof_env": "XITOOL_CORS_CANARY", "profile": "cookie",
                "caller_url": f"http://127.0.0.1:{caller_port}/xitool-lab/caller", "expected_cross_origin_access": False}]})
            engine = Engine(project, scope, config, "cors", target="127.0.0.1", tasks=tasks(project, scope, "cors"))
            with patch.dict("os.environ", {"XITOOL_CORS_COOKIE": "fixture=PRIVATE_BROWSER_TEST", "XITOOL_CORS_CANARY": "BROWSER_CORS_CANARY_721b69a2"}):
                engine.execute()
            self.assertEqual(engine.state["errors"], [])
            self.assertNotIn("PRIVATE_BROWSER_TEST", str(engine.state["results"]))
            return engine.state["results"][0]

    def test_real_browser_reads_owned_canary_with_cookie_across_origins(self):
        result = self.cors_case("cors-open")
        self.assertEqual(result["status"], "VERIFIED", result)

    def test_real_browser_rejects_wrong_allow_origin(self):
        result = self.cors_case("cors-safe")
        self.assertEqual(result["status"], "NO_ISSUES_OBSERVED", result)

    def test_dynamic_dom_links_are_collected_without_out_of_scope_http(self):
        port = self.server.server_address[1]
        settings = copy.deepcopy(DEFAULTS)
        settings["http"].update(allowed_ports=[port], requests_per_second=20, max_retries=0)
        client = HTTPClient(Scope(["127.0.0.1"], [], ["127.0.0.1/32"]), settings)
        with patch.object(client, "get", wraps=client.get) as get:
            result = render(client, f"http://127.0.0.1:{port}/xitool-lab/dynamic")
        self.assertTrue(any("/xitool-lab/generated?id=1" in url for url in result["links"]), result)
        self.assertTrue(all("outside.invalid" not in call.args[0] for call in get.call_args_list))
        self.assertGreaterEqual(result["blocked"], 1)
