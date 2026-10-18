"""DOM XSS innocuo da location.hash: vulnerabile, textContent e CSP reali."""
import copy
import json
import os
from pathlib import Path
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from xitool.controlled import tasks, execute
from xitool.http import HTTPClient
from xitool.scope import Scope
from xitool.storage import DEFAULTS


@unittest.skipUnless(os.environ.get("XITOOL_BROWSER_TESTS") == "1", "Browser opzionale non abilitato")
class DOMBrowserTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.observations = []
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                sink = "textContent" if self.path.endswith("safe") else "innerHTML"
                body = ('<html><div id="result"></div><script>document.getElementById("result").' + sink + '=decodeURIComponent(location.hash.slice(1));</script></html>').encode()
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                if self.path.endswith("csp"):
                    self.send_header("Content-Security-Policy", "script-src 'none'")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            def log_message(self, *args):
                pass
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join()

    def check(self, path):
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory)
            case = {"id": "dom", "module": "xss", "url": f"http://127.0.0.1:{self.server.server_port}/xitool-lab/{path}",
                    "operator_owned": True, "fixture_only": True, "parameter": "fragment", "dom_source": "fragment"}
            (project / "controlled_checks.json").write_text(json.dumps({"version": 1, "checks": [case]}))
            scope = Scope(["127.0.0.1"], [], ["127.0.0.1/32"])
            config = copy.deepcopy(DEFAULTS)
            config["http"].update(allowed_ports=[self.server.server_port], requests_per_second=1000)
            result = execute("xss", tasks(project, scope, "xss")[0], HTTPClient(scope, config), project)[0]
            self.assertNotEqual(result["status"], "UNSUPPORTED")
            self.observations.append({"module": "xss", "fixture": path, "expected_positive": path == "vulnerable",
                                      "outcome": result["status"], "observed_positive": result["status"] == "VERIFIED",
                                      "inconclusive": result["status"] not in ("VERIFIED", "NO_ISSUES_OBSERVED")})
            return result

    def test_dom_innerhtml_demonstrated_twice(self):
        result = self.check("vulnerable")
        self.assertEqual(result["status"], "VERIFIED")
        self.assertTrue(result["evidence"]["dom_source_execution_demonstrated"])

    def test_dom_textcontent_does_not_execute(self):
        self.assertEqual(self.check("safe")["status"], "NO_ISSUES_OBSERVED")

    def test_dom_csp_blocks_script(self):
        self.assertEqual(self.check("csp")["status"], "NO_ISSUES_OBSERVED")
