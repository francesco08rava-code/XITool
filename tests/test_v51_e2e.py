"""Pipeline reale su due domini loopback: scope, crawl, input, piano, ripresa, report/diff."""
import copy
import json
from pathlib import Path
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from xitool.execution import Engine, latest_discovery, scan_diff, load_state
from xitool.plans import SmartPlan
from xitool.scope import Scope
from xitool.storage import Projects, DEFAULTS, read_json


class PipelineTests(unittest.TestCase):
    def test_two_domains_crawl_plan_interrupt_resume_and_diff(self):
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                if self.path == "/api.json":
                    body = json.dumps({"openapi": "3.0.0", "paths": {"/item": {"get": {"parameters": [{"in": "query", "name": "id"}]}}}}).encode()
                    content = "application/json"
                else:
                    body = b'<html><a href="/item?q=lab">item</a><a href="/api.json">API</a><form action="/item" method="POST"><input name="q"></form></html>'
                    content = "text/html"
                self.send_response(200)
                self.send_header("Content-Type", content)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            def log_message(self, *args):
                pass
        servers = []
        for host in ("127.0.0.1", "127.0.0.2"):
            server = ThreadingHTTPServer((host, 0), Handler)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            servers.append(server)
            self.addCleanup(thread.join, 2)
            self.addCleanup(server.server_close)
            self.addCleanup(server.shutdown)
        with tempfile.TemporaryDirectory() as directory:
            domains = ["127.0.0.1", "127.0.0.2"]
            projects = Projects(Path(directory))
            project = projects.create("Pipeline", domains, [])
            scope = Scope(domains, [], ["127.0.0.0/8"])
            config = copy.deepcopy(DEFAULTS)
            config["http"].update(allowed_ports=[server.server_port for server in servers], requests_per_second=1000, max_retries=0)
            config["discovery"].update(max_depth=2, max_pages=10)
            discoveries = []
            for host, server in zip(domains, servers):
                engine = Engine(project, scope, config, "subfinding", target=host,
                                tasks=[{"url": f"http://{host}:{server.server_port}/"}])
                engine.execute()
                self.assertEqual(engine.state["status"], "COMPLETED")
                self.assertTrue(any(row.get("location") == "body" for row in engine.state["inputs"]))
                self.assertTrue(any(row.get("source") == "openapi_document" for row in engine.state["inputs"]))
                self.assertTrue((engine.directory / "crawler/api_endpoints.json").exists())
                discoveries.append(engine)
            plan = SmartPlan(project, scope, config, domains)
            plan.add([{"domain": host, "module": "sensitive", "tasks": [{"url": f"http://{host}:{server.server_port}/resource{number}"} for number in range(2)]}
                      for host, server in zip(domains, servers)])
            def interrupt(state):
                if state["completed"]:
                    raise KeyboardInterrupt()
            plan.run(interrupt)
            self.assertEqual(plan.state["status"], "INTERRUPTED")
            resumed = SmartPlan(project, scope, config, domains, path=plan.path)
            resumed.run()
            self.assertEqual(resumed.state["status"], "COMPLETED")
            for step in resumed.state["steps"]:
                path = project / step["run"]
                self.assertEqual(load_state(path / "checkpoint.json")["domain"], step["domain"])
                for suffix in ("json", "md", "txt"):
                    self.assertTrue((path / f"report.{suffix}").exists())
            report = read_json(plan.path.with_suffix(".report.json"))
            self.assertEqual(len(report["findings"]), 4)
            before = discoveries[0].state
            after = copy.deepcopy(before)
            after["run_id"] = "synthetic_comparison_of_real_run"
            after["status"] = "INTERRUPTED"
            after["live_hosts"] = []
            diff = scan_diff(before, after)
            self.assertFalse(diff["comparison_complete"])
            self.assertIn("127.0.0.1", diff["reachability_changes"]["not_observed"])
            self.assertEqual(diff["absence_interpretation"], "NOT_OBSERVED_NOT_PROVEN_REMOVED")
