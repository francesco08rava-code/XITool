"""Esiti chiari, provenienza URL, preflight e ripresa dei piani Smart."""
import copy
from pathlib import Path
import tempfile
import unittest
import threading
import socket
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import Mock, patch

from xitool.execution import Engine, record_no_input
from xitool.http import HTTPClient, Response
from xitool.outcomes import result_outcome, run_outcome
from xitool.plans import SmartPlan
from xitool.recon_output import outputs
from xitool.scanners import discover, scan
from xitool.scope import Scope
from xitool.storage import DEFAULTS, DataError, Projects, read_json


class CompletionTests(unittest.TestCase):
    def setUp(self):
        self.scope = Scope(["example.com"], [])
        self.config = copy.deepcopy(DEFAULTS)
        self.client = HTTPClient(self.scope, self.config)

    def test_url_reference_provenance_and_out_of_scope_without_queueing(self):
        html = '<a href="/found?q=a">link</a><a href="https://outside.test/path">outside</a><form action="/submit" method="post"><input name="id"></form>'
        inputs, links, references = discover(self.scope, Response("https://example.com/", 200, {"content-type": "text/html"}, html), True)
        self.assertEqual(links, ["https://example.com/found?q=a"])
        self.assertTrue(any(row["scope_status"] == "OUT_OF_SCOPE" for row in references))
        self.assertTrue(any(row["kind"] == "OBSERVED_FORM" for row in references))
        self.assertNotIn("https://example.com/submit", links)
        self.assertTrue(inputs)

    def test_static_js_reference_is_not_reached_or_verified(self):
        _, links, references = discover(self.scope, Response("https://example.com/app.js", 200, {"content-type": "text/javascript"}, "fetch('/api/users')"), True)
        self.assertEqual(references[0]["kind"], "STATIC_HYPOTHESIS")
        self.assertEqual(links, ["https://example.com/api/users"])

    def test_failed_sources_are_not_displayed_as_successful_empty_collection(self):
        state = {"domain": "example.com", "status": "COMPLETED", "hosts": ["example.com"], "live_hosts": [], "inputs": [], "endpoints": [],
                 "provider_metadata": [{"provider": "crtsh", "complete": False}], "provider_errors": [{"provider": "crtsh"}], "errors": [{"type": "network"}]}
        summary = outputs(state, self.scope)[1]["summary.json"]
        self.assertFalse(summary["collection_complete"])
        self.assertIn("incompleta", summary["message"])
        self.assertEqual(summary["unavailable_sources"], ["crtsh"])

    def test_http_error_page_is_not_a_clean_negative_result(self):
        with patch.object(self.client, "get", return_value=Response("https://example.com/", 403, {}, "denied")):
            result = scan("sensitive", {"url": "https://example.com/"}, self.client)[0]
        self.assertEqual(result["verification_outcome"], "PARTIAL")

    def test_archives_and_database_dumps_are_not_downloaded(self):
        from xitool.scanners import safe_url
        for url in ("https://example.com/backup.zip", "https://example.com/db%2esql", "https://example.com/download?file=data.tar.gz"):
            with self.subTest(url=url), self.assertRaises(DataError):
                safe_url(self.scope, url)
            with patch.object(self.client, "_request") as request:
                with self.assertRaises(DataError):
                    self.client.get(url)
                request.assert_not_called()

    def test_archive_content_type_is_rejected_before_reading_body(self):
        addresses = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 80))]
        stream = Mock()
        stream.getpeername.return_value = ("8.8.8.8", 80)
        response = Mock(status=200)
        response.getheaders.return_value = [("Content-Type", "application/zip")]
        with patch.object(self.client, "_resolve", return_value=addresses), patch("xitool.http.socket.socket", return_value=stream), patch("xitool.http.http.client.HTTPConnection") as connection:
            connection.return_value.getresponse.return_value = response
            with self.assertRaises(DataError):
                self.client._request("http://example.com/payload", {})
        response.read1.assert_not_called()

    def test_placeholders_are_counted_but_not_reported_as_credentials(self):
        body = 'api_key="your_example_placeholder_key_123456789"; AKIAIOSFODNN7EXAMPLE'
        with patch.object(self.client, "get", return_value=Response("https://example.com/", 200, {}, body)):
            result = scan("sensitive", {"url": "https://example.com/"}, self.client)[0]
        self.assertEqual(result["status"], "OBSERVED")
        self.assertGreaterEqual(result["evidence"]["ignored_placeholder_count"], 1)

    def test_preflight_is_options_and_restores_client_on_failure(self):
        self.client.limiter.wait = Mock()
        def transport(url, headers):
            self.assertEqual(self.client.method, "OPTIONS")
            self.assertEqual(headers["Access-Control-Request-Method"], "GET")
            self.assertNotIn("Authorization", headers)
            return Response(url, 204, {"access-control-allow-methods": "GET"}, "")
        with patch.object(self.client, "_request", side_effect=transport):
            self.assertEqual(self.client.preflight("https://example.com/", "https://xitool.invalid").status, 204)
        self.assertEqual(self.client.method, "GET")
        with patch.object(self.client, "get", side_effect=DataError("fixture")), self.assertRaises(DataError):
            self.client.preflight("https://example.com/", "https://xitool.invalid")
        self.assertEqual(self.client.method, "GET")

    def test_unstable_sql_baseline_is_partial(self):
        with patch.object(self.client, "get", side_effect=[Response("https://example.com/", 200, {}, "a"), Response("https://example.com/", 200, {}, "b")]):
            result = scan("sqli", {"url": "https://example.com/"}, self.client)[0]
        self.assertFalse(result["evidence"]["response_stable"])
        self.assertEqual(result["verification_outcome"], "PARTIAL")

    def test_content_length_with_connection_close_is_not_a_network_error(self):
        class Handler(BaseHTTPRequestHandler):
            def do_OPTIONS(self):
                body = b"unsupported preflight"
                self.send_response(501)
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(body)
            def log_message(self, *args):
                pass
        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            settings = copy.deepcopy(DEFAULTS)
            settings["http"].update(allowed_ports=[server.server_address[1]], max_retries=0)
            client = HTTPClient(Scope(["127.0.0.1"], [], ["127.0.0.1/32"]), settings)
            response = client.preflight(f"http://127.0.0.1:{server.server_address[1]}/", "https://xitool.invalid")
            self.assertEqual(response.status, 501)
            self.assertEqual(response.body, "unsupported preflight")
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)


class PlanTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        projects = Projects(Path(directory.name))
        self.project = projects.create("PlanLab", ["example.com", "other.test"], [])
        self.scope = projects.load("PlanLab")[1]
        self.config = copy.deepcopy(DEFAULTS)
        self.config["http"]["requests_per_second"] = 20

    def steps(self):
        return [{"domain": host, "module": "misconfiguration", "tasks": [{"url": f"https://{host}/"}]} for host in self.scope.roots()]

    def test_persistent_plan_resume_skips_completed_domain_and_keeps_reports(self):
        plan = SmartPlan(self.project, self.scope, self.config, self.scope.roots())
        plan.add(self.steps())
        with patch("xitool.execution.scan", side_effect=[[], KeyboardInterrupt()]):
            plan.run()
        self.assertEqual([step["status"] for step in plan.state["steps"]], ["COMPLETED", "INTERRUPTED"])
        resumed = SmartPlan(self.project, self.scope, self.config, self.scope.roots(), path=plan.path)
        with patch("xitool.execution.scan", return_value=[]) as scanner:
            resumed.run()
        self.assertEqual(scanner.call_count, 1)
        self.assertEqual(resumed.state["status"], "COMPLETED")
        self.assertTrue(plan.path.with_suffix(".report.md").exists())

    def test_plan_scope_config_and_integrity_are_validated(self):
        plan = SmartPlan(self.project, self.scope, self.config, self.scope.roots())
        plan.add(self.steps())
        restricted = Scope(["example.com"], [])
        with self.assertRaises(DataError):
            SmartPlan(self.project, restricted, self.config, ["example.com"], path=plan.path)
        plan.path.write_text('{"broken":true}', encoding="utf-8")
        with self.assertRaises(DataError):
            SmartPlan(self.project, self.scope, self.config, self.scope.roots(), path=plan.path)

    def test_no_input_is_saved_as_not_started_without_network(self):
        with patch.object(HTTPClient, "get") as get:
            path = record_no_input(self.project, self.scope, "access", "example.com")
        get.assert_not_called()
        value = read_json(path)
        self.assertEqual(value["verification_outcome"], "NO_INPUT")
        self.assertEqual(value["execution_status"], "NOT_STARTED")

    def test_open_projects_exposes_smart_plans_without_writes_or_execution(self):
        from xitool.cli import open_projects
        import io
        plan = SmartPlan(self.project, self.scope, self.config, self.scope.roots())
        plan.add(self.steps())
        before = plan.path.read_bytes()
        projects = Projects(self.project.parent)
        with patch("builtins.input", side_effect=["1", "3", "0"]), patch("xitool.cli.browse") as browse, patch.object(Engine, "execute") as run, patch("sys.stdout", new_callable=io.StringIO):
            open_projects(projects)
        browse.assert_called_once_with(self.project / "plans")
        run.assert_not_called()
        self.assertEqual(plan.path.read_bytes(), before)

    def test_plan_continues_after_one_domain_failure(self):
        plan = SmartPlan(self.project, self.scope, self.config, self.scope.roots())
        plan.add(self.steps())
        with patch("xitool.execution.scan", side_effect=[RuntimeError("fixture"), []]):
            result = plan.run()
        self.assertEqual([row["status"] for row in result], ["FAILED", "COMPLETED"])
        self.assertEqual(plan.state["status"], "PARTIAL")

    def test_recon_plan_remains_awaiting_operator_selection(self):
        plan = SmartPlan(self.project, self.scope, self.config, ["example.com"])
        plan.add([self.steps()[0]], phase="RECON")
        with patch("xitool.execution.scan", return_value=[]):
            plan.run()
        self.assertEqual(plan.state["status"], "AWAITING_SELECTION")

    def test_forged_completed_step_cannot_redirect_engine_to_another_project(self):
        plan = SmartPlan(self.project, self.scope, self.config, self.scope.roots())
        plan.add(self.steps())
        data = read_json(plan.path)
        data["data"]["steps"][0]["run"] = "../outside/run"
        from xitool.storage import fingerprint, save_json
        data["sha256"] = fingerprint(data["data"])
        save_json(plan.path, data)
        with self.assertRaises(DataError):
            SmartPlan(self.project, self.scope, self.config, self.scope.roots(), path=plan.path)
