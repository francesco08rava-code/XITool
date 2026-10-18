"""Worker HTTP reali, cancellazione, classificazione e diff conservativo."""
import copy
import json
from pathlib import Path
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import patch

from xitool.assessment import assess
from xitool.execution import Engine, scan_diff, load_state, run_batch
from xitool.diffing import export_diff
from xitool.http import RateLimiter
from xitool.scope import Scope
from xitool.storage import DEFAULTS, Projects
from xitool.scanners import finding


class WorkerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.guard = threading.Lock()
        cls.active = cls.peak = cls.requests = 0
        cls.started_request = threading.Event()
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                with cls.guard:
                    cls.active += 1
                    cls.peak = max(cls.peak, cls.active)
                    cls.requests += 1
                    cls.started_request.set()
                try:
                    time.sleep(.18)
                    self.send_response(200)
                    self.send_header("Content-Type", "text/html")
                    self.send_header("Content-Length", "12")
                    self.end_headers()
                    self.wfile.write(b"normal page!")
                finally:
                    with cls.guard:
                        cls.active -= 1
            def log_message(self, *args):
                pass
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=2)

    def setUp(self):
        self.__class__.peak = self.__class__.requests = 0
        self.__class__.started_request.clear()
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.project = Projects(Path(directory.name)).create("Workers", ["127.0.0.1"], [])
        self.scope = Scope(["127.0.0.1"], [], ["127.0.0.1/32"])
        self.config = copy.deepcopy(DEFAULTS)
        self.config["http"].update(max_concurrency=3, max_concurrency_per_host=2, requests_per_second=20,
                                   allowed_ports=[self.server.server_port], max_retries=0)
        self.tasks = [{"url": f"http://127.0.0.1:{self.server.server_port}/page{i}"} for i in range(6)]

    def engine(self):
        return Engine(self.project, self.scope, self.config, "sensitive", target="127.0.0.1", tasks=self.tasks)

    def test_workers_really_overlap_and_respect_host_limit(self):
        engine = self.engine()
        engine.execute()
        self.assertEqual(engine.state["status"], "COMPLETED")
        self.assertEqual(self.peak, 2)
        self.assertEqual(len(engine.state["completed"]), 6)
        self.assertEqual(engine.client.stats["requests"], 6)
        self.assertEqual(self.requests, 6)
        self.assertEqual(len({row["id"] for row in engine.state["results"]}), 6)

    def test_interrupt_preserves_inflight_tasks_and_resume_has_no_lost_results(self):
        engine = self.engine()
        def observer(state):
            if state["completed"]:
                raise KeyboardInterrupt()
        engine.execute(observer)
        checkpoint = load_state(engine.directory / "checkpoint.json")
        self.assertEqual(checkpoint["status"], "INTERRUPTED")
        self.assertEqual(len(checkpoint["completed"]) + len(checkpoint["pending"]), 6)
        resumed = Engine(self.project, self.scope, self.config, "sensitive", target="127.0.0.1", resume=engine.directory)
        resumed.execute()
        self.assertEqual(len(resumed.state["results"]), 6)
        self.assertEqual(resumed.state["status"], "COMPLETED")
        self.assertEqual(self.active, 0)

    def test_external_cancel_does_not_mark_an_uncommitted_worker_completed(self):
        engine = self.engine()
        def cancel():
            if self.started_request.wait(timeout=20):
                engine.stop.set()
        stopper = threading.Thread(target=cancel, daemon=True)
        stopper.start()
        engine.execute()
        stopper.join(timeout=2)
        self.assertGreater(self.requests, 0)
        self.assertEqual(engine.state["status"], "INTERRUPTED")
        self.assertEqual(engine.state["completed"], [])
        self.assertEqual(len(engine.state["pending"]), 6)
        self.assertEqual(self.active, 0)

    def test_fixture_and_session_tasks_are_not_dispatched_concurrently(self):
        from xitool.workers import TaskPool
        engine = self.engine()
        pool = TaskPool(engine)
        try:
            self.assertFalse(pool.eligible({**self.tasks[0], "controlled_case": "fixture"}))
            self.assertFalse(pool.eligible({**self.tasks[0], "session": "owner"}))
            self.assertFalse(pool.eligible({**self.tasks[0], "kind": "dns"}))
        finally:
            pool.close()

    def test_parallel_limiter_does_not_burst(self):
        limiter = RateLimiter(20)
        stamps = []
        guard = threading.Lock()
        def wait():
            limiter.wait()
            with guard:
                stamps.append(time.monotonic())
        threads = [threading.Thread(target=wait) for _ in range(5)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=2)
        self.assertEqual(len(stamps), 5)
        self.assertTrue(all(right - left >= .035 for left, right in zip(sorted(stamps), sorted(stamps)[1:])))

    def test_two_domains_share_global_budget_and_keep_reports_isolated(self):
        other = ThreadingHTTPServer(("127.0.0.2", 0), self.server.RequestHandlerClass)
        thread = threading.Thread(target=other.serve_forever, daemon=True)
        thread.start()
        try:
            project = Projects(self.project.parent).create("Domains", ["127.0.0.1", "127.0.0.2"], [])
            scope = Scope(["127.0.0.1", "127.0.0.2"], [], ["127.0.0.0/8"])
            config = copy.deepcopy(self.config)
            config["execution"]["max_concurrent_domains"] = 2
            config["http"]["allowed_ports"] = [self.server.server_port, other.server_port]
            engines = [Engine(project, scope, config, "sensitive", target=host,
                              tasks=[{"url": f"http://{host}:{port}/item{i}"} for i in range(3)])
                       for host, port in (("127.0.0.1", self.server.server_port), ("127.0.0.2", other.server_port))]
            summary = run_batch(engines)
            self.assertEqual([row["status"] for row in summary], ["COMPLETED", "COMPLETED"])
            self.assertGreaterEqual(self.peak, 2)
            self.assertLessEqual(self.peak, 3)
            for engine in engines:
                self.assertTrue(all(row["domain"] == engine.target for row in engine.state["results"]))
            self.assertEqual(len(list((project / "reports").glob("batch_*.json"))), 1)
            report = json.loads(next((project / "reports").glob("batch_*.json")).read_text())
            self.assertEqual(set(report["scope"]), {"127.0.0.1", "127.0.0.2"})
            self.assertIn("sensitive", report["modules_executed"])
            self.assertIn("xss", report["modules_not_executed"])
        finally:
            other.shutdown()
            other.server_close()
            thread.join(timeout=2)


class AssessmentTests(unittest.TestCase):
    def result(self, status, evidence=None):
        return assess(finding("xss", "https://example.com/?b=2&a=1", "controlled", status, evidence or {}, "Limited to fixture"))

    def test_direct_proof_has_explained_review_priority_not_cvss(self):
        row = self.result("VERIFIED", {"baseline_status": 200, "repeat_executed": True})
        self.assertEqual(row["review_priority"], "HIGH REVIEW PRIORITY")
        self.assertEqual(row["confidence_score"], sum(item["points"] for item in row["confidence_factors"]))
        self.assertEqual(row["severity"], "UNKNOWN")

    def test_incomplete_response_is_inconclusive(self):
        self.assertEqual(self.result("POTENTIAL", {"body_truncated": True})["review_priority"], "INCONCLUSIVE")

    def test_false_positive_is_low_priority_and_zero_score(self):
        row = self.result("FALSE_POSITIVE")
        self.assertEqual(row["confidence_score"], 0)
        self.assertEqual(row["review_priority"], "LOW REVIEW PRIORITY")

    def test_normalized_parameter_order_has_same_issue_fingerprint(self):
        left = self.result("OBSERVED")
        right = finding("xss", "https://example.com/?a=1&b=2", "controlled", "OBSERVED", {}, "")
        self.assertEqual(left["issue_fingerprint"], assess(right)["issue_fingerprint"])

    def test_verified_label_without_evidence_is_not_high_priority(self):
        self.assertEqual(self.result("VERIFIED")["review_priority"], "INCONCLUSIVE")

    def test_human_false_positive_preserves_automated_observation(self):
        row = self.result("POTENTIAL")
        row["human_verdict"] = "FALSE_POSITIVE"
        assess(row)
        self.assertEqual(row["status"], "POTENTIAL")
        self.assertEqual(row["classification"], "FALSE_POSITIVE")
        self.assertEqual(row["confidence_score"], 0)


class DiffTests(unittest.TestCase):
    def setUp(self):
        self.before = {"project": "P", "domain": "example.com", "module": "subfinding", "run_id": "old", "scope_hash": "s", "config_hash": "c", "status": "COMPLETED",
                       "hosts": ["example.com", "a.example.com"], "live_hosts": [], "endpoints": ["https://example.com/api"], "inputs": [], "results": [], "seed_hosts": ["example.com"]}
        self.after = copy.deepcopy(self.before)
        self.after.update(run_id="new", hosts=["example.com", "a.example.com", "b.example.com"])

    def test_new_host_and_unchanged_host(self):
        diff = scan_diff(self.before, self.after)
        self.assertEqual(diff["new_subdomains"], ["b.example.com"])
        self.assertIn("a.example.com", diff["hosts"]["unchanged"])

    def test_failed_provider_cannot_prove_removal(self):
        self.after.update(hosts=["example.com"], provider_metadata=[{"complete": False}])
        diff = scan_diff(self.before, self.after)
        self.assertFalse(diff["comparison_complete"])
        self.assertEqual(diff["absence_interpretation"], "NOT_OBSERVED_NOT_PROVEN_REMOVED")

    def test_incomplete_baseline_cannot_produce_a_complete_comparison(self):
        self.before["status"] = "INTERRUPTED"
        self.after["provider_metadata"] = [{"provider": name, "complete": True, "errors": []} for name in ("crtsh", "certspotter")]
        self.assertFalse(scan_diff(self.before, self.after)["comparison_complete"])

    def test_method_and_parameter_change(self):
        self.after["inputs"] = [{"url": "https://example.com/api", "method": "POST", "parameter": "q"}]
        diff = scan_diff(self.before, self.after)
        self.assertEqual(diff["changed_endpoints"][0]["new_methods"], ["POST"])
        self.assertEqual(diff["changed_endpoints"][0]["new_parameters"], ["q"])

    def test_request_ids_and_timestamps_are_not_finding_changes(self):
        row = finding("sensitive", "https://example.com/", "check", "OBSERVED", {}, "")
        self.before["results"] = [row]
        self.after["results"] = [{**row, "request_ids": ["new"], "timestamp": "later"}]
        self.assertEqual(scan_diff(self.before, self.after)["results"]["changed"], [])

    def test_absent_finding_is_unresolved_even_incomplete(self):
        self.before["results"] = [finding("sensitive", "https://example.com/", "check", "OBSERVED", {}, "")]
        self.after["status"] = "INTERRUPTED"
        diff = scan_diff(self.before, self.after)
        self.assertFalse(diff["comparison_complete"])
        self.assertEqual(len(diff["finding_details"]["not_reproduced"]), 1)
        with tempfile.TemporaryDirectory() as directory:
            export_diff(Path(directory), diff)
            self.assertTrue((Path(directory) / "unresolved_findings.json").exists())

    def test_random_nonce_is_not_a_changed_issue(self):
        row = finding("xss", "https://example.com/", "lab", "VERIFIED", {"nonce": "old", "repeat_executed": True}, "")
        self.before["results"] = [row]
        self.after["results"] = [{**row, "evidence": {"nonce": "new", "repeat_executed": True}}]
        self.assertEqual(scan_diff(self.before, self.after)["results"]["changed"], [])


class SmartCompatibilityTests(unittest.TestCase):
    def test_module_version_change_rejects_plan_resume(self):
        from xitool.plans import SmartPlan
        from xitool.storage import read_json, save_json, fingerprint, DataError
        with tempfile.TemporaryDirectory() as directory:
            project = Projects(Path(directory)).create("Versions", ["example.com"], [])
            scope = Scope(["example.com"], [])
            plan = SmartPlan(project, scope, copy.deepcopy(DEFAULTS), ["example.com"])
            plan.save()
            envelope = read_json(plan.path)
            envelope["data"]["module_versions"]["xss"] = "different"
            envelope["sha256"] = fingerprint(envelope["data"])
            save_json(plan.path, envelope)
            with self.assertRaises(DataError):
                SmartPlan(project, scope, copy.deepcopy(DEFAULTS), ["example.com"], path=plan.path)

    def test_discovery_reuse_requires_compatible_config_in_smart_mode(self):
        from xitool.execution import latest_discovery
        with tempfile.TemporaryDirectory() as directory:
            project = Projects(Path(directory)).create("Reuse", ["example.com"], [])
            scope = Scope(["example.com"], [])
            config = copy.deepcopy(DEFAULTS)
            engine = Engine(project, scope, config, "subfinding", target="example.com", tasks=[{"url": "https://example.com/observed"}])
            engine.state.update(status="COMPLETED", pending=[], endpoints=["https://example.com/observed"])
            engine.save()
            self.assertTrue(latest_discovery(project, scope.for_target("example.com"), "example.com", config)[1])
            changed = copy.deepcopy(config)
            changed["http"]["requests_per_second"] = 1
            self.assertEqual(latest_discovery(project, scope.for_target("example.com"), "example.com", changed), ([], []))


class DiscoveryTests(unittest.TestCase):
    def test_openapi_servers_and_swagger_basepath_are_respected_without_requests(self):
        from xitool.inventory import api_references
        self.assertEqual(api_references({"openapi": "3.0.0", "servers": [{"url": "https://example.com/v1"}], "paths": {"/users": {}}}, "https://example.com/openapi.json")[0][0], "https://example.com/v1/users")
        self.assertEqual(api_references({"swagger": "2.0", "host": "example.com", "basePath": "/api", "schemes": ["https"], "paths": {"/items": {}}}, "https://example.com/swagger.json")[0][0], "https://example.com/api/items")

    def test_cookie_and_header_inventory_never_stores_values(self):
        from xitool.scanners import discover
        from xitool.http import Response
        response = Response("https://example.com/", 200, {"content-type": "text/html", "set-cookie": "session=DO_NOT_SAVE_COOKIE; HttpOnly"}, "")
        inputs, _, refs = discover(Scope(["example.com"], []), response, True)
        self.assertNotIn("DO_NOT_SAVE_COOKIE", json.dumps([inputs, refs]))
        self.assertTrue(any(row.get("location") == "cookie" and row["request_input_confirmed"] is False for row in refs))

    def test_crawler_exports_historical_without_verification_and_network_as_verified(self):
        from xitool.crawl_output import export
        state = {"status": "COMPLETED", "endpoints": [], "inputs": [], "url_references": [
            {"url": "https://example.com/old", "kind": "HISTORICAL", "source": "operator_local_export"},
            {"url": "https://example.com/api", "kind": "OBSERVED_NETWORK", "source": "browser_network", "reached": True, "resource_type": "fetch"}]}
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            export(path, state)
            self.assertEqual((path / "verified_urls.txt").read_text(), "https://example.com/api\n")
            self.assertEqual((path / "historical_urls.txt").read_text(), "https://example.com/old\n")

    def test_cookie_attributes_are_shared_by_authentication_and_misconfiguration(self):
        from xitool.scanners import scan
        from xitool.http import HTTPClient, Response
        client = HTTPClient(Scope(["example.com"], []), copy.deepcopy(DEFAULTS))
        response = Response("https://example.com/", 200, {"set-cookie": "sid=PRIVATE_VALUE; Secure; HttpOnly; SameSite=None; Max-Age=0"}, "")
        with patch.object(client, "get", return_value=response):
            auth = scan("authentication", {"url": response.url}, client)[0]
            config = scan("misconfiguration", {"url": response.url}, client)[0]
        self.assertEqual(auth["evidence"]["cookies"], config["evidence"]["cookies"])
        self.assertTrue(auth["evidence"]["cookies"][0]["deletion_cookie_observed"])
        self.assertNotIn("PRIVATE_VALUE", json.dumps([auth, config]))


class PermissionMatrixTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import test_controlled
        cls.fixture_class = test_controlled.ControlledServerTests
        cls.fixture_class.setUpClass()

    @classmethod
    def tearDownClass(cls):
        cls.fixture_class.tearDownClass()

    def setUp(self):
        self.fixture = self.fixture_class()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)

    def test_expected_allowed_access_does_not_report_a_vulnerability(self):
        from xitool.controlled import execute, tasks
        from xitool.http import HTTPClient
        from xitool.storage import save_json
        case = self.fixture.case("access", "/owned-vulnerable")
        case["expected_other_access"] = True
        save_json(self.fixture.project / "controlled_checks.json", {"version": 1, "checks": [case]})
        result = execute("access", tasks(self.fixture.project, self.fixture.scope, "access")[0], HTTPClient(self.fixture.scope, self.fixture.config), self.fixture.project)[0]
        self.assertEqual(result["status"], "NO_ISSUES_OBSERVED")

    def test_unexpected_denial_is_review_not_a_verified_security_violation(self):
        from xitool.controlled import execute, tasks
        from xitool.http import HTTPClient
        from xitool.storage import save_json
        case = self.fixture.case("access", "/owned-safe")
        case["expected_other_access"] = True
        save_json(self.fixture.project / "controlled_checks.json", {"version": 1, "checks": [case]})
        result = execute("access", tasks(self.fixture.project, self.fixture.scope, "access")[0], HTTPClient(self.fixture.scope, self.fixture.config), self.fixture.project)[0]
        self.assertEqual(result["status"], "MANUAL_REVIEW")
