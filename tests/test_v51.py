"""Regressioni V5.1: identità input, API e protezioni manutenzione."""
import copy
import json
from pathlib import Path
import tempfile
import unittest
import os
import time
import threading
import sqlite3
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs
from unittest.mock import patch

from xitool.inputs import merge
from xitool.inventory import api_operations, javascript_targets
from xitool.scanners import discover, smart
from xitool.http import Response
from xitool.scope import Scope
from xitool.storage import DataError, DEFAULTS


class InputInventoryTests(unittest.TestCase):
    def row(self, **kwargs):
        return dict(url="https://example.com/items", method="POST", parameter="id", source="form", **kwargs)

    def test_same_name_in_query_json_and_body_are_distinct(self):
        rows = merge([self.row(location=value) for value in ("query", "json", "body")])
        self.assertEqual(len({r["input_id"] for r in rows}), 3)

    def test_values_removed_and_provenance_merged(self):
        one = self.row(location="query", value="DO_NOT_SAVE", default="DO_NOT_SAVE")
        two = dict(one, source="query")
        values = merge([one, two])
        self.assertEqual(len(values), 1)
        self.assertEqual(values[0]["provenance"], ["form", "query"])
        self.assertNotIn("DO_NOT_SAVE", json.dumps(values))
        self.assertIn("value", one)  # no mutation of caller

    def test_input_identity_stable_across_timestamp_and_source(self):
        self.assertEqual(merge([self.row(timestamp="a")])[0]["input_id"], merge([self.row(timestamp="b")])[0]["input_id"])

    def test_documented_json_and_path_inputs_not_smart_active_candidates(self):
        doc = {"openapi": "3.0.0", "servers": [{"url": "/v1"}], "paths": {"/users/{id}": {
            "get": {"parameters": [{"name": "id", "in": "path"}]},
            "post": {"requestBody": {"content": {"application/json": {"schema": {"properties": {"id": {"type": "string"}}}}}}}}}}
        response = Response("https://example.com/spec.json", 200, {"content-type": "application/json"}, json.dumps(doc))
        inputs, links, refs = discover(Scope(["example.com"], []), response, True)
        declared = [r for r in inputs if r["source"] == "openapi_document"]
        self.assertEqual({r["location"] for r in declared}, {"path", "json"})
        self.assertEqual(smart(declared, []), {})
        self.assertFalse(any("{id}" in url for url in links))
        self.assertTrue(any(r.get("template") for r in refs))

    def test_api_operations_preserve_method_and_no_examples(self):
        doc = {"swagger": "2.0", "host": "example.com", "basePath": "/api", "paths": {"/items": {
            "post": {"parameters": [{"in": "query", "name": "id", "example": "DO_NOT_SAVE"}]}}}}
        values = api_operations(doc, "https://example.com/spec")
        self.assertEqual(values[0]["url"], "https://example.com/api/items")
        self.assertEqual(values[0]["method"], "POST")
        self.assertNotIn("DO_NOT_SAVE", json.dumps(values))

    def test_ast_ignores_calls_in_comments_and_strings(self):
        try:
            import tree_sitter_javascript
        except ImportError:
            self.skipTest("Parser JS opzionale non installato")
        self.assertEqual(javascript_targets('/* fetch("/fake") */ const x = "fetch(\\"/string\\")"; fetch(`/real`); fetch(`/api/${id}`);'), ["/real"])


class CleanupTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / "scope.json").write_text("{}")
        self.cache = self.root / ".xitool-cache"
        self.cache.mkdir()
        (self.cache / "OWNED_BY_XITOOL").write_bytes(b"XITOOL\n")
        self.candidate = self.cache / "xitool-test.cache"
        self.candidate.write_text("cached")
        os.utime(self.candidate, (1, 1))

    def test_dry_run_does_not_delete_and_requires_exact_confirmation(self):
        from xitool.cleanup import dry_run, apply
        plan = dry_run(self.root)
        self.assertEqual(plan["reclaimable_bytes"], 6)
        self.assertTrue(self.candidate.exists())
        with self.assertRaises(DataError):
            apply(plan, "yes")
        self.assertTrue(self.candidate.exists())

    def test_only_candidate_deleted_config_and_results_preserved(self):
        from xitool.cleanup import dry_run, apply
        results = self.root / "runs"
        results.mkdir()
        (results / "checkpoint.json").write_text("protected")
        (self.cache / "user.json").write_text("protected")
        plan = dry_run(self.root)
        result = apply(plan, "ELIMINA " + plan["plan_id"])
        self.assertEqual(result["deleted"], [".xitool-cache/xitool-test.cache"])
        self.assertTrue((self.root / "scope.json").exists())
        self.assertTrue((results / "checkpoint.json").exists())
        self.assertTrue((self.cache / "user.json").exists())

    def test_changed_plan_or_external_path_is_rejected(self):
        from xitool.cleanup import dry_run, apply
        plan = dry_run(self.root)
        plan["files"][0]["path"] = "../../external"
        # Altering candidate metadata cannot change the recomputed allowlist.
        self.candidate.write_text("changed")
        with self.assertRaises(DataError):
            apply(plan, "ELIMINA " + plan["plan_id"])

    def test_missing_marker_protects_cache(self):
        from xitool.cleanup import dry_run
        (self.cache / "OWNED_BY_XITOOL").unlink()
        self.assertEqual(dry_run(self.root)["reclaimable_bytes"], 0)

    def test_unrecognized_root_rejected(self):
        from xitool.cleanup import dry_run
        with self.assertRaises(DataError):
            dry_run(self.cache)

    def test_locked_file_error_is_audited_without_deleting_config(self):
        from xitool.cleanup import dry_run, apply
        plan = dry_run(self.root)
        original = Path.unlink
        def deny(path, *args, **kwargs):
            if path == self.candidate:
                raise PermissionError("locked")
            return original(path, *args, **kwargs)
        with patch.object(Path, "unlink", deny):
            result = apply(plan, "ELIMINA " + plan["plan_id"])
        self.assertEqual(result["errors"][0]["error"], "PermissionError")
        self.assertTrue(self.candidate.exists())
        self.assertTrue((self.root / "cleanup_audit.json").exists())

    def test_symlink_refused_when_platform_supports_it(self):
        from xitool.cleanup import dry_run
        link = self.cache / "xitool-link.cache"
        try:
            link.symlink_to(self.root / "scope.json")
        except OSError:
            # Deterministic reparse rejection remains checked independently below.
            with patch("xitool.cleanup.Path.lstat", return_value=type("Info", (), {"st_mode": 0, "st_file_attributes": 0x400})()):
                with self.assertRaises(DataError):
                    dry_run(self.root)
            return
        plan = dry_run(self.root)
        self.assertTrue(any(row["path"].endswith("link.cache") for row in plan["errors"]))


class SQLBodyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.proof = "CANARY_SQL_BODY_12345678"
        cls.observations = []
        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                raw = self.rfile.read(int(self.headers["Content-Length"]))
                values = json.loads(raw) if "json" in self.headers["Content-Type"] else {key: value[0] for key, value in parse_qs(raw.decode()).items()}
                database = sqlite3.connect(":memory:")
                try:
                    database.execute("CREATE TABLE fixture(id INTEGER, value TEXT)")
                    database.execute("INSERT INTO fixture VALUES(1, ?)", (cls.proof,))
                    database.execute("PRAGMA query_only=ON")
                    if self.path.endswith("/safe"):
                        row = database.execute("SELECT value FROM fixture WHERE id=?", (values["id"],)).fetchone()
                    else:
                        row = database.execute("SELECT value FROM fixture WHERE id=" + values["id"]).fetchone()
                    body = (row[0] if row else "empty").encode()
                    self.send_response(200)
                    self.send_header("Content-Type", "text/plain")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                finally:
                    database.close()
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

    def test_real_sqlite_form_and_json_vulnerable_and_parameterized(self):
        from xitool.controlled import tasks, execute
        from xitool.http import HTTPClient
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory)
            config = copy.deepcopy(DEFAULTS)
            config["http"].update(allowed_ports=[self.server.server_port], requests_per_second=1000, max_retries=0)
            scope = Scope(["127.0.0.1"], [], ["127.0.0.1/32"])
            for mime in ("application/json", "application/x-www-form-urlencoded"):
                for kind in ("vulnerable", "safe"):
                    url = f"http://127.0.0.1:{self.server.server_port}/xitool-lab/{kind}"
                    case = {"id": "sql", "module": "sqli", "url": url, "operator_owned": True,
                            "proof_env": "XITOOL_SQL_BODY_PROOF", "parameter": "id", "fixture_only": True, "read_only_fixture": True,
                            "request": {"method": "POST", "content_type": mime, "fields": {"id": "1"}, "authorized": True}}
                    (project / "controlled_checks.json").write_text(json.dumps({"version": 1, "checks": [case]}))
                    with patch.dict(os.environ, {"XITOOL_SQL_BODY_PROOF": self.proof}):
                        task = tasks(project, scope, "sqli")[0]
                        row = execute("sqli", task, HTTPClient(scope, config), project)[0]
                    self.assertEqual(row["status"], "POTENTIAL" if kind == "vulnerable" else "PARTIAL")
                    self.assertEqual(row["http_method"], "POST")
                    self.assertNotIn(self.proof, json.dumps(row))
                    self.observations.append({"module": "sqli", "fixture": kind, "content_type": mime,
                                              "expected_positive": kind == "vulnerable", "outcome": row["status"],
                                              "observed_positive": row["status"] == "POTENTIAL",
                                              "inconclusive": row["status"] == "PARTIAL" and not row["evidence"]["expression_rejected_consistently"]})


class LimiterFeedbackTests(unittest.TestCase):
    def test_feedback_not_blocked_by_sleeping_waiter(self):
        from xitool.http import RateLimiter
        limiter = RateLimiter(10)
        limiter.next_at = time.monotonic() + .4
        cancel = threading.Event()
        def wait():
            try:
                limiter.wait(cancel)
            except Exception:
                pass
        thread = threading.Thread(target=wait)
        thread.start()
        time.sleep(.02)
        started = time.monotonic()
        limiter.feedback(200)
        elapsed = time.monotonic() - started
        cancel.set()
        thread.join(timeout=1)
        self.assertLess(elapsed, .15)
        self.assertFalse(thread.is_alive())


class DiffAndPolicyTests(unittest.TestCase):
    def state(self):
        return {"project": "P", "domain": "example.com", "module": "misconfiguration", "run_id": "before",
                "scope_hash": "s", "config_hash": "c", "engine_version": "v", "status": "COMPLETED",
                "hosts": ["example.com"], "live_hosts": ["example.com"], "endpoints": [], "inputs": [], "results": []}

    def test_dns_and_api_changes_are_not_removal_proof(self):
        from xitool.execution import scan_diff
        before = self.state()
        before["dns_records"] = {"example.com": {"A": ["8.8.8.8"], "AAAA": [], "CNAME": []}}
        before["url_references"] = [{"url": "https://example.com/api", "method": "GET", "source": "openapi_document", "parameters": []}]
        after = copy.deepcopy(before)
        after.update(run_id="after", status="INTERRUPTED", live_hosts=[])
        after["dns_records"]["example.com"].update(A=[], resolution_status="RESOLVER_ERROR")
        after["url_references"][0]["parameters"] = [{"name": "id", "location": "query"}]
        diff = scan_diff(before, after)
        self.assertEqual(len(diff["dns_changes"]), 1)
        self.assertEqual(len(diff["api_changes"]), 1)
        self.assertFalse(diff["comparison_complete"])
        self.assertIn("NOT_PROVEN_REMOVAL", diff["dns_changes"][0]["interpretation"])

    def test_permissions_policy_context_and_tls_coverage(self):
        from xitool.http import HTTPClient
        from xitool.scanners import scan
        scope = Scope(["example.com"], [])
        client = HTTPClient(scope, copy.deepcopy(DEFAULTS))
        for mime, context in (("text/html", "DOCUMENT"), ("application/json", "NOT_ASSESSED_NON_DOCUMENT")):
            response = Response("https://example.com/", 200, {"content-type": mime, "permissions-policy": "camera=()"}, "")
            with patch.object(client, "get", return_value=response):
                row = scan("misconfiguration", {"url": response.url}, client)[0]
            self.assertEqual(row["evidence"]["permissions_policy"]["applicability"], context)
            self.assertTrue(row["evidence"]["permissions_policy"]["present"])
            self.assertEqual(row["evidence"]["tls_coverage"], "NEGOTIATED_CONNECTION_ONLY")

    def test_versioned_signatures_redact_and_suppress_placeholder(self):
        from xitool.http import HTTPClient
        from xitool.scanners import scan
        client = HTTPClient(Scope(["example.com"], []), copy.deepcopy(DEFAULTS))
        token = "ghp_" + "Ab9x" * 10
        response = Response("https://example.com/", 200, {"content-type": "text/plain"}, token + " " + token)
        with patch.object(client, "get", return_value=response):
            row = scan("sensitive", {"url": response.url}, client)[0]
        self.assertEqual(row["evidence"]["pattern_counts"]["github_token_shape"], 1)
        self.assertIn("catalog_version", row["evidence"])
        self.assertNotIn(token, json.dumps(row))
        response.body = "ghp_" + "X" * 40
        with patch.object(client, "get", return_value=response):
            row = scan("sensitive", {"url": response.url}, client)[0]
        self.assertEqual(row["evidence"]["pattern_counts"]["github_token_shape"], 0)
