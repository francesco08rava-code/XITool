"""Verifiche reali su server locale: sessioni, risorse canary, casi positivi e negativi."""
import copy
import json
import sqlite3
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import Mock, patch
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

from xitool.controlled import execute, load_cases, tasks
from xitool.execution import Engine, load_state
from xitool.http import HTTPClient, NetworkError, Response
from xitool.sessions import Profile, load_profiles
from xitool.scope import Scope
from xitool.storage import DEFAULTS, DataError, Projects, read_json, save_json


class SessionTests(unittest.TestCase):
    def setUp(self):
        self.config = copy.deepcopy(DEFAULTS)
        self.client = HTTPClient(Scope(["example.com", "other.test"], []), self.config)
        self.client.limiter.wait = Mock()
        self.profile = Profile("owner", "https://example.com/", "owner", {"Authorization": "XITOOL_TEST_AUTH"})

    def test_private_headers_are_sent_but_response_is_not_cached(self):
        private = self.client.for_profile(self.profile)
        with patch.dict("os.environ", {"XITOOL_TEST_AUTH": "Bearer DO_NOT_PERSIST"}), patch.object(private, "_request", return_value=Response("https://example.com/", 200, {}, "private")) as request:
            private.get("https://example.com/")
        self.assertEqual(request.call_args.args[1]["Authorization"], "Bearer DO_NOT_PERSIST")
        self.assertEqual(private.cache, {})
        self.assertEqual(self.client.cache, {})

    def test_cross_origin_redirect_does_not_receive_credentials(self):
        private = self.client.for_profile(self.profile)
        with patch.dict("os.environ", {"XITOOL_TEST_AUTH": "Bearer PRIVATE"}), patch.object(private, "_request", return_value=Response("https://example.com/", 302, {"location": "https://other.test/"}, "")) as request:
            with self.assertRaises(DataError):
                private.get("https://example.com/")
        self.assertEqual(request.call_count, 1)

    def test_missing_expired_and_newline_credentials_fail_before_transport(self):
        for value in ("", "bad\r\nvalue"):
            private = self.client.for_profile(self.profile)
            with patch.dict("os.environ", {"XITOOL_TEST_AUTH": value}), patch.object(private, "_request") as request:
                with self.assertRaises(DataError):
                    private.get("https://example.com/")
                request.assert_not_called()
        expired = Profile("expired", "https://example.com/", "test", {"Authorization": "XITOOL_TEST_AUTH"}, "2000-01-01T00:00:00Z")
        with self.assertRaises(DataError):
            self.client.for_profile(expired).get("https://example.com/")

    def test_manifest_forbids_literal_secrets_and_public_cleartext(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for profile in ({"origin": "https://example.com", "token": "secret"},
                            {"origin": "http://example.com", "header_env": {"Authorization": "AUTH"}},
                            {"origin": "https://example.com", "header_env": {"Host": "AUTH"}}):
                save_json(root / "session_profiles.json", {"version": 1, "profiles": {"test": profile}})
                with self.assertRaises(DataError):
                    load_profiles(root)


class ControlledServerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.requests = []
        cls.owner_canary = "XITOOL_OWNER_CANARY_7cefe143"
        cls.other_canary = "XITOOL_OTHER_CANARY_dfe72815"
        cls.fixture_directory = tempfile.TemporaryDirectory()
        cls.canary_file = Path(cls.fixture_directory.name) / "prepared-canary.txt"
        cls.canary_file.write_text(cls.owner_canary, encoding="utf-8")
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                path = urlsplit(self.path).path
                account = self.headers.get("Authorization", "")
                cls.requests.append((path, account))
                status, body = 200, "normal"
                if path == "/other-reference":
                    status, body = (200, cls.other_canary) if account == "Bearer OTHER_PRIVATE" else (401, "login")
                elif path == "/owned-vulnerable":
                    body = cls.owner_canary
                elif path == "/owned-safe":
                    status, body = (200, cls.owner_canary) if account == "Bearer OWNER_PRIVATE" else (403, "denied")
                elif path == "/owned-plain200":
                    body = cls.owner_canary if account == "Bearer OWNER_PRIVATE" else "generic public shell"
                elif path == "/xitool-lab/file":
                    body = cls.canary_file.read_text(encoding="utf-8") if parse_qs(urlsplit(self.path).query).get("file") == ["prepared-canary"] else "normal fixture"
                elif path.startswith("/xitool-lab/sql"):
                    value = parse_qs(urlsplit(self.path).query).get("id", ["0"])[0]
                    connection = sqlite3.connect(":memory:")
                    try:
                        connection.execute("CREATE TABLE fixture(id INTEGER, value TEXT)")
                        connection.execute("INSERT INTO fixture VALUES (1, ?)", (cls.owner_canary,))
                        if path.endswith("safe"):
                            rows = connection.execute("SELECT value FROM fixture WHERE id=?", (value,)).fetchall()
                        else:
                            rows = connection.execute("SELECT value FROM fixture WHERE id=" + value).fetchall()
                        body = " ".join(row[0] for row in rows) or "empty fixture"
                    finally:
                        connection.close()
                elif path == "/xitool-lab/protected":
                    status, body = (200, cls.owner_canary) if account == "Bearer OWNER_PRIVATE" and not cls.revoked else (401, "login")
                elif path == "/xitool-lab/end-session":
                    if cls.logout_effective:
                        cls.revoked = True
                    body = "logout processed"
                self.send_response(status)
                self.send_header("Content-Type", "text/plain")
                self.end_headers()
                self.wfile.write(body.encode())
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
        cls.fixture_directory.cleanup()

    def setUp(self):
        self.__class__.revoked = False
        self.__class__.logout_effective = True
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        projects = Projects(Path(directory.name))
        self.project = projects.create("Lab", ["127.0.0.1"], [])
        self.scope = Scope(["127.0.0.1"], [], ["127.0.0.1/32"])
        self.config = copy.deepcopy(DEFAULTS)
        self.config["http"].update(max_retries=0, requests_per_second=20, allowed_ports=[self.server.server_address[1]])
        self.origin = f"http://127.0.0.1:{self.server.server_address[1]}"
        save_json(self.project / "session_profiles.json", {"version": 1, "profiles": {
            "owner": {"origin": self.origin, "role": "owner", "header_env": {"Authorization": "XITOOL_OWNER_AUTH"}},
            "other": {"origin": self.origin, "role": "other", "header_env": {"Authorization": "XITOOL_OTHER_AUTH"}}}})
        environment = patch.dict("os.environ", {"XITOOL_OWNER_AUTH": "Bearer OWNER_PRIVATE", "XITOOL_OTHER_AUTH": "Bearer OTHER_PRIVATE",
                                                "XITOOL_OWNER_PROOF": self.owner_canary, "XITOOL_OTHER_PROOF": self.other_canary})
        environment.start()
        self.addCleanup(environment.stop)

    def case(self, module="idor", path="/owned-vulnerable"):
        case = {"id": "owned-resource", "module": module, "url": self.origin + path, "operator_owned": True,
                "proof_env": "XITOOL_OWNER_PROOF", "owner_profile": "owner", "other_profile": "other",
                "other_reference_url": self.origin + "/other-reference", "other_proof_env": "XITOOL_OTHER_PROOF", "expected_other_access": False}
        save_json(self.project / "controlled_checks.json", {"version": 1, "checks": [case]})
        return case

    def run_case(self, module="idor", path="/owned-vulnerable"):
        self.case(module, path)
        planned = tasks(self.project, self.scope, module)
        engine = Engine(self.project, self.scope, self.config, module, target="127.0.0.1", tasks=planned)
        engine.execute()
        report = (engine.directory / "report.json").read_text(encoding="utf-8")
        for secret in ("OWNER_PRIVATE", "OTHER_PRIVATE", self.owner_canary, self.other_canary):
            self.assertNotIn(secret, report)
        self.assertEqual(load_state(engine.directory / "checkpoint.json")["domain"], "127.0.0.1")
        return engine

    def test_actual_idor_controlled_resource_read_is_verified(self):
        engine = self.run_case()
        self.assertEqual(engine.state["results"][0]["status"], "VERIFIED")
        self.assertTrue(engine.state["results"][0]["evidence"]["other_reference_valid"])

    def test_actual_role_control_is_verified(self):
        engine = self.run_case("access")
        self.assertEqual(engine.state["results"][0]["status"], "VERIFIED")

    def test_safe_resource_denies_other_valid_account(self):
        engine = self.run_case("access", "/owned-safe")
        self.assertEqual(engine.state["results"][0]["status"], "NO_ISSUES_OBSERVED")

    def test_http200_shell_without_canary_is_inconclusive(self):
        engine = self.run_case("idor", "/owned-plain200")
        self.assertEqual(engine.state["results"][0]["status"], "PARTIAL")

    def test_expired_other_session_cannot_produce_a_negative_or_verified_verdict(self):
        with patch.dict("os.environ", {"XITOOL_OTHER_AUTH": "Bearer EXPIRED"}):
            engine = self.run_case("access", "/owned-safe")
        self.assertEqual(engine.state["results"][0]["status"], "PARTIAL")

    def test_changed_case_or_out_of_scope_resource_never_runs(self):
        case = self.case()
        task = tasks(self.project, self.scope, "idor")[0]
        case["url"] = self.origin + "/owned-safe"
        save_json(self.project / "controlled_checks.json", {"version": 1, "checks": [case]})
        client = HTTPClient(self.scope, self.config)
        with patch.object(client, "get") as get, self.assertRaises(DataError):
            execute("idor", task, client, self.project)
        get.assert_not_called()
        case["url"] = "https://evil.org/"
        save_json(self.project / "controlled_checks.json", {"version": 1, "checks": [case]})
        with self.assertRaises(DataError):
            load_cases(self.project, self.scope, "idor")

    def test_network_error_is_failed_and_saved_without_finding(self):
        self.case("access")
        engine = Engine(self.project, self.scope, self.config, "access", target="127.0.0.1", tasks=tasks(self.project, self.scope, "access"))
        with patch("xitool.http.HTTPClient.get", side_effect=NetworkError("fixture")):
            engine.execute()
        self.assertEqual(engine.state["verification_outcome"], "FAILED")
        self.assertEqual(engine.state["results"], [])

    def test_controlled_check_interrupt_and_resume(self):
        self.case("access")
        engine = Engine(self.project, self.scope, self.config, "access", target="127.0.0.1", tasks=tasks(self.project, self.scope, "access"))
        with patch("xitool.execution.controlled_scan", side_effect=KeyboardInterrupt()):
            engine.execute()
        resumed = Engine(self.project, self.scope, self.config, "access", target="127.0.0.1", resume=engine.directory)
        resumed.execute()
        self.assertEqual(resumed.state["results"][0]["status"], "VERIFIED")

    def test_prepared_file_fixture_is_checked_without_generating_system_paths(self):
        case = {"id": "canary-file", "module": "traversal", "url": self.origin + "/xitool-lab/file?file=prepared-canary",
                "baseline_url": self.origin + "/xitool-lab/file?file=normal", "operator_owned": True, "fixture_only": True,
                "expected_probe_access": False, "proof_env": "XITOOL_OWNER_PROOF"}
        save_json(self.project / "controlled_checks.json", {"version": 1, "checks": [case]})
        engine = Engine(self.project, self.scope, self.config, "traversal", target="127.0.0.1", tasks=tasks(self.project, self.scope, "traversal"))
        engine.execute()
        result = engine.state["results"][0]
        self.assertEqual(result["status"], "VERIFIED")
        self.assertNotIn(self.owner_canary, json.dumps(result))
        case["url"] = self.origin + "/system-file"
        save_json(self.project / "controlled_checks.json", {"version": 1, "checks": [case]})
        with self.assertRaises(DataError):
            load_cases(self.project, self.scope, "traversal")

    def sql_case(self, path):
        case = {"id": "sqlite-read-only", "module": "sqli", "url": self.origin + path + "?id=1", "operator_owned": True,
                "fixture_only": True, "read_only_fixture": True, "proof_env": "XITOOL_OWNER_PROOF", "parameter": "id"}
        save_json(self.project / "controlled_checks.json", {"version": 1, "checks": [case]})
        engine = Engine(self.project, self.scope, self.config, "sqli", target="127.0.0.1", tasks=tasks(self.project, self.scope, "sqli"))
        engine.execute()
        return engine.state["results"][0]

    def test_actual_sqlite_boolean_differential_is_repeatable_but_not_automatically_verified(self):
        result = self.sql_case("/xitool-lab/sql-vulnerable")
        self.assertEqual(result["status"], "POTENTIAL")
        self.assertTrue(result["evidence"]["expected_canary_differential"])
        self.assertEqual(len(result["evidence"]["statuses"]), 6)

    def test_parameterized_sqlite_fixture_is_not_reported_as_sql_injection(self):
        result = self.sql_case("/xitool-lab/sql-safe")
        self.assertEqual(result["status"], "PARTIAL")
        self.assertFalse(result["evidence"]["expected_canary_differential"])

    def logout_case(self):
        case = {"id": "owned-logout", "module": "authentication", "url": self.origin + "/xitool-lab/protected",
                "operator_owned": True, "fixture_only": True, "proof_env": "XITOOL_OWNER_PROOF", "profile": "owner",
                "logout_url": self.origin + "/xitool-lab/end-session", "logout_confirmed": True}
        save_json(self.project / "controlled_checks.json", {"version": 1, "checks": [case]})
        engine = Engine(self.project, self.scope, self.config, "authentication", target="127.0.0.1", tasks=tasks(self.project, self.scope, "authentication"))
        engine.execute()
        return engine.state["results"][0]

    def test_actual_logout_invalidates_the_owned_lab_session(self):
        self.assertEqual(self.logout_case()["status"], "NO_ISSUES_OBSERVED")

    def test_ineffective_logout_is_verified_with_owned_canary(self):
        self.__class__.logout_effective = False
        self.assertEqual(self.logout_case()["status"], "VERIFIED")

    def test_invalid_initial_session_does_not_trigger_logout(self):
        before = len(self.requests)
        with patch.dict("os.environ", {"XITOOL_OWNER_AUTH": "Bearer INVALID"}):
            result = self.logout_case()
        self.assertEqual(result["status"], "PARTIAL")
        self.assertNotIn("/xitool-lab/end-session", [path for path, _ in self.requests[before:]])
