import copy
import json
import socket
import ssl
import threading
import unittest
import tempfile
from pathlib import Path
from unittest.mock import Mock, patch

from xitool.http import HTTPClient, Response, RateLimiter, NetworkError
from xitool.scope import Scope, ScopeViolation
from xitool.storage import DEFAULTS, DataError, save_json
from xitool.passive import collect
from xitool.errors import classify, status_category


class ASTTests(unittest.TestCase):
    def values(self, code):
        try:
            from xitool.javascript import analyze
            return analyze(code)
        except ImportError:
            self.skipTest("AST opzionale non installato")

    def test_const_concat_alias_and_static_template(self):
        rows = self.values('const base="/api";const f=fetch;const p=base+"/items";f(p);axios.get(`${base}/info`);')
        self.assertEqual({r["url"] for r in rows if "url" in r}, {"/api/items", "/api/info"})

    def test_xhr_and_axios_alias(self):
        rows = self.values('const x=new XMLHttpRequest();const get=axios.get;get("/a");x.open("GET","/b");')
        self.assertEqual({r["url"] for r in rows if "url" in r}, {"/a", "/b"})

    def test_shadowed_parameter_does_not_resolve_builtin(self):
        rows = self.values('function app(fetch){fetch("/invented");} fetch("/real");')
        self.assertEqual({r["url"] for r in rows if "url" in r}, {"/real"})
        self.assertTrue(any(r["quality"] == "UNRESOLVED" for r in rows))

    def test_mutable_and_unknown_values_unresolved(self):
        rows = self.values('let p="/a";p=dynamic;fetch(p);fetch(`/api/${unknown}`);')
        self.assertFalse(any("url" in r for r in rows))
        self.assertEqual(len(rows), 2)

    def test_comments_and_malformed_program(self):
        self.assertEqual(self.values('// fetch("/fake")'), [])
        self.assertEqual(self.values('fetch(')[0]["reason"], "PARSE_ERROR")

    def test_future_shadow_not_treated_as_global(self):
        rows = self.values('fetch("/fake");const fetch=custom;')
        self.assertFalse(any("url" in r for r in rows))

    def test_function_and_import_shadow_builtin_names(self):
        for code in ('function fetch(x){} fetch("/fake");', 'import fetch from "./custom"; fetch("/fake");'):
            self.assertFalse(any("url" in r for r in self.values(code)))

    def test_nested_program_reports_analysis_limit(self):
        rows = self.values("{" * 70 + 'fetch("/deep")' + "}" * 70)
        self.assertTrue(any(row.get("reason") == "ANALYSIS_LIMIT" for row in rows))


class ProviderStatesTests(unittest.TestCase):
    def collect(self, responses):
        config = copy.deepcopy(DEFAULTS)
        config["http"]["max_retries"] = 0
        with patch.object(HTTPClient, "_request", side_effect=responses):
            return collect("crtsh", "example.com", config, Mock())

    def test_success_empty_distinct_from_failure(self):
        row = self.collect([Response("https://crt.sh/", 200, {}, "[]")])
        self.assertEqual(row["status"], "SUCCESS_EMPTY")
        self.assertEqual(row["attempts"], 1)

    def test_success_duplicates_and_provenance(self):
        row = self.collect([Response("https://crt.sh/", 200, {}, '[{"name_value":"a.example.com\\na.example.com"}]')])
        self.assertEqual(row["status"], "SUCCESS")
        self.assertEqual(row["duplicates"], 1)
        self.assertEqual(row["pages_completed"], 1)

    def test_rate_limit_and_server_error(self):
        for status, expected in ((429, "RATE_LIMITED"), (500, "FAILED")):
            row = self.collect([Response("https://crt.sh/", status, {}, "")])
            self.assertEqual(row["status"], expected)

    def test_timeout_and_parse_error(self):
        timeout = TimeoutError("fixture")
        row = self.collect([timeout])
        self.assertEqual(row["status"], "TIMEOUT")
        row = self.collect([Response("https://crt.sh/", 200, {}, "bad json")])
        self.assertEqual(row["error_category"], "PARSE_ERROR")

    def test_disabled_provider_never_sends_request(self):
        config = copy.deepcopy(DEFAULTS)
        config["discovery"]["ct_providers"] = []
        with patch.object(HTTPClient, "_request") as request:
            row = collect("crtsh", "example.com", config, Mock())
        self.assertEqual(row["status"], "DISABLED")
        request.assert_not_called()


class ErrorAndBackoffTests(unittest.TestCase):
    def test_stalled_dns_threads_bounded_across_distinct_clients(self):
        release = threading.Event()
        clients = []
        config = copy.deepcopy(DEFAULTS)
        config["http"]["timeout_seconds"] = .02
        def stuck(*args, **kwargs):
            release.wait(2)
            return []
        gate = threading.BoundedSemaphore(2)
        try:
            with patch("xitool.http._DNS_SLOTS", gate), patch("xitool.http.socket.getaddrinfo", side_effect=stuck) as resolver:
                for _ in range(6):
                    client = HTTPClient(Scope(["example.com"], []), config)
                    clients.append(client)
                    with self.assertRaises(TimeoutError):
                        client._resolve("example.com", 443)
                self.assertEqual(resolver.call_count, 2)
                release.set()
                for client in clients:
                    if client._dns_thread:
                        client._dns_thread.join(2)
        finally:
            release.set()

    def test_failure_burst_reduces_once_but_keeps_cooldown(self):
        limiter = RateLimiter(20)
        with patch("xitool.http.time.monotonic", return_value=100):
            limiter.feedback()
            first = limiter.current
            for _ in range(4):
                limiter.feedback()
            self.assertEqual(limiter.current, first)
            self.assertGreaterEqual(limiter.next_at, 100.1)
        with patch("xitool.http.time.monotonic", return_value=101):
            limiter.feedback()
            self.assertLess(limiter.current, first)

    def test_retry_after_not_coalesced_or_shortened(self):
        limiter = RateLimiter(20)
        with patch("xitool.http.time.monotonic", return_value=100):
            limiter.feedback(429, "10")
            limiter.feedback()
            limiter.feedback()
            self.assertGreaterEqual(limiter.next_at, 110)

    def test_jitter_is_bounded_and_injectable(self):
        rng = Mock()
        rng.uniform.return_value = .2
        limiter = RateLimiter(2, jitter=.25, rng=rng)
        with patch("xitool.http.time.monotonic", return_value=100):
            limiter.feedback(503)
            self.assertEqual(limiter.next_at, 101.2)
        rng.uniform.assert_called_once_with(0, .25)

    def test_taxonomy_cause_status_and_cancel(self):
        for exc, expected in ((TimeoutError(), "NETWORK_TIMEOUT"), (socket.gaierror(), "DNS_ERROR"),
                              (ssl.SSLError(), "TLS_ERROR"), (ImportError(), "DEPENDENCY_MISSING"),
                              (ScopeViolation(), "SCOPE_DENIED"), (NetworkError("cancel", category="CANCELLED"), "CANCELLED")):
            self.assertEqual(classify(exc), expected)
        self.assertEqual(status_category(429), "HTTP_RATE_LIMIT")
        self.assertEqual(status_category(503), "HTTP_SERVER_ERROR")
        self.assertEqual(status_category(401), "AUTH_REQUIRED")
        self.assertIsNone(status_category(200))


class CallbackScopeTests(unittest.TestCase):
    def test_fixture_flag_cannot_enable_private_callback_for_public_target(self):
        from xitool.controlled import load_cases
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            case = {"id": "lab", "module": "ssrf", "url": "https://example.com/xitool-lab/check?url=old", "operator_owned": True,
                    "parameter": "url", "callback_base": "http://127.0.0.1:8080/xitool-callback/", "events_file": "events.jsonl",
                    "expected_source_ips": ["127.0.0.1"], "fixture_only": True}
            save_json(root / "controlled_checks.json", {"version": 1, "checks": [case]})
            with self.assertRaises(DataError), patch.object(HTTPClient, "get") as get:
                load_cases(root, Scope(["example.com", "127.0.0.1"], [], ["127.0.0.0/8"]), "ssrf")
            get.assert_not_called()

    def test_fixture_callback_also_requires_scope_ip_authorization(self):
        from xitool.controlled import load_cases
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            case = {"id": "lab", "module": "ssrf", "url": "http://127.0.0.1:8080/xitool-lab/check?url=old", "operator_owned": True,
                    "parameter": "url", "callback_base": "http://127.0.0.1:8080/xitool-callback/", "events_file": "events.jsonl",
                    "expected_source_ips": ["127.0.0.1"], "fixture_only": True}
            save_json(root / "controlled_checks.json", {"version": 1, "checks": [case]})
            with self.assertRaises(DataError):
                load_cases(root, Scope(["127.0.0.1"], []), "ssrf")
