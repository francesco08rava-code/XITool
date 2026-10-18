"""V4: trasporto HTTP reale, inventario e regressioni degli esiti."""
import copy
import gzip
import json
from pathlib import Path
import socket
import ssl
import tempfile
import threading
import unittest
import zlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import Mock, patch

from xitool.http import HTTPClient, NetworkError, Response, TLSVerificationError
from xitool.inventory import historical_references
from xitool.passive import collect
from xitool.recon_output import outputs
from xitool.scanners import discover, scan
from xitool.scope import Scope
from xitool.storage import DEFAULTS, DataError, Projects
from xitool.plans import SmartPlan
from xitool.controlled import execute, tasks, sql_fixture, load_cases
from xitool.storage import save_json
from xitool.storage import read_json
from xitool.dns import DNSResolver
import dns.resolver
import dns.message
import dns.rcode


class WireTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_HEAD(self):
                self.send_response(200)
                self.send_header("Content-Length", "9000")
                self.end_headers()

            def do_POST(self):
                body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
                self.send_response(307 if self.path == "/redirect" else 200)
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Location", "/destination")
                self.end_headers()
                self.wfile.write(body)

            def do_OPTIONS(self):
                allowed = self.path == "/preflight"
                self.send_response(204 if allowed else 403)
                if allowed:
                    self.send_header("Access-Control-Allow-Origin", self.headers.get("Origin", ""))
                    self.send_header("Access-Control-Allow-Methods", "GET")
                self.send_header("Content-Length", "0")
                self.end_headers()

            def do_GET(self):
                plain = b"hello transport" if self.path != "/bomb" else b"x" * 100000
                encoding = "gzip" if self.path in ("/gzip", "/bomb", "/bad", "/concat") else "deflate" if self.path == "/deflate" else "identity"
                data = gzip.compress(plain) if encoding == "gzip" else zlib.compress(plain) if encoding == "deflate" else plain
                if self.path == "/bad":
                    data = data[:-5]
                if self.path == "/concat":
                    data += gzip.compress(b"second")
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.send_header("Content-Encoding", encoding)
                if self.path in ("/chunked", "/ambiguous"):
                    self.send_header("Transfer-Encoding", "chunked")
                if self.path != "/chunked":
                    self.send_header("Content-Length", str(len(data) + (10 if self.path == "/short" else 0)))
                self.send_header("Connection", "close")
                self.end_headers()
                try:
                    if self.path in ("/chunked", "/ambiguous"):
                        self.wfile.write(f"{len(data):x}\r\n".encode() + data + b"\r\n0\r\n\r\n")
                    else:
                        self.wfile.write(data)
                except (OSError, ConnectionError):
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
        self.config = copy.deepcopy(DEFAULTS)
        self.config["http"].update(max_retries=0, requests_per_second=20, allowed_ports=[self.server.server_port], max_body_bytes=1024)
        self.client = HTTPClient(Scope(["127.0.0.1"], [], ["127.0.0.1/32"]), self.config)
        self.origin = f"http://127.0.0.1:{self.server.server_port}"

    def test_real_gzip(self):
        self.assertEqual(self.client.get(self.origin + "/gzip").body, "hello transport")

    def test_real_deflate(self):
        self.assertEqual(self.client.get(self.origin + "/deflate").body, "hello transport")

    def test_compression_bomb_is_bounded_and_truncated(self):
        result = self.client.get(self.origin + "/bomb")
        self.assertTrue(result.truncated)
        self.assertEqual(len(result.body), 1024)

    def test_incomplete_compressed_stream_is_rejected(self):
        with self.assertRaises(NetworkError):
            self.client.get(self.origin + "/bad")

    def test_concatenated_compression_is_rejected(self):
        with self.assertRaises(NetworkError):
            self.client.get(self.origin + "/concat")

    def test_chunked_response_is_decoded(self):
        self.assertEqual(self.client.get(self.origin + "/chunked").body, "hello transport")

    def test_ambiguous_framing_is_rejected(self):
        with self.assertRaises(NetworkError):
            self.client.get(self.origin + "/ambiguous")

    def test_short_content_length_is_not_a_successful_partial_body(self):
        with self.assertRaises(NetworkError):
            self.client.get(self.origin + "/short")

    def test_head_does_not_wait_for_or_cache_a_body(self):
        result = self.client.head(self.origin + "/head")
        self.assertEqual(result.body, "")
        self.assertEqual(self.client.method, "GET")
        self.assertFalse(self.client.cache)

    def test_request_ids_are_unique_and_not_body_values(self):
        first = self.client.get(self.origin + "/one", cache=False)
        second = self.client.get(self.origin + "/two", cache=False)
        self.assertNotEqual(first.request_id, second.request_id)
        self.assertEqual(len(first.request_id), 32)

    def test_post_requires_exact_authorization_before_transport(self):
        with patch.object(self.client, "_request") as request, self.assertRaises(DataError):
            self.client.post(self.origin + "/post", b"{}", "application/json", authorized_urls=())
        request.assert_not_called()

    def test_explicit_post_echo_has_no_cache_or_method_leak(self):
        url = self.origin + "/post"
        self.assertEqual(self.client.post(url, b'{"fixture":true}', "application/json", authorized_urls=(url,)).body, '{"fixture":true}')
        self.assertEqual(self.client.method, "GET")
        self.assertFalse(self.client.cache)

    def test_post_redirect_is_not_replayed(self):
        url = self.origin + "/redirect"
        with self.assertRaises(NetworkError):
            self.client.post(url, b"{}", "application/json", authorized_urls=(url,))
        self.assertEqual(self.client.stats["requests"], 1)

    def test_post_error_is_never_retried(self):
        self.config["http"]["max_retries"] = 3
        url = self.origin + "/post"
        with patch.object(HTTPClient, "_request", side_effect=TimeoutError()) as request, self.assertRaises(NetworkError):
            self.client.post(url, b"{}", "application/json", authorized_urls=(url,))
        self.assertEqual(request.call_count, 1)

    def test_tls_verification_failure_is_identifiable_and_not_retried(self):
        with patch.object(self.client, "_request", side_effect=ssl.SSLCertVerificationError("private details")) as request, self.assertRaises(TLSVerificationError) as error:
            self.client.get(self.origin + "/tls", cache=False)
        self.assertNotIn("private details", str(error.exception))
        self.assertEqual(request.call_count, 1)

    def test_real_preflight_allowed(self):
        result = self.client.preflight(self.origin + "/preflight", "https://fixture.invalid")
        self.assertEqual(result.status, 204)
        self.assertEqual(result.headers["access-control-allow-origin"], "https://fixture.invalid")

    def test_real_preflight_denied(self):
        self.assertEqual(self.client.preflight(self.origin + "/denied-preflight", "https://fixture.invalid").status, 403)


class InventoryTests(unittest.TestCase):
    def setUp(self):
        self.scope = Scope(["example.com"], [])
        self.client = HTTPClient(self.scope, copy.deepcopy(DEFAULTS))

    def discover(self, body, content="application/javascript", url="https://example.com/js/app.js"):
        return discover(self.scope, Response(url, 200, {"content-type": content}, body), True)

    def test_js_fetch_relative_xhr_and_generic_strings(self):
        _, links, refs = self.discover('fetch("../api?q=x"); xhr.open("GET", "/users"); const wallpaper="/not-an-endpoint";')
        self.assertEqual(links, ["https://example.com/api?q=x", "https://example.com/users"])
        self.assertTrue(all(row["kind"] == "STATIC_HYPOTHESIS" for row in refs))

    def test_js_comments_and_dynamic_templates_are_not_queued(self):
        self.assertEqual(self.discover('// fetch("/comment")\nfetch(`/api/${id}`); /*fetch("/comment2")*/')[1], [])

    def test_canonical_is_identified(self):
        self.assertEqual(self.discover('<link rel="canonical" href="/canonical">', "text/html")[2][0]["kind"], "OBSERVED_CANONICAL")

    def test_openapi_is_inventory_without_sending_operations(self):
        body = json.dumps({"openapi": "3.1.0", "paths": {"/items": {"post": {}}, "/items/{id}": {"get": {}}}})
        _, links, refs = self.discover(body, "application/json")
        self.assertFalse(links)
        self.assertEqual(refs[0]["source"], "openapi_document")

    def test_observed_graphql_does_not_trigger_queries(self):
        _, links, refs = self.discover('{"data":{"__schema":{}}}', "application/json", "https://example.com/graphql")
        self.assertFalse(links)
        self.assertEqual(refs[0]["source"], "graphql_schema_observed")

    def test_historical_export_stays_unreached_and_deduplicated(self):
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory)
            (project / "historical_urls.txt").write_text("https://example.com/gone\nhttps://example.com/gone\nhttps://foreign.test/a\nhttps://example.com/?token=secret", encoding="utf-8")
            refs = historical_references(project, self.scope, "example.com")
        self.assertEqual(len(refs), 1)
        self.assertEqual(refs[0]["kind"], "HISTORICAL")
        self.assertFalse(refs[0]["reached"])

    def test_sensitive_duplicates_are_not_distinct_exposures(self):
        token = "AKIA0123456789ABCDEF"
        with patch.object(self.client, "get", return_value=Response("https://example.com/", 200, {}, token + " " + token)):
            result = scan("sensitive", {"url": "https://example.com/"}, self.client)[0]
        self.assertEqual(result["evidence"]["pattern_counts"]["aws_access_key_shape"], 1)
        self.assertNotIn(token, json.dumps(result))

    def test_entropy_alone_is_not_a_secret(self):
        with patch.object(self.client, "get", return_value=Response("https://example.com/", 200, {}, "nZ02pRk6vCbUf7xeW9jDo4Ys")):
            result = scan("sensitive", {"url": "https://example.com/"}, self.client)[0]
        self.assertEqual(result["verification_outcome"], "NO_ISSUES_OBSERVED")

    def test_truncated_xss_is_not_potential(self):
        def response(url, **kwargs):
            from urllib.parse import parse_qs, urlsplit
            body = parse_qs(urlsplit(url).query).get("q", [""])[0]
            return Response(url, 200, {"content-type": "text/html"}, body, truncated=True)
        with patch.object(self.client, "get", side_effect=response):
            result = scan("xss", {"url": "https://example.com/?q=hello", "parameter": "q", "source": "query", "method": "GET"}, self.client)[0]
        self.assertNotEqual(result["status"], "POTENTIAL")
        self.assertTrue(result["evidence"]["body_truncated"])

    def test_hsts_disabled_and_downgrade_are_observations(self):
        response = Response("http://example.com/", 200, {"strict-transport-security": "max-age=0"}, "", redirects=[{"url": "https://example.com/", "destination": "http://example.com/", "status": 302}])
        with patch.object(self.client, "get", return_value=response):
            result = scan("misconfiguration", {"url": "https://example.com/"}, self.client)[0]
        self.assertTrue(result["evidence"]["hsts_disabled"])
        self.assertTrue(result["evidence"]["https_downgrade_observed"])
        self.assertEqual(result["severity"], "UNKNOWN")

    def test_smart_unavailable_module_does_not_mutate_or_save(self):
        with tempfile.TemporaryDirectory() as directory:
            project = Projects(Path(directory)).create("Plan", ["example.com"], [])
            plan = SmartPlan(project, self.scope, copy.deepcopy(DEFAULTS), ["example.com"])
            with self.assertRaises(DataError):
                plan.add([{"domain": "example.com", "module": "unavailable", "tasks": [{"url": "https://example.com/"}]}])
            self.assertEqual(plan.state["steps"], [])
            self.assertFalse(plan.path.exists())

    def test_smart_aggregate_deduplicates_findings_within_domain(self):
        with tempfile.TemporaryDirectory() as directory:
            project = Projects(Path(directory)).create("Plan", ["example.com"], [])
            plan = SmartPlan(project, self.scope, copy.deepcopy(DEFAULTS), ["example.com"])
            plan.add([{"domain": "example.com", "module": "sensitive", "tasks": [{"url": "https://example.com/"}]}])
            plan.state["steps"][0]["run"] = "run-fixture"
            row = {"id": "repeat", "url": "https://example.com/", "status": "OBSERVED"}
            save_json(project / "run-fixture" / "report.json", {"project": "Plan", "domain": "example.com", "module": "sensitive", "findings": [row, row]})
            plan.save()
            report = read_json(plan.path.with_suffix(".report.json"))
            self.assertEqual(report["unique_findings"], 1)

    def test_smart_rejects_checkpoint_from_a_different_domain(self):
        with tempfile.TemporaryDirectory() as directory:
            project = Projects(Path(directory)).create("Plan", ["example.com", "second.test"], [])
            scope = Scope(["example.com", "second.test"], [])
            config = copy.deepcopy(DEFAULTS)
            plan = SmartPlan(project, scope, config, scope.roots())
            from xitool.storage import fingerprint
            wrong = {"project": "Plan", "domain": "second.test", "module": "sensitive", "scope_hash": scope.for_target("second.test").digest, "config_hash": fingerprint(config)}
            with self.assertRaises(DataError):
                plan.validate_run({"domain": "example.com", "module": "sensitive"}, wrong)

    def test_provider_raw_unique_and_seed_counts(self):
        response = Response("https://crt.sh/", 200, {}, '[{"name_value":"example.com\\na.example.com\\na.example.com\\n*.example.com"}]')
        with patch.object(HTTPClient, "_request", return_value=response):
            result = collect("crtsh", "example.com", copy.deepcopy(DEFAULTS), Mock())
        self.assertEqual((result["raw_results"], result["unique_results"], result["seed_excluded"]), (4, 2, 1))

    def test_host_states_do_not_confuse_discovery_with_reachability(self):
        state = {"domain": "example.com", "hosts": [], "live_hosts": ["a.example.com"], "inputs": [], "endpoints": [],
                 "host_observations": {"example.com": {}, "a.example.com": {}, "b.example.com": {}},
                 "dns_records": {"a.example.com": {"resolved": True}, "b.example.com": {"resolved": False}}}
        _, detail = outputs(state, Scope(["example.com", "*.example.com"], []))
        self.assertEqual(detail["host_observations.json"]["a.example.com"]["states"], ["DISCOVERED", "DNS_RESOLVED", "HTTP_REACHABLE"])
        self.assertIn("DNS_FAILED", detail["host_observations.json"]["b.example.com"]["states"])
        self.assertEqual(detail["summary.json"]["seed_excluded"], 1)

    def test_failed_provider_does_not_mean_the_seed_http_is_unreachable(self):
        state = {"domain": "example.com", "hosts": ["example.com"], "live_hosts": [], "inputs": [], "endpoints": [],
                 "host_observations": {"example.com": {}}, "errors": [{"url": "https://example.com/", "provider": "crtsh", "type": "NetworkError"}]}
        _, detail = outputs(state, self.scope)
        self.assertNotIn("HTTP_UNREACHABLE", detail["host_observations.json"]["example.com"]["states"])


class DNSEdgeTests(unittest.TestCase):
    def resolve(self, failure):
        resolver = DNSResolver(Scope(["example.com"], []), .1, Mock())
        with patch("dns.resolver.Resolver") as factory:
            factory.return_value.resolve.side_effect = failure
            return resolver.resolve("example.com")

    def test_nxdomain_is_domain_absence(self):
        self.assertEqual(self.resolve(dns.resolver.NXDOMAIN())["resolution_status"], "NOT_FOUND")

    def test_no_nameservers_is_not_domain_absence(self):
        self.assertEqual(self.resolve(dns.resolver.NoNameservers())["resolution_status"], "RESOLVER_ERROR")

    def test_socket_error_is_not_domain_absence(self):
        self.assertEqual(self.resolve(OSError("network"))["resolution_status"], "RESOLVER_ERROR")

    def test_timeout_is_explicit(self):
        self.assertIn("A:LifetimeTimeout", self.resolve(dns.resolver.LifetimeTimeout(timeout=.1, errors=[]))["errors"])

    def test_servfail_requires_a_real_dns_response_code(self):
        query = dns.message.make_query("example.com", "A")
        response = dns.message.make_response(query)
        response.set_rcode(dns.rcode.SERVFAIL)
        error = dns.resolver.NoNameservers(request=query, errors=[("resolver", False, 53, "SERVFAIL", response)])
        result = self.resolve(error)
        self.assertIn("A:SERVFAIL", result["errors"])
        self.assertNotIn("NXDOMAIN", result["errors"])


class CallbackEdgeTests(unittest.TestCase):
    def verify(self, wrong=False):
        from datetime import datetime, timezone
        from xitool.callback_checks import verify
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory)
            events = project / "events.jsonl"
            events.write_text("", encoding="utf-8")
            case = {"url": "https://example.com/?url=initial", "parameter": "url", "callback_base": "https://callback.operator.test/xitool-callback/",
                    "events_file": "events.jsonl", "expected_source_ips": ["8.8.8.8"]}
            client = HTTPClient(Scope(["example.com"], []), copy.deepcopy(DEFAULTS))
            client.limiter.wait = Mock()
            def request(url, **kwargs):
                row = {"id": "b" * 32 if wrong else "a" * 32, "received_at": datetime.now(timezone.utc).isoformat(), "source_ip": "8.8.8.8"}
                events.write_text((json.dumps(row) + "\n") * 2, encoding="utf-8")
                return Response(url, 200, {}, "accepted")
            public = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 443))]
            with patch("xitool.callback_checks.uuid.uuid4", return_value=Mock(hex="a" * 32)), patch.object(HTTPClient, "_resolve", return_value=public), patch.object(client, "get", side_effect=request), patch("xitool.callback_checks.time", Mock(monotonic=Mock(side_effect=[0, 4]))):
                return verify(case, client, project)[0]

    def test_duplicate_callback_is_a_single_unique_event(self):
        result = self.verify()
        self.assertEqual(result["status"], "VERIFIED")
        self.assertEqual(result["evidence"]["unique_matching_events"], 1)

    def test_wrong_callback_nonce_cannot_verify(self):
        self.assertEqual(self.verify(wrong=True)["status"], "PARTIAL")


class ControlledEdgeTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.project = Projects(Path(directory.name)).create("Edges", ["127.0.0.1"], [])
        self.scope = Scope(["127.0.0.1"], [], ["127.0.0.1/32"])
        self.client = HTTPClient(self.scope, copy.deepcopy(DEFAULTS))
        self.proof = "LAB_CANARY_0123456789"
        environment = patch.dict("os.environ", {"EDGE_PROOF": self.proof, "EDGE_OTHER_PROOF": "OTHER_CANARY_0123456789", "EDGE_OWNER": "Bearer owner", "EDGE_OTHER": "Bearer other"})
        environment.start()
        self.addCleanup(environment.stop)
        save_json(self.project / "session_profiles.json", {"version": 1, "profiles": {
            name: {"origin": "http://127.0.0.1/", "role": name, "header_env": {"Authorization": "EDGE_" + name.upper()}} for name in ("owner", "other")}})

    def authorization(self, module, mode):
        case = {"id": "roles", "module": module, "url": "http://127.0.0.1/owned", "operator_owned": True,
                "proof_env": "EDGE_PROOF", "owner_profile": "owner", "other_profile": "other", "other_reference_url": "http://127.0.0.1/reference",
                "other_proof_env": "EDGE_OTHER_PROOF", "expected_other_access": False}
        save_json(self.project / "controlled_checks.json", {"version": 1, "checks": [case]})
        reference_calls = []
        def response(client, url, **kwargs):
            if url.endswith("reference"):
                reference_calls.append(url)
                return Response(url, 401 if mode == "expires_mid_test" and len(reference_calls) == 2 else 200, {}, "OTHER_CANARY_0123456789")
            if client.profile.name == "owner":
                return Response(url, 200, {}, self.proof)
            status, body = {"denied": (403, "denied"), "missing": (404, "missing"), "login": (200, "<form>login</form>"), "expires_mid_test": (401, "login")}[mode]
            return Response(url, status, {}, body)
        with patch.object(HTTPClient, "get", response):
            return execute(module, tasks(self.project, self.scope, module)[0], self.client, self.project)[0]

    def test_idor_missing_resource_is_inconclusive(self):
        self.assertEqual(self.authorization("idor", "missing")["status"], "PARTIAL")

    def test_access_login_html_200_is_not_a_violation(self):
        self.assertEqual(self.authorization("access", "login")["status"], "PARTIAL")

    def test_idor_denied_with_two_valid_session_references(self):
        self.assertEqual(self.authorization("idor", "denied")["status"], "NO_ISSUES_OBSERVED")

    def test_session_expiring_during_access_comparison_is_not_clean(self):
        self.assertEqual(self.authorization("access", "expires_mid_test")["status"], "PARTIAL")

    def test_traversal_unstable_baseline_cannot_verify_canary_read(self):
        case = {"id": "files", "module": "traversal", "url": "http://127.0.0.1/xitool-lab/files?file=canary", "baseline_url": "http://127.0.0.1/xitool-lab/files?file=normal",
                "operator_owned": True, "fixture_only": True, "expected_probe_access": False, "proof_env": "EDGE_PROOF"}
        save_json(self.project / "controlled_checks.json", {"version": 1, "checks": [case]})
        rows = [Response(case["baseline_url"], 200, {}, text) for text in ("normal1", "normal2", self.proof, self.proof)]
        with patch.object(self.client, "get", side_effect=rows):
            result = execute("traversal", tasks(self.project, self.scope, "traversal")[0], self.client, self.project)[0]
        self.assertEqual(result["status"], "PARTIAL")
        self.assertFalse(result["evidence"]["baseline_stable"])

    def test_sql_unstable_baseline_is_not_potential(self):
        case = {"url": "http://127.0.0.1/xitool-lab/sql?id=1", "id": "sql", "parameter": "id"}
        bodies = [self.proof, self.proof + "dynamic", self.proof, self.proof, "empty", "empty"]
        with patch.object(self.client, "get", side_effect=[Response(case["url"], 200, {}, body) for body in bodies]):
            result = sql_fixture(case, self.client, self.proof)[0]
        self.assertEqual(result["status"], "PARTIAL")

    def test_sql_denied_responses_are_not_negative_or_potential(self):
        case = {"url": "http://127.0.0.1/xitool-lab/sql?id=1", "id": "sql", "parameter": "id"}
        with patch.object(self.client, "get", return_value=Response(case["url"], 403, {}, "denied")):
            self.assertEqual(sql_fixture(case, self.client, self.proof)[0]["status"], "PARTIAL")

    def test_xss_post_without_explicit_authorization_is_rejected(self):
        case = {"id": "xss-post", "module": "xss", "url": "http://127.0.0.1/xitool-lab/xss", "operator_owned": True,
                "parameter": "q", "fixture_only": True, "request": {"method": "POST", "fields": {"q": "baseline"}, "content_type": "application/json", "authorized": False}}
        save_json(self.project / "controlled_checks.json", {"version": 1, "checks": [case]})
        with self.assertRaises(DataError):
            load_cases(self.project, self.scope, "xss")
