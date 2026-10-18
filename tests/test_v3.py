"""V3: provider HTTP controllati, DNS simulato e regressioni senza target pubblici."""
import copy
import io
import json
from pathlib import Path
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import Mock, patch
from urllib.parse import parse_qs, urlsplit

import dns.exception
import dns.resolver

from xitool.cli import seeds, execute_smart, edit_rules
from xitool.dns import DNSResolver
from xitool.execution import Engine, build_tasks, load_state
from xitool.http import HTTPClient, NetworkError, Response
from xitool.passive import collect, passive_tasks
from xitool.recon_output import outputs
from xitool.scanners import discover, finding, scan, smart_reasons
from xitool.scope import Scope, ScopeViolation, parse_rules
from xitool.storage import DEFAULTS, DataError, Projects, read_json


def config():
    result = copy.deepcopy(DEFAULTS)
    result["http"].update(max_retries=0, requests_per_second=20)
    return result


class PassiveTests(unittest.TestCase):
    def collect(self, provider, responses):
        limiter = Mock()
        with patch.object(HTTPClient, "_request", side_effect=responses) as transport:
            result = collect(provider, "example.com", config(), limiter)
        return result, transport

    def test_crtsh_adapter_normalizes_deduplicates_and_excludes_unrelated_sans(self):
        data = [{"name_value": "EXAMPLE.COM\na.example.com\na.example.com\n*.example.com\nevil.org\nb..example.com"}]
        result, transport = self.collect("crtsh", [Response("https://crt.sh/", 200, {}, json.dumps(data))])
        self.assertEqual(result["hosts"], ["a.example.com", "example.com"])
        self.assertEqual(result["wildcard_certificates"], ["*.example.com"])
        self.assertTrue(result["complete"])
        self.assertEqual(parse_qs(urlsplit(transport.call_args.args[0]).query)["q"], ["%.example.com"])

    def test_certspotter_pagination_and_provenance(self):
        result, transport = self.collect("certspotter", [
            Response("https://api.certspotter.com/", 200, {}, '[{"id":"123","dns_names":["a.example.com"]}]'),
            Response("https://api.certspotter.com/", 200, {}, '[]')])
        self.assertEqual(result["hosts"], ["a.example.com"])
        self.assertEqual(result["provider"], "certspotter")
        self.assertEqual(parse_qs(urlsplit(transport.call_args.args[0]).query)["after"], ["123"])
        self.assertEqual(result["requests"], 2)

    def test_provider_failure_retains_previous_page(self):
        result, _ = self.collect("certspotter", [
            Response("https://api.certspotter.com/", 200, {}, '[{"id":"123","dns_names":["a.example.com"]}]'),
            NetworkError("fixture")])
        self.assertEqual(result["hosts"], ["a.example.com"])
        self.assertTrue(result["errors"])
        self.assertFalse(result["complete"])

    def test_unavailable_invalid_and_truncated_providers(self):
        for response in (Response("https://crt.sh/", 429, {}, ""), Response("https://crt.sh/", 200, {}, "not json"),
                         Response("https://crt.sh/", 200, {}, "{}"), Response("https://crt.sh/", 200, {}, "[]", True)):
            with self.subTest(response=response):
                result, _ = self.collect("crtsh", [response])
                self.assertTrue(result["errors"])
                self.assertEqual(result["hosts"], [])

    def test_missing_schema_fields_are_errors_not_successful_empty_results(self):
        for provider in ("crtsh", "certspotter"):
            result, _ = self.collect(provider, [Response("https://fixture.invalid/", 200, {}, '[{"unexpected":true}]')])
            self.assertTrue(result["errors"])
            self.assertFalse(result["complete"])

    def test_certificate_wildcard_never_becomes_a_concrete_host(self):
        result, _ = self.collect("crtsh", [Response("https://crt.sh/", 200, {}, '[{"name_value":"*.example.com"}]')])
        self.assertEqual(result["hosts"], [])

    def test_provider_redirect_cannot_contact_another_host(self):
        result, transport = self.collect("crtsh", [Response("https://crt.sh/", 302, {"location": "https://evil.org/"}, "")])
        self.assertTrue(result["errors"])
        self.assertEqual(transport.call_count, 1)

    def test_invalid_provider_and_ip_seeds(self):
        self.assertEqual(passive_tasks("127.0.0.1"), [])
        self.assertEqual(len(passive_tasks("my.example.com")), 2)
        with self.assertRaises(DataError):
            collect("arbitrary", "example.com", config(), Mock())


class DNSTests(unittest.TestCase):
    def setUp(self):
        self.resolver = DNSResolver(Scope(["example.com", "*.example.com"], []), 1, Mock())

    @staticmethod
    def answer(value, ttl=5):
        class Answer(list):
            rrset = Mock(ttl=ttl)
        return Answer([Mock(to_text=Mock(return_value=value))])

    def test_a_aaaa_cname_and_cache_ttl(self):
        answers = [self.answer("8.8.8.8"), self.answer("2001:4860:4860::8888"), self.answer("edge.example.com.")]
        with patch("dns.resolver.Resolver.resolve", side_effect=answers * 2) as resolve, patch("xitool.dns.time.monotonic", return_value=100):
            first = self.resolver.resolve("example.com")
            self.resolver.resolve("example.com")
            self.assertEqual(resolve.call_count, 3)
            self.assertEqual(first["CNAME"], ["edge.example.com"])
        with patch("dns.resolver.Resolver.resolve", side_effect=answers) as resolve, patch("xitool.dns.time.monotonic", return_value=106):
            self.resolver.resolve("example.com")
            self.assertEqual(resolve.call_count, 3)

    def test_nxdomain_timeout_and_noanswer(self):
        for error, count in ((dns.resolver.NXDOMAIN(), 1), (dns.exception.Timeout(), 3), (dns.resolver.NoAnswer(), 3)):
            with patch("dns.resolver.Resolver.resolve", side_effect=error) as resolve:
                result = self.resolver.resolve("example.com")
                self.assertFalse(result["resolved"])
                self.assertEqual(resolve.call_count, count)

    def test_out_of_scope_is_not_resolved(self):
        with patch("dns.resolver.Resolver.resolve") as resolve, self.assertRaises(DataError):
            self.resolver.resolve("evil.org")
        resolve.assert_not_called()

    def test_wildcard_samples_require_authorization(self):
        exact = DNSResolver(Scope(["example.com"], []), 1, Mock())
        with patch.object(exact, "resolve") as resolve:
            self.assertFalse(exact.wildcard("example.com")["tested"])
            resolve.assert_not_called()

    def test_wildcard_evidence_is_not_a_verified_finding(self):
        with patch.object(self.resolver, "resolve", return_value={"A": ["8.8.8.8"], "AAAA": []}):
            result = self.resolver.wildcard("example.com")
        self.assertTrue(result["possible_wildcard"])
        self.assertNotIn("VERIFIED", json.dumps(result))


class ScopePathTests(unittest.TestCase):
    def test_sensitive_or_mutative_redirect_is_blocked_before_second_request(self):
        for destination in ("/logout", "/?token=NEVER_PERSIST"):
            client = HTTPClient(Scope(["example.com"], []), config())
            client.limiter.wait = Mock()
            with patch.object(client, "_request", return_value=Response("https://example.com/", 302, {"location": destination}, "")) as transport:
                with self.assertRaises(ScopeViolation):
                    client.get("https://example.com/")
            self.assertEqual(transport.call_count, 1)

    def test_path_and_origin_are_enforced_after_target_binding(self):
        scope = Scope(["https://example.com/webtrading/"], []).for_target("example.com")
        for url in ("https://example.com/webtrading/", "https://example.com/webtrading/page?q=ok"):
            self.assertEqual(scope.url(url), url)
        for url in ("https://example.com/", "https://example.com/webtrading-other", "http://example.com/webtrading/",
                    "https://example.com/webtrading/../admin", "https://example.com/webtrading/%2e%2e/admin",
                    "https://example.com/webtrading//admin", "https://example.com:8080/webtrading/"):
            with self.subTest(url=url), self.assertRaises(ScopeViolation):
                scope.url(url)

    def test_parser_preserves_paths_and_rejects_ambiguous_query_rule(self):
        self.assertEqual(parse_rules("https://EXAMPLE.com/app/")["rules"], ["https://example.com/app/"])
        self.assertTrue(parse_rules("https://example.com/app?token=secret")["invalid"])

    def test_project_roundtrip_preserves_restrictions(self):
        with tempfile.TemporaryDirectory() as directory:
            projects = Projects(Path(directory))
            projects.create("Lab", ["https://example.com/app"], [])
            scope = projects.load("Lab")[1]
            with self.assertRaises(ScopeViolation):
                scope.url("https://example.com/admin")

    def test_blocked_request_is_logged_before_transport(self):
        client = HTTPClient(Scope(["https://example.com/app"], []), config())
        with patch.object(client, "_request") as transport, self.assertLogs("xitool", level="WARNING") as logs:
            with self.assertRaises(ScopeViolation):
                client.get("https://example.com/admin")
        transport.assert_not_called()
        self.assertEqual(client.stats["scope_blocked"], 1)
        self.assertIn("scope_blocked", logs.output[0])


class DiscoveryV3Tests(unittest.TestCase):
    def setUp(self):
        self.scope = Scope(["example.com"], [])

    def test_direct_paste_at_domain_menu_is_consumed_as_one_batch(self):
        with patch("builtins.input", side_effect=["https://example.com/CaseSensitive/", "api.example.com", "", "0"]), patch("sys.stdout", new_callable=io.StringIO):
            rules = edit_rules("DOMINI", required=True)
        self.assertEqual(rules, ["https://example.com/CaseSensitive/", "api.example.com"])

    def test_sitemap_scope_and_external_entities(self):
        xml = '<urlset><url><loc>https://example.com/search?q=a</loc></url><url><loc>https://evil.org/</loc></url></urlset>'
        inputs, links = discover(self.scope, Response("https://example.com/sitemap.xml", 200, {"content-type": "application/xml"}, xml))
        self.assertEqual(links, ["https://example.com/search?q=a"])
        self.assertEqual(inputs[0]["location"], "query")
        self.assertEqual(discover(self.scope, Response("https://example.com/sitemap.xml", 200, {"content-type": "text/xml"}, '<!DOCTYPE x [<!ENTITY a SYSTEM "file:///etc/passwd">]><x>&a;</x>'))[1], [])

    def test_robots_is_informational_and_still_scoped(self):
        _, links = discover(self.scope, Response("https://example.com/robots.txt", 200, {"content-type": "text/plain"},
                                                'Disallow: /admin\nSitemap: https://evil.org/map.xml\nAllow: /public\nDisallow: /*?'))
        self.assertEqual(links, ["https://example.com/admin", "https://example.com/public"])

    def test_json_response_fields_are_not_automatically_request_inputs(self):
        inputs, _ = discover(self.scope, Response("https://example.com/api", 200, {"content-type": "application/json"}, '{"user":{"id":3},"token":"NEVER_STORE"}'))
        self.assertTrue(inputs)
        self.assertTrue(all(entry["location"] == "response_json" for entry in inputs))
        self.assertNotIn("NEVER_STORE", json.dumps(inputs))
        self.assertEqual(build_tasks("xss", self.scope, inputs, []), [])
        self.assertEqual(build_tasks("idor", self.scope, inputs, []), [])

    def test_rest_path_identifier_and_smart_reasons(self):
        inputs, _ = discover(self.scope, Response("https://example.com/users/123", 200, {}, ""))
        self.assertEqual(inputs[0]["input_type"], "identifier")
        self.assertEqual(inputs[0]["location"], "path")
        self.assertIn("reason", smart_reasons(inputs, ["https://example.com/users/123"])["idor"])


class ScannerV3Tests(unittest.TestCase):
    def setUp(self):
        self.client = HTTPClient(Scope(["example.com"], []), config())

    def test_sqli_repeats_observed_error_without_modifying_input(self):
        url = "https://example.com/?q=test"
        with patch.object(self.client, "get", return_value=Response(url, 500, {}, "sqlite3.OperationalError: fixture")) as get:
            result = scan("sqli", {"url": url}, self.client)[0]
        self.assertEqual(result["status"], "MANUAL_REVIEW")
        self.assertFalse(result["evidence"]["input_modified"])
        self.assertEqual([call.args[0] for call in get.call_args_list], [url, url])
        self.assertNotIn("VERIFIED", json.dumps(result))

    def test_sqli_unstable_error_and_plain_200_are_not_findings(self):
        url = "https://example.com/"
        with patch.object(self.client, "get", side_effect=[Response(url, 500, {}, "ORA-12345"), Response(url, 200, {}, "normal")]):
            self.assertEqual(scan("sqli", {"url": url}, self.client)[0]["status"], "OBSERVED")
        with patch.object(self.client, "get", return_value=Response(url, 200, {}, "normal")) as get:
            self.assertEqual(scan("sqli", {"url": url}, self.client)[0]["evidence"]["error_families"], [])
            self.assertEqual(get.call_count, 2)

    def test_unstable_xss_is_not_potential(self):
        count = [0]
        def reply(url, **kwargs):
            count[0] += 1
            value = parse_qs(urlsplit(url).query)["q"][0] if count[0] == 2 else "normal"
            return Response(url, 200, {"content-type": "text/html"}, value)
        with patch.object(self.client, "get", side_effect=reply):
            result = scan("xss", {"url": "https://example.com/?q=test", "parameter": "q", "method": "GET", "source": "query"}, self.client)[0]
        self.assertEqual(result["status"], "OBSERVED")
        self.assertFalse(result["evidence"]["stable_unescaped_reflection"])

    def test_cors_requires_repeat_and_records_vary(self):
        def reply(url, headers=None, **kwargs):
            response_headers = {"vary": "Accept, Origin"}
            if headers:
                response_headers.update({"access-control-allow-origin": headers["Origin"], "access-control-allow-credentials": "true"})
            return Response(url, 200, response_headers, "")
        with patch.object(self.client, "get", side_effect=reply):
            result = scan("cors", {"url": "https://example.com/"}, self.client)[0]
        self.assertEqual(result["status"], "POTENTIAL")
        self.assertTrue(result["evidence"]["vary_origin"])

    def test_cookie_policy_is_recorded_without_session_values(self):
        with patch.object(self.client, "get", return_value=Response("https://example.com/", 200,
                 {"set-cookie": "session=SECRET; SameSite=None; Max-Age=3600", "cache-control": "no-store"}, "")):
            result = scan("authentication", {"url": "https://example.com/"}, self.client)[0]
        self.assertTrue(result["evidence"]["cookies"][0]["samesite_none_without_secure"])
        self.assertEqual(result["evidence"]["cookies"][0]["max_age_seconds"], 3600)
        self.assertNotIn("SECRET", json.dumps(result))

    def test_schema_contains_verification_confidence_and_unknown_severity(self):
        result = finding("cors", "https://example.com/", "fixture", "OBSERVED", {}, "fixture")
        self.assertTrue({"verification_method", "confidence", "severity"} <= result.keys())
        self.assertEqual(result["severity"], "UNKNOWN")

    def test_high_entropy_candidate_and_configuration_reference_are_minimized(self):
        secret = "AbCDefGH0123456789_qWeRtYuiOpASDF"
        body = 'api_key="' + secret + '"; config="/.env"'
        with patch.object(self.client, "get", return_value=Response("https://example.com/", 200, {}, body)):
            result = scan("sensitive", {"url": "https://example.com/"}, self.client)[0]
        self.assertEqual(result["evidence"]["pattern_counts"]["high_entropy_assignment"], 1)
        self.assertTrue(result["evidence"]["configuration_reference_hint"])
        self.assertNotIn(secret, json.dumps(result))


class ReconEngineTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.projects = Projects(Path(temporary.name))
        self.project = self.projects.create("Lab", ["example.com"], [])
        self.scope = self.projects.load("Lab")[1]

    @staticmethod
    def source(provider, root, config, limiter):
        return {"provider": provider, "root": root, "hosts": ["example.com", "outside.example.com"],
                "errors": [], "requests": 1, "complete": True, "queried_at": "fixture"}

    def test_seed_is_not_discovered_and_outside_host_never_receives_dns_or_http(self):
        engine = Engine(self.project, self.scope, config(), "subfinding", target="example.com", tasks=passive_tasks("example.com"))
        with patch("xitool.execution.collect", side_effect=self.source), patch.object(engine.dns, "resolve") as dns, patch.object(engine.client, "get") as http:
            # Il seed restituito dalla fonte è autorizzato; la verifica DNS non risolve.
            dns.return_value = {"host": "example.com", "resolved": False, "A": [], "AAAA": [], "CNAME": [], "errors": []}
            engine.execute()
        self.assertEqual([call.args[0] for call in dns.call_args_list], ["example.com"])
        http.assert_not_called()
        folder = engine.output_root / "subfinding"
        self.assertEqual((folder / "all_subdomains.txt").read_text().strip(), "outside.example.com")
        self.assertEqual((folder / "out_of_scope_hosts.txt").read_text().strip(), "outside.example.com")
        self.assertEqual(read_json(folder / "summary.json")["new_subdomains"], 1)
        self.assertEqual(read_json(folder / "host_observations.json")["outside.example.com"]["sources"], ["crtsh", "certspotter"])

    def test_empty_provider_results_report_zero_not_seed(self):
        engine = Engine(self.project, self.scope, config(), "subfinding", target="example.com", tasks=passive_tasks("example.com"))
        def empty(*args):
            return {**self.source(*args), "hosts": []}
        with patch("xitool.execution.collect", side_effect=empty):
            engine.execute()
        self.assertEqual(read_json(engine.output_root / "subfinding/summary.json")["message"], "0 nuovi sottodomini scoperti")
        self.assertEqual((engine.output_root / "subfinding/all_subdomains.txt").read_text(), "")

    def test_provider_error_continues_with_second_source(self):
        engine = Engine(self.project, self.scope, config(), "subfinding", target="example.com", tasks=passive_tasks("example.com"))
        def sources(*args):
            return {**self.source(*args), "hosts": [], "errors": ["HTTP_503"] if args[0] == "crtsh" else []}
        with patch("xitool.execution.collect", side_effect=sources):
            state = engine.execute()
        self.assertEqual(len(state["provider_metadata"]), 2)
        self.assertEqual(len(state["provider_errors"]), 1)
        self.assertTrue(state["errors"])

    def test_interrupted_source_is_resumed_without_losing_first_source(self):
        engine = Engine(self.project, self.scope, config(), "subfinding", target="example.com", tasks=passive_tasks("example.com"))
        first = {**self.source("crtsh", "example.com", {}, None), "hosts": []}
        with patch("xitool.execution.collect", side_effect=[first, KeyboardInterrupt()]):
            engine.execute()
        self.assertEqual(engine.state["status"], "INTERRUPTED")
        resumed = Engine(self.project, self.scope, config(), "subfinding", target="example.com", resume=engine.directory)
        with patch("xitool.execution.collect", return_value={**first, "provider": "certspotter"}) as provider:
            resumed.execute()
        self.assertEqual(provider.call_count, 1)
        self.assertEqual(len(load_state(resumed.directory / "checkpoint.json")["provider_metadata"]), 2)

    def test_wildcard_only_scope_can_start_passive_recon_without_apex_probe(self):
        scope = Scope(["*.example.com"], [])
        engine = Engine(self.project, scope, config(), "subfinding", target="example.com", tasks=passive_tasks("example.com"))
        with patch("xitool.execution.collect", return_value={"provider": "crtsh", "hosts": [], "errors": [], "requests": 1}), patch.object(engine.client, "get") as get:
            engine.execute()
        get.assert_not_called()

    def test_provider_errors_survive_resume_with_wildcard_only_scope(self):
        scope = Scope(["*.example.com"], [])
        engine = Engine(self.project, scope, config(), "subfinding", target="example.com", tasks=passive_tasks("example.com"))
        failed = {"provider": "crtsh", "hosts": [], "errors": ["HTTP_503"], "requests": 1}
        with patch("xitool.execution.collect", side_effect=[failed, KeyboardInterrupt()]):
            engine.execute()
        resumed = Engine(self.project, scope, config(), "subfinding", target="example.com", resume=engine.directory)
        self.assertEqual(len(resumed.state["errors"]), 1)
        self.assertEqual(resumed.state["errors"][0]["provider"], "crtsh")

    def test_optional_file_prompt_produces_dns_tasks_and_accepts_custom_urls(self):
        with patch("builtins.input", side_effect=["", "https://example.com/app"]), patch("sys.stdout", new_callable=io.StringIO):
            tasks = seeds(self.scope, config())
        self.assertEqual(tasks[0]["kind"], "dns")
        self.assertTrue(any(task["url"] == "https://example.com/app" for task in tasks))

    def test_url_scoped_dns_tasks_only_generate_the_authorized_path(self):
        scope = Scope(["https://example.com/app/"], [])
        engine = Engine(self.project, scope, config(), "subfinding", target="example.com",
                        tasks=[{"url": "https://example.com/", "kind": "dns"}])
        with patch.object(engine.dns, "resolve", return_value={"host": "example.com", "resolved": True}), patch.object(engine.client, "get", return_value=Response("https://example.com/app/", 200, {}, "")) as get:
            engine.execute()
        self.assertEqual([call.args[0] for call in get.call_args_list], ["https://example.com/app/"])

    def test_smart_refusal_never_starts_network(self):
        discovery = Engine(self.project, self.scope, config(), "subfinding", target="example.com", tasks=[{"url": "https://example.com/"}])
        with patch.object(discovery.client, "get", return_value=Response("https://example.com/", 200, {"content-type": "text/html"}, '<a href="/?q=x">search</a>')):
            discovery.execute()
        with patch("builtins.input", side_effect=["1,2", "n"]), patch("sys.stdout", new_callable=io.StringIO), patch.object(Engine, "execute") as execute:
            execute_smart([(self.project, self.scope, ["example.com"])], config())
        execute.assert_not_called()


class LocalCrawlerTests(unittest.TestCase):
    def test_real_http_crawler_reads_robots_sitemap_and_json_without_post(self):
        requests = []
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                requests.append(self.path)
                if self.path == "/robots.txt":
                    body, content_type = "Disallow: /informational", "text/plain"
                elif self.path == "/sitemap.xml":
                    body, content_type = "<urlset><url><loc>/api/users/123</loc></url></urlset>", "application/xml"
                elif self.path == "/api/users/123":
                    body, content_type = '{"id":123,"name":"fixture"}', "application/json"
                else:
                    body, content_type = '<title>Local fixture</title><form method="post" action="/submit"><input name="q"></form>', "text/html"
                self.send_response(200)
                self.send_header("Content-Type", content_type)
                self.end_headers()
                self.wfile.write(body.encode())
            def log_message(self, *args):
                pass
        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with tempfile.TemporaryDirectory() as directory:
                projects = Projects(Path(directory))
                project = projects.create("Loopback", ["127.0.0.1"], [])
                scope = Scope(["127.0.0.1"], [], ["127.0.0.1/32"])
                settings = config()
                port = server.server_address[1]
                settings["http"]["allowed_ports"] = [port]
                url = f"http://127.0.0.1:{port}/"
                engine = Engine(project, scope, settings, "subfinding", target="127.0.0.1", tasks=[{"url": url, "depth": 0, "recon": True}])
                state = engine.execute()
                self.assertEqual(state["errors"], [])
                self.assertIn("/robots.txt", requests)
                self.assertIn("/sitemap.xml", requests)
                self.assertIn("/api/users/123", requests)
                self.assertNotIn("/submit", requests)
                self.assertTrue(any(entry["location"] == "response_json" for entry in state["inputs"]))
                self.assertEqual(read_json(engine.output_root / "subfinding/summary.json")["new_subdomains"], 0)
                self.assertTrue(read_json(engine.output_root / "subfinding/http_probes.json")[0]["title_present"])
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)


if __name__ == "__main__":
    unittest.main()
