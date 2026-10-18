"""Pipeline integrata ripetibile, catalogo etichettato e metriche per contratto."""
import copy
import hashlib
import json
import os
from pathlib import Path
import tempfile
from unittest.mock import patch

from lab_app import Laboratory
from test_controlled import ControlledServerTests
from xitool.controlled import tasks as controlled_tasks
from xitool.execution import Engine, build_tasks, scan_diff, load_state
from xitool.plans import SmartPlan
from xitool.scope import Scope
from xitool.storage import DEFAULTS, Projects, save_json, read_json


def metrics(rows):
    groups = {}
    for row in rows:
        group = groups.setdefault(row["module"] + ":" + row["category"], {key: 0 for key in ("TP", "FP", "TN", "FN", "ERROR", "TIMEOUT", "UNSUPPORTED", "NOT_EXECUTED", "MANUAL_REVIEW", "INCONCLUSIVE")})
        statuses = group.setdefault("observed_status_counts", {})
        statuses[row["observed"]] = statuses.get(row["observed"], 0) + 1
        if row["observed_positive"] is None:
            key = row["observed"] if row["observed"] in group else "INCONCLUSIVE"
        elif row["observed_positive"]:
            key = "TP" if row["ground_truth"] else "FP"
        else:
            key = "FN" if row["ground_truth"] else "TN"
        group[key] += 1
    for group in groups.values():
        tp, fp, tn, fn = (group[key] for key in ("TP", "FP", "TN", "FN"))
        for name, numerator, denominator in (("precision", tp, tp+fp), ("recall", tp, tp+fn), ("specificity", tn, tn+fp), ("FPR", fp, fp+tn), ("FNR", fn, fn+tp)):
            group[name] = numerator / denominator if denominator else None
        group["evaluated"] = tp + fp + tn + fn
        group["total"] = sum(group[key] for key in ("TP", "FP", "TN", "FN", "ERROR", "TIMEOUT", "UNSUPPORTED", "NOT_EXECUTED", "MANUAL_REVIEW", "INCONCLUSIVE"))
        group["conclusive_coverage"] = group["evaluated"] / group["total"] if group["total"] else None
    return groups


def run(output=None):
    rows = []
    preserved_reports = []
    def record(module, identity, truth, status, positive, category="controlled_detector", error=None):
        rows.append({"id": module + ":" + identity + ":" + str(len(rows)), "module": module, "category": category, "ground_truth": truth,
                     "initial_conditions": "Owned loopback app, synthetic accounts/canary, explicit scope and manifest",
                     "input": identity, "expected_behavior": "INCONCLUSIVE_OR_TECHNICAL_STATE" if truth is None else "detector positive" if truth else "detector negative",
                     "required_evidence": "Browser/canary proof; SQL differential stays POTENTIAL; infrastructure uses contract only",
                     "observed": status, "observed_positive": positive, "error": error})
    with tempfile.TemporaryDirectory() as directory, Laboratory() as lab:
        project = Projects(Path(directory)).create("Integrated", ["127.0.0.1", "lab.test", "*.lab.test"], [])
        other = Projects(Path(directory)).create("Isolated", ["127.0.0.1"], [])
        scope = Scope(["127.0.0.1", "lab.test", "*.lab.test"], [], ["127.0.0.0/8"])
        config = copy.deepcopy(DEFAULTS)
        config["http"].update(allowed_ports=[lab.server.server_port, lab.caller.server_port], max_retries=0, requests_per_second=1000)
        config["discovery"].update(max_depth=2, max_pages=15)
        lab.callback_events = project / "callback_events.jsonl"
        lab.callback_events.write_text("")
        save_json(project / "session_profiles.json", {"version": 1, "profiles": {
            "owner": {"origin": lab.origin, "role": "owner", "header_env": {"Authorization": "XITOOL_OWNER_AUTH"}},
            "other": {"origin": lab.origin, "role": "other", "header_env": {"Authorization": "XITOOL_OTHER_AUTH"}},
            "cookie": {"origin": lab.origin, "role": "owner", "header_env": {"Cookie": "XITOOL_LAB_COOKIE"}}}})
        env = {"XITOOL_OWNER_AUTH": "Bearer OWNER_PRIVATE", "XITOOL_OTHER_AUTH": "Bearer OTHER_PRIVATE",
               "XITOOL_OWNER_PROOF": ControlledServerTests.owner_canary, "XITOOL_OTHER_PROOF": ControlledServerTests.other_canary,
               "XITOOL_LAB_COOKIE": "lab=synthetic"}
        def check(module, path, extra=None, truth=None, classify=None, category=None):
            url = lab.origin + path
            if extra is not None:
                case = {"id": module + "-fixture", "module": module, "url": url, "operator_owned": True, **extra}
                save_json(project / "controlled_checks.json", {"version": 1, "checks": [case]})
                tasks = controlled_tasks(project, scope, module)
            else:
                tasks = [{"url": url}]
            engine = Engine(project, scope, config, module, target="127.0.0.1", tasks=tasks)
            engine.execute()
            result = engine.state["results"][0] if engine.state["results"] else None
            status = result["status"] if result else "TIMEOUT" if engine.state["errors"] and engine.state["errors"][0].get("category") == "NETWORK_TIMEOUT" else "ERROR"
            observed = classify(result) if result and classify else True if status in ("VERIFIED", "POTENTIAL") else False if status == "NO_ISSUES_OBSERVED" else None
            default_category = {"sqli": "sql_candidate_differential", "sensitive": "redacted_pattern_detector", "misconfiguration": "missing_security_headers"}.get(module, "canary_or_browser_proof")
            reason = engine.state["errors"][0].get("category") if engine.state["errors"] else result.get("evidence", {}).get("reason") if result else None
            record(module, path, truth, status, observed, category or default_category, error=reason or ("INCONCLUSIVE_EVIDENCE" if status == "PARTIAL" else None))
            rows[-1]["conditions"] = {"controlled_case": extra, "transport": "real loopback HTTP", "independent_project": other.name}
            report = (engine.directory / "report.json").read_text()
            preserved_reports.append((engine.directory / "report.json", hashlib.sha256(report.encode()).hexdigest()))
            assert all(value not in report for value in env.values())
            return engine
        with patch.dict(os.environ, env):
            from lab_sources import exercise
            source_evidence = exercise(project, scope, config, lab)
            record("subfinding", "provider-failed", None, "ERROR", None, "provider_availability", "HTTP_SERVER_ERROR")
            record("subfinding", "CT-DNS-HTTP-new-host", True, "OBSERVED", "new.lab.test" in source_evidence["reached"], "provider_dns_contract")
            record("subfinding", "outside-CNAME-not-queried", False, "OBSERVED", source_evidence["outside_queried"], "scope_contract")
            record("subfinding", "NXDOMAIN", False, "OBSERVED", source_evidence["missing_dns_status"] != "NOT_FOUND", "dns_contract")
            recon = Engine(project, scope, config, "subfinding", target="127.0.0.1", tasks=[{"url": lab.origin + "/"}])
            recon.execute()
            record("subfinding", "seed-not-new", False, "OBSERVED", bool(set(recon.state["hosts"]) - {"127.0.0.1"}), "seed_discovery")
            record("subfinding", "seed-reachable", True, "OBSERVED", "127.0.0.1" in recon.state["live_hosts"], "reachability")
            inputs, urls = recon.state["inputs"], recon.state["endpoints"]
            record("crawler", "query-and-form", True, "OBSERVED", any(row["location"] == "body" for row in inputs) and any(row["parameter"] == "q" for row in inputs), "input_contract")
            record("crawler", "outside-not-reached", False, "OBSERVED", any("outside.invalid" in url for url in urls), "scope_contract")
            assert any(row.get("source") == "openapi_document" for row in inputs)
            assert {row.get("method") for row in recon.state["url_references"] if row.get("source") == "openapi_document"} >= {"GET", "POST"}
            record("crawler", "static-JS-not-queued", False, "OBSERVED", any(path in lab.counts for path in ("/api/items", "/api/info", "/api/xhr")), "scope_contract")
            from xitool.dynamic import render
            from xitool.http import HTTPClient
            dynamic = render(HTTPClient(scope.for_target("127.0.0.1"), config), lab.origin + "/spa")
            record("crawler", "SPA-network", True, dynamic["status"], any(row.get("kind") == "OBSERVED_NETWORK" and row.get("resource_type") == "fetch" for row in dynamic["references"]), "dynamic_contract")
            record("crawler", "SPA-DOM-link", True, dynamic["status"], any("/dynamic?q=spa" in url for url in dynamic["links"]), "dynamic_contract")
            failed_crawl = Engine(project, scope, config, "subfinding", target="127.0.0.1", tasks=[{"url": lab.origin + "/xitool-lab/drop"}])
            failed_crawl.execute()
            record("crawler", "connection-drop", None, "ERROR", None, "technical_error", failed_crawl.state["errors"][0].get("category"))
            # Consume actual recon URLs/inputs, not a hand-written independent task list.
            plan = SmartPlan(project, scope, config, ["127.0.0.1"])
            discovered = build_tasks("misconfiguration", scope, inputs, urls)[:3]
            assert len(discovered) >= 2
            plan.add([{"domain": "127.0.0.1", "module": "misconfiguration", "tasks": discovered}])
            def stop(state):
                if state["completed"]:
                    raise KeyboardInterrupt()
            plan.run(stop)
            interrupted = plan.state["status"] == "INTERRUPTED"
            resumed = SmartPlan(project, scope, config, ["127.0.0.1"], path=plan.path)
            resumed.run()
            record("smart", "interrupt-resume", True, resumed.state["status"], interrupted and resumed.state["status"] == "COMPLETED", "execution_contract")
            report = read_json(plan.path.with_suffix(".report.json"))
            record("smart", "duplicate-findings", False, "OBSERVED", len({r["id"] for r in report["findings"]}) != len(report["findings"]), "dedup_contract")
            broken_plan = SmartPlan(project, scope, config, ["127.0.0.1"])
            broken_plan.add([{"domain": "127.0.0.1", "module": "subfinding", "tasks": [{"url": lab.origin + "/xitool-lab/drop"}]},
                             {"domain": "127.0.0.1", "module": "misconfiguration", "tasks": [{"url": lab.origin + "/must-not-run"}]}])
            broken_plan.run()
            assert broken_plan.state["status"] == "PARTIAL" and broken_plan.state["steps"][1]["status"] == "BLOCKED_DEPENDENCY"
            assert "/must-not-run" not in lab.counts
            record("smart", "dependency-error-blocked", None, "ERROR", None, "technical_error", "CONNECTION_ERROR")
            assert not list(other.rglob("checkpoint.json"))
            from xitool.sessions import load_profiles
            assert load_profiles(other) == {}
            permissions = {"proof_env": "XITOOL_OWNER_PROOF", "owner_profile": "owner", "other_profile": "other", "other_reference_url": lab.origin + "/other-reference", "other_proof_env": "XITOOL_OTHER_PROOF", "expected_other_access": False}
            for module in ("idor", "access"):
                for path, truth in (("/owned-vulnerable", True), ("/owned-safe", False), ("/owned-plain200", None)):
                    check(module, path, permissions, truth)
                check(module, "/xitool-lab/drop", permissions)
                with patch.dict(os.environ, {"XITOOL_OTHER_AUTH": "Bearer EXPIRED"}):
                    check(module, "/owned-safe", permissions)
            xss = {"parameter": "q", "fixture_only": True}
            for path, truth in (("/xitool-lab/xss-vulnerable?q=hello", True), ("/xitool-lab/xss-safe?q=hello", False)):
                check("xss", path, xss, truth)
            check("xss", "/xitool-lab/xss-csp?q=hello", xss, False)
            dom = {"parameter": "fragment", "fixture_only": True, "dom_source": "fragment"}
            check("xss", "/xitool-lab/dom-vulnerable", dom, True)
            check("xss", "/xitool-lab/dom-safe", dom, False)
            check("xss", "/xitool-lab/drop?q=hello", xss)
            sql = {"proof_env": "XITOOL_OWNER_PROOF", "parameter": "id", "fixture_only": True, "read_only_fixture": True}
            for path, truth in (("/xitool-lab/sql-vulnerable?id=1", True), ("/xitool-lab/sql-safe?id=1", False)):
                check("sqli", path, sql, truth, lambda r: True if r["status"] == "POTENTIAL" else False if r["evidence"].get("expression_rejected_consistently") else None)
            check("sqli", "/xitool-lab/drop?id=1", sql)
            for mime in ("application/json", "application/x-www-form-urlencoded"):
                body_case = {**sql, "request": {"method": "POST", "content_type": mime, "authorized": True, "fields": {"id": "1"}}}
                for kind, truth in (("vulnerable", True), ("safe", False)):
                    check("sqli", "/xitool-lab/sql-" + kind, body_case, truth, lambda r: True if r["status"] == "POTENTIAL" else False if r["evidence"].get("expression_rejected_consistently") else None)
            check("sqli", "/xitool-lab/sql-unstable?id=1", sql)
            traversal = {"proof_env": "XITOOL_OWNER_PROOF", "baseline_url": lab.origin + "/xitool-lab/file", "fixture_only": True, "expected_probe_access": False}
            check("traversal", "/xitool-lab/file?file=prepared-canary", traversal, True)
            check("traversal", "/xitool-lab/denied", traversal, False)
            check("traversal", "/xitool-lab/missing", traversal, None)
            check("traversal", "/xitool-lab/drop", traversal)
            check("traversal", "/xitool-lab/file?file=prepared%2Dcanary", traversal, True)
            check("traversal", "/xitool-lab/file?file=prepared-canary", {**traversal, "baseline_url": lab.origin + "/xitool-lab/unstable"})
            for path, truth in (("/xitool-lab/secret-positive", True), ("/xitool-lab/secret-safe", False)):
                check("sensitive", path, truth=truth, classify=lambda r: bool(sum(r["evidence"]["pattern_counts"].values())))
            check("sensitive", "/xitool-lab/drop")
            for path, truth in (("/item", True), ("/xitool-lab/headers-safe", False)):
                check("misconfiguration", path, truth=truth, classify=lambda r: bool(r["evidence"]["missing_headers"]))
            check("misconfiguration", "/xitool-lab/drop")
            from test_v4_tls import TLSTests
            from xitool.http import TLSVerificationError
            for kind in ("valid", "expired", "wrong-host"):
                try:
                    response = TLSTests().request(kind)
                    accepted = response.tls["hostname_verified"]
                except TLSVerificationError:
                    accepted = False
                record("misconfiguration", "TLS-" + kind, kind == "valid", "OBSERVED", accepted, "tls_acceptance_contract")
            old_http = dict(config["http"])
            config["http"].update(timeout_seconds=.1, connect_timeout_seconds=.1, read_timeout_seconds=.1)
            try:
                check("misconfiguration", "/xitool-lab/slow")
            finally:
                config["http"] = old_http
            auth = {"proof_env": "XITOOL_OWNER_PROOF", "profile": "owner", "logout_url": lab.origin + "/xitool-lab/end-session", "fixture_only": True, "logout_confirmed": True}
            for effective in (False, True):
                ControlledServerTests.revoked, ControlledServerTests.logout_effective = False, effective
                check("authentication", "/xitool-lab/protected", auth, not effective)
            check("authentication", "/xitool-lab/drop", auth)
            ControlledServerTests.revoked = True
            check("authentication", "/xitool-lab/protected", auth)
            cors = {"proof_env": "XITOOL_OWNER_PROOF", "profile": "cookie", "caller_url": lab.caller_origin + "/xitool-lab/caller", "fixture_only": True, "expected_cross_origin_access": False}
            for path, truth in (("/xitool-lab/cors-vulnerable", True), ("/xitool-lab/cors-safe", False)):
                check("cors", path, cors, truth)
                preflight = HTTPClient(scope.for_target("127.0.0.1"), config).preflight(lab.origin + path, lab.caller_origin)
                record("cors", path + "-preflight", truth, "OBSERVED", preflight.headers.get("access-control-allow-origin") == lab.caller_origin, "preflight_contract")
            check("cors", "/xitool-lab/cors-public", truth=False, classify=lambda row: row["status"] in ("VERIFIED", "POTENTIAL"), category="public_wildcard_false_positive_guard")
            check("cors", "/xitool-lab/drop", cors)
            callback = {"parameter": "url", "callback_base": lab.origin + "/xitool-callback/", "events_file": "callback_events.jsonl", "expected_source_ips": ["127.0.0.1"], "fixture_only": True}
            check("ssrf", "/xitool-lab/ssrf-vulnerable?url=initial", callback, True)
            check("ssrf", "/xitool-lab/ssrf-safe?url=initial", callback, False)
            lab.duplicate_callbacks = True
            duplicate = check("ssrf", "/xitool-lab/ssrf-vulnerable?url=initial&mode=duplicate", callback, True)
            assert duplicate.state["results"][0]["evidence"]["unique_matching_events"] == 1
            lab.duplicate_callbacks = False
            lab.wrong_nonce = True
            check("ssrf", "/xitool-lab/ssrf-vulnerable?url=initial&mode=wrong-nonce", callback)
            lab.wrong_nonce = False
            lab.callback_events.unlink()
            before = lab.counts.get("/xitool-lab/ssrf-vulnerable", 0)
            check("ssrf", "/xitool-lab/ssrf-vulnerable?url=initial", callback)
            assert lab.counts.get("/xitool-lab/ssrf-vulnerable", 0) == before
            lab.callback_events.write_text("")
            check("ssrf", "/xitool-lab/drop?url=initial", callback)
            # A second real run produces the diff; all preceding reports must survive.
            second = Engine(project, scope, config, "subfinding", target="127.0.0.1", tasks=[{"url": lab.origin + "/"}])
            second.execute()
            diff = scan_diff(recon.state, second.state)
            assert diff["new_subdomains"] == []
            assert (recon.directory / "report.json").exists()
            assert len(list(project.rglob("report.json"))) >= 25
            for path, expected_hash in preserved_reports:
                assert hashlib.sha256(path.read_text().encode()).hexdigest() == expected_hash
            for checkpoint in project.rglob("checkpoint.json"):
                state = load_state(checkpoint)
                assert state["project"] == project.name
                assert all(row.get("domain") == state["domain"] for row in state["results"])
    failures = [row for row in rows if (row["ground_truth"] is True and row["observed_positive"] is not True) or
                (row["ground_truth"] is False and row["observed_positive"] is True)]
    result = {"success": not failures, "cases": rows, "metrics": metrics(rows), "source_evidence": source_evidence, "modules": sorted({row["module"] for row in rows}),
              "limitations": "Synthetic local contracts only. POTENTIAL SQL is candidate detection, not VERIFIED. No aggregation across detector contracts. CT and DNS fixtures validated separately; no public provider availability inferred."}
    if output:
        save_json(Path(output), result)
    return result
