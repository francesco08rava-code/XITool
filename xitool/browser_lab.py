"""Prova XSS opzionale: HTML realmente raccolto, browser isolato senza egress."""
from __future__ import annotations

import os
import json
from http.cookies import SimpleCookie
import uuid
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit, quote

from .scanners import finding
from .storage import fingerprint


def launch_options():
    options = {"headless": True, "timeout": 10000,
               "args": ["--disable-background-networking", "--disable-component-update", "--disable-extensions",
                        "--force-webrtc-ip-handling-policy=disable_non_proxied_udp", "--host-resolver-rules=MAP * ~NOTFOUND"],
               "proxy": {"server": "http://127.0.0.1:9", "bypass": "<-loopback>"}}
    channel = os.environ.get("XITOOL_BROWSER_CHANNEL")
    if channel in ("chrome", "msedge", "chromium"):
        options["channel"] = channel
    return options


def verify_xss(case: dict, client) -> list[dict]:
    url = case["url"]
    try:
        from playwright.sync_api import sync_playwright, Error as BrowserError
    except ImportError:
        return [finding("xss", url, "controlled_browser_execution", "UNSUPPORTED", {"reason": "PLAYWRIGHT_NOT_INSTALLED"},
                        "Installare requirements-browser.txt e un Chromium supportato. Nessuna esecuzione simulata.", case["parameter"])]
    nonce = uuid.uuid4().hex
    binding = "xitoolProof_" + uuid.uuid4().hex
    # L'unica azione del payload è notificare un nonce al processo del laboratorio.
    payload = f'<svg onload="window.{binding}(\'{nonce}\')"></svg>'
    parsed = urlsplit(url)
    pairs = [(key, payload if key == case["parameter"] else value) for key, value in parse_qsl(parsed.query, keep_blank_values=True)]
    probe_url = urlunsplit((parsed.scheme, parsed.netloc, parsed.path, urlencode(pairs), ""))
    if case.get("dom_source") == "fragment":
        baseline, probe, repeat = [client.get(url, cache=False) for _ in range(3)]
    elif case.get("request"):
        request = case["request"]
        def submit(fields):
            body = json.dumps(fields).encode() if request["content_type"] == "application/json" else urlencode(fields).encode()
            return client.post(url, body, request["content_type"], authorized_urls=(url,))
        baseline = submit(request["fields"])
        fields = {**request["fields"], case["parameter"]: payload}
        probe, repeat = submit(fields), submit(fields)
    else:
        baseline = client.get(url, cache=False)
        probe, repeat = client.get(probe_url, cache=False), client.get(probe_url, cache=False)
    executed = [False, False, False]
    blocked = [0]
    channel = os.environ.get("XITOOL_BROWSER_CHANNEL")
    if channel not in (None, "chrome", "msedge", "chromium"):
        return [finding("xss", url, "controlled_browser_execution", "UNSUPPORTED", {"reason": "BROWSER_CHANNEL_INVALID"}, "Usare un canale browser supportato.")]
    try:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(**launch_options())
            try:
                for index, response in enumerate((baseline, probe, repeat)):
                    context = browser.new_context(service_workers="block", accept_downloads=False)
                    try:
                        context.route_web_socket("**/*", lambda route: route.close())
                        served = [False]
                        def route_request(route):
                            request = route.request
                            if request.method == "GET" and request.url == response.url and not served[0]:
                                served[0] = True
                                headers = {key: value for key, value in response.headers.items() if key in
                                           ("content-type", "content-security-policy", "x-content-type-options", "referrer-policy")}
                                route.fulfill(status=response.status, headers=headers, body=response.body)
                            else:
                                blocked[0] += 1
                                route.abort()
                        context.route("**/*", route_request)
                        page = context.new_page()
                        page.expose_function(binding, lambda value: executed.__setitem__(index, value == nonce))
                        navigation = response.url + ("#" + quote(payload, safe="") if case.get("dom_source") == "fragment" and index else "")
                        page.goto(navigation, wait_until="load", timeout=5000)
                        page.wait_for_timeout(250)
                    finally:
                        context.close()
            finally:
                browser.close()
    except BrowserError:
        return [finding("xss", url, "controlled_browser_execution", "UNSUPPORTED", {"reason": "BROWSER_UNAVAILABLE_OR_FAILED"},
                        "Il browser non è stato verificato; nessun risultato di esecuzione inventato.", case["parameter"])]
    comparable = baseline.status == probe.status == repeat.status == 200 and not any(row.truncated for row in (baseline, probe, repeat)) and probe.body == repeat.body
    proof = comparable and executed[1] and executed[2] and not executed[0]
    outcome = "VERIFIED" if proof else "NO_ISSUES_OBSERVED" if comparable and not any(executed) else "PARTIAL"
    result = finding("xss", url, "controlled_browser_execution", outcome,
                     {"controlled_case": case["id"], "baseline_executed": executed[0], "probe_executed": executed[1],
                      "nonce": nonce, "baseline_status": baseline.status, "probe_status": probe.status,
                      "repeat_executed": executed[2], "responses_stable": probe.body == repeat.body,
                      "request_method": "POST" if case.get("request") else "GET",
                      "dom_source": "location.hash" if case.get("dom_source") else None,
                      "dom_source_execution_demonstrated": bool(proof and case.get("dom_source")),
                      "sink_identification": "NOT_INSTRUMENTED",
                      "blocked_browser_requests": blocked[0], "network_mode": "PREFETCHED_HTML_ONLY_NO_BROWSER_EGRESS"},
                     "Prova limitata alla pagina di laboratorio configurata. Nessun cookie, token o dato personale letto; DOM e applicazioni pubbliche generiche non sono coperti.", case["parameter"])
    result["baseline"] = {"status": baseline.status, "body_sha256": fingerprint(baseline.body)}
    result["http_method"] = "POST" if case.get("request") else "GET"
    result["confidence"] = "HIGH" if proof else "NOT_ASSESSED"
    return [result]


def verify_cors(case, client, profile, proof):
    try:
        from playwright.sync_api import sync_playwright, Error as BrowserError
    except ImportError:
        return [finding("cors", case["url"], "controlled_browser_read", "UNSUPPORTED", {"reason": "PLAYWRIGHT_NOT_INSTALLED"}, "Browser opzionale non installato.")]
    parsed = urlsplit(case["caller_url"])
    origin = urlunsplit((parsed.scheme, parsed.netloc, "", "", ""))
    private = client.for_profile(profile)
    baseline = private.get(case["url"], cache=False)
    tested = private.get(case["url"], {"Origin": origin}, cache=False)
    caller = client.get(case["caller_url"], cache=False)
    credentials = profile.headers(case["url"])
    raw_cookie = next(value for key, value in credentials.items() if key.lower() == "cookie")
    cookie = SimpleCookie()
    cookie.load(raw_cookie)
    if not cookie or not all(200 <= response.status < 300 and not response.truncated for response in (baseline, tested, caller)) or proof not in baseline.body:
        return [finding("cors", case["url"], "controlled_browser_read", "PARTIAL", {"baseline_canary_confirmed": proof in baseline.body}, "Sessione o fixture di riferimento non verificata.")]
    seen = {"cookie_sent": False, "origin_sent": False}
    try:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(**launch_options())
            try:
                context = browser.new_context(service_workers="block", accept_downloads=False)
                context.add_cookies([{"name": name, "value": morsel.value, "url": profile.origin,
                                      "httpOnly": True, "sameSite": "Lax"} for name, morsel in cookie.items()])
                context.route_web_socket("**/*", lambda route: route.close())
                def bridge(route):
                    request = route.request
                    if request.method != "GET":
                        route.abort()
                        return
                    if request.url == caller.url:
                        response = caller
                    elif request.url == tested.url:
                        headers = request.all_headers()
                        offered = SimpleCookie()
                        offered.load(headers.get("cookie", ""))
                        seen["cookie_sent"] = all(name in offered and offered[name].value == morsel.value for name, morsel in cookie.items())
                        seen["origin_sent"] = headers.get("origin") == origin
                        if not all(seen.values()):
                            route.abort()
                            return
                        response = tested
                    else:
                        route.abort()
                        return
                    headers = {key: value for key, value in response.headers.items() if key in
                               ("content-type", "content-security-policy", "access-control-allow-origin", "access-control-allow-credentials", "vary")}
                    # Playwright otherwise adds a permissive ACAO/ACAC automatically.
                    # Empty ACAO preserves the denial semantics of an absent header.
                    headers.setdefault("access-control-allow-origin", "")
                    route.fulfill(status=response.status, headers=headers, body=response.body)
                context.route("**/*", bridge)
                page = context.new_page()
                page.goto(caller.url, timeout=5000)
                readable = page.evaluate("""async ({url, proof}) => {
                    try { const r = await fetch(url, {credentials: 'include'}); return (await r.text()).includes(proof); }
                    catch { return false; }
                }""", {"url": tested.url, "proof": proof})
                context.close()
            finally:
                browser.close()
    except BrowserError:
        return [finding("cors", case["url"], "controlled_browser_read", "UNSUPPORTED", {"reason": "BROWSER_UNAVAILABLE_OR_FAILED"}, "Nessuna lettura browser dichiarata verificata.")]
    policy_allows = tested.headers.get("access-control-allow-origin") == origin and tested.headers.get("access-control-allow-credentials", "").lower() == "true"
    outcome = "VERIFIED" if readable and policy_allows and all(seen.values()) else "NO_ISSUES_OBSERVED" if not readable and all(seen.values()) else "PARTIAL"
    return [finding("cors", case["url"], "controlled_browser_read", outcome,
                    {"controlled_case": case["id"], "baseline_canary_confirmed": True, "browser_read_canary": bool(readable),
                     "browser_sent_test_cookie": seen["cookie_sent"], "browser_sent_expected_origin": seen["origin_sent"],
                     "original_policy_allows": policy_allows, "missing_allow_origin_denied": "access-control-allow-origin" not in tested.headers,
                     "network_mode": "PREFETCHED_RESPONSES_ONLY_NO_BROWSER_EGRESS"},
                    "Prova limitata a due origini loopback e cookie canary dell'operatore. Le risposte reali prefetched sono sottoposte ai controlli CORS del browser; nessun dato personale esportato.")]
