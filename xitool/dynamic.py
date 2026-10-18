"""Discovery DOM opzionale: ogni GET passa dal client con IP e scope validati."""
from urllib.parse import urlsplit

from .browser_lab import launch_options
from .http import Response
from .scanners import discover, safe_url
from .storage import DataError


def render(client, url):
    try:
        from playwright.sync_api import sync_playwright, Error as BrowserError
    except ImportError:
        return {"status": "UNSUPPORTED", "inputs": [], "links": [], "references": [], "blocked": 0, "reason": "PLAYWRIGHT_NOT_INSTALLED"}
    result = {"status": "PARTIAL", "inputs": [], "links": [], "references": [], "blocked": 0, "requests": 0, "errors": []}
    try:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(**launch_options())
            try:
                context = browser.new_context(service_workers="block", accept_downloads=False)
                context.route_web_socket("**/*", lambda route: route.close())
                def bridge(route):
                    request = route.request
                    if request.method != "GET" or request.resource_type not in ("document", "script", "xhr", "fetch") or result["requests"] >= 10:
                        result["blocked"] += 1
                        route.abort()
                        return
                    try:
                        checked = safe_url(client.scope, request.url)
                        result["requests"] += 1
                        response = client.get(checked)
                        result["references"].append({"url": response.url, "source": "browser_network", "kind": "OBSERVED_NETWORK",
                                                     "resource_type": request.resource_type, "method": request.method,
                                                     "scope_status": "AUTHORIZED", "reached": True})
                        if response.redirects:
                            hop = response.redirects[0]
                            route.fulfill(status=hop["status"], headers={"Location": hop["destination"]}, body="")
                            return
                        inputs, links, references = discover(client.scope, response, include_references=True)
                        result["inputs"].extend(inputs)
                        result["links"].extend(links)
                        result["references"].extend(references)
                        headers = {key: value for key, value in response.headers.items() if key in
                                   ("content-type", "content-security-policy", "x-content-type-options", "referrer-policy")}
                        route.fulfill(status=response.status, headers=headers, body=response.body)
                    except (OSError, DataError):
                        result["blocked"] += 1
                        result["errors"].append("RESOURCE_BLOCKED_OR_FAILED")
                        route.abort()
                context.route("**/*", bridge)
                page = context.new_page()
                navigation = page.goto(url, wait_until="load", timeout=15000)
                page.wait_for_timeout(500)
                rendered_url = safe_url(client.scope, page.url)
                if navigation is None:
                    raise DataError("Risposta di navigazione non osservata")
                if page.evaluate("() => document.documentElement.outerHTML.length") > client.config["http"]["max_body_bytes"]:
                    raise DataError("DOM oltre il budget configurato")
                inputs, links, references = discover(client.scope, Response(rendered_url, navigation.status, {"content-type": "text/html"}, page.content()), True)
                for entry in inputs:
                    entry["discovery_engine"] = "browser_dom"
                for reference in references:
                    reference.update(source="browser_dom", kind="OBSERVED_DOM")
                result["inputs"].extend(inputs)
                result["links"].extend(links)
                result["references"].extend(references)
                context.close()
                result["status"] = "PARTIAL" if result["errors"] or result["requests"] >= 10 else "COMPLETED"
            finally:
                browser.close()
    except (BrowserError, DataError):
        result.update(status="UNSUPPORTED", reason="BROWSER_UNAVAILABLE_OR_NAVIGATION_FAILED")
    result["links"] = sorted(set(result["links"]))[:1000]
    result["inputs"] = result["inputs"][:1000]
    result["references"] = result["references"][:1000]
    return result
