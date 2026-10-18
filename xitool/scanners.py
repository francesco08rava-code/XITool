"""Discovery statica e controlli conservativi; nessuna esecuzione JavaScript."""
from __future__ import annotations

from html.parser import HTMLParser
from html import escape
import json
import math
import re
import xml.etree.ElementTree as ET
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit
import uuid

from .http import HTTPClient, Response
from .scope import Scope, normalize_host, blocked_request
from .storage import DataError, fingerprint, utcnow
from .outcomes import result_outcome
from .sessions import session_state
from .cookie_policy import attributes as cookie_attributes


MODULES = {
    "subfinding": ("SUB FINDING", "PARTIAL"),
    "xss": ("XSS", "PARTIAL"),
    "sqli": ("SQL INJECTION — ERRORI OSSERVABILI", "PARTIAL"),
    "idor": ("IDOR — CANDIDATI PER REVISIONE", "PARTIAL"),
    "access": ("BROKEN ACCESS CONTROL — RISORSE DI TEST", "PARTIAL"),
    "ssrf": ("SSRF — CANDIDATI PER REVISIONE", "PARTIAL"),
    "traversal": ("PATH TRAVERSAL — CANDIDATI PER REVISIONE", "PARTIAL"),
    "misconfiguration": ("SECURITY MISCONFIGURATION", "PARTIAL"),
    "sensitive": ("SENSITIVE DATA EXPOSURE", "PARTIAL"),
    "authentication": ("AUTHENTICATION", "PARTIAL"),
    "cors": ("CORS", "PARTIAL"),
}
SECRET_KEY = re.compile(r"pass(?:word)?|secret|token|session|cookie|authorization|api[_-]?key|credential|signature", re.I)
MUTATIVE = re.compile(r"(?:^|[/_.-])(?:logout|signout|delete|remove|unsubscribe|destroy|checkout|purchase)(?:$|[/_.?-])", re.I)


def safe_url(scope: Scope, value: str) -> str:
    """Non persiste né visita URL contenenti parametri di autenticazione riconoscibili."""
    url = scope.url(value)
    parsed = urlsplit(url)
    if blocked_request(url):
        raise DataError("URL sensibile, archivio/dump o azione riconoscibile esclusi")
    return url


def classify(name: str, field_type: str = "") -> str:
    if SECRET_KEY.search(name) or field_type == "password":
        return "authentication"
    if re.search(r"url|uri|redirect|callback|webhook|return", name, re.I):
        return "url"
    if re.search(r"file|path|folder|document|download", name, re.I) or field_type == "file":
        return "file"
    if re.search(r"(?:^|_)id$|uuid|account|user", name, re.I):
        return "identifier"
    return "text"


class Discovery(HTMLParser):
    def __init__(self, scope: Scope, url: str):
        super().__init__(convert_charrefs=True)
        self.scope, self.url = scope, url
        self.links: set[str] = set()
        self.inputs: list[dict] = []
        self.form: tuple[str, str] | None = None
        self.references: list[dict] = []
        for name, _ in parse_qsl(urlsplit(url).query, keep_blank_values=True):
            self.add_input(url, "GET", name, "text", "query")

    def add_reference(self, target: str, source: str, kind: str, enqueue: bool = True) -> None:
        if len(self.references) >= 1000:
            return
        try:
            absolute = urljoin(self.url, target)
            host = normalize_host(urlsplit(absolute).hostname or "")
            normalized = safe_url(Scope([host], []), absolute)
        except (DataError, ValueError):
            return
        try:
            authorized = safe_url(self.scope, normalized)
        except DataError:
            authorized = None
        self.references.append({"url": normalized, "source_url": self.url, "source": source, "kind": kind,
                                "scope_status": "AUTHORIZED" if authorized else "OUT_OF_SCOPE", "timestamp": utcnow()})
        if authorized and enqueue and len(self.links) < 1000:
            self.links.add(authorized)

    def add_input(self, url: str, method: str, name: str, kind: str, source: str) -> None:
        if len(self.inputs) >= 1000 or not name or len(name) > 200 or any(ord(c) < 32 for c in name):
            return
        try:
            url = safe_url(self.scope, url)
        except DataError:
            return
        self.inputs.append({"host": urlsplit(url).hostname, "url": url, "method": method,
                            "parameter": name, "input_type": classify(name, kind),
                            "field_type": kind, "form_action": url if source == "form" else None,
                            "source": source, "timestamp": utcnow(), "scope_status": "AUTHORIZED",
                            "verification_status": "OBSERVED_NOT_ACTIVELY_VERIFIED", "location": "query" if source in ("query", "link") else "body" if source == "form" and method == "POST" else "query"})

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attributes = dict(attrs)
        if tag in ("a", "script", "iframe", "link"):
            target = attributes.get("href") or attributes.get("src")
            if target and len(self.links) < 1000:
                canonical = tag == "link" and "canonical" in (attributes.get("rel") or "").lower().split()
                self.add_reference(target, "canonical" if canonical else "html", "OBSERVED_CANONICAL" if canonical else "OBSERVED_LINK")
        if tag == "form":
            method = (attributes.get("method") or "GET").upper()
            self.add_reference(attributes.get("action") or self.url, "html_form", "OBSERVED_FORM", enqueue=False)
            try:
                self.form = (safe_url(self.scope, urljoin(self.url, attributes.get("action") or self.url)), method)
            except DataError:
                self.form = None
        if tag in ("input", "textarea", "select", "button") and self.form:
            action, method = self.form
            self.add_input(action, method, attributes.get("name") or "", attributes.get("type") or "text", "form")

    def handle_endtag(self, tag: str) -> None:
        if tag == "form":
            self.form = None


def deduplicate_inputs(entries: list[dict]) -> list[dict]:
    """Una query GET osservata non deve essere declassata a form durante il merge."""
    from .inputs import merge
    return merge(entries)


def discover(scope: Scope, response: Response, include_references: bool = False):
    parser = Discovery(scope, response.url)
    content_type = response.headers.get("content-type", "").lower()
    if "html" in content_type:
        parser.feed(response.body)
        parser.close()
    elif "javascript" in content_type:
        # Solo riferimenti letterali, senza valutazione del codice scaricato.
        from .inventory import javascript_targets
        try:
            from .javascript import analyze
            parser.js_analysis = analyze(response.body)
            targets = sorted({row["url"] for row in parser.js_analysis if row.get("url")})
        except ImportError:
            parser.js_analysis = []
            targets = javascript_targets(response.body)
        for target in targets:
            if len(parser.links) >= 1000:
                break
            parser.add_reference(target, "javascript_literal", "STATIC_HYPOTHESIS")
            quality = next((row["quality"] for row in parser.js_analysis if row.get("url") == target), "HEURISTIC")
            if parser.references and parser.references[-1].get("source") == "javascript_literal":
                parser.references[-1]["endpoint_quality"] = quality
    elif "xml" in content_type and "<!DOCTYPE" not in response.body.upper() and "<!ENTITY" not in response.body.upper():
        # ElementTree non risolve risorse remote. Limiti del client anche per le sitemap.
        try:
            document = ET.fromstring(response.body)
            for element in document.iter():
                if len(parser.links) >= 1000:
                    break
                if element.tag.rsplit("}", 1)[-1] == "loc" and element.text:
                    parser.add_reference(element.text.strip(), "sitemap", "OBSERVED_SITEMAP")
        except ET.ParseError:
            pass
    elif urlsplit(response.url).path == "/robots.txt":
        # Disallow è una fonte di riferimenti, mai un'autorizzazione a visitarli.
        for line in response.body.splitlines()[:1000]:
            key, separator, value = line.partition(":")
            value = value.split("#", 1)[0].strip()
            if separator and key.lower().strip() in ("allow", "disallow", "sitemap") and value and "*" not in value and "$" not in value:
                parser.add_reference(value, "robots", "OBSERVED_ROBOTS")
    elif "json" in content_type:
        try:
            document = json.loads(response.body)
            from .inventory import api_references
            for target, source in api_references(document, response.url):
                parser.add_reference(target, source, "OBSERVED_API_DOCUMENT", enqueue=False)
            from .inventory import api_operations
            for operation in api_operations(document, response.url):
                operation.update(source_url=response.url, timestamp=utcnow())
                try:
                    safe_url(scope, operation["url"])
                except DataError:
                    operation["scope_status"] = "OUT_OF_SCOPE"
                else:
                    operation["scope_status"] = "AUTHORIZED"
                    for parameter in operation["parameters"]:
                        if len(parser.inputs) >= 1000:
                            break
                        parser.inputs.append({"host": urlsplit(operation["url"]).hostname, "url": operation["url"],
                            "method": operation["method"], "parameter": parameter["name"], "location": parameter["location"],
                            "input_type": classify(parameter["name"]), "source": "openapi_document", "timestamp": utcnow(),
                            "scope_status": "AUTHORIZED", "request_input_confirmed": False, "reachability": "NOT_VERIFIED"})
                if len(parser.references) < 1000:
                    parser.references.append(operation)
            stack = [(document, "", 0)]
            visited = 0
            while stack and visited < 1000:
                value, prefix, depth = stack.pop()
                visited += 1
                if depth > 8:
                    continue
                if isinstance(value, dict):
                    for name, child in list(value.items())[:1000]:
                        name = str(name)
                        if SECRET_KEY.search(name):
                            continue
                        path = f"{prefix}.{name}" if prefix else name
                        before = len(parser.inputs)
                        parser.add_input(response.url, "GET", path, "text", "response_json")
                        if len(parser.inputs) > before:
                            parser.inputs[-1]["location"] = "response_json"
                            parser.inputs[-1]["request_input_confirmed"] = False
                        stack.append((child, path, depth + 1))
                elif isinstance(value, list):
                    stack.extend((child, prefix + "[]", depth + 1) for child in value[:100])
        except (ValueError, RecursionError):
            pass
    from http.cookies import SimpleCookie, CookieError
    observations = [(name, "response_header") for name in ("content-type", "www-authenticate", "access-control-allow-origin") if name in response.headers]
    for line in response.headers.get("set-cookie", "").splitlines():
        cookie = SimpleCookie()
        try:
            cookie.load(line)
        except CookieError:
            continue
        observations.extend((name, "cookie") for name in list(cookie)[:50] if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.-]{0,99}", name))
    for name, location in ([] if "javascript" in content_type else observations[:53]):
        if len(parser.references) >= 1000:
            break
        parser.references.append({"url": response.url, "source": "response_metadata", "kind": "OBSERVED_RESPONSE_METADATA",
                                  "parameter": name, "location": location, "request_input_confirmed": False,
                                  "scope_status": "AUTHORIZED", "timestamp": utcnow()})
    # Gli identificatori nei percorsi sono candidati osservati, non parametri modificati.
    for index, segment in enumerate(urlsplit(response.url).path.split("/")):
        if re.fullmatch(r"\d{1,20}|[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}", segment):
            before = len(parser.inputs)
            parser.add_input(response.url, "GET", f"path[{index}]", "text", "path")
            if len(parser.inputs) > before:
                parser.inputs[-1].update(location="path", input_type="identifier")
    for target in parser.links:
        for name, _ in parse_qsl(urlsplit(target).query, keep_blank_values=True):
            parser.add_input(target, "GET", name, "text", "link")
    entries = deduplicate_inputs(parser.inputs)
    for row in entries:
        if row["url"] == response.url and row["method"] == "GET" and row.get("source") in ("query", "path"):
            row["reachability"] = "URL_REACHED_INPUT_NOT_VERIFIED"
    result = entries, sorted(parser.links)
    if "javascript" in content_type:
        for row in entries:
            row.update(request_input_confirmed=False, reachability="NOT_VERIFIED", endpoint_quality="STATIC_JS")
        for unresolved in getattr(parser, "js_analysis", []):
            if unresolved.get("quality") == "UNRESOLVED" and len(parser.references) < 1000:
                parser.references.append({**unresolved, "url": response.url, "source": "javascript_unresolved", "kind": "UNRESOLVED", "reached": False})
    quality = {"OBSERVED_NETWORK": "OBSERVED_NETWORK", "OBSERVED_LINK": "OBSERVED_HTML", "OBSERVED_FORM": "OBSERVED_HTML", "STATIC_HYPOTHESIS": "STATIC_JS", "OBSERVED_API_DOCUMENT": "DOCUMENTED_API", "HISTORICAL": "HISTORICAL"}
    for row in parser.references:
        row.setdefault("endpoint_quality", quality.get(row.get("kind"), row.get("kind", "HEURISTIC")))
    return (*result, parser.references) if include_references else result


def finding(module: str, url: str, check: str, status: str, evidence: dict, limitation: str, parameter: str = "") -> dict:
    from .errors import status_category
    statuses = [evidence[key] for key in ("status", "baseline_status", "probe_status") if type(evidence.get(key)) is int]
    categories = sorted({status_category(value) for value in statuses if status_category(value)})
    result = {"error_categories": categories, "id": fingerprint([module, url, check, parameter])[:24], "module": module,
            "url": url, "resource": url, "host": urlsplit(url).hostname, "parameter": parameter,
            "check": check, "check_type": check, "status": status, "evidence": evidence,
            "limitations": limitation, "timestamp": utcnow(),
            "manual_review": status in ("POTENTIAL", "MANUAL_REVIEW"),
            "verification_method": check, "confidence": "HIGH" if status == "VERIFIED" else "LOW" if status == "POTENTIAL" else "NOT_ASSESSED",
            "severity": "UNKNOWN", "http_method": "GET", "input": {"parameter": parameter} if parameter else None,
            "baseline": None, "differences": {}, "errors": []}
    result["verification_outcome"] = result_outcome(result)
    return result


def smart(inputs: list[dict], urls: list[str]) -> dict[str, int]:
    proposals: dict[str, int] = {}
    mapping = {"identifier": "idor", "url": "ssrf", "file": "traversal", "authentication": "authentication", "text": "xss"}
    for entry in inputs:
        if entry.get("source") == "response_json" or entry.get("request_input_confirmed") is False:
            continue
        module = mapping.get(entry.get("input_type"), "xss")
        if module == "xss" and (entry.get("method") != "GET" or entry.get("source") not in ("query", "link")):
            continue
        proposals[module] = proposals.get(module, 0) + 1
    for module in ("cors", "misconfiguration", "authentication", "sensitive"):
        if urls:
            proposals[module] = proposals.get(module, 0) + len(urls)
    return proposals


def smart_reasons(inputs: list[dict], urls: list[str]) -> dict[str, dict]:
    reasons = {"xss": "Query GET osservata: verificare eventuali riflessioni.",
               "idor": "Identificatore osservato: revisione delle autorizzazioni, senza enumerazione.",
               "ssrf": "Input URL osservato: candidato da rivedere, nessuna SSRF confermata.",
               "traversal": "Input file/percorso osservato: verifica manuale con fixture innocue.",
               "cors": "Risposta disponibile: confrontare origini di test innocue.",
               "authentication": "Risposta/input disponibile: attributi di sessione osservabili.",
               "misconfiguration": "Risposta disponibile: controlli di header e HTTPS.",
               "sensitive": "Risposta disponibile: firme di esposizione con valori oscurati."}
    return {module: {"count": count, "reason": reasons[module]} for module, count in smart(inputs, urls).items()
            if MODULES[module][1] != "NOT_IMPLEMENTED"}


def scan(module: str, task: dict, client: HTTPClient) -> list[dict]:
    """Mantiene osservazioni, candidati e prove confermate semanticamente distinti."""
    if module not in MODULES or MODULES[module][1] == "NOT_IMPLEMENTED":
        raise DataError("Modulo non implementato")
    url = safe_url(client.scope, task["url"])
    parameter = task.get("parameter") or ""
    if not isinstance(parameter, str):
        raise DataError("Nome parametro non valido")
    if module == "access":
        return [finding(module, url, "controlled_configuration_required", "UNSUPPORTED", {},
                        "Configurare due profili e una risorsa canary dell'operatore in controlled_checks.json. Nessuna richiesta inviata.")]
    if module in ("idor", "ssrf", "traversal"):
        result = finding(module, url, "input_candidate", "MANUAL_REVIEW", {"input_type": task.get("input_type"), "method": task.get("method")},
                         "Solo classificazione dell'input; preparare account o fixture autorizzate per la verifica.", parameter)
        result.update(http_method=None, verification_method="INPUT_CLASSIFICATION_ONLY")
        return [result]
    if module == "xss":
        if task.get("method") != "GET" or task.get("source", "query") not in ("query", "link") or SECRET_KEY.search(parameter):
            raise DataError("XSS automatico limitato a query GET osservate, senza form")
        parsed = urlsplit(url)
        pairs = parse_qsl(parsed.query, keep_blank_values=True)
        if not parameter or parameter not in [key for key, _ in pairs]:
            raise DataError("Parametro GET assente dall'URL")
        baseline = client.get(url, cache=False)
        marker = "xitool_" + uuid.uuid4().hex
        probe = marker + "<'\""
        changed = [(key, probe if key == parameter else val) for key, val in pairs]
        probe_url = urlunsplit((parsed.scheme, parsed.netloc, parsed.path, urlencode(changed), ""))
        response = client.get(probe_url, cache=False)
        repeat = client.get(probe_url, cache=False)
        reflected = marker in response.body and marker not in baseline.body
        unescaped = probe in response.body
        html = "html" in response.headers.get("content-type", "").lower()
        comparable = baseline.status == response.status == repeat.status == 200 and not any(row.truncated for row in (baseline, response, repeat))
        stable = probe in repeat.body and repeat.status == response.status
        status = "POTENTIAL" if reflected and unescaped and html and comparable and stable else "OBSERVED"
        position = response.body.find(marker)
        prefix = response.body[max(0, position - 500):position] if position >= 0 else ""
        if "json" in response.headers.get("content-type", "").lower():
            context = "json"
        elif prefix.lower().rfind("<script") > prefix.lower().rfind("</script"):
            context = "javascript_heuristic"
        elif prefix.rfind("<") > prefix.rfind(">"):
            context = "html_attribute_heuristic"
        else:
            context = "html_text" if html else "other"
        return [finding(module, url, "reflection", status,
                        {"reflected": reflected, "unescaped_characters": unescaped, "content_type_html": html,
                         "context_hint": context, "baseline_status": baseline.status, "probe_status": response.status,
                         "repeat_status": repeat.status, "stable_unescaped_reflection": stable,
                         "html_encoding_observed": escape(probe, quote=True) in response.body,
                         "body_truncated": any(row.truncated for row in (baseline, response, repeat)), "javascript_encoding_observed": "\\u003c" in response.body.lower() or "\\x3c" in response.body.lower(),
                         "url_attribute_context_hint": bool(re.search(r"(?:href|src|action)\s*=\s*[\"'][^\"']*$", prefix, re.I)) if position >= 0 else False,
                         "browser_verification": "UNSUPPORTED"},
                        "Marcatore inerte; nessun browser eseguito. Una riflessione non dimostra XSS. Contesto euristico.", parameter)]
    response = client.get(url)
    headers = response.headers
    if module == "sqli":
        # Nessuna quote, condizione SQL, ritardo o payload: confronta solo GET invariati.
        signatures = {"postgresql": r"(?:SQLSTATE\[|PostgreSQL[^\n]{0,80}ERROR|psycopg\w*\.errors)",
                      "mysql": r"(?:You have an error in your SQL syntax|mysql_fetch_\w+|mysqli?_sql_exception)",
                      "sqlite": r"(?:sqlite3?\.OperationalError|SQLiteException|SQLITE_ERROR)",
                      "mssql": r"(?:Unclosed quotation mark after the character string|System\.Data\.SqlClient\.SqlException)",
                      "oracle": r"\bORA-\d{5}\b"}
        first = sorted(name for name, pattern in signatures.items() if re.search(pattern, response.body, re.I))
        repeated = client.get(url, cache=False)
        stable = sorted(name for name in first if re.search(signatures[name], repeated.body, re.I)) if repeated else []
        return [finding(module, url, "database_error_observation", "MANUAL_REVIEW" if stable else "OBSERVED",
                        {"error_families": first, "repeat_error_families": stable, "baseline_status": response.status,
                         "repeat_status": repeated.status, "input_modified": False,
                         "response_stable": response.status == repeated.status and fingerprint(response.body) == fingerprint(repeated.body),
                         "baseline_body_sha256": fingerprint(response.body), "repeat_body_sha256": fingerprint(repeated.body)},
                        "Errore database osservato con GET invariato: non dimostra SQL injection. Nessun payload o estrazione.")]
    if module == "misconfiguration":
        expected = ["content-security-policy", "x-content-type-options", "referrer-policy"]
        if urlsplit(response.url).scheme == "https":
            expected.append("strict-transport-security")
        return [finding(module, url, "security_headers", "OBSERVED",
                        {"missing_headers": [h for h in expected if h not in headers], "status": response.status,
                         "https": response.url.startswith("https:"), "body_truncated": response.truncated,
                         "directory_listing_hint": bool(re.search(r"<title>Index of /", response.body, re.I)),
                         "nosniff": headers.get("x-content-type-options", "").lower() == "nosniff",
                         "hsts_max_age_present": bool(re.search(r"(?:^|;)\s*max-age=\d+", headers.get("strict-transport-security", ""), re.I)),
                         "csp_present": "content-security-policy" in headers,
                         "csp_unsafe_inline": "'unsafe-inline'" in headers.get("content-security-policy", ""),
                         "version_header_hint": any(re.search(r"\d+\.\d+", headers.get(key, "")) for key in ("server", "x-powered-by")),
                         "tls": response.tls, "cookies": cookie_attributes(headers),
                         "tls_coverage": "NEGOTIATED_CONNECTION_ONLY",
                         "permissions_policy": {"applicability": "DOCUMENT" if "html" in headers.get("content-type", "").lower() else "NOT_ASSESSED_NON_DOCUMENT",
                                                "present": "permissions-policy" in headers,
                                                "empty": "permissions-policy" in headers and not headers["permissions-policy"].strip()},
                         "hsts_disabled": bool(re.search(r"(?:^|;)\s*max-age=0(?:;|$)", headers.get("strict-transport-security", ""), re.I)),
                         "referrer_policy_recognized": headers.get("referrer-policy", "").strip().lower() in {"no-referrer", "same-origin", "strict-origin", "strict-origin-when-cross-origin", "origin", "origin-when-cross-origin", "no-referrer-when-downgrade", "unsafe-url"},
                         "https_downgrade_observed": any(row["url"].startswith("https:") and row["destination"].startswith("http:") for row in response.redirects),
                         "cache_control_present": "cache-control" in headers,
                         "redirect_http_to_https_observed": any(row["url"].startswith("http:") and row["destination"].startswith("https:") for row in response.redirects)},
                        "Header mancanti e firme HTML richiedono contesto. Certificato TLS validato dal sistema; nessun audit TLS completo.")]
    if module == "authentication":
        from .cookie_policy import attributes
        cookies = attributes(headers)
        return [finding(module, url, "cookie_attributes", "MANUAL_REVIEW" if cookies else "OBSERVED",
                        {"cookies": cookies, "authentication_required_hint": response.status in (401, 403),
                         "status": response.status, "cache_no_store": "no-store" in headers.get("cache-control", "").lower(),
                         "session_profile_configured": client.profile is not None,
                         "session_state": session_state(response),
                         "login_redirect_hint": any(re.search(r"/(?:login|signin)(?:/|$)", urlsplit(row["destination"]).path, re.I) for row in response.redirects) or bool(re.search(r"/(?:login|signin)(?:/|$)", urlsplit(response.url).path, re.I))},
                        "Attributi della risposta: un eventuale profilo selezionato non dimostra da solo una sessione valida.")]
    if module == "sensitive":
        from .signatures import SIGNATURES, CATALOG_VERSION
        signatures = SIGNATURES
        counts = {name: len(set(re.findall(pattern, response.body))) for name, pattern in signatures.items()}
        def placeholder(value):
            return len(set(value)) <= 3 or bool(re.search(r"example|placeholder|changeme|your[_-]|dummy", value, re.I))
        for name in ("github_token_shape", "github_fine_grained_shape"):
            counts[name] = sum(not placeholder(value.split("_", 1)[-1]) for value in set(re.findall(signatures[name], response.body)))
        aws_values = set(re.findall(signatures["aws_access_key_shape"], response.body))
        assignments = set(re.findall(r'''(?i)(?:api[_-]?key|secret|access_token)\s*[=:]\s*["']([A-Za-z0-9_/-]{20,})["']''', response.body))
        ignored = sum(placeholder(value) for value in list(aws_values) + list(assignments))
        counts["aws_access_key_shape"] = sum(not placeholder(value) for value in aws_values)
        counts["secret_assignment"] = sum(not placeholder(value) for value in assignments)
        candidates = re.findall(r'''(?i)(?:secret|token|api[_-]?key)\s*[=:]\s*["']([A-Za-z0-9_/-]{24,200})["']''', response.body)[:256]
        counts["high_entropy_assignment"] = sum(
            -sum((value.count(char) / len(value)) * math.log2(value.count(char) / len(value)) for char in set(value)) >= 3.5
            for value in set(candidates) if not placeholder(value))
        configuration_reference = bool(re.search(r'''["'](?:[^"']*/)?(?:\.env|config\.(?:ya?ml|json)|credentials\.[a-z]+)["']''', response.body, re.I))
        return [finding(module, url, "public_secret_patterns", "MANUAL_REVIEW" if any(counts.values()) else "OBSERVED",
                        {"catalog_version": CATALOG_VERSION, "pattern_counts": counts, "values": "[REDACTED]", "body_truncated": response.truncated,
                         "status": response.status,
                         "configuration_reference_hint": configuration_reference, "ignored_placeholder_count": ignored},
                        "Firme limitate, possibili esempi o dati di test; nessuna credenziale viene utilizzata o salvata.")]
    if module == "cors":
        origin = "https://xitool.invalid"
        tested = client.get(url, {"Origin": origin}, cache=False)
        allowed = tested.headers.get("access-control-allow-origin", "")
        credentials = tested.headers.get("access-control-allow-credentials", "").lower() == "true"
        suspicious = allowed == origin and credentials
        second_origin = "https://second.xitool.invalid"
        second = client.get(url, {"Origin": second_origin}, cache=False)
        preflight = client.preflight(url, origin)
        repeated = second.headers.get("access-control-allow-origin") == second_origin and second.headers.get("access-control-allow-credentials", "").lower() == "true"
        comparable = all(200 <= row.status < 300 and not row.truncated for row in (response, tested, second))
        return [finding(module, url, "cors_policy", "POTENTIAL" if suspicious and repeated and comparable else "OBSERVED",
                        {"test_origin_reflected": allowed == origin, "wildcard": allowed == "*", "credentials": credentials,
                         "baseline_allow_origin_present": "access-control-allow-origin" in headers,
                         "second_origin_reflected_with_credentials": repeated,
                         "vary_origin": "origin" in [part.strip().lower() for part in tested.headers.get("vary", "").split(",")],
                         "probe_status": tested.status, "second_probe_status": second.status,
                         "responses_comparable": comparable,
                         "public_wildcard_policy_observed": allowed == "*" and not credentials,
                         "preflight_status": preflight.status,
                         "preflight_get_allowed": "GET" in [part.strip().upper() for part in preflight.headers.get("access-control-allow-methods", "").split(",")],
                         "browser_verification": "UNSUPPORTED"},
                        "Nessuna prova di lettura di dati autenticati nel browser; wildcard da sola non è una vulnerabilità.")]
    raise DataError("Modulo non implementato")
