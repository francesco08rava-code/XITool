"""Discovery statica e controlli conservativi; nessuna esecuzione JavaScript."""
from __future__ import annotations

from html.parser import HTMLParser
import re
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit
import uuid

from .http import HTTPClient, Response
from .scope import Scope
from .storage import DataError, fingerprint, utcnow


MODULES = {
    "subfinding": ("SUB FINDING", "PARTIAL"),
    "xss": ("XSS", "PARTIAL"),
    "sqli": ("SQL INJECTION", "NOT_IMPLEMENTED"),
    "idor": ("IDOR", "PARTIAL"),
    "access": ("BROKEN ACCESS CONTROL", "NOT_IMPLEMENTED"),
    "ssrf": ("SSRF", "PARTIAL"),
    "traversal": ("PATH TRAVERSAL", "PARTIAL"),
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
    if MUTATIVE.search(parsed.path) or any(SECRET_KEY.search(key) for key, _ in parse_qsl(parsed.query)):
        raise DataError("URL sensibile o potenzialmente mutativo escluso")
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
        for name, _ in parse_qsl(urlsplit(url).query, keep_blank_values=True):
            self.add_input(url, "GET", name, "text", "query")

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
                            "source": source, "timestamp": utcnow()})

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attributes = dict(attrs)
        if tag in ("a", "script", "iframe", "link"):
            target = attributes.get("href") or attributes.get("src")
            if target and len(self.links) < 1000:
                try:
                    self.links.add(safe_url(self.scope, urljoin(self.url, target)))
                except DataError:
                    pass
        if tag == "form":
            method = (attributes.get("method") or "GET").upper()
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


def discover(scope: Scope, response: Response) -> tuple[list[dict], list[str]]:
    parser = Discovery(scope, response.url)
    content_type = response.headers.get("content-type", "").lower()
    if "html" in content_type:
        parser.feed(response.body)
        parser.close()
    elif "javascript" in content_type:
        # Solo riferimenti letterali, senza valutazione del codice scaricato.
        for target in re.findall(r'''["']((?:https?://|/)[^\s"'<>]{1,2048})["']''', response.body):
            if len(parser.links) >= 1000:
                break
            try:
                parser.links.add(safe_url(scope, urljoin(response.url, target)))
            except DataError:
                continue
    for target in parser.links:
        for name, _ in parse_qsl(urlsplit(target).query, keep_blank_values=True):
            parser.add_input(target, "GET", name, "text", "link")
    unique = {fingerprint([v["url"], v["method"], v["parameter"]]): v for v in parser.inputs}
    return list(unique.values()), sorted(parser.links)


def finding(module: str, url: str, check: str, status: str, evidence: dict, limitation: str, parameter: str = "") -> dict:
    return {"id": fingerprint([module, url, check, parameter])[:24], "module": module,
            "url": url, "host": urlsplit(url).hostname, "parameter": parameter,
            "check": check, "status": status, "evidence": evidence,
            "limitations": limitation, "timestamp": utcnow(),
            "manual_review": status in ("POTENTIAL", "MANUAL_REVIEW")}


def smart(inputs: list[dict], urls: list[str]) -> dict[str, int]:
    proposals: dict[str, int] = {}
    mapping = {"identifier": "idor", "url": "ssrf", "file": "traversal", "authentication": "authentication", "text": "xss"}
    for entry in inputs:
        module = mapping.get(entry.get("input_type"), "xss")
        if module == "xss" and (entry.get("method") != "GET" or entry.get("source") == "form"):
            continue
        proposals[module] = proposals.get(module, 0) + 1
    for module in ("cors", "misconfiguration", "authentication", "sensitive"):
        if urls:
            proposals[module] = proposals.get(module, 0) + len(urls)
    return proposals


def scan(module: str, task: dict, client: HTTPClient) -> list[dict]:
    """Mantiene osservazioni, candidati e prove confermate semanticamente distinti."""
    url = safe_url(client.scope, task["url"])
    parameter = task.get("parameter", "")
    if module in ("idor", "ssrf", "traversal"):
        return [finding(module, url, "input_candidate", "MANUAL_REVIEW", {"input_type": task.get("input_type"), "method": task.get("method")},
                        "Solo classificazione dell'input; preparare account o fixture autorizzate per la verifica.", parameter)]
    if module == "xss":
        if task.get("method") != "GET" or task.get("source") == "form" or SECRET_KEY.search(parameter):
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
        reflected = marker in response.body and marker not in baseline.body
        unescaped = probe in response.body
        html = "html" in response.headers.get("content-type", "").lower()
        comparable = baseline.status == response.status == 200
        status = "POTENTIAL" if reflected and unescaped and html and comparable else "OBSERVED"
        position = response.body.find(marker)
        prefix = response.body[max(0, position - 500):position] if position >= 0 else ""
        context = "script" if prefix.rfind("<script") > prefix.rfind("</script") else "markup_or_text"
        return [finding(module, url, "reflection", status,
                        {"reflected": reflected, "unescaped_characters": unescaped, "content_type_html": html,
                         "context_hint": context, "baseline_status": baseline.status, "probe_status": response.status},
                        "Marcatore inerte; nessun browser eseguito. Una riflessione non dimostra XSS. Contesto euristico.", parameter)]
    response = client.get(url)
    headers = response.headers
    if module == "misconfiguration":
        expected = ["content-security-policy", "x-content-type-options", "referrer-policy"]
        if urlsplit(response.url).scheme == "https":
            expected.append("strict-transport-security")
        return [finding(module, url, "security_headers", "OBSERVED",
                        {"missing_headers": [h for h in expected if h not in headers], "status": response.status,
                         "https": response.url.startswith("https:"), "body_truncated": response.truncated,
                         "directory_listing_hint": bool(re.search(r"<title>Index of /", response.body, re.I))},
                        "Header mancanti e firme HTML richiedono contesto. Certificato TLS validato dal sistema; nessun audit TLS completo.")]
    if module == "authentication":
        cookies = []
        for cookie in headers.get("set-cookie", "").splitlines():
            # Non salva nome, valore o contenuto della sessione.
            attrs = {part.strip().split("=", 1)[0].lower() for part in cookie.split(";")[1:]}
            cookies.append({"secure": "secure" in attrs, "httponly": "httponly" in attrs, "samesite": "samesite" in attrs})
        return [finding(module, url, "cookie_attributes", "MANUAL_REVIEW" if cookies else "OBSERVED",
                        {"cookies": cookies, "authentication_required_hint": response.status in (401, 403)},
                        "Analisi anonima degli attributi; nessun accesso account o verifica della logica di autenticazione.")]
    if module == "sensitive":
        signatures = {"private_key": r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
                      "aws_access_key_shape": r"\bAKIA[0-9A-Z]{16}\b",
                      "secret_assignment": r'''(?i)(?:api[_-]?key|secret|access_token)\s*[=:]\s*["'][A-Za-z0-9_/-]{20,}["']'''}
        counts = {name: len(re.findall(pattern, response.body)) for name, pattern in signatures.items()}
        return [finding(module, url, "public_secret_patterns", "MANUAL_REVIEW" if any(counts.values()) else "OBSERVED",
                        {"pattern_counts": counts, "values": "[REDACTED]", "body_truncated": response.truncated},
                        "Firme limitate, possibili esempi o dati di test; nessuna credenziale viene utilizzata o salvata.")]
    if module == "cors":
        origin = "https://xitool.invalid"
        tested = client.get(url, {"Origin": origin}, cache=False)
        allowed = tested.headers.get("access-control-allow-origin", "")
        credentials = tested.headers.get("access-control-allow-credentials", "").lower() == "true"
        suspicious = allowed == origin and credentials
        return [finding(module, url, "cors_policy", "POTENTIAL" if suspicious else "OBSERVED",
                        {"test_origin_reflected": allowed == origin, "wildcard": allowed == "*", "credentials": credentials,
                         "baseline_allow_origin_present": "access-control-allow-origin" in headers},
                        "Nessuna prova di lettura di dati autenticati nel browser; wildcard da sola non è una vulnerabilità.")]
    raise DataError("Modulo non implementato")
