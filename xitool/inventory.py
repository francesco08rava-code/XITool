"""Inventario statico: osservazioni documentali, mai prova di raggiungibilità."""
import re
from pathlib import Path
from urllib.parse import urljoin, urlsplit


def historical_references(project: Path, scope, root: str | None):
    """Import opzionale di un export locale: nessuna consultazione o visita automatica."""
    from .storage import DataError, confined, utcnow
    from .scope import Scope, blocked_request, normalize_host
    path = confined(project, project / "historical_urls.txt")
    if not path.exists():
        return []
    if path.stat().st_size > 1024 * 1024:
        raise DataError("Export storico oltre 1 MiB")
    result, seen = [], set()
    for line in path.read_text(encoding="utf-8").splitlines()[:1000]:
        try:
            host = urlsplit(line.strip()).hostname
            host = normalize_host(host) if host else None
            if not host or (root and host != root and not host.endswith("." + root)):
                continue
            url = Scope([host], []).url(line.strip())
            if blocked_request(url) or url in seen:
                continue
            seen.add(url)
            result.append({"url": url, "kind": "HISTORICAL", "source": "operator_local_export",
                           "scope_status": "AUTHORIZED" if scope.allowed(host) else "OUT_OF_SCOPE",
                           "timestamp": utcnow(), "reached": False})
        except (DataError, ValueError):
            continue
    return result


def javascript_targets(body):
    try:
        from .javascript import targets
        return targets(body)
    except ImportError:
        pass
    # Analisi limitata a chiamate note e argomenti letterali; nessun eval.
    # I template interpolati, le stringhe generiche e i commenti non sono endpoint.
    body = re.sub(r"/\*[\s\S]*?\*/|(?m:^\s*//[^\n]*)", "", body)
    patterns = (
        r'''\bfetch\s*\(\s*["']([^"'\s<>]{1,2048})["']''',
        r'''\.open\s*\(\s*["'](?:GET|HEAD|OPTIONS)["']\s*,\s*["']([^"'\s<>]{1,2048})["']''',
        r'''\baxios\.get\s*\(\s*["']([^"'\s<>]{1,2048})["']''',
    )
    found = set()
    for pattern in patterns:
        for match in re.finditer(pattern, body):
            target = match.group(1)
            if "${" not in target and not target.startswith(("data:", "javascript:", "#")):
                found.add(target)
                if len(found) >= 1000:
                    return sorted(found)
    return sorted(found)


def api_references(document, base):
    if not isinstance(document, dict):
        return []
    rows = []
    if (isinstance(document.get("openapi"), str) or document.get("swagger") == "2.0") and isinstance(document.get("paths"), dict):
        servers = document.get("servers", [])
        bases = []
        if isinstance(servers, list):
            for server in servers[:10]:
                if not isinstance(server, dict) or not isinstance(server.get("url"), str):
                    continue
                value = server["url"]
                variables = server.get("variables", {})
                if isinstance(variables, dict):
                    for key, settings in list(variables.items())[:10]:
                        if isinstance(settings, dict) and isinstance(settings.get("default"), str):
                            value = value.replace("{" + key + "}", settings["default"])
                if "{" not in value:
                    bases.append(urljoin(base, value))
        if not bases and document.get("swagger") == "2.0":
            host = document.get("host", urlsplit(base).netloc)
            prefix = document.get("basePath", "/")
            schemes = document.get("schemes", [urlsplit(base).scheme])
            if isinstance(host, str) and isinstance(prefix, str) and isinstance(schemes, list):
                bases = [scheme + "://" + host + "/" + prefix.lstrip("/") for scheme in schemes[:2] if scheme in ("https", "http")]
        bases = bases or [base.rsplit("/", 1)[0] + "/"]
        # Serve a inventariare; non indovina parametri o invia operazioni.
        for path in list(document["paths"])[:500]:
            if isinstance(path, str) and path.startswith("/") and "{" not in path:
                for server in bases:
                    rows.append((server.rstrip("/") + "/" + path.lstrip("/"), "openapi_document"))
    if isinstance(document.get("data"), dict) and "__schema" in document["data"]:
        rows.append((base, "graphql_schema_observed"))
    elif urlsplit(base).path.rstrip("/").rsplit("/", 1)[-1] == "graphql" and any(key in document for key in ("data", "errors")):
        rows.append((base, "graphql_response_observed"))
    return rows


def api_operations(document, base):
    """Metodi e parametri dichiarati, inclusi template: mai inviati automaticamente."""
    if not isinstance(document, dict) or not isinstance(document.get("paths"), dict):
        return []
    if not (document.get("openapi") or document.get("swagger") == "2.0"):
        return []
    # Reuse existing server/basePath normalization with a sentinel concrete path.
    draft = dict(document, paths={"/__xitool_inventory__": {}})
    bases = [url.rsplit("/__xitool_inventory__", 1)[0] for url, _ in api_references(draft, base)]
    rows = []
    methods = {"get", "head", "options", "post", "put", "patch", "delete", "trace"}
    for path, item in list(document["paths"].items())[:500]:
        if not isinstance(path, str) or not path.startswith("/") or not isinstance(item, dict):
            continue
        for method, operation in item.items():
            if method not in methods or not isinstance(operation, dict):
                continue
            parameters = []
            common = item.get("parameters", [])
            local = operation.get("parameters", [])
            for parameter in (common if isinstance(common, list) else []) + (local if isinstance(local, list) else []):
                if not isinstance(parameter, dict) or not isinstance(parameter.get("name"), str):
                    continue
                if parameter.get("in") in ("path", "query", "header", "cookie", "body", "formData"):
                    parameters.append({"name": parameter["name"][:200], "location": parameter["in"],
                                       "required": parameter.get("required") is True})
            request = operation.get("requestBody", {})
            content = request.get("content", {}) if isinstance(request, dict) else {}
            if isinstance(content, dict):
                for mime, description in list(content.items())[:5]:
                    schema = description.get("schema", {}) if isinstance(description, dict) else {}
                    properties = schema.get("properties", {}) if isinstance(schema, dict) else {}
                    if isinstance(properties, dict):
                        parameters.extend({"name": str(name)[:200], "location": "json" if "json" in mime else "body", "required": False}
                                          for name in list(properties)[:100])
            for server in bases:
                rows.append({"url": server + path, "method": method.upper(), "parameters": parameters[:200],
                             "template": "{" in path, "source": "openapi_document", "kind": "OBSERVED_API_DOCUMENT",
                             "reached": False, "request_input_confirmed": False})
                if len(rows) >= 1000:
                    return rows
    return rows
