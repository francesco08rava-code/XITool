"""Adapter CT per crt.sh e CertSpotter, autorizzati dall'operatore."""
from __future__ import annotations

import copy
import ipaddress
import json
import os
import re
import time
from urllib.parse import urlencode

from .http import HTTPClient, NetworkError
from .scope import Scope, normalize_host
from .storage import DataError, utcnow
from .sessions import Profile

PROVIDERS = {"crtsh": ("crt.sh", "https://crt.sh/?"),
             "certspotter": ("api.certspotter.com", "https://api.certspotter.com/v1/issuances?")}


def passive_tasks(root: str) -> list[dict]:
    root = normalize_host(root)
    try:
        ipaddress.ip_address(root)
        return []
    except ValueError:
        if "." not in root:
            return []
    return [{"url": f"https://{root}/", "kind": "passive", "provider": name} for name in PROVIDERS]


def collect(provider: str, root: str, config: dict, limiter) -> dict:
    """Invia il dominio solo ai due endpoint fissi; nessun redirect di provider."""
    if provider not in PROVIDERS:
        raise DataError("Fonte passiva sconosciuta")
    started = time.monotonic()
    root = normalize_host(root)
    if provider not in config.get("discovery", {}).get("ct_providers", list(PROVIDERS)):
        return {"provider": provider, "root": root, "queried_at": utcnow(), "status": "DISABLED", "legacy_status": "DISABLED",
                "hosts": [], "wildcard_certificates": [], "errors": [], "requests": 0, "attempts": 0, "duplicates": 0,
                "pages": 0, "pages_requested": 0, "pages_completed": 0, "raw_results": 0, "unique_results": 0,
                "seed_excluded": 0, "complete": False, "empty_success": False, "availability": "NOT_CHECKED",
                "response_time_seconds": 0, "limits": [], "error_category": None}
    host, endpoint = PROVIDERS[provider]
    settings = copy.deepcopy(config)
    settings["http"].update(max_retries=min(1, settings["http"]["max_retries"]), max_redirects=0, allowed_ports=[443])
    client = HTTPClient(Scope([host], []), settings)
    client.limiter = limiter
    shared = vars(limiter)
    if shared.get("request_budget") is not None:
        client.budget = shared["request_budget"]
        client.host_limiters = shared.get("shared_host_limiters", {})
    if provider == "certspotter" and os.environ.get("XITOOL_CERTSPOTTER_AUTH"):
        client = client.for_profile(Profile("certspotter", "https://api.certspotter.com/", "provider", {"Authorization": "XITOOL_CERTSPOTTER_AUTH"}))
    result = {"provider": provider, "queried_at": utcnow(), "root": root, "hosts": [],
              "wildcard_certificates": [], "errors": [], "pages_requested": 0, "pages_completed": 0, "available": None, "pages": 0, "raw_results": 0, "complete": False}
    names, wildcards = set(), set()
    cursor, cursors = "", set()
    duplicates = 0
    terminal_category = None
    limit = config["execution"]["max_tasks"]
    for _ in range(3 if provider == "certspotter" else 1):
        params = ({"q": "%." + root, "output": "json"} if provider == "crtsh" else
                  {"domain": root, "include_subdomains": "true", "expand": "dns_names"})
        if cursor:
            params["after"] = cursor
        result["pages_requested"] += 1
        try:
            response = client.get(endpoint + urlencode(params), cache=False)
            result["available"] = True
            from .errors import status_category
            terminal_category = status_category(response.status)
            if response.status != 200 or response.truncated:
                raise DataError(f"HTTP_{response.status}" if response.status != 200 else "RESPONSE_LIMIT")
            data = json.loads(response.body)
            if not isinstance(data, list) or any(not isinstance(row, dict) for row in data):
                raise DataError("PROVIDER_FORMAT")
            result["pages"] += 1
            result["pages_completed"] = result["pages"]
            for row in data:
                if provider == "crtsh":
                    value = row.get("name_value")
                    if not isinstance(value, str):
                        raise DataError("PROVIDER_NAMES_FORMAT")
                    values = value.splitlines()
                else:
                    values = row.get("dns_names")
                if not isinstance(values, list):
                    raise DataError("PROVIDER_NAMES_FORMAT")
                result["raw_results"] += len(values)
                for value in values:
                    if not isinstance(value, str):
                        continue
                    wildcard = value.startswith("*.")
                    try:
                        name = normalize_host(value[2:] if wildcard else value)
                    except DataError:
                        continue
                    if name != root and not name.endswith("." + root):
                        continue
                    if wildcard:
                        if len(wildcards) < limit:
                            wildcards.add("*." + name)
                    elif name in names:
                        duplicates += 1
                    elif len(names) < limit:
                        names.add(name)
                    else:
                        result["errors"].append("HOST_LIMIT")
            if provider == "crtsh" or not data:
                result["complete"] = True
                break
            cursor = data[-1].get("id")
            if not isinstance(cursor, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", cursor) or cursor in cursors:
                raise DataError("PROVIDER_CURSOR")
            cursors.add(cursor)
        except (DataError, NetworkError, json.JSONDecodeError, RecursionError) as exc:
            from .errors import classify
            terminal_category = terminal_category or ("PARSE_ERROR" if isinstance(exc, DataError) else classify(exc))
            result["errors"].append(str(exc) if isinstance(exc, DataError) else type(exc).__name__)
            break
    if not result["complete"] and not result["errors"]:
        result["errors"].append("PAGE_LIMIT")
    result.update(unique_results=len(names), seed_excluded=int(root in names), hosts=sorted(names), wildcard_certificates=sorted(wildcards), requests=client.stats["requests"])
    result["provenance"] = {"provider": provider, "endpoint": endpoint.split("?")[0], "root": root}
    result["availability"] = "RESPONDED" if result["available"] else "UNCONFIRMED"
    result["empty_success"] = bool(result["complete"] and not result["errors"] and not names)
    result["errors"] = sorted(set(result["errors"]))
    result.update(response_time_seconds=round(time.monotonic() - started, 4), status="SUCCEEDED" if result["complete"] and not result["errors"] else "PARTIAL" if result["hosts"] else "FAILED", limits=[error for error in result["errors"] if error.endswith("LIMIT")])
    result["legacy_status"] = result["status"]
    result["status"] = ("SUCCESS_EMPTY" if result["empty_success"] else "SUCCESS") if result["complete"] and not result["errors"] else "PARTIAL" if result["hosts"] else "RATE_LIMITED" if terminal_category == "HTTP_RATE_LIMIT" else "TIMEOUT" if terminal_category == "NETWORK_TIMEOUT" else "FAILED"
    result.update(attempts=client.stats["requests"], duplicates=duplicates, error_category=terminal_category)
    return result
