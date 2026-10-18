"""Proiezioni separate della ricognizione: seed e scoperte non sono sinonimi."""
from __future__ import annotations

import re
from urllib.parse import urlsplit

from .storage import utcnow


def observe_host(state: dict, scope, host: str, source: str) -> None:
    root = state.get("domain")
    if root and host != root and not host.endswith("." + root):
        return
    observations = state.setdefault("host_observations", {})
    limit = state.get("host_limit", 1000)
    if host not in observations and len(observations) >= limit:
        state.setdefault("limits_reached", []).append("host_limit")
        return
    entry = observations.setdefault(host, {"host": host, "sources": [], "first_seen": utcnow()})
    entry["last_seen"] = utcnow()
    entry["authorized"] = scope.allowed(host)
    if source not in entry["sources"]:
        entry["sources"].append(source)


def probe_metadata(response, scope) -> dict:
    title = re.search(r"<title\b[^>]*>(.*?)</title\s*>", response.body, re.I | re.S)
    # Il titolo può contenere dati personali: si conserva solo la presenza.
    return {"url": response.url, "status": response.status, "error_category": getattr(response, "error_category", None),
            "elapsed_seconds": getattr(response, "elapsed_seconds", None), "request_id": getattr(response, "request_id", None),
            "redirects": getattr(response, "redirects", []), "title_present": bool(title),
            "technology_headers": [key for key in ("server", "x-powered-by") if key in response.headers],
            "truncated": response.truncated, "content_type": response.headers.get("content-type", "").partition(";")[0],
            "body_bytes_retained": len(response.body.encode("utf-8")), "tls": response.tls}


def outputs(state: dict, scope) -> tuple[dict, dict]:
    seed_hosts = set(state.get("seed_hosts", []))
    if state.get("domain"):
        seed_hosts.add(state["domain"])
    observations = state.get("host_observations", {})
    observations = {host: {**entry, "authorized": scope.allowed(host)} for host, entry in observations.items()}
    resolved = {host for host, row in state.get("dns_records", {}).items() if row.get("resolved")}
    attempted = {urlsplit(row.get("url", "")).hostname for row in state.get("errors", []) if row.get("url") and row.get("stage") == "http"}
    for host, entry in observations.items():
        states = ["SEED" if host in seed_hosts else "DISCOVERED"]
        if not entry["authorized"]:
            states.append("OUT_OF_SCOPE")
        else:
            if host in state.get("dns_records", {}):
                states.append("DNS_RESOLVED" if host in resolved else "DNS_FAILED")
            if host in state["live_hosts"]:
                states.append("HTTP_REACHABLE")
            elif host in attempted:
                states.append("HTTP_UNREACHABLE")
        entry["states"] = states
        entry["dns"] = state.get("dns_records", {}).get(host)
        entry["seed"] = host in seed_hosts
    discovered = set(observations) - seed_hosts
    # Per run precedenti non attribuire retroattivamente provenienze mai registrate.
    if not observations:
        discovered = set(state["hosts"]) - seed_hosts
    root = state.get("domain")
    if root:
        discovered = {host for host in discovered if host.endswith("." + root)}
    live = set(state["live_hosts"])
    metadata = state.get("provider_metadata", [])
    unavailable = sorted({entry["provider"] for entry in state.get("provider_errors", [])})
    complete = (state.get("status") == "COMPLETED" and len({row["provider"] for row in metadata}) == 2
                and all(row.get("complete") and not row.get("errors") for row in metadata)
                and not state.get("limits_reached") and not state.get("errors"))
    texts = {"initial_domains.txt": sorted(seed_hosts), "all_subdomains.txt": sorted(discovered),
             "reached_urls.txt": state["endpoints"],
             "live_subdomains.txt": sorted(discovered & live), "http_reachable_hosts.txt": sorted(live),
             "resolved_hosts.txt": sorted(host for host, row in state.get("dns_records", {}).items() if row.get("resolved")),
             "out_of_scope_hosts.txt": sorted(host for host in discovered if not scope.allowed(host)),
             "authorized_hosts.txt": sorted(host for host in seed_hosts | discovered if scope.allowed(host)),
             "domains_with_inputs.txt": sorted({entry["host"] for entry in state["inputs"]})}
    detail = {"discovered_inputs.json": state["inputs"], "host_observations.json": observations,
              "url_references.json": [{**row, "reached": row["url"] in state["endpoints"] or (row.get("kind") == "OBSERVED_NETWORK" and bool(row.get("reached")))} for row in state.get("url_references", [])],
              "dns_records.json": state.get("dns_records", {}), "http_probes.json": state.get("http_probes", []),
              "provider_metadata.json": state.get("provider_metadata", []),
              "provider_errors.json": state.get("provider_errors", []),
              "summary.json": {"new_subdomains": len(discovered), "initial_hosts": len(seed_hosts),
                               "http_reachable": len(live), "dns_resolved": len(texts["resolved_hosts.txt"]),
                               "out_of_scope": len(texts["out_of_scope_hosts.txt"]),
                               "message": f"{len(discovered)} nuovi sottodomini scoperti" + (" — raccolta incompleta o non verificata" if not complete else ""),
                               "collection_complete": complete, "unavailable_sources": unavailable,
                               "raw_provider_results": sum(row.get("raw_results", 0) for row in metadata),
                               "unique_observed_hosts": len(observations), "seed_excluded": len(seed_hosts & set(observations)),
                               "successful_sources": sorted({row["provider"] for row in metadata if row.get("complete") and not row.get("errors")}),
                               "wildcard_dns": state.get("wildcard_dns", {"tested": False}),
                               "passive_sources_queried": sorted({item["provider"] for item in state.get("provider_metadata", [])})}}
    texts.update({"seed_domains.txt": texts["initial_domains.txt"], "discovered_subdomains.txt": texts["all_subdomains.txt"],
                  "resolved_subdomains.txt": sorted(discovered & resolved), "out_of_scope.txt": texts["out_of_scope_hosts.txt"]})
    detail.update({"providers.json": detail["provider_metadata.json"], "dns_results.json": detail["dns_records.json"]})
    return texts, detail
