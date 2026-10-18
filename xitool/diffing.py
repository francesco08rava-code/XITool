"""Diff conservativo; una mancata osservazione non è una risoluzione."""
from .storage import atomic_write, save_json


def semantic(value):
    volatile = {"timestamp", "first_seen", "last_seen", "run_id", "request_ids", "request_id", "nonce", "correlation_id", "received_at", "elapsed_seconds", "duration_seconds"}
    if isinstance(value, dict):
        return {key: semantic(item) for key, item in value.items() if key not in volatile}
    if isinstance(value, list):
        return [semantic(item) for item in value]
    return value


def finding_semantic(row):
    from .assessment import canonical_resource
    result = semantic(row)
    result.pop("id", None)
    for key in ("url", "resource"):
        if key in result:
            result[key] = canonical_resource(result[key])
    return result


def extend_diff(result, before, after):
    def complete(state):
        metadata = state.get("provider_metadata", [])
        sources = state.get("module") != "subfinding" or {row.get("provider") for row in metadata} >= {"crtsh", "certspotter"}
        return (state.get("status") == "COMPLETED" and not state.get("errors") and not state.get("limits_reached")
                and sources and all(row.get("complete") and not row.get("errors") for row in metadata))
    result["comparable"] = not result["scope_changed"] and not result["config_changed"] and before.get("engine_version") == after.get("engine_version")
    result["comparison_complete"] = bool(complete(before) and complete(after) and result["comparable"])
    result["absence_interpretation"] = "NOT_OBSERVED_NOT_PROVEN_REMOVED"
    old = {row.get("issue_fingerprint", row["id"]): row for row in before["results"]}
    new = {row.get("issue_fingerprint", row["id"]): row for row in after["results"]}
    result["finding_details"] = {
        "new": [new[key] for key in sorted(new.keys() - old.keys())],
        "still_present": sorted(new.keys() & old.keys()),
        "not_reproduced": [old[key] for key in sorted(old.keys() - new.keys())],
        "verified": [key for key in sorted(new) if new[key].get("status") == "VERIFIED"],
        "modified": result["results"]["changed"],
    }
    def endpoints(state):
        values = {url: {"methods": {"GET"}, "parameters": set()} for url in state.get("endpoints", [])}
        for row in state.get("inputs", []):
            entry = values.setdefault(row["url"], {"methods": set(), "parameters": set()})
            entry["methods"].add(row["method"])
            entry["parameters"].add(row["parameter"])
        return values
    previous, current = endpoints(before), endpoints(after)
    changed = []
    for url in sorted(previous.keys() | current.keys()):
        left, right = previous.get(url, {"methods": set(), "parameters": set()}), current.get(url, {"methods": set(), "parameters": set()})
        if left != right:
            changed.append({"url": url, "new_methods": sorted(right["methods"] - left["methods"]),
                            "not_observed_methods": sorted(left["methods"] - right["methods"]),
                            "new_parameters": sorted(right["parameters"] - left["parameters"]),
                            "not_observed_parameters": sorted(left["parameters"] - right["parameters"])})
    result["changed_endpoints"] = changed
    seeds = set(before.get("seed_hosts", [])) | set(after.get("seed_hosts", [])) | {before.get("domain"), after.get("domain")}
    result["new_subdomains"] = sorted(set(after["hosts"]) - set(before["hosts"]) - seeds)
    old_dns, new_dns = before.get("dns_records", {}), after.get("dns_records", {})
    def dns_value(row):
        return {key: sorted(row.get(key, [])) for key in ("A", "AAAA", "CNAME")}
    result["dns_changes"] = [{"host": host, "before": dns_value(old_dns[host]), "after": dns_value(new_dns[host]),
                              "after_status": new_dns[host].get("resolution_status"),
                              "interpretation": "OBSERVED_CHANGE_NOT_PROVEN_REMOVAL"}
                             for host in sorted(old_dns.keys() & new_dns.keys()) if dns_value(old_dns[host]) != dns_value(new_dns[host])]
    result["reachability_changes"] = {"newly_observed": sorted(set(after.get("live_hosts", [])) - set(before.get("live_hosts", []))),
                                      "not_observed": sorted(set(before.get("live_hosts", [])) - set(after.get("live_hosts", [])))}
    def apis(state):
        return {(row["url"], row.get("method", "GET")): semantic({"parameters": row.get("parameters", []), "template": row.get("template", False)})
                for row in state.get("url_references", []) if row.get("source") == "openapi_document" and row.get("method")}
    left, right = apis(before), apis(after)
    result["api_changes"] = [{"url": key[0], "method": key[1], "before": left.get(key), "after": right.get(key),
                              "interpretation": "DECLARATION_CHANGE_NOT_REACHABILITY_PROOF"}
                             for key in sorted(left.keys() | right.keys()) if left.get(key) != right.get(key)]
    return result


def export_diff(directory, value):
    directory.mkdir(parents=True, exist_ok=True)
    atomic_write(directory / "new_subdomains.txt", "".join(host + "\n" for host in value["new_subdomains"]))
    save_json(directory / "changed_endpoints.json", value["changed_endpoints"])
    save_json(directory / "new_findings.json", value["finding_details"]["new"])
    save_json(directory / "unresolved_findings.json", value["finding_details"]["not_reproduced"])
    save_json(directory / "diff.json", value)
    save_json(directory / "dns_changes.json", value.get("dns_changes", []))
    save_json(directory / "api_changes.json", value.get("api_changes", []))
    atomic_write(directory / "diff_report.md", f"# Scan Diff\n\n{value['before']} → {value['after']}\n\nConfronto completo: {value['comparison_complete']}\n\nNuovi sottodomini: {len(value['new_subdomains'])}; nuovi finding: {len(value['finding_details']['new'])}.\n\nFinding non riprodotti restano da verificare; nessuna risoluzione automatica.\n")
