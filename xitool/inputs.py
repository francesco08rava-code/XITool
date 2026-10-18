"""Inventario v2: identità distinta per posizione, nessun valore di input."""
from urllib.parse import urlsplit
from .storage import fingerprint


def normalize(entry):
    row = dict(entry)
    location = row.get("location") or ("body" if row.get("source") == "form" and row["method"].upper() == "POST" else "query")
    row.update(schema_version=2, method=row["method"].upper(), location=location)
    identity = [row.get("project"), row.get("domain", row.get("host") or urlsplit(row["url"]).hostname),
                row["url"], row["method"], location, row["parameter"]]
    row["input_id"] = fingerprint(identity)[:24]
    row.setdefault("reachability", "NOT_VERIFIED")
    row.setdefault("provenance", [row.get("source", "legacy")])
    row.setdefault("observed_types", [row.get("input_type", "unknown")])
    row.setdefault("first_seen", row.get("timestamp"))
    row.setdefault("last_seen", row.get("timestamp"))
    # Values are intentionally never part of this interface.
    for key in ("value", "default", "example", "examples", "cookie_value"):
        row.pop(key, None)
    return row


def merge(entries):
    selected = {}
    priority = {"query": 2, "link": 1, "form": 0}
    for value in entries:
        row = normalize(value)
        key = row["input_id"]
        old = selected.get(key)
        if old:
            sources = sorted(set(old["provenance"]) | set(row["provenance"]))
            types = sorted(set(old["observed_types"]) | set(row["observed_types"]))
            observations = [value for value in (old.get("first_seen"), old.get("last_seen"), row.get("first_seen"), row.get("last_seen")) if isinstance(value, str)]
            if priority.get(row.get("source"), 0) < priority.get(old.get("source"), 0):
                row = old
            row["provenance"] = sources
            row["observed_types"] = types
            if observations:
                row["first_seen"], row["last_seen"] = min(observations), max(observations)
        selected[key] = row
    return list(selected.values())
