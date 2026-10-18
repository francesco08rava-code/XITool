"""Viste compatibili del crawler, derivate dalla stessa run di ricognizione."""
from urllib.parse import urlsplit
from .storage import atomic_write, save_json


def export(directory, state):
    directory.mkdir(parents=True, exist_ok=True)
    references = state.get("url_references", [])
    verified = set(state.get("endpoints", [])) | {row["url"] for row in references if row.get("kind") == "OBSERVED_NETWORK" and row.get("reached")}
    historical = {row["url"] for row in references if row.get("kind") == "HISTORICAL"}
    discovered = {row["url"] for row in references} | verified
    forms = [row for row in references if row.get("kind") == "OBSERVED_FORM"]
    apis = [row for row in references if "api" in row.get("source", "") or row.get("resource_type") in ("fetch", "xhr")]
    javascript = [row for row in references if row.get("source") == "javascript_literal"]
    parameters = list(state.get("inputs", [])) + [{**row, "method": "GET", "verification_status": "OBSERVED_VALUE_NOT_RECORDED"} for row in references if row.get("kind") == "OBSERVED_RESPONSE_METADATA"]
    for name, values in (("discovered_urls.txt", discovered), ("verified_urls.txt", verified), ("historical_urls.txt", historical)):
        atomic_write(directory / name, "".join(url + "\n" for url in sorted(values)))
    for name, value in (("forms.json", forms), ("parameters.json", parameters),
                        ("api_endpoints.json", apis), ("javascript_endpoints.json", javascript),
                        ("crawl_summary.json", {"discovered": len(discovered), "verified": len(verified), "historical": len(historical),
                         "forms": len(forms), "parameters": len(state.get("inputs", [])), "errors": len(state.get("errors", [])),
                         "limits": state.get("limits_reached", []), "run_status": state["status"],
                         "complete": state["status"] == "COMPLETED" and not state.get("errors") and not state.get("limits_reached")})):
        save_json(directory / name, value)
