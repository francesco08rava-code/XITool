"""Esito tecnico distinto da COMPLETED, che indica soltanto l'elaborazione della coda."""
from collections import Counter

OUTCOMES = {"NO_ISSUES_OBSERVED", "NO_INPUT", "FAILED", "UNSUPPORTED", "PARTIAL", "POTENTIAL", "VERIFIED", "MANUAL_REVIEW"}


def result_outcome(result: dict) -> str:
    explicit = result.get("verification_outcome")
    if explicit in OUTCOMES:
        return explicit
    status = result.get("status")
    if status in OUTCOMES:
        return status
    evidence, check = result.get("evidence", {}), result.get("check")
    negative = ((check == "reflection" and evidence.get("reflected") is False) or
                (check == "database_error_observation" and not evidence.get("error_families")) or
                (check == "public_secret_patterns" and not any(evidence.get("pattern_counts", {}).values())))
    status_code = evidence.get("baseline_status", evidence.get("status", 200))
    successful = all(isinstance(value, int) and 200 <= value < 300 for key, value in evidence.items() if key in ("status", "baseline_status", "probe_status", "repeat_status") and value is not None)
    return "NO_ISSUES_OBSERVED" if negative and successful and isinstance(status_code, int) and 200 <= status_code < 300 and not evidence.get("body_truncated") and evidence.get("response_stable", True) else "PARTIAL"


def run_outcome(state: dict) -> str:
    if state["status"] in ("FAILED",):
        return "FAILED"
    if state["status"] != "COMPLETED":
        return "PARTIAL"
    if state.get("errors") or state.get("limits_reached"):
        return "PARTIAL" if state.get("results") or state.get("http_probes") or any(row.get("pages") for row in state.get("provider_metadata", [])) else "FAILED"
    if state["module"] == "subfinding":
        metadata = state.get("provider_metadata", [])
        return "PARTIAL" if not metadata or any(not row.get("complete") for row in metadata) else "NO_ISSUES_OBSERVED"
    outcomes = {result_outcome(result) for result in state["results"]}
    for outcome in ("VERIFIED", "POTENTIAL", "MANUAL_REVIEW", "PARTIAL", "UNSUPPORTED"):
        if outcome in outcomes:
            return outcome
    return "NO_ISSUES_OBSERVED" if outcomes else "UNSUPPORTED"


def summary(state: dict) -> dict:
    return {"execution_status": state["status"], "verification_outcome": run_outcome(state),
            "result_outcomes": dict(Counter(result_outcome(result) for result in state["results"]))}
