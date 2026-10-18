"""Confidenza e priorità spiegabili: punteggi ordinali, non probabilità/CVSS."""
from .storage import fingerprint
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit


def canonical_resource(value):
    parsed = urlsplit(value)
    return urlunsplit((parsed.scheme.lower(), parsed.netloc.lower(), parsed.path or "/", urlencode(sorted(parse_qsl(parsed.query, keep_blank_values=True))), ""))


def assess(result):
    evidence = result.get("evidence", {})
    status = result.get("status", "UNSUPPORTED")
    factors = []
    score = 0
    def add(name, points):
        nonlocal score
        factors.append({"factor": name, "points": points})
        score += points
    if result.get("baseline") or "baseline_status" in evidence:
        add("baseline_available", 15)
    if any(evidence.get(key) is True for key in ("responses_stable", "response_stable", "baseline_stable", "stable_unescaped_reflection", "repeat_executed")):
        add("repeatability_observed", 20)
    direct = any(evidence.get(key) is True for key in ("repeat_executed", "browser_read_canary", "other_reads_test_canary", "callback_observed", "probe_canary_present_twice", "canary_still_readable_twice"))
    if status == "VERIFIED" and direct:
        add("direct_controlled_evidence", 60)
    elif status == "POTENTIAL":
        add("reproducible_signal_not_proof", 20)
    elif status in ("OBSERVED", "MANUAL_REVIEW", "NO_ISSUES_OBSERVED"):
        add("observation_only", 10)
    incomplete = (status in ("PARTIAL", "ERROR", "UNSUPPORTED") or (status == "VERIFIED" and not direct) or evidence.get("body_truncated") or evidence.get("response_stable") is False or evidence.get("responses_stable") is False)
    if incomplete:
        add("insufficient_or_incomplete_evidence", -30)
    human_rejected = result.get("human_verdict") == "FALSE_POSITIVE"
    if status == "FALSE_POSITIVE" or human_rejected:
        score, factors = 0, [{"factor": "human_rejected", "points": 0}]
    score = max(0, min(100, score))
    priority = ("INCONCLUSIVE" if incomplete else "HIGH REVIEW PRIORITY" if status == "VERIFIED" else
                "MEDIUM REVIEW PRIORITY" if status in ("POTENTIAL", "MANUAL_REVIEW") else "LOW REVIEW PRIORITY")
    if human_rejected:
        priority = "LOW REVIEW PRIORITY"
    result.update(confidence_score=score, confidence_factors=factors, confidence_model="ordinal-v1-not-a-probability",
                  review_priority=priority, priority_reason="Stato della verifica e qualità delle evidenze; impatto non calibrato, severità separata.")
    result["classification"] = "FALSE_POSITIVE" if human_rejected else status if status in {"OBSERVED", "POTENTIAL", "VERIFIED", "FALSE_POSITIVE", "MANUAL_REVIEW", "ERROR", "UNSUPPORTED"} else "OBSERVED" if status == "NO_ISSUES_OBSERVED" else "ERROR" if status == "FAILED" else "MANUAL_REVIEW"
    result["issue_fingerprint"] = fingerprint([result.get("domain", result.get("host")), canonical_resource(result["url"]), result.get("check"), result.get("parameter", "")])
    result.setdefault("severity", "UNKNOWN")
    return result
