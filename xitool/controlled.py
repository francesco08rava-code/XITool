"""Verifiche su risorse predisposte dall'operatore, mai enumerazione di oggetti."""
from __future__ import annotations

import os
import ipaddress
import re
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from .scanners import finding, safe_url
from .scope import normalize_url_rule
from .sessions import load_profiles, session_state
from .storage import DataError, confined, fingerprint, read_json

SUPPORTED = {"idor", "access", "traversal", "xss", "ssrf", "sqli", "authentication", "cors"}


def load_cases(project, scope, module: str) -> list[dict]:
    path = confined(project, project / "controlled_checks.json")
    if not path.exists() or module not in SUPPORTED:
        return []
    data = read_json(path)
    if not isinstance(data, dict) or set(data) != {"version", "checks"} or data["version"] != 1 or not isinstance(data["checks"], list) or len(data["checks"]) > 25:
        raise DataError("Manifest controlli: versione 1 e massimo 25 casi richiesti")
    profiles = load_profiles(project)
    cases, identities = [], set()
    for case in data["checks"]:
        if not isinstance(case, dict) or not isinstance(case.get("module"), str):
            raise DataError("Caso controllato malformato")
        if case["module"] != module:
            continue
        common = {"id", "module", "url", "operator_owned"}
        fieldsets = {"xss": {"parameter", "fixture_only"},
                     "ssrf": {"parameter", "callback_base", "events_file", "expected_source_ips"},
                     "sqli": {"proof_env", "parameter", "fixture_only", "read_only_fixture"},
                     "traversal": {"proof_env", "baseline_url", "fixture_only", "expected_probe_access"},
                     "authentication": {"proof_env", "profile", "logout_url", "fixture_only", "logout_confirmed"},
                     "cors": {"proof_env", "profile", "caller_url", "fixture_only", "expected_cross_origin_access"},
                     "idor": {"proof_env", "owner_profile", "other_profile", "other_reference_url", "other_proof_env", "expected_other_access"},
                     "access": {"proof_env", "owner_profile", "other_profile", "other_reference_url", "other_proof_env", "expected_other_access"}}
        fields = common | fieldsets[module]
        if module == "ssrf" and "fixture_only" in case:
            fields.add("fixture_only")
            if case["fixture_only"] is not True:
                raise DataError("Callback laboratorio richiede fixture_only true")
        if module == "xss" and "dom_source" in case:
            fields.add("dom_source")
            if case["dom_source"] != "fragment" or "request" in case or case.get("parameter") != "fragment":
                raise DataError("DOM XSS di laboratorio supporta solo location.hash, senza POST")
        if module in ("xss", "sqli") and "request" in case:
            fields.add("request")
            request = case["request"]
            if (not isinstance(request, dict) or set(request) != {"method", "content_type", "fields", "authorized"} or
                    request["method"] != "POST" or request["authorized"] is not True or
                    request["content_type"] not in ("application/json", "application/x-www-form-urlencoded") or
                    not isinstance(request["fields"], dict) or not 1 <= len(request["fields"]) <= 20 or
                    case.get("parameter") not in request["fields"]):
                raise DataError("POST XSS di laboratorio richiede autorizzazione e campi espliciti")
            from .scanners import SECRET_KEY
            if any(not isinstance(key, str) or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,49}", key) or SECRET_KEY.search(key) or
                   not isinstance(value, str) or len(value) > 2000 for key, value in request["fields"].items()):
                raise DataError("Campi POST laboratorio non validi o sensibili")
        if set(case) != fields or case["operator_owned"] is not True or not isinstance(case.get("id"), str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,50}", case["id"]):
            raise DataError("Controllo richiede risorsa dell'operatore e campi espliciti")
        if case["id"] in identities:
            raise DataError("Identificativo del controllo duplicato")
        identities.add(case["id"])
        candidate_host = urlsplit(case.get("url", "")).hostname
        if scope.target and candidate_host and scope.owner(candidate_host) not in (None, scope.target):
            continue  # Il caso di un altro dominio configurato verrà gestito nel suo batch.
        if module not in ("xss", "ssrf") and (not isinstance(case["proof_env"], str) or not re.fullmatch(r"[A-Z][A-Z0-9_]{0,127}", case["proof_env"])):
            raise DataError("Canary: riferimento env richiesto")
        url = safe_url(scope, case["url"])
        if module in ("idor", "access"):
            if type(case["expected_other_access"]) is not bool or case["owner_profile"] == case["other_profile"]:
                raise DataError("Servono due account distinti e un permesso booleano atteso")
            for name in (case["owner_profile"], case["other_profile"]):
                if not isinstance(name, str) or name not in profiles:
                    raise DataError("Profilo di test non configurato")
                parsed, bound = urlsplit(url), urlsplit(profiles[name].origin)
                if (parsed.scheme, parsed.netloc) != (bound.scheme, bound.netloc):
                    raise DataError("Il profilo non appartiene all'origine della risorsa")
            reference = safe_url(scope, case["other_reference_url"])
            if reference == url or (urlsplit(reference).scheme, urlsplit(reference).netloc) != (urlsplit(url).scheme, urlsplit(url).netloc):
                raise DataError("La sessione del secondo account richiede una propria risorsa di riferimento")
            if not isinstance(case["other_proof_env"], str) or not re.fullmatch(r"[A-Z][A-Z0-9_]{0,127}", case["other_proof_env"]):
                raise DataError("Riferimento env canary del secondo account richiesto")
        elif module == "traversal":
            baseline = safe_url(scope, case["baseline_url"])
            if (case["fixture_only"] is not True or case["expected_probe_access"] is not False or baseline == url or
                    not all(urlsplit(value).path.startswith("/xitool-lab/") for value in (baseline, url)) or
                    (urlsplit(baseline).scheme, urlsplit(baseline).netloc) != (urlsplit(url).scheme, urlsplit(url).netloc)):
                raise DataError("Traversal limitato a due risorse innocue predisposte sotto /xitool-lab/")
        elif module == "cors":
            caller = safe_url(scope, case["caller_url"])
            try:
                local = all(ipaddress.ip_address(urlsplit(value).hostname).is_loopback for value in (url, caller))
            except ValueError:
                local = False
            if (not local or case["fixture_only"] is not True or case["expected_cross_origin_access"] is not False or
                    not all(urlsplit(value).path.startswith("/xitool-lab/") for value in (url, caller)) or
                    urlsplit(url).netloc == urlsplit(caller).netloc):
                raise DataError("Browser CORS richiede due origini loopback di laboratorio e permesso negato atteso")
            profile = profiles.get(case.get("profile")) if isinstance(case.get("profile"), str) else None
            if profile is None or {header.lower() for header in profile.header_env} != {"cookie"}:
                raise DataError("Browser CORS richiede un profilo con solo cookie di test")
            if (urlsplit(profile.origin).scheme, urlsplit(profile.origin).netloc) != (urlsplit(url).scheme, urlsplit(url).netloc):
                raise DataError("Profilo CORS di origine differente")
        elif module == "authentication":
            try:
                local = ipaddress.ip_address(urlsplit(url).hostname).is_loopback
            except ValueError:
                local = False
            logout = safe_url(scope, case["logout_url"])
            if (not local or case["fixture_only"] is not True or case["logout_confirmed"] is not True or
                    not urlsplit(url).path.startswith("/xitool-lab/") or urlsplit(logout).path != "/xitool-lab/end-session" or
                    (urlsplit(url).scheme, urlsplit(url).netloc) != (urlsplit(logout).scheme, urlsplit(logout).netloc)):
                raise DataError("Logout automatico solo su fixture loopback predisposta e confermata")
            if not isinstance(case["profile"], str) or case["profile"] not in profiles:
                raise DataError("Profilo controllato per il logout richiesto")
            profile = urlsplit(profiles[case["profile"]].origin)
            if (profile.scheme, profile.netloc) != (urlsplit(url).scheme, urlsplit(url).netloc):
                raise DataError("Profilo logout di origine differente")
        elif module == "ssrf":
            callback = normalize_url_rule(case["callback_base"])
            parsed = urlsplit(callback)
            local_callback = case.get("fixture_only") is True
            if local_callback:
                try:
                    local = all(ipaddress.ip_address(urlsplit(value).hostname).is_loopback for value in (url, callback))
                except ValueError:
                    local = False
                if not local or parsed.scheme != "http" or parsed.path != "/xitool-callback/" or not urlsplit(url).path.startswith("/xitool-lab/"):
                    raise DataError("Callback laboratorio solo tra IP loopback e percorsi predisposti")
                safe_url(scope, callback)
                scope.validate_ip(parsed.hostname)
            if not local_callback and (parsed.scheme != "https" or parsed.port not in (None, 443) or parsed.path != "/xitool-callback/"):
                raise DataError("Callback: HTTPS pubblico e percorso /xitool-callback/ richiesti")
            try:
                if not local_callback and not ipaddress.ip_address(parsed.hostname).is_global:
                    raise DataError("Callback interno non consentito")
            except ValueError as exc:
                if isinstance(exc, DataError):
                    raise
            if not isinstance(case["events_file"], str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,80}\.jsonl", case["events_file"]):
                raise DataError("Il log callback deve essere un file JSONL nella cartella del progetto")
            if not isinstance(case["expected_source_ips"], list) or not 1 <= len(case["expected_source_ips"]) <= 10:
                raise DataError("Specificare da 1 a 10 IP del mittente o proxy fidato atteso")
            try:
                for value in case["expected_source_ips"]:
                    ipaddress.ip_address(value)
            except (ValueError, TypeError) as exc:
                raise DataError("IP sorgente callback non valido") from exc
            case = {**case, "expected_source_ips": sorted({str(ipaddress.ip_address(value)) for value in case["expected_source_ips"]})}
            if not isinstance(case["parameter"], str) or case["parameter"] not in dict(parse_qsl(urlsplit(url).query, keep_blank_values=True)):
                raise DataError("Parametro URL osservato richiesto per il callback")
        else:  # Browser XSS o differenziale SQL esclusivamente di laboratorio.
            try:
                loopback = ipaddress.ip_address(urlsplit(url).hostname).is_loopback
            except ValueError:
                loopback = False
            if (not loopback or case["fixture_only"] is not True or not urlsplit(url).path.startswith("/xitool-lab/") or
                    not isinstance(case["parameter"], str) or ("request" not in case and "dom_source" not in case and case["parameter"] not in dict(parse_qsl(urlsplit(url).query, keep_blank_values=True)))):
                raise DataError("Controllo avanzato limitato a query di fixture loopback sotto /xitool-lab/")
            if module == "sqli":
                values = ([case["request"]["fields"][case["parameter"]]] if "request" in case else
                          [value for key, value in parse_qsl(urlsplit(url).query) if key == case["parameter"]])
                if case["read_only_fixture"] is not True or len(values) != 1 or not re.fullmatch(r"\d{1,9}", values[0]):
                    raise DataError("SQL laboratorio richiede fixture read-only e un singolo parametro numerico")
        cases.append({**case, "url": url})
    return cases


def tasks(project, scope, module: str) -> list[dict]:
    return [{"url": case["url"], "controlled_case": case["id"], "control_hash": fingerprint(case)} for case in load_cases(project, scope, module)]


def execute(module: str, task: dict, client, project) -> list[dict]:
    cases = load_cases(project, client.scope, module)
    case = next((case for case in cases if case["id"] == task["controlled_case"]), None)
    if case is None or fingerprint(case) != task.get("control_hash") or case["url"] != task["url"]:
        raise DataError("Definizione del controllo modificata o assente: creare una nuova run")
    if module == "xss":
        from .browser_lab import verify_xss
        return verify_xss(case, client)
    if module == "ssrf":
        from .callback_checks import verify
        return verify(case, client, project)
    proof = os.environ.get(case["proof_env"], "")
    if not re.fullmatch(r"[A-Za-z0-9_-]{16,128}", proof):
        raise DataError("Canary di laboratorio assente o non valido nell'ambiente")
    if module == "cors":
        from .browser_lab import verify_cors
        return verify_cors(case, client, load_profiles(project)[case["profile"]], proof)
    if module == "sqli":
        return sql_fixture(case, client, proof)
    if module == "authentication":
        return logout_fixture(case, client, project, proof)
    if module in ("idor", "access"):
        profiles = load_profiles(project)
        owner = client.for_profile(profiles[case["owner_profile"]])
        other = client.for_profile(profiles[case["other_profile"]])
        other_proof = os.environ.get(case["other_proof_env"], "")
        if not re.fullmatch(r"[A-Za-z0-9_-]{16,128}", other_proof) or other_proof == proof:
            raise DataError("Canary distinto del secondo account richiesto nell'ambiente")
        other_reference = other.get(case["other_reference_url"], cache=False)
        baseline = owner.get(case["url"], cache=False)
        baseline_repeat = owner.get(case["url"], cache=False)
        tested = other.get(case["url"], cache=False)
        repeated = other.get(case["url"], cache=False)
        owner_valid = all(session_state(response, proof) == "VALID_FOR_CONTROLLED_RESOURCE" and not response.truncated for response in (baseline, baseline_repeat))
        other_reference_after = other.get(case["other_reference_url"], cache=False)
        other_valid = session_state(other_reference_after, other_proof) == "VALID_FOR_CONTROLLED_RESOURCE" and not other_reference_after.truncated and session_state(other_reference, other_proof) == "VALID_FOR_CONTROLLED_RESOURCE" and not other_reference.truncated
        other_read = all(session_state(response, proof) == "VALID_FOR_CONTROLLED_RESOURCE" and not response.truncated for response in (tested, repeated))
        denied = all(response.status in (401, 403) and proof not in response.body for response in (tested, repeated))
        if case["expected_other_access"]:
            outcome = "NO_ISSUES_OBSERVED" if owner_valid and other_valid and other_read else "MANUAL_REVIEW" if owner_valid and other_valid and denied else "PARTIAL"
        else:
            outcome = "VERIFIED" if owner_valid and other_valid and other_read else "NO_ISSUES_OBSERVED" if owner_valid and other_valid and denied else "PARTIAL"
        evidence = {"controlled_case": case["id"], "expected_other_access": case["expected_other_access"],
                    "permission_matrix": {"resource": case["url"], "operation": "GET", "expected_access": case["expected_other_access"],
                                          "observed_canary_access": other_read, "result": outcome, "subject_role": profiles[case["other_profile"]].role},
                    "owner_role": profiles[case["owner_profile"]].role, "other_role": profiles[case["other_profile"]].role,
                    "owner_reference_valid": owner_valid, "other_reference_valid": other_valid, "other_reads_test_canary": other_read,
                    "owner_statuses": [baseline.status, baseline_repeat.status], "other_statuses": [tested.status, repeated.status],
                    "other_session_state": session_state(tested, proof), "canary_sha256": fingerprint(proof)}
        limitation = "Prova limitata alla risorsa canary dell'operatore e ai due account configurati. Nessun ID enumerato o contenuto esportato. HTTP 200 da solo non è una conferma."
        result = finding(module, case["url"], "controlled_authorization", outcome, evidence, limitation)
    else:
        baseline = client.get(case["baseline_url"], cache=False)
        baseline_repeat = client.get(case["baseline_url"], cache=False)
        tested = client.get(case["url"], cache=False)
        repeated = client.get(case["url"], cache=False)
        baseline_stable = baseline.status == baseline_repeat.status and baseline.body == baseline_repeat.body and not baseline_repeat.truncated
        comparable = baseline_stable and all(200 <= row.status < 300 and not row.truncated for row in (baseline, tested, repeated))
        observed = comparable and proof not in baseline.body and proof in tested.body and proof in repeated.body
        denied = baseline_stable and 200 <= baseline.status < 300 and not baseline.truncated and proof not in baseline.body and all(row.status == 403 and not row.truncated and proof not in row.body for row in (tested, repeated))
        outcome = "VERIFIED" if observed else "NO_ISSUES_OBSERVED" if denied or (comparable and proof not in tested.body and proof not in repeated.body) else "PARTIAL"
        result = finding(module, case["url"], "controlled_fixture_read", outcome,
                         {"controlled_case": case["id"], "baseline_status": baseline.status, "probe_statuses": [tested.status, repeated.status],
                          "baseline_stable": baseline_stable, "baseline_canary_absent": proof not in baseline.body, "probe_canary_present_twice": observed,
                          "canary_sha256": fingerprint(proof)},
                         "Conferma soltanto la lettura del canary innocuo predisposto: non dimostra accesso ad altri file. Nessun percorso viene generato automaticamente.")
    result["verification_outcome"] = outcome
    result["confidence"] = "HIGH" if outcome == "VERIFIED" else "NOT_ASSESSED"
    result["baseline"] = {"status": baseline.status, "body_sha256": fingerprint(baseline.body)}
    result["differences"] = {"baseline_body_equals_probe": baseline.body == tested.body}
    return [result]


def sql_fixture(case, client, proof):
    parsed = urlsplit(case["url"])
    pairs = parse_qsl(parsed.query, keep_blank_values=True)
    original = case["request"]["fields"][case["parameter"]] if case.get("request") else next(value for key, value in pairs if key == case["parameter"])
    def variant(condition):
        changed = [(key, original + condition if key == case["parameter"] else value) for key, value in pairs]
        return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, urlencode(changed), ""))
    urls = [case["url"], case["url"], variant(" AND 1=1"), variant(" AND 1=1"), variant(" AND 1=2"), variant(" AND 1=2")]
    if case.get("request"):
        import json
        request = case["request"]
        responses = []
        for condition in ("", "", " AND 1=1", " AND 1=1", " AND 1=2", " AND 1=2"):
            fields = {**request["fields"], case["parameter"]: original + condition}
            body = json.dumps(fields).encode() if request["content_type"] == "application/json" else urlencode(fields).encode()
            responses.append(client.post(case["url"], body, request["content_type"], authorized_urls=(case["url"],)))
    else:
        responses = [client.get(url, cache=False) for url in urls]
    healthy = all(response.status == 200 and not response.truncated for response in responses)
    stable = all(fingerprint(responses[index].body) == fingerprint(responses[index + 1].body) for index in (0, 2, 4))
    differential = (healthy and stable and all(proof in response.body for response in responses[:4]) and
                    all(proof not in response.body for response in responses[4:]) and responses[0].body == responses[2].body)
    rejected_expression = healthy and stable and all(proof in response.body for response in responses[:2]) and all(proof not in response.body for response in responses[2:]) and responses[2].body == responses[4].body
    result = finding("sqli", case["url"], "controlled_read_only_boolean_differential", "POTENTIAL" if differential else "PARTIAL",
                     {"controlled_case": case["id"], "statuses": [response.status for response in responses],
                      "responses_stable": stable, "expected_canary_differential": differential,
                      "expression_rejected_consistently": rejected_expression,
                      "body_hashes": [fingerprint(response.body) for response in responses],
                      "fixture_read_only_declared": True},
                     "Solo fixture loopback read-only predisposta dall'operatore. Il differenziale è ripetibile ma non prova da solo la semantica SQL del server: nessun VERIFIED, estrazione o modifica dati.", case["parameter"])
    result["http_method"] = "POST" if case.get("request") else "GET"
    result["input"]["location"] = ("json" if case["request"]["content_type"] == "application/json" else "body") if case.get("request") else "query"
    result["baseline"] = {"status": responses[0].status, "body_sha256": fingerprint(responses[0].body)}
    return [result]


def logout_fixture(case, client, project, proof):
    profile = load_profiles(project)[case["profile"]]
    private = client.for_profile(profile)
    baseline = private.get(case["url"], cache=False)
    valid = session_state(baseline, proof) == "VALID_FOR_CONTROLLED_RESOURCE" and not baseline.truncated
    if not valid:
        return [finding("authentication", case["url"], "controlled_logout_invalidation", "PARTIAL",
                        {"baseline_session_valid": False, "logout_executed": False}, "Sessione iniziale non valida: nessun logout effettuato.")]
    logout = private.get(case["logout_url"], cache=False)
    after = [private.get(case["url"], cache=False) for _ in range(2)]
    logout_completed = 200 <= logout.status < 300
    invalidated = all(session_state(response, proof) == "INVALID_OR_DENIED" and proof not in response.body for response in after)
    remains = all(session_state(response, proof) == "VALID_FOR_CONTROLLED_RESOURCE" and not response.truncated for response in after)
    outcome = "VERIFIED" if logout_completed and remains else "NO_ISSUES_OBSERVED" if logout_completed and invalidated else "PARTIAL"
    return [finding("authentication", case["url"], "controlled_logout_invalidation", outcome,
                    {"baseline_session_valid": True, "logout_executed": True, "logout_status": logout.status,
                     "session_invalidated_twice": invalidated, "canary_still_readable_twice": remains,
                     "post_logout_statuses": [response.status for response in after]},
                    "Prova limitata all'account e alla fixture loopback confermati. Nessun logout su account pubblici o di terzi.")]
