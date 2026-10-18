"""Correlazione SSRF con nonce e log del sensore controllato, senza destinazioni interne."""
from datetime import datetime, timezone
import ipaddress
import json
import time
import uuid
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from .http import HTTPClient
from .scope import Scope
from .scanners import finding
from .storage import DataError, confined, fingerprint, utcnow


def verify(case, client, project):
    events_file = confined(project, project / case["events_file"])
    if not events_file.is_file():
        return [finding("ssrf", case["url"], "controlled_callback", "UNSUPPORTED", {"reason": "CALLBACK_SENSOR_LOG_MISSING"},
                        "Avviare il sensore e configurare il proxy HTTPS pubblico dell'operatore.", case["parameter"])]
    callback = urlsplit(case["callback_base"])
    local_fixture = case.get("fixture_only") is True
    if local_fixture:
        try:
            local = all(ipaddress.ip_address(urlsplit(value).hostname).is_loopback for value in (case["url"], case["callback_base"]))
        except ValueError:
            local = False
        if not local or callback.scheme != "http" or callback.path != "/xitool-callback/" or not urlsplit(case["url"]).path.startswith("/xitool-lab/"):
            raise DataError("Callback fixture non locale")
        client.scope.url(case["callback_base"])
        client.scope.validate_ip(callback.hostname)
    provider = HTTPClient(Scope([callback.hostname], [], ["127.0.0.0/8", "::1/128"] if local_fixture else []), client.config)
    client.limiter.wait()
    addresses = provider._resolve(callback.hostname, callback.port or 443)
    if not addresses:
        raise DataError("DNS callback privo di destinazioni")
    for address in addresses:
        # Nessuna eccezione CIDR: il callback deve risolvere esclusivamente a IP pubblici.
        provider.scope.validate_ip(address[4][0])
    identity = uuid.uuid4().hex
    destination = case["callback_base"].rstrip("/") + "/" + identity
    parsed = urlsplit(case["url"])
    changed = [(key, destination if key == case["parameter"] else value) for key, value in parse_qsl(parsed.query, keep_blank_values=True)]
    probe_url = urlunsplit((parsed.scheme, parsed.netloc, parsed.path, urlencode(changed), ""))
    started = datetime.now(timezone.utc)
    response = client.get(probe_url, cache=False)
    deadline = time.monotonic() + 3
    observed = None
    matching_events = set()
    while True:
        if events_file.stat().st_size > 8 * 1024 * 1024:
            raise DataError("Log callback oltre 8 MiB: ruotarlo prima del test")
        for line in events_file.read_text(encoding="utf-8").splitlines()[-10000:]:
            try:
                row = json.loads(line)
                if not isinstance(row, dict) or row.get("id") != identity:
                    continue
                received = datetime.fromisoformat(row["received_at"].replace("Z", "+00:00"))
                source = str(ipaddress.ip_address(row["source_ip"]))
                if received.tzinfo is not None and started <= received <= datetime.now(timezone.utc) and source in case["expected_source_ips"]:
                    matching_events.add((row["id"], row["received_at"], source))
                    observed = row
            except (ValueError, TypeError, KeyError):
                continue
        if observed or time.monotonic() >= deadline:
            break
        time.sleep(0.2)
    result = finding("ssrf", case["url"], "controlled_callback", "VERIFIED" if observed else "PARTIAL",
                     {"correlation_id": identity, "callback_observed": bool(observed), "unique_matching_events": len(matching_events),
                      "received_at": observed["received_at"] if observed else None,
                      "request_id": getattr(response, "request_id", None), "source_matches_operator_expectation": bool(observed), "probe_status": response.status,
                      "callback_origin": callback.netloc, "fixture_only": local_fixture},
                     "Conferma solo il callback correlato dal sensore fidato e dalla sorgente attesa. Un callback assente è inconclusivo. Proxy e log sono configurati dall'operatore; nessuna risorsa interna usata.", case["parameter"])
    result["confidence"] = "HIGH" if observed else "NOT_ASSESSED"
    return [result]
