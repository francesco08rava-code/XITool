"""Risoluzione DNS limitata, con TTL e campioni wildcard autorizzati."""
from __future__ import annotations

import copy
import ipaddress
import time
import uuid

from .scope import Scope, normalize_host
from .storage import DataError, utcnow


class DNSResolver:
    def __init__(self, scope: Scope, timeout: float, limiter):
        self.scope, self.timeout, self.limiter = scope, timeout, limiter
        self.cache: dict = {}

    def resolve(self, host: str) -> dict:
        host = normalize_host(host)
        if not self.scope.allowed(host):
            raise DataError("DNS fuori scope")
        try:
            address = ipaddress.ip_address(host)
            return {"host": host, "A": [host] if address.version == 4 else [],
                    "AAAA": [host] if address.version == 6 else [], "CNAME": [], "errors": [],
                    "resolved": True, "literal_ip": True, "timestamp": utcnow()}
        except ValueError:
            pass
        cached = self.cache.get(host)
        if cached and cached[0] > time.monotonic():
            return copy.deepcopy(cached[1])
        try:
            import dns.exception
            import dns.resolver
        except ImportError as exc:
            raise DataError("Installare le dipendenze: dnspython richiesto") from exc
        resolver = dns.resolver.Resolver()
        result = {"host": host, "A": [], "AAAA": [], "CNAME": [], "errors": [], "timestamp": utcnow()}
        result["cname_chain"] = []
        ttl = 300
        for kind in ("A", "AAAA", "CNAME"):
            self.limiter.wait()
            try:
                answer = resolver.resolve(host, kind, lifetime=self.timeout, search=False)
                # Conserve aliases already received; never issue extra off-scope queries.
                message = getattr(answer, "response", None)
                for rrset in getattr(message, "answer", []) or []:
                    if getattr(rrset, "rdtype", None) == 5:
                        for record in rrset:
                            edge = {"from": str(rrset.name).rstrip("."), "to": str(record.target).rstrip(".")}
                            if edge not in result["cname_chain"] and len(result["cname_chain"]) < 16:
                                result["cname_chain"].append(edge)
                if answer.rrset:
                    ttl = min(ttl, max(0, answer.rrset.ttl))
                result[kind] = sorted({record.to_text().rstrip(".") for record in answer})
            except dns.resolver.NXDOMAIN:
                result["errors"].append("NXDOMAIN")
                break
            except dns.resolver.NoAnswer:
                continue
            except dns.resolver.NoNameservers as exc:
                result["errors"].append(kind + ":NoNameservers")
                # Non inferire SERVFAIL da un testo generico del resolver.
                import dns.rcode
                for failure in exc.kwargs.get("errors", []):
                    message = failure[4] if len(failure) > 4 else None
                    if message is not None and hasattr(message, "rcode") and message.rcode() == dns.rcode.SERVFAIL:
                        result["errors"].append(kind + ":SERVFAIL")
            except dns.exception.DNSException as exc:
                result["errors"].append(kind + ":" + type(exc).__name__)
            except OSError:
                result["errors"].append(kind + ":NETWORK_ERROR")
        result["resolved"] = bool(result["A"] or result["AAAA"])
        result["ttl_seconds"] = ttl if result["resolved"] else None
        result["resolution_status"] = ("RESOLVED_PARTIAL" if result["errors"] else "RESOLVED") if result["resolved"] else "NOT_FOUND" if "NXDOMAIN" in result["errors"] else "RESOLVER_ERROR" if result["errors"] else "NO_ADDRESS_RECORDS"
        if result["resolved"] and not result["errors"] and ttl > 0:
            if len(self.cache) >= 1000:
                self.cache.pop(next(iter(self.cache)))
            self.cache[host] = (time.monotonic() + ttl, copy.deepcopy(result))
        return result

    def wildcard(self, root: str) -> dict:
        samples = ["xitool-" + uuid.uuid4().hex + "." + root for _ in range(2)]
        if not all(self.scope.allowed(host) for host in samples):
            return {"tested": False, "reason": "Campioni DNS non autorizzati"}
        answers = [self.resolve(host) for host in samples]
        sets = [set(row["A"] + row["AAAA"]) for row in answers]
        return {"tested": True, "possible_wildcard": bool(sets[0] & sets[1]),
                "addresses": sorted(sets[0] & sets[1]), "samples": answers,
                "limitations": "Due campioni: rotazione DNS/CDN può produrre falsi negativi."}
