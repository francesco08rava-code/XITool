"""Scope deny-by-default e normalizzazione centralizzata delle destinazioni."""
from __future__ import annotations

import ipaddress
import re
from urllib.parse import quote, urlsplit, urlunsplit

from .storage import DataError, fingerprint


class ScopeViolation(DataError):
    """Destinazione non autorizzata."""


def normalize_host(value: str) -> str:
    if not isinstance(value, str) or not value or value != value.strip() or any(c in value for c in "/\\@%?#\x00"):
        raise DataError("Host malformato")
    if value.endswith(".."):
        raise DataError("Punti finali multipli non validi")
    value = value.removesuffix(".").lower()
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        pass
    try:
        host = value.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise DataError("Hostname IDNA non valido") from exc
    if len(host) > 253 or any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) for label in host.split(".")):
        raise DataError("Hostname non valido")
    # Evita forme IPv4 abbreviate, numeriche od ottali interpretate dai resolver.
    if all(part.isdigit() for part in host.split(".")) or host.startswith("0x"):
        raise DataError("Indirizzo numerico ambiguo")
    return host


def normalize_rule(value: str) -> str:
    wildcard = isinstance(value, str) and value.startswith("*.")
    host = normalize_host(value[2:] if wildcard else value)
    if wildcard:
        try:
            ipaddress.ip_address(host)
        except ValueError:
            return "*." + host
        raise DataError("Wildcard su IP non consentita")
    return host


def matches(host: str, rule: str) -> bool:
    return host.endswith("." + rule[2:]) if rule.startswith("*.") else host == rule


def parse_rules(text: str) -> dict:
    """Importa elenchi espliciti; le righe descrittive ambigue non diventano scope."""
    rules: list[str] = []
    invalid: list[str] = []
    warnings: list[str] = []
    duplicates = 0
    for number, line in enumerate(text.splitlines(), 1):
        line = line.strip()
        if not line:
            continue
        # Nelle tabelle solo la prima colonna identifica il target, non le descrizioni.
        if "\t" in line or "|" in line:
            cells = [cell.strip() for cell in re.split(r"[\t|]", line) if cell.strip()]
            line = cells[0] if cells else ""
        tokens = [token.strip("`\"'") for token in re.split(r"[,;\s]+", line) if token]
        if len(tokens) > 1 and not any(separator in line for separator in (",", ";")) and any(not ("." in token or ":" in token or token == "localhost") for token in tokens):
            invalid.append(f"Riga {number}: testo ambiguo; incollare soltanto domini o colonne separate da TAB")
            continue
        for token in tokens:
            try:
                if "://" in token:
                    parsed = urlsplit(token)
                    if parsed.scheme not in ("http", "https") or parsed.username is not None or parsed.password is not None:
                        raise DataError("URL non ammesso")
                    if parsed.port is not None and not 1 <= parsed.port <= 65535:
                        raise DataError("Porta non valida")
                    rule = normalize_host(parsed.hostname or "")
                    if parsed.path not in ("", "/") or parsed.query or parsed.fragment or parsed.port:
                        warnings.append(f"Riga {number}: URL ridotto a {rule}; percorso, query, frammento e porta non limitano lo scope")
                else:
                    rule = normalize_rule(token)
                if "." not in rule and ":" not in rule and rule != "localhost":
                    raise DataError("Dominio non riconoscibile")
                if rule in rules:
                    duplicates += 1
                else:
                    rules.append(rule)
            except (DataError, ValueError):
                invalid.append(f"Riga {number}: dominio o URL non valido")
    return {"rules": rules, "duplicates": duplicates, "invalid": invalid, "warnings": warnings}


class Scope:
    def __init__(self, domains: list[str], excluded: list[str], allowed_ip_ranges: list[str] | None = None):
        if not isinstance(domains, list) or not domains or not isinstance(excluded, list):
            raise DataError("Scope: domains non vuoto ed excluded_hosts devono essere elenchi")
        self.domains = sorted({normalize_rule(rule) for rule in domains})
        self.excluded = sorted({normalize_rule(rule) for rule in excluded})
        if allowed_ip_ranges is not None and not isinstance(allowed_ip_ranges, list):
            raise DataError("allowed_ip_ranges deve essere un elenco CIDR")
        if any(not isinstance(value, str) for value in (allowed_ip_ranges or [])):
            raise DataError("CIDR testuale esplicito richiesto")
        try:
            self.networks = [ipaddress.ip_network(value, strict=True) for value in (allowed_ip_ranges or [])]
        except (ValueError, TypeError) as exc:
            raise DataError("Intervallo IP esplicito non valido") from exc
        self.digest = fingerprint([self.domains, self.excluded, [str(n) for n in self.networks]])
        self.target: str | None = None

    def roots(self) -> list[str]:
        """Deriva i root dalle regole, mai dalle cartelle presenti sul disco."""
        roots = set()
        for rule in self.domains:
            root = rule.removeprefix("*.")
            if rule.startswith("*."):
                blocked = any(deny.startswith("*.") and (deny[2:] == root or root.endswith("." + deny[2:])) for deny in self.excluded)
                if not blocked:
                    roots.add(root)
            elif not any(matches(root, deny) for deny in self.excluded):
                roots.add(root)
        return sorted(roots)

    def owner(self, host: str) -> str | None:
        """Il root più specifico possiede l'host: niente duplicati fra root sovrapposti."""
        host = normalize_host(host)
        candidates = [root for root in self.roots() if host == root or host.endswith("." + root)]
        return max(candidates, key=len) if candidates else None

    def for_target(self, target: str) -> Scope:
        target = normalize_host(target)
        base = Scope(self.domains, self.excluded, [str(network) for network in self.networks])
        if target not in base.roots():
            raise ScopeViolation("Dominio iniziale non autorizzato nel progetto")
        base.target = target
        base.digest = fingerprint([base.digest, target, base.roots()])
        return base

    def allowed(self, host: str) -> bool:
        try:
            host = normalize_host(host)
        except DataError:
            return False
        allowed = not any(matches(host, rule) for rule in self.excluded) and any(matches(host, rule) for rule in self.domains)
        return allowed and (self.target is None or self.owner(host) == self.target)

    def url(self, value: str, ports: list[int] | None = None) -> str:
        """Rifiuta credenziali, controlli, porte e protocolli non ammessi."""
        if not isinstance(value, str) or len(value) > 8192 or any(ord(c) <= 32 or ord(c) == 127 for c in value) or "\\" in value:
            raise ScopeViolation("URL malformato")
        try:
            parsed = urlsplit(value)
            if parsed.scheme not in ("http", "https") or parsed.username is not None or parsed.password is not None:
                raise ScopeViolation("Schema o credenziali URL non consentiti")
            host = normalize_host(parsed.hostname or "")
            port = parsed.port if parsed.port is not None else (443 if parsed.scheme == "https" else 80)
            if not 1 <= port <= 65535:
                raise ScopeViolation("Porta non valida")
        except (ValueError, DataError) as exc:
            raise ScopeViolation("URL non valido") from exc
        if not self.allowed(host) or (ports is not None and port not in ports):
            raise ScopeViolation("Host o porta fuori scope")
        authority = f"[{host}]" if ":" in host else host
        if port != (443 if parsed.scheme == "https" else 80):
            authority += f":{port}"
        return urlunsplit((parsed.scheme, authority, quote(parsed.path or "/", safe="/%:@!$&'()*+,;=-._~"),
                           quote(parsed.query, safe="%/?@:!$&'()*+,;=-._~"), ""))

    def validate_ip(self, value: str) -> None:
        address = ipaddress.ip_address(value)
        if not address.is_global and not any(address in network for network in self.networks):
            raise ScopeViolation("IP speciale non autorizzato: aggiungere un CIDR esplicito allo scope")
        if address.is_multicast or address.is_unspecified:
            raise ScopeViolation("IP multicast o non specificato non consentito")
