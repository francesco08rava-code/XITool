"""Profili opzionali: nel progetto solo riferimenti a variabili d'ambiente."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import ipaddress
import os
import re
from urllib.parse import urlsplit

from .scope import normalize_url_rule
from .storage import DataError, confined, read_json


class SessionError(DataError):
    category = "AUTH_REQUIRED"


@dataclass(frozen=True)
class Profile:
    name: str
    origin: str
    role: str
    header_env: dict[str, str]
    expires_at: str | None = None

    def headers(self, url: str) -> dict[str, str]:
        parsed = urlsplit(url)
        if (parsed.scheme, parsed.netloc) != (urlsplit(self.origin).scheme, urlsplit(self.origin).netloc):
            raise DataError("Sessione bloccata: cambio di origine")
        if self.expires_at:
            expiry = datetime.fromisoformat(self.expires_at.replace("Z", "+00:00"))
            if expiry <= datetime.now(timezone.utc):
                raise SessionError("Profilo di sessione scaduto")
        result = {}
        for header, variable in self.header_env.items():
            value = os.environ.get(variable)
            if not value or len(value) > 16384 or any(ord(char) < 32 or ord(char) == 127 for char in value):
                raise SessionError("Credenziale di sessione assente o non valida nell'ambiente")
            result[header] = value
        return result


def load_profiles(project) -> dict[str, Profile]:
    path = confined(project, project / "session_profiles.json")
    if not path.exists():
        return {}
    data = read_json(path)
    if not isinstance(data, dict) or set(data) != {"version", "profiles"} or data["version"] != 1 or not isinstance(data["profiles"], dict) or len(data["profiles"]) > 20:
        raise DataError("Manifest dei profili non valido")
    profiles = {}
    for name, value in data["profiles"].items():
        if not re.fullmatch(r"[A-Za-z0-9_-]{1,40}", name) or not isinstance(value, dict) or set(value) - {"origin", "role", "header_env", "expires_at"}:
            raise DataError("Profilo non valido: sono ammessi solo riferimenti env")
        if not isinstance(value.get("origin"), str):
            raise DataError("Origine del profilo richiesta")
        origin = normalize_url_rule(value["origin"])
        parsed = urlsplit(origin)
        if parsed.path != "/":
            raise DataError("Il profilo deve indicare un'origine, senza percorso")
        if parsed.scheme != "https":
            try:
                loopback = ipaddress.ip_address(parsed.hostname).is_loopback
            except ValueError:
                loopback = False
            if not loopback:
                raise DataError("Credenziali su HTTP consentite solo a IP loopback di laboratorio")
        headers = value.get("header_env")
        if not isinstance(headers, dict) or not 1 <= len(headers) <= 5:
            raise DataError("header_env deve contenere da 1 a 5 riferimenti")
        for header, variable in headers.items():
            if (not isinstance(header, str) or not re.fullmatch(r"Authorization|Cookie|X-[A-Za-z0-9-]{1,50}", header, re.I)
                    or header.lower() in ("x-forwarded-host", "x-forwarded-for", "x-http-method-override")
                    or not isinstance(variable, str) or not re.fullmatch(r"[A-Z][A-Z0-9_]{0,127}", variable)):
                raise DataError("Header o riferimento env non ammesso")
        role = value.get("role", "test")
        if not isinstance(role, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,40}", role):
            raise DataError("Ruolo non valido")
        expiry = value.get("expires_at")
        if expiry is not None:
            try:
                if not isinstance(expiry, str) or datetime.fromisoformat(expiry.replace("Z", "+00:00")).tzinfo is None:
                    raise ValueError()
            except ValueError as exc:
                raise DataError("Scadenza profilo: timestamp con fuso richiesto") from exc
        profiles[name] = Profile(name, origin, role, headers, expiry)
    return profiles


def session_state(response, proof: str | None = None) -> str:
    path = urlsplit(response.url).path
    if response.status in (401, 403) or re.search(r"/(?:login|signin|sign-in)(?:/|$)", path, re.I):
        return "INVALID_OR_DENIED"
    if proof and 200 <= response.status < 300 and proof in response.body:
        return "VALID_FOR_CONTROLLED_RESOURCE"
    return "INCONCLUSIVE"
