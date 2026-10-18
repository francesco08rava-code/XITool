"""Persistenza atomica, configurazione e directory dei progetti."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import tempfile
from datetime import datetime, timezone
from typing import Any

import yaml


class DataError(ValueError):
    """Dati locali invalidi o non compatibili."""


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def fingerprint(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=True).encode()).hexdigest()


def atomic_write(path: Path, text: str) -> None:
    """Sostituisce il file solo dopo flush e fsync del temporaneo adiacente."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=".xitool-", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(text)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        if os.name == "posix":
            directory = os.open(path.parent, os.O_RDONLY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def save_json(path: Path, value: Any) -> None:
    content = json.dumps(value, ensure_ascii=True, indent=2) + "\n"
    if len(content.encode("utf-8")) > 32 * 1024 * 1024:
        raise DataError("Snapshot oltre 32 MiB: suddividere la scansione")
    atomic_write(path, content)


def read_json(path: Path) -> Any:
    if path.stat().st_size > 32 * 1024 * 1024:
        raise DataError(f"File troppo grande: {path.name}")
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise DataError(f"JSON corrotto: {path.name}") from exc


def confined(root: Path, path: Path) -> Path:
    """Impedisce traversal e symlink in qualsiasi segmento sotto la radice."""
    root = root.absolute()
    candidate = path.absolute()
    try:
        parts = candidate.relative_to(root).parts
    except ValueError as exc:
        raise DataError("Percorso esterno al progetto") from exc
    if root.is_symlink():
        raise DataError("Radice symlink non consentita")
    current = root
    for part in parts:
        if part in ("..", "."):
            raise DataError("Percorso non valido")
        current /= part
        if current.is_symlink():
            raise DataError("Symlink non consentito")
    if not candidate.resolve().is_relative_to(root.resolve()):
        raise DataError("Percorso esterno al progetto")
    return candidate


DEFAULTS = {
    "http": {"timeout_seconds": 10, "max_retries": 2, "max_concurrency": 1,
             "connect_timeout_seconds": 10, "read_timeout_seconds": 10, "retry_jitter_seconds": 0.0,
             "requests_per_second": 2, "max_body_bytes": 1048576,
             "max_redirects": 5, "allowed_ports": [80, 443], "max_concurrency_per_host": 2},
    "checkpoint": {"enabled": True, "interval_seconds": 30, "completed_items_interval": 10},
    "cache": {"enabled": True, "ttl_seconds": 300},
    "execution": {"require_confirmation": True, "resume_enabled": True, "max_tasks": 1000, "max_concurrent_domains": 1, "max_duration_seconds": 600},
    "discovery": {"max_depth": 2, "max_pages": 50, "ct_providers": ["crtsh", "certspotter"]},
    "logging": {"level": "INFO"},
}


def load_config(path: Path) -> dict:
    """Valida tipi, limiti e chiavi; non disabilita le conferme di sicurezza."""
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (yaml.YAMLError, UnicodeError) as exc:
        raise DataError("config.yaml malformato") from exc
    if not isinstance(raw, dict):
        raise DataError("config.yaml deve contenere una mappa")
    result = json.loads(json.dumps(DEFAULTS))
    limits = {
        "timeout_seconds": (0.1, 60), "connect_timeout_seconds": (0.1, 60), "read_timeout_seconds": (0.1, 60), "max_retries": (0, 5), "max_concurrency": (1, 10),
        "requests_per_second": (0.01, 20), "max_body_bytes": (1024, 4194304),
        "retry_jitter_seconds": (0, 1), "max_redirects": (0, 10), "interval_seconds": (1, 300),
        "completed_items_interval": (1, 1000), "ttl_seconds": (1, 3600),
        "max_concurrency_per_host": (1, 10), "max_concurrent_domains": (1, 5), "max_duration_seconds": (1, 86400), "max_tasks": (1, 10000), "max_depth": (0, 5), "max_pages": (1, 500),
    }
    for section, settings in raw.items():
        if section not in result or not isinstance(settings, dict):
            raise DataError(f"Sezione configurazione invalida: {section}")
        for key, value in settings.items():
            if key not in result[section]:
                raise DataError(f"Chiave sconosciuta: {section}.{key}")
            default = result[section][key]
            if isinstance(default, bool):
                if type(value) is not bool:
                    raise DataError(f"{key}: booleano richiesto")
            elif key == "ct_providers":
                if not isinstance(value, list) or any(not isinstance(name, str) or name not in ("crtsh", "certspotter") for name in value) or len(value) != len(set(value)):
                    raise DataError("ct_providers: elenco senza duplicati di crtsh/certspotter richiesto")
            elif key == "allowed_ports":
                if not isinstance(value, list) or not value or any(type(p) is not int or not 1 <= p <= 65535 for p in value):
                    raise DataError("allowed_ports: elenco di porte valido richiesto")
            elif key == "level":
                if value not in ("DEBUG", "INFO", "WARNING", "ERROR"):
                    raise DataError("Livello logging non valido")
            else:
                low, high = limits[key]
                numeric_type = (int, float) if key in ("timeout_seconds", "connect_timeout_seconds", "read_timeout_seconds", "requests_per_second", "retry_jitter_seconds") else (int,)
                if type(value) not in numeric_type or not low <= value <= high:
                    raise DataError(f"{key}: intervallo {low}..{high} richiesto")
            result[section][key] = value
    if not result["execution"]["require_confirmation"] or not result["checkpoint"]["enabled"]:
        raise DataError("Questa versione richiede conferma e checkpoint abilitati")
    return result


class Projects:
    def __init__(self, root: Path):
        self.root = root.absolute()
        confined(self.root, self.root)
        self.root.mkdir(parents=True, exist_ok=True)

    def path(self, name: str) -> Path:
        if (not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}", name)
                or name.upper() in {"CON", "PRN", "AUX", "NUL", *(f"COM{i}" for i in range(10)), *(f"LPT{i}" for i in range(10))}):
            raise DataError("Nome: 1–64 lettere ASCII, numeri, _ o -; iniziare con lettera/numero")
        return confined(self.root, self.root / name)

    def list(self) -> list[str]:
        return sorted(p.name for p in self.root.iterdir() if p.is_dir() and not p.is_symlink() and (p / "scope.json").is_file())

    def create(self, name: str, domains: list[str], excluded: list[str]) -> Path:
        from .scope import Scope
        scope = Scope(domains, excluded)
        path = self.path(name)
        if any(p.name.casefold() == name.casefold() for p in self.root.iterdir()):
            raise DataError("Progetto già esistente")
        path.mkdir()
        save_json(path / "scope.json", {"name": name, "domains": scope.raw_domains,
                  "excluded_hosts": scope.excluded, "created_at": utcnow()})
        self.prepare(path, scope)
        return path

    def prepare(self, project: Path, scope: Any) -> list[str]:
        """Crea soltanto le cartelle dei root autorizzati; non sposta lo storico."""
        project = confined(self.root, project)
        roots = scope.roots()
        names = [target_path(project, root).name.casefold() for root in roots]
        if len(names) != len(set(names)):
            raise DataError("Collisione fra nomi di cartelle dominio")
        for root in roots:
            target_path(project, root).mkdir(exist_ok=True)
        return roots

    def load(self, name: str) -> tuple[Path, Any]:
        from .scope import Scope
        path = self.path(name)
        value = read_json(confined(path, path / "scope.json"))
        if not isinstance(value, dict) or value.get("name", name) != name:
            raise DataError("Metadati progetto incoerenti")
        return path, Scope(value.get("domains", []), value.get("excluded_hosts", []), value.get("allowed_ip_ranges", []))


def target_path(project: Path, domain: str) -> Path:
    """Mantiene il nome DNS completo; codifica solo IP v6 e nomi riservati."""
    from .scope import normalize_host
    host = normalize_host(domain)
    folder = host.replace(":", "-") if ":" in host else host
    if ":" in host:
        folder = "ip6-" + folder
    if folder.lower() in {"scope.json", "runs", "reports", "plans", "crawler", "diff", "subfinding", "xss", "sqli", "idor", "access", "ssrf", "traversal", "authentication", "sensitive", "cors", "misconfiguration", "con", "prn", "aux", "nul", *(f"com{i}" for i in range(10)), *(f"lpt{i}" for i in range(10))}:
        folder = "host-" + folder
    return confined(project, project / folder)
