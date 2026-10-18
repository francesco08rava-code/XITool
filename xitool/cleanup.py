"""Manutenzione conservativa: anteprima obbligatoria e soli file rigenerabili noti."""
import os
from pathlib import Path
import stat
import time

from .storage import DataError, fingerprint, save_json, utcnow


def _plain(path):
    info = path.lstat()
    if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
        raise DataError("Link e reparse point esclusi dalla pulizia")
    return info


def _root(value):
    root = Path(os.path.abspath(value))
    for item in (root, *root.parents):
        _plain(item)
    if root == Path(root.anchor) or not ((root / "scope.json").is_file() or
            ((root / "main.py").is_file() and (root / "xitool").is_dir())):
        raise DataError("La pulizia richiede una cartella XITool o un progetto riconoscibile")
    return root


def _category(relative):
    parts = relative.parts
    if any(part in {"targets", "runs", "reports", "plans", "results", "checkpoints"} for part in parts):
        return "RESULTS_OR_CHECKPOINTS", False
    if relative.suffix in (".yaml", ".yml") or relative.name in {"scope.json", "controlled_checks.json", "sessions.json"}:
        return "CONFIGURATION", False
    if len(parts) >= 3 and parts[0] in ("xitool", "tests", "benchmarks") and "__pycache__" in parts and relative.suffix == ".pyc":
        return "RECREATABLE_BYTECODE", True
    if len(parts) == 2:
        rules = {".xitool-cache": (".cache", "RECREATABLE_CACHE"), ".xitool-tmp": (".tmp", "TEMPORARY"), ".xitool-logs": (".log", "LOG")}
        if parts[0] in rules:
            suffix, category = rules[parts[0]]
            return category, relative.suffix == suffix and relative.name.startswith("xitool-")
    return "ESSENTIAL_OR_USER_FILE", False


def dry_run(value, retention_days=30, now=None):
    if type(retention_days) is not int or not 1 <= retention_days <= 3650:
        raise DataError("Retention non valida")
    root = _root(value)
    now = time.time() if now is None else now
    files, errors = [], []
    def walk_error(exc):
        errors.append({"path": "INACCESSIBLE_DIRECTORY", "error": type(exc).__name__})
    for directory, folders, names in os.walk(root, followlinks=False, onerror=walk_error):
        safe = []
        for name in folders:
            try:
                _plain(Path(directory) / name)
                if name not in (".git", ".venv", "node_modules"):
                    safe.append(name)
            except (OSError, DataError) as exc:
                errors.append({"path": str((Path(directory) / name).relative_to(root)), "error": type(exc).__name__})
        folders[:] = safe
        for name in names:
            path = Path(directory) / name
            relative = path.relative_to(root)
            try:
                info = _plain(path)
                if not stat.S_ISREG(info.st_mode):
                    continue
                category, candidate = _category(relative)
                # Managed disk caches/logs require the ownership marker as well as a known name.
                if category in ("RECREATABLE_CACHE", "TEMPORARY", "LOG"):
                    marker = path.parent / "OWNED_BY_XITOOL"
                    candidate = candidate and marker.is_file()
                    if candidate:
                        _plain(marker)
                        candidate = marker.stat().st_size == 7 and marker.read_bytes() == b"XITOOL\n"
                candidate = candidate and now - info.st_mtime >= retention_days * 86400
                files.append({"path": relative.as_posix(), "category": category, "bytes": info.st_size,
                              "mtime_ns": info.st_mtime_ns, "inode": info.st_ino, "device": info.st_dev,
                              "delete_candidate": candidate})
            except (OSError, DataError) as exc:
                errors.append({"path": relative.as_posix(), "error": type(exc).__name__})
            if len(files) >= 100000:
                raise DataError("Inventario oltre 100000 file: nessuna cancellazione")
    files.sort(key=lambda row: row["path"])
    plan = {"root": str(root), "retention_days": retention_days, "files": files, "errors": errors,
            "total_bytes": sum(row["bytes"] for row in files),
            "reclaimable_bytes": sum(row["bytes"] for row in files if row["delete_candidate"])}
    recovery = set()
    for row in files:
        parts = Path(row["path"]).parts
        for index, part in enumerate(parts):
            if part.startswith("run_"):
                run = Path(*parts[:index + 1])
                if not (root / run / "checkpoint.json").is_file():
                    recovery.add(run.as_posix())
    plan["possible_unreferenced_runs"] = sorted(recovery)
    plan["unreferenced_interpretation"] = "MISSING_CHECKPOINT_REVIEW_ONLY_NEVER_DELETE"
    plan["excluded_directories"] = [".git", ".venv", "node_modules"]
    plan["plan_id"] = fingerprint(plan)
    return plan


def apply(plan, confirmation):
    if fingerprint({key: value for key, value in plan.items() if key != "plan_id"}) != plan.get("plan_id"):
        raise DataError("Anteprima alterata: ripetere l'inventario")
    if confirmation != "ELIMINA " + plan.get("plan_id", ""):
        raise DataError("Anteprima e conferma distruttiva esatta obbligatorie")
    current = dry_run(plan["root"], plan["retention_days"])
    if current["plan_id"] != plan["plan_id"]:
        raise DataError("Inventario cambiato: ripetere l'anteprima")
    root = _root(plan["root"])
    result = {"plan_id": plan["plan_id"], "timestamp": utcnow(), "deleted": [], "errors": []}
    for row in current["files"]:
        if not row["delete_candidate"]:
            continue
        path = root / row["path"]
        try:
            for item in (path, *path.parents):
                _plain(item)
                if item == root:
                    break
            if not path.resolve().is_relative_to(root):
                raise DataError("Percorso esterno escluso")
            info = path.lstat()
            if (info.st_ino, info.st_dev, info.st_size, info.st_mtime_ns) != (row["inode"], row["device"], row["bytes"], row["mtime_ns"]):
                raise DataError("File modificato dopo anteprima")
            path.unlink()  # one allowlisted file only, never recursive deletion
            result["deleted"].append(row["path"])
        except (OSError, DataError) as exc:
            result["errors"].append({"path": row["path"], "error": type(exc).__name__})
    save_json(root / "cleanup_audit.json", result)
    return result
