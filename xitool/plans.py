"""Checkpoint del piano Smart: riferimenti alle run, nessun corpo HTTP o credenziale."""
from __future__ import annotations

from pathlib import Path
import os
import uuid

from .execution import Engine, load_state
from .scanners import MODULES
from . import __version__
from .storage import DataError, atomic_write, confined, fingerprint, read_json, save_json, utcnow


class SmartPlan:
    def __init__(self, project: Path, scope, config: dict, domains: list[str], path: Path | None = None):
        self.project, self.scope, self.config = project, scope, config
        if path:
            self.path = confined(project, path)
            envelope = read_json(self.path)
            if not isinstance(envelope, dict) or set(envelope) != {"sha256", "data"} or envelope["sha256"] != fingerprint(envelope["data"]):
                raise DataError("Piano Smart corrotto")
            self.state = envelope["data"]
            if isinstance(self.state, dict) and self.state.get("module_versions") != {name: __version__ for name in MODULES}:
                raise DataError("Versioni dei moduli cambiate: creare un nuovo piano")
            if (not isinstance(self.state, dict) or self.state.get("version") != 1 or self.state.get("engine_version") != __version__ or self.state.get("project") != project.name or self.state.get("scope_hash") != scope.digest or
                    self.state.get("config_hash") != fingerprint(config) or self.state.get("domains") != sorted(domains)):
                raise DataError("Scope, configurazione o domini del piano sono cambiati: creare un nuovo piano")
            if not isinstance(self.state.get("steps"), list) or len(self.state["steps"]) > 1000:
                raise DataError("Passi del piano non validi")
            seen_steps = set()
            for step in self.state["steps"]:
                if not isinstance(step, dict) or not {"domain", "module", "tasks", "run", "status"} <= step.keys() or step["domain"] not in domains or step["module"] not in MODULES or not isinstance(step["tasks"], list) or not step["tasks"]:
                    raise DataError("Passo del piano non valido")
                if step["run"]:
                    confined(project, project / step["run"])
                if "step_id" in step:
                    dependencies = step.get("depends_on", [])
                    if not isinstance(step["step_id"], str) or not isinstance(dependencies, list) or any(not isinstance(key, str) or key not in seen_steps for key in dependencies) or step["step_id"] in seen_steps:
                        raise DataError("Dipendenze Smart non valide o cicliche")
                    seen_steps.add(step["step_id"])
        else:
            identity = "smart_" + uuid.uuid4().hex
            self.path = confined(project, project / "plans" / (identity + ".json"))
            self.state = {"version": 1, "engine_version": __version__, "id": identity, "project": project.name, "domains": sorted(domains),
                          "module_versions": {name: __version__ for name in MODULES},
                          "scope_hash": scope.digest, "config_hash": fingerprint(config), "steps": [],
                          "status": "AWAITING_SELECTION", "phase": "RECON", "updated_at": utcnow()}

    def save(self):
        self.state["updated_at"] = utcnow()
        save_json(self.path, {"sha256": fingerprint(self.state), "data": self.state})
        lines = [f"# Piano Smart — {self.project.name}", f"Stato: {self.state['status']}", f"Fase: {self.state['phase']}",
                 "", "| Dominio | Modulo | Esecuzione | Esito | Run |", "|---|---|---|---|---|"]
        for step in self.state["steps"]:
            lines.append(f"| {step['domain']} | {step['module']} | {step['status']} | {step.get('verification_outcome', 'PARTIAL')} | {step['run'] or 'non avviata'} |")
        atomic_write(self.path.with_suffix(".report.md"), "\n".join(lines) + "\n")
        findings = {}
        for step in self.state["steps"]:
            if not step["run"]:
                continue
            report_path = confined(self.project, self.project / step["run"] / "report.json")
            if not report_path.exists():
                continue
            report = read_json(report_path)
            if report.get("project") != self.project.name or report.get("domain") != step["domain"] or report.get("module") != step["module"]:
                raise DataError("Report Smart di un altro progetto, dominio o modulo")
            for row in report.get("findings", []):
                key = (step["domain"], step["module"], row["id"])
                findings[key] = {"id": row["id"], "domain": step["domain"], "module": step["module"],
                                 "status": row["status"], "resource": row["url"], "run": step["run"],
                                 "confidence_score": row.get("confidence_score"), "review_priority": row.get("review_priority"),
                                 "severity": row.get("severity", "UNKNOWN")}
        save_json(self.path.with_suffix(".report.json"), {"project": self.project.name, "version": __version__, "scope": self.scope.raw_domains,
                  "domains": self.state["domains"], "module_versions": self.state["module_versions"], "plan_id": self.state["id"],
                  "status": self.state["status"], "findings": list(findings.values()), "unique_findings": len(findings),
                  "steps": [{key: value for key, value in step.items() if key != "tasks"} for step in self.state["steps"]]})

    def add(self, steps: list[dict], phase="ANALYSIS"):
        for step in steps:
            if not isinstance(step, dict) or step.get("domain") not in self.state["domains"] or step.get("module") not in MODULES:
                raise DataError("Modulo o dominio non disponibile nel piano")
            if not isinstance(step.get("tasks"), list) or not step["tasks"] or len(step["tasks"]) > self.config["execution"]["max_tasks"]:
                raise DataError("Passo Smart senza task validi o oltre il limite")
        draft = list(self.state["steps"])
        known = {fingerprint([step["domain"], step["module"], step["tasks"]]) for step in draft}
        for step in steps:
            key = fingerprint([step["domain"], step["module"], step["tasks"]])
            if key not in known:
                identity = fingerprint([step["domain"], step["module"], step["tasks"]])[:24]
                draft.append({**step, "step_id": identity, "depends_on": [row["step_id"] for row in draft if row["domain"] == step["domain"] and row["module"] == "subfinding" and row.get("step_id")],
                              "budget": {"max_tasks": self.config["execution"]["max_tasks"], "max_duration_seconds": self.config["execution"]["max_duration_seconds"]},
                              "input_count": len(step["tasks"]), "result_count": 0, "error_count": 0, "run": None, "status": "PENDING"})
                known.add(key)
        if len(draft) > 1000:
            raise DataError("Piano oltre 1000 passi")
        self.state["steps"] = draft
        self.state.update(phase=phase, status="PENDING" if self.state["steps"] else "AWAITING_SELECTION")
        self.save()

    def run(self, observer=None) -> list[dict]:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        lock = confined(self.project, self.path.with_suffix(".lock"))
        try:
            descriptor = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError as exc:
            raise DataError("Piano Smart occupato; verificare il processo prima di rimuovere il lock") from exc
        os.close(descriptor)
        summary = []
        shared_limiter = None
        try:
            self.state["status"] = "RUNNING"
            self.save()
            for step in self.state["steps"]:
                dependencies = set(step.get("depends_on", []))
                satisfied = {row.get("step_id") for row in self.state["steps"] if row["status"] == "COMPLETED" and not row.get("error_count") and row.get("verification_outcome") != "FAILED"}
                if dependencies - satisfied:
                    step["status"] = "BLOCKED_DEPENDENCY"
                    self.save()
                    continue
                if step["status"] == "COMPLETED":
                    if not step["run"]:
                        raise DataError("Passo completato senza run")
                    checkpoint = confined(self.project, self.project / step["run"] / "checkpoint.json")
                    completed = load_state(checkpoint)
                    self.validate_run(step, completed)
                    if completed["status"] != "COMPLETED":
                        raise DataError("Passo e checkpoint non concordano")
                    continue
                try:
                    directory = confined(self.project, self.project / step["run"]) if step["run"] else None
                    if directory and (directory / "checkpoint.json").exists():
                        state = load_state(directory / "checkpoint.json")
                        self.validate_run(step, state)
                        if state["status"] == "COMPLETED":
                            step["status"] = "COMPLETED"
                            self.save()
                            continue
                        engine = Engine(self.project, self.scope, self.config, step["module"], target=step["domain"], resume=directory)
                    else:
                        engine = Engine(self.project, self.scope, self.config, step["module"], target=step["domain"], tasks=step["tasks"])
                    step["run"] = engine.directory.relative_to(self.project).as_posix()
                    self.save()  # Il riferimento alla run precede ogni richiesta.
                    def progress(value):
                        if observer:
                            observer(value)
                    # run_batch conserva il budget del singolo batch; tra i passi lo riagganciamo.
                    from .http import RateLimiter
                    if shared_limiter is None:
                        shared_limiter = RateLimiter(self.config["http"]["requests_per_second"])
                    engine.client.limiter = shared_limiter
                    engine.execute(progress)
                    step["status"] = engine.state["status"]
                    step["result_count"] = len(engine.state["results"])
                    step["error_count"] = len(engine.state["errors"])
                    step["verification_outcome"] = engine.state.get("verification_outcome", "PARTIAL")
                    summary.append({"project": self.project.name, "domain": step["domain"], "module": step["module"],
                                    "status": step["status"], "verification_outcome": step["verification_outcome"],
                                    "processed": True, "errors": len(engine.state["errors"])})
                    if step["status"] == "INTERRUPTED":
                        self.state["status"] = "INTERRUPTED"
                        self.save()
                        return summary
                except KeyboardInterrupt:
                    step["status"] = "INTERRUPTED"
                    self.state["status"] = "INTERRUPTED"
                    self.save()
                    return summary
                except Exception as exc:
                    step["status"] = "FAILED"
                    summary.append({"project": self.project.name, "domain": step["domain"], "module": step["module"],
                                    "status": "FAILED", "processed": False, "errors": 1, "error_type": type(exc).__name__})
                self.save()
            self.state["status"] = ("PARTIAL" if any(step["status"] != "COMPLETED" or step.get("error_count") or step.get("verification_outcome") == "FAILED" for step in self.state["steps"])
                                    else "AWAITING_SELECTION" if self.state["phase"] == "RECON" else "COMPLETED")
            self.save()
            return summary
        finally:
            lock.unlink(missing_ok=True)

    def validate_run(self, step, state):
        if (state.get("project") != self.project.name or state.get("domain") != step["domain"] or
                state.get("module") != step["module"] or state.get("scope_hash") != self.scope.for_target(step["domain"]).digest or
                state.get("config_hash") != self.state["config_hash"]):
            raise DataError("Run del piano incompatibile con progetto, dominio, modulo, scope o configurazione")


def incomplete(project: Path) -> list[Path]:
    root = confined(project, project / "plans")
    if not root.exists():
        return []
    output = []
    for path in sorted(root.glob("smart_*.json"), reverse=True):
        value = read_json(confined(project, path))
        if isinstance(value, dict) and isinstance(value.get("data"), dict) and value["data"].get("status") != "COMPLETED":
            output.append(path)
    return output
