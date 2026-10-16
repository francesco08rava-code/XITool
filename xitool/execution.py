"""Code persistenti, ripresa, risultati, revisioni e report separati per progetto."""
from __future__ import annotations

import json
import copy
import logging
import os
from pathlib import Path
import threading
import time
from urllib.parse import urlsplit
import uuid

from .http import HTTPClient, NetworkError, RateLimiter
from .scanners import MODULES, deduplicate_inputs, discover, safe_url, scan
from .scope import Scope
from .storage import DataError, atomic_write, confined, fingerprint, read_json, save_json, target_path, utcnow

LOGGER = logging.getLogger("xitool")


def task_id(task: dict) -> str:
    return fingerprint(task)


def load_state(path: Path) -> dict:
    """Controlla checksum e invarianti prima di usare una coda persistente."""
    path = confined(path.parent.parent.parent.parent, path)
    envelope = read_json(path)
    if not isinstance(envelope, dict) or set(envelope) != {"sha256", "data"}:
        raise DataError("Formato checkpoint non valido")
    state = envelope["data"]
    if envelope["sha256"] != fingerprint(state):
        raise DataError("Integrità checkpoint non valida")
    required = {"version", "run_id", "project", "module", "status", "pending", "completed", "results", "errors", "inputs", "endpoints", "hosts", "live_hosts", "scope_hash", "config_hash", "updated_at", "stats"}
    if not isinstance(state, dict) or not required <= state.keys() or state["version"] not in (1, 2):
        raise DataError("Versione o campi checkpoint non validi")
    project = path.parent.parent.parent if state["version"] == 1 else path.parent.parent.parent.parent
    if state["version"] == 2:
        if not isinstance(state.get("domain"), str) or target_path(project, state["domain"]) != path.parent.parent.parent:
            raise DataError("Dominio checkpoint incoerente")
    if state["run_id"] != path.parent.name or state["project"] != project.name or state["module"] not in MODULES:
        raise DataError("Identità checkpoint incoerente")
    if state["status"] not in ("PENDING", "RUNNING", "INTERRUPTED", "COMPLETED", "FAILED", "PAUSED"):
        raise DataError("Stato checkpoint non valido")
    for key in ("pending", "completed", "results", "errors", "inputs", "endpoints", "hosts", "live_hosts"):
        if not isinstance(state[key], list):
            raise DataError(f"Checkpoint: {key} non è un elenco")
    for key in ("completed", "endpoints", "hosts", "live_hosts"):
        if any(not isinstance(value, str) for value in state[key]):
            raise DataError(f"Checkpoint: elemento {key} malformato")
    if any(not isinstance(task, dict) or not isinstance(task.get("url"), str) for task in state["pending"]):
        raise DataError("Coda checkpoint malformata")
    for key in ("results", "errors", "inputs"):
        if any(not isinstance(item, dict) or not isinstance(item.get("url"), str) for item in state[key]):
            raise DataError(f"Checkpoint: elemento {key} malformato")
    if any(not isinstance(item.get("id"), str) or not isinstance(item.get("manual_review"), bool) for item in state["results"]):
        raise DataError("Finding checkpoint malformato")
    if any(not {"url", "host", "method", "parameter"} <= item.keys() for item in state["inputs"]):
        raise DataError("Input checkpoint malformato")
    if len(state["completed"]) != len(set(state["completed"])):
        raise DataError("Attività completate duplicate")
    return state


def runs(project: Path, module: str | None = None, target: str | None = None) -> list[tuple[Path, dict]]:
    output = target_path(project, target) if target else project
    root = confined(project, output / "runs")
    if not root.exists():
        return []
    result = []
    for path in sorted(root.glob("*/checkpoint.json"), reverse=True):
        confined(project, path)
        state = load_state(path)
        if module is None or state["module"] == module:
            result.append((path.parent, state))
    return result


def latest_discovery(project: Path, scope: Scope, target: str | None = None) -> tuple[list[dict], list[str]]:
    for _, state in runs(project, "subfinding", target):
        if state["status"] == "COMPLETED":
            inputs, urls = [], []
            for entry in state["inputs"]:
                try:
                    inputs.append({**entry, "url": safe_url(scope, entry["url"])})
                except DataError:
                    continue
            for url in state["endpoints"]:
                try:
                    urls.append(safe_url(scope, url))
                except DataError:
                    continue
            return inputs, urls
    return [], []


def build_tasks(module: str, scope: Scope, inputs: list[dict], urls: list[str]) -> list[dict]:
    if module not in MODULES or MODULES[module][1] == "NOT_IMPLEMENTED":
        raise DataError("Modulo non implementato")
    tasks = []
    if module in ("xss", "idor", "ssrf", "traversal"):
        kinds = {"idor": "identifier", "ssrf": "url", "traversal": "file"}
        for entry in inputs:
            if module == "xss":
                if entry.get("method") != "GET" or entry.get("source") == "form" or entry.get("input_type") == "authentication":
                    continue
            elif entry.get("input_type") != kinds[module]:
                continue
            try:
                tasks.append({**{key: entry.get(key) for key in ("parameter", "method", "input_type", "source")},
                              "url": safe_url(scope, entry["url"])})
            except DataError:
                continue
    else:
        for url in urls:
            try:
                tasks.append({"url": safe_url(scope, url), "depth": 0} if module == "subfinding" else {"url": safe_url(scope, url)})
            except DataError:
                continue
    return list({task_id(task): task for task in tasks}.values())


class Engine:
    def __init__(self, project: Path, scope: Scope, config: dict, module: str,
                 tasks: list[dict] | None = None, resume: Path | None = None,
                 target: str | None = None, export_only: bool = False):
        self.project, self.config, self.module = project, config, module
        self.target = target
        self.export_only = export_only
        self._resume_snapshot: dict | None = None
        self.scope = scope.for_target(target) if target else scope
        scope = self.scope
        self.output_root = target_path(project, target) if target else project
        self.guard = threading.RLock()
        self.stop = threading.Event()
        self.timer_error: OSError | DataError | None = None
        self.client = HTTPClient(scope, config)
        if module not in MODULES or MODULES[module][1] == "NOT_IMPLEMENTED":
            raise DataError("Modulo non disponibile")
        if resume:
            self.directory = confined(project, resume)
            self.state = load_state(self.directory / "checkpoint.json")
            if self.state["module"] != module or self.state["project"] != project.name or self.state.get("domain") != target:
                raise DataError("Checkpoint di altro progetto o modulo")
            if export_only:
                return
            if self.state["status"] == "COMPLETED":
                raise DataError("Esecuzione già completata")
            if self.state["config_hash"] != fingerprint(config):
                raise DataError("Configurazione cambiata: ripristinarla oppure avviare una nuova scansione")
            if self.state["scope_hash"] != scope.digest:
                self._resume_snapshot = copy.deepcopy(self.state)
            # Anche a scope modificato ogni elemento è ricontrollato e ripulito.
            state = self.state
            state["pending"] = self._filter_tasks(state["pending"])
            for key in ("inputs", "results"):
                state[key] = [entry for entry in state[key] if self._allowed_url(entry.get("url", ""))]
            state["endpoints"] = [url for url in state["endpoints"] if self._allowed_url(url)]
            state["attempted_urls"] = [url for url in state.get("attempted_urls", []) if self._allowed_url(url)]
            for key in ("hosts", "live_hosts"):
                state[key] = [host for host in state[key] if scope.allowed(host)]
            state["scope_hash"] = scope.digest
            state["errors"] = [e for e in state["errors"] if self._allowed_url(e.get("url", ""))]
        else:
            tasks = self._filter_tasks(tasks or [])
            if not tasks:
                raise DataError("Nessun input autorizzato disponibile")
            if len(tasks) > config["execution"]["max_tasks"]:
                raise DataError("Troppi input: ridurre l'elenco o modificare max_tasks")
            if module == "subfinding" and len(tasks) > config["discovery"]["max_pages"]:
                raise DataError("I seed del dominio superano discovery.max_pages")
            run_id = "run_" + utcnow().replace("-", "").replace(":", "").replace(".", "_") + "_" + uuid.uuid4().hex[:8]
            self.directory = confined(project, self.output_root / "runs" / run_id)
            self.state = {"version": 2 if target else 1, "run_id": run_id, "project": project.name, "module": module,
                          "status": "PENDING", "pending": tasks, "completed": [], "results": [], "errors": [],
                          "inputs": [], "endpoints": [], "hosts": sorted({urlsplit(t["url"]).hostname for t in tasks}),
                          "live_hosts": [], "scope_hash": scope.digest, "config_hash": fingerprint(config),
                          "updated_at": utcnow(), "created_at": utcnow(), "stats": {}, "limits_reached": []}
            if target:
                self.state["domain"] = target

    def _allowed_url(self, url: str) -> bool:
        try:
            safe_url(self.scope, url)
            self.scope.url(url, self.config["http"]["allowed_ports"])
            return True
        except DataError:
            return False

    def _filter_tasks(self, tasks: list[dict]) -> list[dict]:
        return list({task_id(t): t for t in tasks if isinstance(t, dict) and self._allowed_url(t.get("url", ""))}.values())

    def save(self) -> None:
        """Snapshot unico: avanzamento e risultati diventano persistenti insieme."""
        with self.guard:
            self.state["updated_at"] = utcnow()
            self.state["stats"] = dict(self.client.stats)
            save_json(self.directory / "checkpoint.json", {"sha256": fingerprint(self.state), "data": self.state})

    def _timer(self) -> None:
        while not self.stop.wait(self.config["checkpoint"]["interval_seconds"]):
            try:
                self.save()
            except (OSError, DataError) as exc:
                self.timer_error = exc
                self.stop.set()

    def event(self, kind: str) -> None:
        event = {"timestamp": utcnow(), "event": kind, "completed": len(self.state["completed"]),
                 "pending": len(self.state["pending"]), "run_id": self.state["run_id"]}
        with confined(self.project, self.directory / "events.jsonl").open("a", encoding="utf-8") as stream:
            stream.write(json.dumps(event) + "\n")
            stream.flush()

    def monitor(self) -> dict:
        state = self.state
        completed, pending = len(state["completed"]), len(state["pending"])
        duration = state.get("duration_seconds") if state["status"] != "RUNNING" else None
        if duration is None:
            duration = time.monotonic() - self.client.started
        return {"project": state["project"], "domain": self.target, "module": self.module, "status": state["status"],
                "completed": completed, "remaining": pending,
                "progress": None if self.module == "subfinding" and pending else round(100 * completed / max(1, completed + pending), 1),
                "requests_per_second": round(self.client.stats["requests"] / max(0.001, duration), 2),
                **self.client.stats, "results": len(state["results"]), "hosts": len(state["hosts"]),
                "task_errors": len(state["errors"]),
                "live_hosts": len(state["live_hosts"]), "inputs": len(state["inputs"]),
                "last_checkpoint": state["updated_at"], "rate_limit": round(self.client.limiter.current, 3)}

    def execute(self, observer=None) -> dict:
        """Una sola attività in volo; lock esclusivo e checkpoint anche su interruzione."""
        if self.export_only:
            raise DataError("Una run aperta per consultazione non può eseguire richieste")
        self.output_root.mkdir(parents=True, exist_ok=True)
        lock_path = confined(self.project, self.output_root / ".execution.lock")
        try:
            fd = os.open(lock_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError as exc:
            raise DataError("Progetto occupato. Se il processo è terminato, controllare e rimuovere .execution.lock manualmente") from exc
        timer = threading.Thread(target=self._timer, daemon=True)
        try:
            with os.fdopen(fd, "w") as stream:
                stream.write(str(os.getpid()))
            self.directory.mkdir(parents=True, exist_ok=True)
            if self._resume_snapshot is not None:
                old = self._resume_snapshot
                backup = confined(self.project, self.directory / ("checkpoint_before_" + fingerprint(old)[:24] + ".json"))
                if not backup.exists():
                    save_json(backup, {"sha256": fingerprint(old), "data": old})
            self.state["status"] = "RUNNING"
            self.state.pop("duration_seconds", None)
            self.client.started = time.monotonic()
            self.save()
            if not (self.directory / "metadata.json").exists():
                save_json(self.directory / "metadata.json", {**{key: self.state[key] for key in ("version", "run_id", "project", "module", "created_at", "scope_hash", "config_hash")},
                          "scope": {"domains": self.scope.domains, "excluded_hosts": self.scope.excluded,
                                    "allowed_ip_ranges": [str(n) for n in self.scope.networks]}})
            self.event("started")
            timer.start()
            while self.state["pending"]:
                if self.timer_error:
                    raise self.timer_error
                if observer:
                    observer(self.monitor())
                task = self.state["pending"][0]
                results, inputs, links = [], [], []
                live_url = None
                error = None
                try:
                    if not self._allowed_url(task["url"]):
                        raise DataError("Input fuori scope")
                    if self.module == "subfinding":
                        response = self.client.get(task["url"])
                        live_url = response.url
                        inputs, links = discover(self.scope, response)
                    else:
                        results = scan(self.module, task, self.client)
                except (DataError, NetworkError) as exc:
                    # Nessuna stringa di risposta o URL remoto nel messaggio tecnico.
                    error = {"task_id": task_id(task), "url": task["url"], "type": type(exc).__name__, "timestamp": utcnow()}
                    LOGGER.warning(json.dumps({"event": "task_error", "type": type(exc).__name__, "run_id": self.state["run_id"]}))
                with self.guard:
                    self.state["pending"].pop(0)
                    self.state["completed"].append(task_id(task))
                    if error:
                        self.state["errors"].append(error)
                    if live_url:
                        self.state["live_hosts"] = sorted(set(self.state["live_hosts"]) | {urlsplit(live_url).hostname, urlsplit(task["url"]).hostname})
                        self.state["endpoints"] = sorted(set(self.state["endpoints"]) | {live_url})
                    for result in results:
                        result.update(project=self.project.name, run_id=self.state["run_id"])
                        if self.target:
                            result["domain"] = self.target
                        existing = {r["id"] for r in self.state["results"]}
                        if result["id"] not in existing:
                            self.state["results"].append(result)
                    all_inputs = self.state["inputs"] + inputs
                    unique_inputs = deduplicate_inputs(all_inputs)
                    self.state["inputs"] = unique_inputs[:self.config["execution"]["max_tasks"]]
                    if len(unique_inputs) > self.config["execution"]["max_tasks"]:
                        self.state.setdefault("limits_reached", []).append("input_limit")
                    if self.module == "subfinding":
                        seen = {t["url"] for t in self.state["pending"]} | set(self.state["endpoints"]) | set(self.state.get("attempted_urls", []))
                        # Una URL fallita resta un tentativo già effettuato, senza dipendere dalla profondità.
                        self.state["attempted_urls"] = sorted(set(self.state.get("attempted_urls", [])) | {task["url"]})
                        seen.add(task["url"])
                        completed = set(self.state["completed"])
                        for link in links:
                            self.state["hosts"] = sorted(set(self.state["hosts"]) | {urlsplit(link).hostname})
                            next_task = {"url": link, "depth": task.get("depth", 0) + 1}
                            total = len(completed) + len(self.state["pending"])
                            if (next_task["depth"] <= self.config["discovery"]["max_depth"] and link not in seen
                                    and total < min(self.config["execution"]["max_tasks"], self.config["discovery"]["max_pages"])):
                                self.state["pending"].append(next_task)
                                seen.add(link)
                            elif link not in seen:
                                self.state.setdefault("limits_reached", []).append("crawl_limit")
                        self.state["limits_reached"] = sorted(set(self.state.get("limits_reached", [])))
                if len(self.state["completed"]) % self.config["checkpoint"]["completed_items_interval"] == 0:
                    self.save()
                    self.event("checkpoint")
            self.state["status"] = "COMPLETED"
        except KeyboardInterrupt:
            self.state["status"] = "INTERRUPTED"
        except BaseException:
            self.state["status"] = "FAILED"
            raise
        finally:
            self.stop.set()
            if timer.is_alive():
                timer.join(timeout=5)
            try:
                self.state["duration_seconds"] = max(0.0, time.monotonic() - self.client.started)
                self.save()
                self.event(self.state["status"].lower())
                self.export()
            except BaseException as exc:
                self.state["status"] = "INTERRUPTED" if isinstance(exc, KeyboardInterrupt) else "FAILED"
                try:
                    self.save()
                except (OSError, DataError):
                    LOGGER.error(json.dumps({"event": "checkpoint_write_failed", "project": self.project.name, "domain": self.target}))
                raise
            finally:
                self.client.cache.clear()
                lock_path.unlink(missing_ok=True)
        if observer:
            observer(self.monitor())
        return self.state

    def export(self) -> None:
        """I risultati storici restano nella run; gli export iniziali non sono sovrascritti."""
        state = self.state
        save_json(self.directory / "findings.json", state["results"])
        queue_path = confined(self.project, self.directory / "manual_review.json")
        previous_queue = read_json(queue_path) if queue_path.exists() else []
        if not isinstance(previous_queue, list):
            raise DataError("Coda revisione malformata")
        previous = {item["finding_id"]: item for item in previous_queue}
        queue = []
        for result in state["results"]:
            if result["manual_review"]:
                queue.append(previous.get(result["id"], {"finding_id": result["id"], "project": self.project.name,
                             "module": self.module, "endpoint": result["url"], "reason": result["check"],
                             "evidence": result["evidence"], "required_checks": result["limitations"],
                             "status": "PENDING_REVIEW", "timestamp": utcnow()}))
        save_json(queue_path, queue)
        if self.module == "subfinding":
            output = confined(self.project, self.directory / "subfinding")
            output.mkdir(exist_ok=True)
            texts = {"all_subdomains.txt": state["hosts"], "live_subdomains.txt": state["live_hosts"],
                     "domains_with_inputs.txt": sorted({i["host"] for i in state["inputs"]})}
            for name, values in texts.items():
                atomic_write(output / name, "".join(value + "\n" for value in values))
            save_json(output / "discovered_inputs.json", state["inputs"])
            initial = confined(self.project, self.output_root / "subfinding")
            if not self.target and state["status"] == "COMPLETED" and not initial.exists():
                initial.mkdir()
                for path in output.iterdir():
                    atomic_write(initial / path.name, path.read_text(encoding="utf-8"))
        report = {"project": self.project.name, "domain": self.target, "run_id": state["run_id"], "date": utcnow(),
                  "module": self.module, "status": state["status"],
                  "scope": {"domains": self.scope.domains, "excluded_hosts": self.scope.excluded,
                            "allowed_ip_ranges": [str(n) for n in self.scope.networks]},
                  "summary": self.monitor(), "findings": state["results"], "errors": state["errors"],
                  "limits_reached": state.get("limits_reached", []),
                  "manual_review": read_json(queue_path),
                  "limitations": ["Versione alpha: moduli parziali, nessuna conferma automatica di vulnerabilità.",
                                   "Discovery limitata e anonima; risultati mancanti non dimostrano assenza di vulnerabilità.",
                                   "La run può essere COMPLETED con errori: consultarne il conteggio."]}
        if state.get("import_only"):
            report["limitations"].append("Import di file storici: la data di creazione è quella dell'importazione, non di una nuova scansione.")
        save_json(self.directory / "report.json", report)
        lines = [f"# XITool — {self.project.name}", f"Dominio: {self.target or 'storico progetto'}", f"Run: {state['run_id']}", f"Modulo: {self.module}",
                 f"Stato: {state['status']} — errori: {len(state['errors'])}", "", "## Scope", json.dumps(report["scope"], ensure_ascii=True), "", "## Risultati"]
        for result in state["results"]:
            lines += [f"- {result['id']} — {result['status']} — {result['check']}",
                      "  " + json.dumps({"url": result["url"], "evidence": result["evidence"], "limitations": result["limitations"]}, ensure_ascii=True)]
        lines += ["", "## Limiti raggiunti", json.dumps(report["limits_reached"]),
                  "", "## Revisione manuale", json.dumps(report["manual_review"], ensure_ascii=True),
                  "", "## Errori", json.dumps(state["errors"], ensure_ascii=True),
                  "", "## Limitazioni", *report["limitations"]]
        atomic_write(self.directory / "report.md", "\n\n".join(lines) + "\n")
        if self.target:
            reports = confined(self.project, self.output_root / "reports")
            for extension in ("json", "md"):
                source = self.directory / f"report.{extension}"
                atomic_write(confined(self.project, reports / f"{state['run_id']}.{extension}"), source.read_text(encoding="utf-8"))
            if state["status"] == "COMPLETED":
                sources = list((self.directory / "subfinding").iterdir()) if self.module == "subfinding" else [self.directory / "findings.json", queue_path]
                self._publish(sources)

    def _publish(self, sources: list[Path]) -> None:
        """Aggiorna la vista corrente solo se i file precedenti sono ancora quelli generati."""
        destination = confined(self.project, self.output_root / self.module)
        destination.mkdir(exist_ok=True)
        manifest_path = confined(self.project, destination / "latest.json")
        previous = read_json(manifest_path) if manifest_path.exists() else None
        if previous is not None:
            if not isinstance(previous, dict) or not isinstance(previous.get("files"), dict):
                raise DataError("Indice dei risultati correnti corrotto")
            if self.state.get("import_only"):
                return
            if previous.get("created_at", "") > self.state["created_at"]:
                return
        for source in sources:
            target = confined(self.project, destination / source.name)
            if target.exists() and (previous is None or previous["files"].get(source.name) != fingerprint(target.read_text(encoding="utf-8"))):
                LOGGER.warning(json.dumps({"event": "export_preserved", "project": self.project.name, "domain": self.target,
                                           "reason": "File esistente o modificato: consultare la run"}))
                return
        contents = {source.name: source.read_text(encoding="utf-8") for source in sources}
        for name, content in contents.items():
            atomic_write(confined(self.project, destination / name), content)
        save_json(manifest_path, {"run_id": self.state["run_id"], "created_at": self.state["created_at"],
                                 "files": {name: fingerprint(content) for name, content in contents.items()}})


def review(directory: Path, finding_id: str, status: str) -> None:
    if status not in ("PENDING_REVIEW", "IN_REVIEW", "CONFIRMED", "DISMISSED"):
        raise DataError("Stato revisione non valido")
    path = confined(directory.parent.parent, directory / "manual_review.json")
    queue = read_json(path)
    if not isinstance(queue, list):
        raise DataError("Coda revisione malformata")
    entry = next((item for item in queue if item["finding_id"] == finding_id), None)
    if entry is None:
        raise DataError("Finding assente dalla coda")
    entry.update(status=status, timestamp=utcnow())
    save_json(path, queue)


def migrate_legacy(project: Path, scope: Scope, config: dict) -> list[str]:
    """Copia lo storico per dominio senza modificare o eliminare alcun originale."""
    if confined(project, project / ".execution.lock").exists():
        raise DataError("Migrazione rinviata: esecuzione precedente ancora bloccata dal lock del progetto")
    originals = runs(project)
    legacy = confined(project, project / "subfinding")
    # Supporta anche vecchi export privi di un checkpoint: l'origine rimane esplicita.
    if not originals and legacy.is_dir():
        data = read_json(confined(project, legacy / "discovered_inputs.json")) if (legacy / "discovered_inputs.json").exists() else []
        if not isinstance(data, list) or any(not isinstance(item, dict) or not {"url", "host", "method", "parameter"} <= item.keys() for item in data):
            raise DataError("Export precedente degli input malformato")
        def hosts(filename: str) -> list[str]:
            path = confined(project, legacy / filename)
            if not path.exists():
                return []
            if path.stat().st_size > 8 * 1024 * 1024:
                raise DataError("Export precedente oltre 8 MiB")
            return [line.strip() for line in path.read_text(encoding="utf-8").splitlines() if scope.allowed(line.strip())]
        known = hosts("all_subdomains.txt")
        live = hosts("live_subdomains.txt")
        content_hash = fingerprint([data, known, live])
        timestamp = utcnow()
        originals = [(legacy, {"version": 1, "project": project.name, "module": "subfinding", "run_id": "import_" + content_hash[:16],
                      "created_at": timestamp, "updated_at": timestamp, "status": "COMPLETED", "import_only": True,
                      "pending": [], "completed": [], "results": [], "errors": [], "inputs": data,
                      "endpoints": sorted({item["url"] for item in data}), "hosts": known, "live_hosts": live,
                      "stats": {}, "scope_hash": scope.digest, "config_hash": fingerprint(config)})]
    imported = []
    for directory, original in originals:
        source_hash = fingerprint({key: value for key, value in original.items() if not original.get("import_only") or key not in ("created_at", "updated_at")})
        for target in scope.roots():
            bounded = scope.for_target(target)
            def valid_url(value: str) -> bool:
                try:
                    safe_url(bounded, value)
                    return True
                except DataError:
                    return False
            state = copy.deepcopy(original)
            for key in ("pending", "results", "errors", "inputs"):
                state[key] = [item for item in state[key] if valid_url(item["url"])]
            for key in ("endpoints", "attempted_urls"):
                state[key] = [url for url in state.get(key, []) if valid_url(url)]
            for key in ("hosts", "live_hosts"):
                state[key] = [host for host in state[key] if bounded.allowed(host)]
            if not any(state[key] for key in ("pending", "results", "errors", "inputs", "hosts", "live_hosts", "endpoints")):
                continue
            run_id = original["run_id"] + "__" + source_hash[:8]
            destination = confined(project, target_path(project, target) / "runs" / run_id)
            if (destination / "checkpoint.json").exists():
                previous = load_state(destination / "checkpoint.json")
                if previous.get("legacy_source_hash") != source_hash:
                    raise DataError("Conflitto nella migrazione: lo storico esistente è stato preservato")
                continue
            state.update(version=2, domain=target, run_id=run_id, stats={}, completed=[],
                         legacy_source_hash=source_hash, legacy_completed_count=len(original["completed"]),
                         scope_hash=bounded.digest, legacy_scope_hash=original["scope_hash"],
                         created_at=original.get("created_at", original["updated_at"]))
            for result in state["results"]:
                result.update(domain=target, run_id=run_id)
            destination.mkdir(parents=True, exist_ok=True)
            save_json(destination / "metadata.json", {"project": project.name, "domain": target,
                      "legacy_source": directory.relative_to(project).as_posix(), "legacy_source_hash": source_hash,
                      "legacy_scope_hash": original["scope_hash"], "imported_at": utcnow(),
                      "limitations": "Conteggi HTTP e ID completati legacy non attribuibili ai singoli domini: non ripartiti artificialmente."})
            original_queue = confined(project, directory / "manual_review.json")
            if original_queue.exists():
                queue = read_json(original_queue)
                ids = {item["id"] for item in state["results"]}
                if not isinstance(queue, list) or any(not isinstance(item, dict) or "finding_id" not in item for item in queue):
                    raise DataError("Coda di revisione precedente corrotta")
                save_json(destination / "manual_review.json", [item for item in queue if item["finding_id"] in ids])
            save_json(destination / "checkpoint.json", {"sha256": fingerprint(state), "data": state})
            imported.append(f"{target}: {run_id}")
            Engine(project, scope, config, state["module"], target=target, resume=destination, export_only=True).export()
    return imported


def run_batch(engines: list[Engine], observer=None) -> list[dict]:
    """Continua sugli altri domini dopo errori; un'interruzione ferma l'intero batch."""
    summary = []
    interrupted = False
    # Il cambio di dominio non deve azzerare il budget HTTP o il backoff del batch.
    limiter = RateLimiter(min(engine.config["http"]["requests_per_second"] for engine in engines)) if engines else None
    for index, engine in enumerate(engines, 1):
        row = {"project": engine.project.name, "domain": engine.target,
               "module": engine.module, "run_id": engine.state["run_id"], "errors": 0}
        if interrupted:
            summary.append({**row, "status": "PENDING", "processed": False})
            continue
        try:
            engine.client.limiter = limiter
            def monitor(state: dict) -> None:
                if observer:
                    observer({**state, "batch_index": index, "batch_total": len(engines)})
            engine.execute(monitor)
            status = engine.state["status"]
            summary.append({**row, "status": status, "processed": True, "errors": len(engine.state["errors"])})
            interrupted = status == "INTERRUPTED"
        except KeyboardInterrupt:
            summary.append({**row, "status": "INTERRUPTED", "processed": True})
            interrupted = True
        except Exception as exc:
            LOGGER.error(json.dumps({"event": "domain_failed", "project": engine.project.name,
                                     "domain": engine.target, "type": type(exc).__name__}))
            summary.append({**row, "status": "FAILED", "processed": True, "errors": max(1, len(engine.state["errors"])),
                            "reason": type(exc).__name__})
    return summary


def scan_diff(before: dict, after: dict) -> dict:
    """Assenza di rilevazione non equivale a risoluzione o a mancata riproducibilità."""
    if before["project"] != after["project"] or before["module"] != after["module"] or before.get("domain") != after.get("domain"):
        raise DataError("Confrontare soltanto stesso progetto, dominio e modulo")
    result = {"before": before["run_id"], "after": after["run_id"],
              "scope_changed": before["scope_hash"] != after["scope_hash"],
              "config_changed": before["config_hash"] != after["config_hash"],
              "limitations": "Non più rilevato non significa risolto. Non più riproducibile richiede verifica umana."}
    for key in ("hosts", "live_hosts", "endpoints", "inputs", "results"):
        def index(state: dict) -> dict:
            if key == "results":
                return {r["id"]: {k: v for k, v in r.items() if k not in ("timestamp", "run_id")} for r in state[key]}
            if key == "inputs":
                return {fingerprint([r["url"], r["method"], r["parameter"]]): {k: v for k, v in r.items() if k != "timestamp"} for r in state[key]}
            return {r: r for r in state[key]}
        old, new = index(before), index(after)
        common = old.keys() & new.keys()
        result[key] = {"new": sorted(new.keys() - old.keys()), "not_detected": sorted(old.keys() - new.keys()),
                       "changed": sorted(k for k in common if old[k] != new[k]), "unchanged": sorted(k for k in common if old[k] == new[k])}
    return result
