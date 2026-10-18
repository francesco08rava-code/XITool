"""Code persistenti, ripresa, risultati, revisioni e report separati per progetto."""
from __future__ import annotations

import json
import copy
import logging
import os
from pathlib import Path
import threading
import time
from urllib.parse import urlsplit, urlunsplit
import uuid

from .http import HTTPClient, NetworkError, RateLimiter
from .dns import DNSResolver
from .passive import PROVIDERS, collect
from .recon_output import observe_host, outputs as recon_outputs, probe_metadata
from .controlled import execute as controlled_scan
from .sessions import load_profiles
from .outcomes import run_outcome, summary as outcome_summary
from .scanners import MODULES, deduplicate_inputs, discover, safe_url, scan
from .scope import Scope
from .storage import DataError, atomic_write, confined, fingerprint, read_json, save_json, target_path, utcnow

LOGGER = logging.getLogger("xitool")


def record_no_input(project: Path, scope: Scope, module: str, target: str) -> Path:
    if module not in MODULES:
        raise DataError("Modulo non valido")
    bounded = scope.for_target(target)
    path = confined(project, target_path(project, target) / "reports" / ("no_input_" + uuid.uuid4().hex + ".json"))
    save_json(path, {"project": project.name, "domain": target, "module": module, "timestamp": utcnow(),
                    "execution_status": "NOT_STARTED", "verification_outcome": "NO_INPUT", "findings": [],
                    "scope_hash": bounded.digest, "reason": "Nessun input o risorsa controllata configurata; nessun controllo eseguito."})
    return path


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


def latest_discovery(project: Path, scope: Scope, target: str | None = None, config=None) -> tuple[list[dict], list[str]]:
    for _, state in runs(project, "subfinding", target):
        if config is not None:
            from . import __version__
            if state.get("engine_version") != __version__ or state.get("config_hash") != fingerprint(config) or state.get("scope_hash") != scope.digest:
                continue
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
    if module == "access":
        return []  # Senza risorse controllate non trasformare URL generici in test di autorizzazione.
    tasks = []
    if module in ("xss", "idor", "ssrf", "traversal"):
        kinds = {"idor": "identifier", "ssrf": "url", "traversal": "file"}
        for entry in inputs:
            if module == "xss":
                if entry.get("method") != "GET" or entry.get("source") not in ("query", "link") or entry.get("input_type") == "authentication":
                    continue
            if entry.get("source") == "response_json" or entry.get("request_input_confirmed") is False:
                continue
            if module != "xss" and entry.get("input_type") != kinds[module]:
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
        self.dns = DNSResolver(scope, config["http"]["timeout_seconds"], self.client.limiter)
        if module not in MODULES or MODULES[module][1] == "NOT_IMPLEMENTED":
            raise DataError("Modulo non disponibile")
        if resume:
            self.directory = confined(project, resume)
            self.state = load_state(self.directory / "checkpoint.json")
            if self.state["module"] != module or self.state["project"] != project.name or self.state.get("domain") != target:
                raise DataError("Checkpoint di altro progetto o modulo")
            if export_only:
                return
            from . import __version__
            if self.state.get("engine_version") != __version__:
                raise DataError("Versione del motore cambiata: creare una nuova run")
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
            state["errors"] = [e for e in state["errors"] if self._allowed_url(e.get("url", "")) or
                               self._allowed_task({"url": e.get("url", ""), "kind": "passive", "provider": e.get("provider")})]
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
                          "inputs": [], "endpoints": [], "hosts": sorted({urlsplit(t["url"]).hostname for t in tasks if scope.allowed(urlsplit(t["url"]).hostname)}),
                          "live_hosts": [], "scope_hash": scope.digest, "config_hash": fingerprint(config),
                          "updated_at": utcnow(), "created_at": utcnow(), "stats": {}, "limits_reached": []}
            if target:
                self.state["domain"] = target
            self.state.update(seed_hosts=[target] if target else list(self.state["hosts"]),
                              host_limit=config["execution"]["max_tasks"], host_observations={},
                              dns_records={}, http_probes=[], provider_metadata=[], provider_errors=[])
            from . import __version__
            self.state["engine_version"] = __version__
            self.state["dynamic_browser"] = os.environ.get("XITOOL_DYNAMIC_BROWSER") == "1"
            if module == "subfinding":
                from .inventory import historical_references
                self.state["url_references"] = historical_references(project, self.scope, target)
                for task in tasks:
                    observe_host(self.state, self.scope, urlsplit(task["url"]).hostname, "initial_input")

    def _allowed_url(self, url: str) -> bool:
        try:
            safe_url(self.scope, url)
            self.scope.url(url, self.config["http"]["allowed_ports"])
            return True
        except DataError:
            return False

    def _filter_tasks(self, tasks: list[dict]) -> list[dict]:
        return list({task_id(t): t for t in tasks if isinstance(t, dict) and self._allowed_task(t)}.values())

    def _allowed_task(self, task: dict) -> bool:
        if task.get("kind") == "passive":
            # È un identificatore di ricerca, non una URL da visitare sul target.
            root = self.target
            return (self.module == "subfinding" and root in self.scope.roots() and
                    task.get("provider") in PROVIDERS and task.get("url") == f"https://{root}/")
        if task.get("kind") == "dns":
            try:
                parsed = urlsplit(task.get("url", ""))
                return (self.module == "subfinding" and parsed.scheme == "https" and parsed.path == "/" and
                        not parsed.query and not parsed.fragment and parsed.username is None and parsed.password is None and parsed.port is None and
                        self.scope.allowed(parsed.hostname or ""))
            except ValueError:
                return False
        return self._allowed_url(task.get("url", ""))

    def enqueue(self, tasks: list[dict]) -> None:
        """Limita anche il lavoro generato da DNS/provider e rende persistente la deduplica."""
        known = set(self.state["completed"]) | {task_id(task) for task in self.state["pending"]}
        for task in self._filter_tasks(tasks):
            identity = task_id(task)
            if identity in known:
                continue
            limit = min(self.config["execution"]["max_tasks"], self.config["discovery"]["max_pages"])
            if len(known) >= limit:
                self.state.setdefault("limits_reached", []).append("task_limit")
                break
            self.state["pending"].append(task)
            known.add(identity)

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
                "new_subdomains": len(recon_outputs(state, self.scope)[0]["all_subdomains.txt"]) if self.module == "subfinding" else 0,
                "live_hosts": len(state["live_hosts"]), "inputs": len(state["inputs"]),
                "last_checkpoint": state["updated_at"], "rate_limit": round(self.client.limiter.current, 3)}

    def _perform(self, task, client=None):
        client = client or self.client
        resolver = self.dns
        results, inputs, links = [], [], []
        generated = []
        dns_record = None
        client.request_ids.clear()
        probe = None
        provider_result = None
        references = []
        live_url = None
        error = None
        try:
            if not self._allowed_task(task):
                raise DataError("Input fuori scope")
            if self.module == "subfinding":
                if task.get("kind") == "passive":
                    client.limiter.request_budget = client.budget
                    client.limiter.shared_host_limiters = client.host_limiters
                    provider_result = collect(task["provider"], self.target, self.config, client.limiter)
                elif task.get("kind") == "dns":
                    resolver.limiter = client.limiter
                    host = urlsplit(task["url"]).hostname
                    if self.target and "wildcard_dns" not in self.state:
                        self.state["wildcard_dns"] = resolver.wildcard(self.target)
                    dns_record = resolver.resolve(host)
                    if dns_record["resolved"]:
                        authority = f"[{host}]" if ":" in host else host
                        generated = [{"url": f"{scheme}://{authority}/", "depth": 0, "recon": True}
                                     for scheme, port in (("https", 443), ("http", 80)) if port in self.config["http"]["allowed_ports"]]
                        if host in self.scope.path_limits:
                            generated = [{"url": rule, "depth": 0, "recon": True} for rule in self.scope.path_limits[host]]
                else:
                    response = client.get(task["url"])
                    live_url = safe_url(self.scope, response.url)
                    probe = probe_metadata(response, self.scope)
                    inputs, links, references = discover(self.scope, response, include_references=True)
                    if self.state.get("dynamic_browser") and "html" in response.headers.get("content-type", "").lower():
                        from .dynamic import render
                        dynamic = render(client, response.url)
                        inputs += dynamic["inputs"]
                        links = sorted(set(links) | set(dynamic["links"]))
                        references += dynamic["references"]
                        self.state.setdefault("browser_observations", []).append({"url": response.url,
                            "status": dynamic["status"], "requests": dynamic.get("requests", 0), "blocked": dynamic["blocked"]})
                        if dynamic["status"] != "COMPLETED":
                            self.state.setdefault("limits_reached", []).append("dynamic_browser_partial_or_unsupported")
                    if task.get("recon") and urlsplit(task["url"]).path == "/":
                        parsed = urlsplit(response.url)
                        generated = [{"url": urlunsplit((parsed.scheme, parsed.netloc, path, "", "")), "depth": 0, "recon": True}
                                     for path in ("/robots.txt", "/sitemap.xml")]
            else:
                active_client = client
                if task.get("session"):
                    profiles = load_profiles(self.project)
                    profile = profiles.get(task["session"])
                    if profile is None:
                        raise DataError("Profilo di sessione non disponibile")
                    active_client = client.for_profile(profile)
                results = (controlled_scan(self.module, task, active_client, self.project) if task.get("controlled_case") else
                           scan(self.module, task, active_client))
        except (DataError, NetworkError) as exc:
            # Nessuna stringa di risposta o URL remoto nel messaggio tecnico.
            error = {"task_id": task_id(task), "url": task["url"], "type": type(exc).__name__, "timestamp": utcnow()}
            from .errors import classify, LABELS
            error["category"] = classify(exc)
            error["message"] = LABELS[error["category"]]
            error["stage"] = (task.get("kind") or "http") if self.module == "subfinding" else "scanner"
            LOGGER.warning(json.dumps({"event": "task_error", "type": type(exc).__name__, "run_id": self.state["run_id"]}))
        return {name: value for name, value in locals().items() if name in {
            "results", "inputs", "links", "generated", "dns_record", "probe", "provider_result",
            "references", "live_url", "error", "client"}}

    def execute(self, observer=None) -> dict:
        """Task bounded; solo il coordinatore modifica code e checkpoint."""
        if self.export_only:
            raise DataError("Una run aperta per consultazione non può eseguire richieste")
        self.output_root.mkdir(parents=True, exist_ok=True)
        lock_path = confined(self.project, self.output_root / ".execution.lock")
        try:
            fd = os.open(lock_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError as exc:
            raise DataError("Progetto occupato. Se il processo è terminato, controllare e rimuovere .execution.lock manualmente") from exc
        from .workers import TaskPool
        pool = TaskPool(self)
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
                          "scope": {"domains": self.scope.raw_domains, "excluded_hosts": self.scope.excluded,
                                    "allowed_ip_ranges": [str(n) for n in self.scope.networks]}})
            self.event("started")
            timer.start()
            while self.state["pending"]:
                if self.stop.is_set():
                    raise KeyboardInterrupt()
                if time.monotonic() - self.client.started > self.config["execution"].get("max_duration_seconds", 600):
                    self.state["limits_reached"].append("duration_limit")
                    self.state["status"] = "PAUSED"
                    break
                if self.timer_error:
                    raise self.timer_error
                if observer:
                    observer(self.monitor())
                task = self.state["pending"][0]
                output = pool.take(task)
                if self.stop.is_set() and pool.eligible(task):
                    raise KeyboardInterrupt()  # Task annullato/in volo rimane pendente nel checkpoint.
                results, inputs, links = output["results"], output["inputs"], output["links"]
                generated, dns_record, probe = output["generated"], output["dns_record"], output["probe"]
                provider_result, references = output["provider_result"], output["references"]
                live_url, error = output["live_url"], output["error"]
                request_ids = list(output["client"].request_ids)
                with self.guard:
                    self.state["pending"].pop(0)
                    self.state["completed"].append(task_id(task))
                    if error:
                        self.state["errors"].append(error)
                    if provider_result is not None:
                        self.state.setdefault("provider_metadata", []).append(provider_result)
                        self.client.stats["requests"] += provider_result["requests"]
                        for host in provider_result["hosts"]:
                            observe_host(self.state, self.scope, host, provider_result["provider"])
                            if self.scope.allowed(host):
                                self.state["hosts"] = sorted(set(self.state["hosts"]) | {host})
                                generated.append({"url": f"https://{host}/", "kind": "dns"})
                        for message in provider_result["errors"]:
                            entry = {"provider": task["provider"], "type": message, "timestamp": utcnow()}
                            self.state.setdefault("provider_errors", []).append(entry)
                            self.state["errors"].append({**entry, "url": task["url"], "task_id": task_id(task)})
                    if dns_record is not None:
                        self.state.setdefault("dns_records", {})[dns_record["host"]] = dns_record
                        for problem in dns_record.get("errors", []):
                            if problem != "NXDOMAIN":
                                self.state["errors"].append({"url": task["url"], "task_id": task_id(task), "type": "DNS_" + problem, "timestamp": utcnow()})
                    if probe is not None:
                        self.state.setdefault("http_probes", []).append(probe)
                    if live_url:
                        self.state["live_hosts"] = sorted(set(self.state["live_hosts"]) | {urlsplit(live_url).hostname, urlsplit(task["url"]).hostname})
                        self.state["endpoints"] = sorted(set(self.state["endpoints"]) | {live_url})
                    for result in results:
                        from .assessment import assess
                        assess(result)
                        result.update(project=self.project.name, run_id=self.state["run_id"], request_ids=request_ids)
                        if self.target:
                            result["domain"] = self.target
                        existing = {r["id"] for r in self.state["results"]}
                        if result["id"] not in existing:
                            self.state["results"].append(result)
                    all_inputs = [{**row, "project": self.project.name, "domain": self.target or row.get("host")}
                                  for row in self.state["inputs"] + inputs]
                    unique_inputs = deduplicate_inputs(all_inputs)
                    self.state["inputs"] = unique_inputs[:self.config["execution"]["max_tasks"]]
                    if len(unique_inputs) > self.config["execution"]["max_tasks"]:
                        self.state.setdefault("limits_reached", []).append("input_limit")
                    if self.module == "subfinding":
                        combined = self.state.get("url_references", []) + references
                        if any(row.get("reason") == "ANALYSIS_LIMIT" for row in references):
                            self.state.setdefault("limits_reached", []).append("javascript_analysis_limit")
                        self.state["url_references"] = list({fingerprint([entry["url"], entry["source"], entry["kind"], entry.get("method"), entry.get("line"), entry.get("column")]): entry for entry in combined}.values())[:self.config["execution"]["max_tasks"]]
                        for link in links:
                            observe_host(self.state, self.scope, urlsplit(link).hostname, "crawl")
                        self.enqueue(generated)
                        seen = {t["url"] for t in self.state["pending"]} | set(self.state["endpoints"]) | set(self.state.get("attempted_urls", []))
                        # Una URL fallita resta un tentativo già effettuato, senza dipendere dalla profondità.
                        self.state["attempted_urls"] = sorted(set(self.state.get("attempted_urls", [])) | {task["url"]})
                        if task.get("kind") not in ("dns", "passive"):
                            seen.add(task["url"])
                        completed = set(self.state["completed"])
                        static_only = {row["url"] for row in references if row.get("kind") == "STATIC_HYPOTHESIS"}
                        observed = {row["url"] for row in references if row.get("kind") in
                                    ("OBSERVED_LINK", "OBSERVED_CANONICAL", "OBSERVED_ROBOTS", "OBSERVED_SITEMAP", "OBSERVED_DOM") or
                                    (row.get("kind") == "OBSERVED_NETWORK" and row.get("reached"))}
                        for link in links:
                            if link in static_only and link not in observed:
                                continue  # inventory is not permission or evidence of reachability
                            self.state["hosts"] = sorted(set(self.state["hosts"]) | {urlsplit(link).hostname})
                            next_task = {"url": link, "depth": task.get("depth", 0) + 1}
                            if task.get("recon"):
                                next_task["recon"] = True
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
            if not self.state["pending"]:
                self.state["status"] = "COMPLETED"
        except KeyboardInterrupt:
            self.state["status"] = "INTERRUPTED"
        except BaseException:
            self.state["status"] = "FAILED"
            raise
        finally:
            pool.close()
            if timer.is_alive():
                timer.join(timeout=5)
            try:
                self.state["duration_seconds"] = max(0.0, time.monotonic() - self.client.started)
                self.state["verification_outcome"] = run_outcome(self.state)
                self.save()
                self.event(self.state["status"].lower())
                self.export()
            except BaseException as exc:
                self.state["status"] = "INTERRUPTED" if isinstance(exc, KeyboardInterrupt) else "FAILED"
                self.state["verification_outcome"] = "PARTIAL" if isinstance(exc, KeyboardInterrupt) else "FAILED"
                try:
                    self.save()
                except (OSError, DataError):
                    LOGGER.error(json.dumps({"event": "checkpoint_write_failed", "project": self.project.name, "domain": self.target}))
                raise
            finally:
                self.client.cache.clear()
                lock_path.unlink(missing_ok=True)
        if observer:
            try:
                observer(self.monitor())
            except KeyboardInterrupt:
                pass  # Risultati e checkpoint già salvati; nessun altro task da avviare.
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
        from .assessment import assess
        human = {row["finding_id"]: row["status"] for row in queue}
        report_findings = [assess({**row, "human_verdict": human.get(row["id"])}) for row in state["results"]]
        if self.module == "subfinding":
            output = confined(self.project, self.directory / "subfinding")
            output.mkdir(exist_ok=True)
            from .crawl_output import export as export_crawler
            export_crawler(self.directory / "crawler", state)
            texts, details = recon_outputs(state, self.scope)
            for name, values in texts.items():
                atomic_write(output / name, "".join(value + "\n" for value in values))
            for name, values in details.items():
                save_json(output / name, values)
            initial = confined(self.project, self.output_root / "subfinding")
            if not self.target and state["status"] == "COMPLETED" and not initial.exists():
                initial.mkdir()
                for path in output.iterdir():
                    atomic_write(initial / path.name, path.read_text(encoding="utf-8"))
        report = {"project": self.project.name, "domain": self.target, "run_id": state["run_id"], "date": utcnow(),
                  "module": self.module, "status": state["status"], "version": state.get("engine_version", "legacy"),
                  "modules_executed": [self.module] + (["crawler"] if self.module == "subfinding" else []),
                  "modules_not_executed": [key for key in MODULES if key != self.module],
                  **outcome_summary(state),
                  "scope": {"domains": self.scope.raw_domains, "excluded_hosts": self.scope.excluded,
                            "allowed_ip_ranges": [str(n) for n in self.scope.networks]},
                  "summary": self.monitor(), "findings": report_findings, "errors": state["errors"],
                  "limits_reached": state.get("limits_reached", []),
                  "manual_review": read_json(queue_path),
                  "limitations": ["Versione alpha: moduli parziali, nessuna conferma automatica di vulnerabilità.",
                                   "Discovery limitata; risultati mancanti non dimostrano assenza di vulnerabilità.",
                                   "La run può essere COMPLETED con errori: consultarne il conteggio."]}
        if state.get("import_only"):
            report["limitations"].append("Import di file storici: la data di creazione è quella dell'importazione, non di una nuova scansione.")
        if self.module == "subfinding":
            report["reconnaissance"] = recon_outputs(state, self.scope)[1]["summary.json"]
            report["limitations"].append("Fonti CT limitate: massimo 3 pagine CertSpotter e una risposta crt.sh. Errori, rate limit e troncamenti sono espliciti; nessuna completezza garantita.")
        save_json(self.directory / "report.json", report)
        lines = [f"# XITool — {self.project.name}", f"Dominio: {self.target or 'storico progetto'}", f"Run: {state['run_id']}", f"Modulo: {self.module}",
                 f"Stato: {state['status']} — errori: {len(state['errors'])}", "", "## Scope", json.dumps(report["scope"], ensure_ascii=True), "", "## Risultati"]
        for result in report_findings:
            lines += [f"- {result['id']} — {result['status']} — {result['check']}",
                      "  " + json.dumps({"url": result["url"], "evidence": result["evidence"], "limitations": result["limitations"],
                                         "confidence_score": result.get("confidence_score"), "confidence_factors": result.get("confidence_factors"),
                                         "review_priority": result.get("review_priority"), "severity": result.get("severity", "UNKNOWN")}, ensure_ascii=True)]
        lines += ["", "## Limiti raggiunti", json.dumps(report["limits_reached"]),
                  "", "## Revisione manuale", json.dumps(report["manual_review"], ensure_ascii=True),
                  "", "## Errori", json.dumps(state["errors"], ensure_ascii=True),
                  "", "## Limitazioni", *report["limitations"]]
        if self.module == "subfinding":
            lines += ["", "## Ricognizione", json.dumps(report["reconnaissance"], ensure_ascii=True)]
        atomic_write(self.directory / "report.md", "\n\n".join(lines) + "\n")
        atomic_write(self.directory / "report.txt", "\n".join(lines) + "\n")
        if self.target:
            reports = confined(self.project, self.output_root / "reports")
            for extension in ("json", "md", "txt"):
                source = self.directory / f"report.{extension}"
                atomic_write(confined(self.project, reports / f"{state['run_id']}.{extension}"), source.read_text(encoding="utf-8"))
            if state["status"] == "COMPLETED":
                sources = list((self.directory / "subfinding").iterdir()) if self.module == "subfinding" else [self.directory / "findings.json", queue_path]
                self._publish(sources)
                if self.module == "subfinding":
                    self._publish(list((self.directory / "crawler").iterdir()), "crawler")

    def _publish(self, sources: list[Path], projection=None) -> None:
        """Aggiorna la vista corrente solo se i file precedenti sono ancora quelli generati."""
        destination = confined(self.project, self.output_root / (projection or self.module))
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
    if status not in ("PENDING_REVIEW", "IN_REVIEW", "CONFIRMED", "DISMISSED", "FALSE_POSITIVE"):
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
    if not engines:
        return []
    if min(engine.config["execution"].get("max_concurrent_domains", 1) for engine in engines) > 1:
        from .domain_workers import execute as execute_domains
        summary = execute_domains(engines, _run_batch_serial, observer)
    else:
        summary = _run_batch_serial(engines, observer)
    from .reporting import export_project
    for project in {engine.project for engine in engines}:
        export_project(project, engines, summary)
    return summary


def _run_batch_serial(engines: list[Engine], observer=None, shared_limiter=None, shared_budget=None) -> list[dict]:
    """Continua sugli altri domini dopo errori; un'interruzione ferma l'intero batch."""
    summary = []
    interrupted = False
    # Il cambio di dominio non deve azzerare il budget HTTP o il backoff del batch.
    limiter = shared_limiter or (RateLimiter(min(engine.config["http"]["requests_per_second"] for engine in engines)) if engines else None)
    for index, engine in enumerate(engines, 1):
        row = {"project": engine.project.name, "domain": engine.target,
               "module": engine.module, "run_id": engine.state["run_id"], "errors": 0}
        if interrupted:
            summary.append({**row, "status": "PENDING", "processed": False})
            continue
        try:
            engine.client.limiter = limiter
            if shared_budget is not None:
                engine.client.budget = shared_budget
            def monitor(state: dict) -> None:
                if observer:
                    observer({**state, "batch_index": index, "batch_total": len(engines)})
            engine.execute(monitor)
            status = engine.state["status"]
            summary.append({**row, "status": status, "verification_outcome": run_outcome(engine.state), "processed": True, "errors": len(engine.state["errors"])})
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
                from .diffing import finding_semantic
                return {r.get("issue_fingerprint", r["id"]): finding_semantic(r) for r in state[key]}
            if key == "inputs":
                from .diffing import semantic
                return {fingerprint([r["url"], r["method"], r.get("location", "query"), r["parameter"]]): semantic(r) for r in state[key]}
            return {r: r for r in state[key]}
        old, new = index(before), index(after)
        common = old.keys() & new.keys()
        result[key] = {"new": sorted(new.keys() - old.keys()), "not_detected": sorted(old.keys() - new.keys()),
                       "changed": sorted(k for k in common if old[k] != new[k]), "unchanged": sorted(k for k in common if old[k] == new[k])}
    from .diffing import extend_diff
    return extend_diff(result, before, after)
