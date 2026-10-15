"""Menu terminale: input, conferme e presentazione, senza algoritmi di scansione."""
from __future__ import annotations

import argparse
import json
import logging
from pathlib import Path
from urllib.parse import urlsplit

import yaml

from .execution import Engine, build_tasks, latest_discovery, review, runs, scan_diff
from .scanners import MODULES, smart
from .scope import Scope, matches, normalize_host, normalize_rule
from .storage import DataError, Projects, confined, load_config, read_json, save_json


MAIN_MENU = """========================================
                 XITOOL
             SECURITY TOOLKIT
========================================

[1] CREA PROGETTO
[2] APRI PROGETTI
[3] ESECUZIONE

[0] ESCI"""


def ask(prompt: str) -> str:
    value = input(prompt).strip()
    if len(value) > 8192:
        raise DataError("Input troppo lungo")
    return value


def confirm(prompt: str = "Confermare? [s/N]: ") -> bool:
    return ask(prompt).casefold() == "s"


def choose(items: list[str], multiple: bool = False) -> list[int]:
    for index, value in enumerate(items, 1):
        print(f"[{index}] {value}")
    print("[0] INDIETRO")
    text = ask("Scelta (numeri separati da virgole): " if multiple else "Scelta: ")
    if text == "0":
        return []
    pieces = text.split(",") if multiple else [text]
    if not pieces or any(not piece.strip().isdigit() or not 1 <= int(piece.strip()) <= len(items) for piece in pieces):
        raise DataError("Selezione non valida")
    return sorted({int(piece.strip()) - 1 for piece in pieces})


def edit_rules(title: str, required: bool = False) -> list[str]:
    rules: list[str] = []
    while True:
        print("\n" + title)
        for index, value in enumerate(rules, 1):
            print(f"[{index}] {value}")
        print("[A] AGGIUNGI  [R] RIMUOVI  [0] TERMINA")
        action = ask("Scelta: ").upper()
        try:
            if action == "A":
                rule = normalize_rule(ask("Dominio o *.dominio: "))
                if rule not in rules:
                    rules.append(rule)
            elif action == "R":
                selected = choose(rules)
                if selected:
                    rules.pop(selected[0])
            elif action == "0":
                if required and not rules:
                    print("Inserire almeno una regola autorizzata.")
                else:
                    return rules
            else:
                print("Scelta non valida.")
        except DataError as exc:
            print(f"Errore: {exc}")


def create_project(projects: Projects) -> None:
    print("\nCREA PROGETTO")
    name = ask("Nome progetto: ")
    projects.path(name)
    domains = edit_rules("DOMINI AUTORIZZATI", required=True)
    excluded = edit_rules("DOMINI NEGATI")
    scope = Scope(domains, excluded)
    print(json.dumps({"name": name, "domains": scope.domains, "excluded_hosts": scope.excluded}, indent=2))
    for rule in scope.domains:
        blocked = (rule in scope.excluded or
                   any(rule.startswith("*.") and exclusion.startswith("*.") and
                       matches(rule[2:], exclusion) for exclusion in scope.excluded) or
                   not rule.startswith("*.") and not scope.allowed(rule))
        if blocked:
            print(f"Conflitto: {rule} è negato; prevale l'esclusione.")
    if confirm():
        projects.create(name, domains, excluded)
        print("Progetto creato.")


def show_file(root: Path, path: Path) -> None:
    """Legge per righe con paginazione, senza interpretare escape del terminale."""
    path = confined(root, path)
    if path.suffix.lower() not in (".txt", ".json", ".csv", ".yaml", ".yml", ".log", ".jsonl", ".md"):
        raise DataError("Tipo file non visualizzabile")
    if path.suffix.lower() == ".json":
        read_json(path)
    if path.suffix.lower() in (".yaml", ".yml"):
        if path.stat().st_size > 1024 * 1024:
            raise DataError("YAML oltre il limite di visualizzazione di 1 MiB")
        try:
            yaml.safe_load(path.read_text(encoding="utf-8"))
        except yaml.YAMLError as exc:
            raise DataError("YAML corrotto") from exc
    with path.open(encoding="utf-8", errors="strict") as stream:
        index = 0
        while True:
            line = stream.readline(16385)
            if not line:
                break
            if len(line) > 16384:
                print("[Riga oltre 16 KiB: visualizzazione interrotta]")
                break
            print("".join(c if c == "\t" or ord(c) >= 32 and ord(c) != 127 else "?" for c in line.rstrip("\r\n")))
            index += 1
            if index % 25 == 0 and ask("Invio: continua; 0: indietro: ") == "0":
                break


def browse(project: Path) -> None:
    current = project
    while True:
        print(f"\nPROGETTO {project.name} / {current.relative_to(project)}")
        entries = sorted((p for p in current.iterdir() if not p.is_symlink()), key=lambda p: (not p.is_dir(), p.name))
        selected = choose([p.name + ("/" if p.is_dir() else "") for p in entries])
        if not selected:
            if current == project:
                return
            current = current.parent
            continue
        target = confined(project, entries[selected[0]])
        if target.is_dir():
            current = target
        else:
            try:
                show_file(project, target)
            except (OSError, UnicodeError, DataError) as exc:
                print(f"File non leggibile: {exc}")


def print_monitor(state: dict) -> None:
    progress = "indeterminato" if state["progress"] is None else f"{state['progress']}%"
    print(f"\n{state['project']} | {state['module']} | {state['status']} | progresso {progress}")
    print(f"Completati {state['completed']} | rimanenti {state['remaining']} | finding {state['results']} | input {state['inputs']}")
    print(f"Richieste/s {state['requests_per_second']} | limite {state['rate_limit']} | errori HTTP {state['errors']} | timeout {state['timeouts']} | cache hit {state['cache_hits']}")
    print(f"Checkpoint UTC {state['last_checkpoint']} | Ctrl+C interrompe e salva")


def seeds(scope: Scope, config: dict) -> list[dict]:
    """Importa output passivo locale prima di qualsiasi probing attivo."""
    hosts = {rule for rule in scope.domains if not rule.startswith("*.") and scope.allowed(rule)}
    source = ask("File TXT di host da fonti passive (vuoto per soli domini esatti): ")
    if source:
        path = Path(source).expanduser()
        if path.stat().st_size > 8 * 1024 * 1024:
            raise DataError("Elenco passivo oltre 8 MiB")
        discarded = 0
        for raw in path.read_text(encoding="utf-8").splitlines():
            try:
                host = normalize_host(raw.strip())
            except DataError:
                discarded += 1
                continue
            if scope.allowed(host):
                hosts.add(host)
            else:
                discarded += 1
        print(f"Host autorizzati: {len(hosts)}; righe scartate: {discarded}")
    urls = []
    for host in sorted(hosts):
        authority = f"[{host}]" if ":" in host else host
        for scheme, port in (("https", 443), ("http", 80)):
            if port in config["http"]["allowed_ports"]:
                urls.append(f"{scheme}://{authority}/")
    custom = ask("URL iniziali aggiuntivi, separati da virgole (vuoto per continuare): ")
    if custom:
        urls += [scope.url(value.strip(), config["http"]["allowed_ports"]) for value in custom.split(",")]
    tasks = build_tasks("subfinding", scope, [], urls)
    if len(tasks) > config["discovery"]["max_pages"]:
        raise DataError("I seed superano max_pages: suddividere gli input o aumentare il limite")
    return tasks


def post_run(engine: Engine) -> None:
    while True:
        print(f"\nRISULTATI: {engine.directory}")
        selected = choose(["File dei risultati", "Manual Review Queue", "Scan Diff", "Rigenera report"])
        if not selected:
            return
        if selected[0] == 0:
            browse(engine.project)
        elif selected[0] == 1:
            queue = read_json(engine.directory / "manual_review.json")
            if not queue:
                print("Nessuna revisione richiesta.")
                continue
            selected_entry = choose([f"{item['finding_id']} {item['status']} {item['reason']}" for item in queue])
            if not selected_entry:
                continue
            entry = queue[selected_entry[0]]
            print(json.dumps(entry, indent=2, ensure_ascii=True))
            statuses = ["PENDING_REVIEW", "IN_REVIEW", "CONFIRMED", "DISMISSED"]
            status = choose(statuses)
            if status and confirm("Registrare la valutazione umana? [s/N]: "):
                review(engine.directory, entry["finding_id"], statuses[status[0]])
                engine.export()
        elif selected[0] == 2:
            previous = [(directory, state) for directory, state in runs(engine.project, engine.module)
                        if directory != engine.directory and state["status"] == "COMPLETED"]
            if not previous:
                print("Nessuna run precedente completata per lo stesso modulo.")
                continue
            index = choose([directory.name for directory, _ in previous])
            if index:
                diff = scan_diff(previous[index[0]][1], engine.state)
                save_json(engine.directory / ("diff_" + previous[index[0]][0].name + ".json"), diff)
                print(json.dumps(diff, indent=2))
        else:
            engine.export()
            print("Report JSON e Markdown aggiornati nella run.")


def execute(projects: Projects, config: dict) -> None:
    names = projects.list()
    selected = choose(names, multiple=True)
    if not selected:
        return
    keys = list(MODULES)
    print("\nESECUZIONE")
    module_index = choose([f"{label} [{status}]" for label, status in MODULES.values()])
    if not module_index:
        return
    module = keys[module_index[0]]
    if MODULES[module][1] == "NOT_IMPLEMENTED":
        raise DataError("Modulo NOT_IMPLEMENTED: nessuna attività avviata")
    plans = []
    for index in selected:
        project, scope = projects.load(names[index])
        resume = None
        incomplete = [(directory, state) for directory, state in runs(project, module) if state["status"] != "COMPLETED"]
        if config["execution"]["resume_enabled"] and incomplete:
            directory, state = incomplete[0]
            print(f"\nSCANSIONE INTERROTTA: {project.name} / {module}")
            print(f"Completati {len(state['completed'])}; rimanenti {len(state['pending'])}")
            action = choose(["RIPRENDI SCANSIONE", "NUOVA SCANSIONE"])
            if not action:
                return
            if action[0] == 0:
                resume = directory
        if resume:
            engine = Engine(project, scope, config, module, resume=resume)
        else:
            if module == "subfinding":
                tasks = seeds(scope, config)
            else:
                inputs, urls = latest_discovery(project, scope)
                proposals = smart(inputs, urls)
                print(f"Smart Execution — proposte per {project.name}: {json.dumps(proposals)}")
                tasks = build_tasks(module, scope, inputs, urls)
            engine = Engine(project, scope, config, module, tasks=tasks)
        print(f"\nPROGETTO: {project.name}\nModulo: {module} [{MODULES[module][1]}]")
        print(f"Autorizzati: {scope.domains}\nNegati: {scope.excluded}")
        print(f"CIDR speciali espliciti: {[str(n) for n in scope.networks]}")
        print(f"Attività: {len(engine.state['pending'])}; ripresa: {bool(resume)}")
        print(f"Limiti HTTP: {json.dumps(config['http'])}; esecuzione sequenziale")
        print(f"Output: {engine.directory} (checkpoint, eventi, finding, report, review)")
        plans.append(engine)
    if not confirm("Confermo autorizzazione allo scope e avvio dei controlli descritti [s/N]: "):
        return
    for engine in plans:
        engine.execute(print_monitor)
        if engine.state["status"] == "INTERRUPTED":
            print("Scansione interrotta e salvata; gli altri progetti non sono stati avviati.")
            return
        post_run(engine)


def main(base: Path) -> None:
    parser = argparse.ArgumentParser(description="XITool 2.0 alpha — verifiche web autorizzate")
    parser.add_argument("--data-dir", type=Path, default=base / "targets")
    parser.add_argument("--config", type=Path, default=base / "config.yaml")
    parser.add_argument("--version", action="version", version="XITool 2.0.0a1")
    options = parser.parse_args()
    try:
        config = load_config(options.config)
        projects = Projects(options.data_dir)
    except (OSError, DataError) as exc:
        print(f"Avvio non riuscito: {exc}")
        raise SystemExit(2) from exc
    # Gli eventi persistenti contengono contatori e tipi di errore, senza risposte HTTP.
    logging.basicConfig(level=getattr(logging, config["logging"]["level"]), format="%(message)s")
    while True:
        try:
            print("\n" + MAIN_MENU)
            action = ask("Scelta: ")
            if action == "0":
                return
            if action == "1":
                create_project(projects)
            elif action == "2":
                names = projects.list()
                selected = choose(names)
                if selected:
                    project, _ = projects.load(names[selected[0]])
                    browse(project)
            elif action == "3":
                execute(projects, config)
            else:
                print("Scelta non valida: usare 0, 1, 2 o 3.")
        except EOFError:
            print("\nInput terminato.")
            return
        except KeyboardInterrupt:
            print("\nOperazione annullata.")
        except (OSError, UnicodeError, DataError) as exc:
            print(f"Errore: {exc}")
