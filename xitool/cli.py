"""Menu terminale: input, conferme e presentazione, senza algoritmi di scansione."""
from __future__ import annotations

import argparse
import json
import logging
import os
import re
from pathlib import Path
import sys
from urllib.parse import urlsplit

import yaml

from . import __version__
from .execution import Engine, build_tasks, latest_discovery, migrate_legacy, review, run_batch, runs, scan_diff, record_no_input
from .scanners import MODULES, smart, smart_reasons
from .passive import passive_tasks
from .controlled import tasks as controlled_tasks
from .sessions import load_profiles
from .plans import SmartPlan, incomplete as incomplete_plans
from .scope import Scope, matches, normalize_host, parse_rules
from .storage import DataError, Projects, confined, fingerprint, load_config, read_json, save_json, target_path


BANNER = """
██╗  ██╗██╗████████╗ ██████╗  ██████╗ ██╗
╚██╗██╔╝██║╚══██╔══╝██╔═══██╗██╔═══██╗██║
 ╚███╔╝ ██║   ██║   ██║   ██║██║   ██║██║
 ██╔██╗ ██║   ██║   ██║   ██║██║   ██║██║
██╔╝ ██╗██║   ██║   ╚██████╔╝╚██████╔╝███████╗
╚═╝  ╚═╝╚═╝   ╚═╝    ╚═════╝  ╚═════╝ ╚══════╝"""

MAIN_MENU = f"""{BANNER}

        XITool | Feel free
        SECURITY TOOLKIT
        Versione {__version__}

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
    if not items:
        print("Nessuna voce disponibile.")
        return []
    for index, value in enumerate(items, 1):
        print(f"[{index}] {value}")
    print("[0] INDIETRO")
    text = ask("Scelta (numeri separati da virgole): " if multiple else "Scelta: ")
    if text == "0":
        return []
    if multiple:
        return sorted(selection_indices(text, len(items)))
    if not text.isdigit() or len(text) > 6 or not 1 <= int(text) <= len(items):
        raise DataError("Selezione non valida")
    return [int(text) - 1]


def edit_rules(title: str, required: bool = False) -> list[str]:
    rules: list[str] = []
    while True:
        print("\n" + title)
        for index, value in enumerate(rules, 1):
            print(f"[{index}] {value}")
        print("[A] AGGIUNGI DOMINI (poi incolla l'elenco)  [R] RIMUOVI  [0] TERMINA")
        try:
            raw_action = ask("Scelta (A/R/0, oppure incolla direttamente i domini): ")
            action = raw_action.upper()
            if action == "A":
                read_rule_batch(rules)
            elif action == "R":
                selected = choose(rules, multiple=True)
                rules[:] = [rule for index, rule in enumerate(rules) if index not in selected]
            elif action == "0":
                if required and not rules:
                    print("Inserire almeno una regola autorizzata.")
                else:
                    return rules
            else:
                if parse_rules(raw_action)["rules"]:
                    read_rule_batch(rules, first_line=raw_action)
                else:
                    print("Scelta non valida: usare A/R/0 o incollare domini validi.")
        except DataError as exc:
            print(f"Errore: {exc}")
        except KeyboardInterrupt:
            print("\nOperazione annullata; i domini inseriti restano nell'elenco.")
        except EOFError:
            if rules or not required:
                return rules
            raise


def read_rule_batch(rules: list[str], first_line: str | None = None) -> None:
    """Consuma tutte le righe incollate prima di tornare al menu dei domini."""
    print("Incolla uno o più domini. Premi INVIO su una riga vuota per terminare.")
    valid, duplicates, invalid, size = 0, 0, 0, 0
    try:
        while True:
            try:
                line = first_line if first_line is not None else ask("")
                first_line = None
                if not line:
                    break
                size += len(line)
                if size > 1024 * 1024:
                    invalid += 1
                    continue
                parsed = parse_rules(line)
                duplicates += parsed["duplicates"]
                invalid += len(parsed["invalid"])
                for message in parsed["warnings"] + parsed["invalid"]:
                    print(message)
                for rule in parsed["rules"]:
                    if rule in rules:
                        duplicates += 1
                    else:
                        rules.append(rule)
                        valid += 1
            except DataError as exc:
                invalid += 1
                print(f"Errore: {exc}")
    except (KeyboardInterrupt, EOFError):
        print("\nInserimento terminato; i domini validi sono conservati.")
    print(f"[+] Domini validi: {valid}\n[+] Duplicati: {duplicates}\n[+] Non validi: {invalid}")


def selection_indices(text: str, count: int) -> set[int]:
    """Interpreta numeri e intervalli senza espandere limiti non validati."""
    selected: set[int] = set()
    for piece in re.split(r"\s*,\s*|\s+", text.strip()):
        if not piece:
            raise DataError("Selezione vuota o separatori ripetuti")
        limits = piece.split("-")
        if len(limits) not in (1, 2) or any(not part.isdigit() or len(part) > 6 for part in limits):
            raise DataError("Usare numeri, virgole e intervalli come 1-4")
        start, end = int(limits[0]), int(limits[-1])
        if not 1 <= start <= end <= count:
            raise DataError(f"Selezionare numeri fra 1 e {count}")
        selected.update(range(start - 1, end))
    return selected


def select_domains(roots: list[str], project_name: str) -> list[str]:
    if not roots:
        print("Nessun dominio iniziale autorizzato disponibile.")
        return []
    print(f"\nESECUZIONE — {project_name}")
    action = choose(["TUTTI I DOMINI", "SELEZIONA DOMINI"])
    if not action:
        return []
    if action[0] == 0:
        return list(roots)
    selected: set[int] = set()
    while True:
        print(f"\nSELEZIONA DOMINI — {project_name}")
        for index, root in enumerate(roots):
            print(f"[{index + 1}] [{'X' if index in selected else ' '}] {root}")
        print("[A] SELEZIONA TUTTI\n[D] DESELEZIONA TUTTI\n[C] CONFERMA\n[0] INDIETRO")
        text = ask("Scelta: ").upper()
        if text == "0":
            return []
        if text == "A":
            selected = set(range(len(roots)))
        elif text == "D":
            selected.clear()
        elif text == "C":
            if selected:
                return [roots[index] for index in sorted(selected)]
            print("Seleziona almeno un dominio prima di confermare.")
        else:
            try:
                selected.symmetric_difference_update(selection_indices(text, len(roots)))
            except DataError as exc:
                print(f"Errore: {exc}")


def create_project(projects: Projects) -> None:
    print("\nCREA PROGETTO")
    name = ask("Nome progetto: ")
    projects.path(name)
    domains = edit_rules("DOMINI AUTORIZZATI", required=True)
    excluded = edit_rules("DOMINI NEGATI")
    scope = Scope(domains, excluded)
    print(json.dumps({"name": name, "domains": scope.raw_domains, "excluded_hosts": scope.excluded}, indent=2))
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


def open_domain(project: Path, domain: str) -> None:
    """Navigazione dei risultati senza creazione di cartelle o avvio del motore."""
    root = target_path(project, domain)
    if not root.is_dir():
        print("Nessun risultato per questo dominio. La cartella sarà preparata in ESECUZIONE.")
        return
    while True:
        print(f"\nDOMINIO — {domain}")
        keys = [key for key, (_, status) in MODULES.items() if status != "NOT_IMPLEMENTED" or (root / key).exists()]
        if (root / "crawler").is_dir():
            keys.append("crawler")
        labels = [f"{MODULES.get(key, ('CRAWLER / INPUT DISCOVERY', 'PARTIAL'))[0]} — {'RISULTATI DISPONIBILI' if (root / key).is_dir() else 'NESSUN RISULTATO'}" for key in keys]
        selected = choose(labels + ["REPORT", "CRONOLOGIA E CHECKPOINT"])
        if not selected:
            return
        index = selected[0]
        if index >= len(keys):
            folder = confined(project, root / ("reports" if index == len(keys) else "runs"))
            if folder.is_dir():
                browse(folder)
            else:
                print("Nessun risultato disponibile.")
            continue
        module = keys[index]
        folder = confined(project, root / module)
        if not folder.is_dir():
            print("Nessun risultato disponibile per questo modulo.")
            continue
        if module != "subfinding":
            browse(folder)
            continue
        names = ["all_subdomains.txt", "live_subdomains.txt", "domains_with_inputs.txt", "discovered_inputs.json",
                 "initial_domains.txt", "resolved_hosts.txt", "http_reachable_hosts.txt", "out_of_scope_hosts.txt",
                 "host_observations.json", "dns_records.json", "http_probes.json", "provider_errors.json", "summary.json", "url_references.json"]
        titles = ["NUOVI SOTTODOMINI SCOPERTI", "NUOVI SOTTODOMINI RAGGIUNGIBILI HTTP", "DOMINI CON INPUT", "INPUT DETTAGLIATI",
                  "DOMINI INIZIALI", "HOST RISOLTI DNS", "TUTTI GLI HOST RAGGIUNGIBILI HTTP", "SCOPERTI FUORI SCOPE",
                  "PROVENIENZA HOST", "RECORD DNS", "PROBE HTTP", "ERRORI DELLE FONTI", "RIEPILOGO SCOPERTE", "URL OSSERVATI / IPOTIZZATI / FUORI SCOPE"]
        while True:
            print(f"\nSUB FINDING — {domain}")
            selection = choose(titles)
            if not selection:
                break
            path = confined(project, folder / names[selection[0]])
            if not path.is_file():
                print("File non ancora disponibile.")
                continue
            if path.suffix == ".txt" and path.stat().st_size == 0:
                summary_file = confined(project, folder / "summary.json")
                message = read_json(summary_file).get("message") if summary_file.exists() and path.name == "all_subdomains.txt" else None
                print(message or ("0 nuovi sottodomini scoperti — raccolta non verificata" if path.name == "all_subdomains.txt" else "Nessun elemento in questo elenco."))
                continue
            manifest = confined(project, folder / "latest.json")
            if manifest.exists():
                value = read_json(manifest)
                files = value.get("files") if isinstance(value, dict) else None
                if not isinstance(files, dict) or files.get(path.name) != fingerprint(path.read_text(encoding="utf-8")):
                    print("Vista corrente modificata o incompleta: consultare CRONOLOGIA E CHECKPOINT.")
                    continue
            show_file(root, path)


def open_projects(projects: Projects) -> None:
    names = projects.list()
    selected = choose(names)
    if not selected:
        return
    project, scope = projects.load(names[selected[0]])
    roots = scope.roots()
    while True:
        print(f"\nPROGETTO — {project.name}")
        legacy = any((project / name).is_dir() for name in ("runs", "subfinding"))
        extras = ([('RISULTATI PRECEDENTI (formato progetto)', project)] if legacy else [])
        if (project / "plans").is_dir():
            extras.append(("PIANI SMART — SOLA LETTURA", confined(project, project / "plans")))
        selected_domain = choose(roots + [label for label, _ in extras])
        if not selected_domain:
            return
        if selected_domain[0] >= len(roots):
            # Anche lo storico rimane consultabile senza migrazioni o salvataggi impliciti.
            browse(extras[selected_domain[0] - len(roots)][1])
        else:
            open_domain(project, roots[selected_domain[0]])


def print_monitor(state: dict) -> None:
    progress = "indeterminato" if state["progress"] is None else f"{state['progress']}%"
    batch = f"[{state['batch_index']}/{state['batch_total']}] " if "batch_index" in state else ""
    print(f"\n{batch}{state['project']} | {state.get('domain') or 'storico progetto'} | {state['module']} | {state['status']} | progresso {progress}")
    print(f"Completati {state['completed']} | rimanenti {state['remaining']} | finding {state['results']} | input {state['inputs']}")
    if state["module"] == "subfinding":
        print(f"{state.get('new_subdomains', 0)} nuovi sottodomini scoperti")
    print(f"Richieste/s {state['requests_per_second']} | limite {state['rate_limit']} | errori HTTP {state['errors']} | errori attività {state.get('task_errors', 0)} | timeout {state['timeouts']} | cache hit {state['cache_hits']}")
    print(f"Checkpoint UTC {state['last_checkpoint']} | Ctrl+C interrompe e salva")


def print_summary(summary: list[dict]) -> None:
    print("\nRIEPILOGO FINALE")
    for row in summary:
        print(f"{row['project']} / {row['domain']}: {row['status']} | esito {row.get('verification_outcome', row['status'])} | errori {row['errors']} | {'elaborato' if row['processed'] else 'non elaborato'}")
    successes = sum(row["status"] == "COMPLETED" and not row["errors"] for row in summary)
    print(f"Successi: {successes} | con errori: {sum(bool(row['errors']) for row in summary)} | non elaborati: {sum(not row['processed'] for row in summary)}")


def seeds(scope: Scope, config: dict) -> list[dict]:
    """Importa output passivo locale prima di qualsiasi probing attivo."""
    hosts = {rule for rule in scope.domains if not rule.startswith("*.") and scope.allowed(rule)}
    source = ask("File TXT facoltativo di host già raccolti (INVIO per saltare): ")
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
    print("Sub Finding cerca automaticamente nei certificati pubblici tramite crt.sh e CertSpotter.")
    print("Il dominio viene inviato ai provider. DNS/HTTP solo per host autorizzati; file TXT facoltativo.")
    if os.environ.get("XITOOL_DYNAMIC_BROWSER") == "1":
        print("Browser DOM opzionale attivo: GET entro scope, massimo 10 risorse per pagina; nessun form inviato.")
    urls = []
    custom = ask("URL iniziali aggiuntivi, separati da virgole (vuoto per continuare): ")
    if custom:
        urls += [scope.url(value.strip(), config["http"]["allowed_ports"]) for value in custom.split(",")]
    tasks = [{"url": f"https://{'[' + host + ']' if ':' in host else host}/", "kind": "dns"}
             for host in sorted(hosts)]
    # Gli URL personalizzati possono usare porte di laboratorio e percorsi specifici.
    tasks += [{**task, "recon": True} for task in build_tasks("subfinding", scope, [], urls)]
    return tasks


def post_run(engine: Engine) -> None:
    while True:
        print(f"\nRISULTATI: {engine.directory}")
        selected = choose(["File dei risultati", "Manual Review Queue", "Scan Diff", "Rigenera report", "Pulizia sicura (anteprima)"])
        if not selected:
            return
        if selected[0] == 0:
            browse(engine.output_root)
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
            statuses = ["PENDING_REVIEW", "IN_REVIEW", "CONFIRMED", "DISMISSED", "FALSE_POSITIVE"]
            status = choose(statuses)
            if status and confirm("Registrare la valutazione umana? [s/N]: "):
                review(engine.directory, entry["finding_id"], statuses[status[0]])
                engine.export()
        elif selected[0] == 2:
            previous = [(directory, state) for directory, state in runs(engine.project, engine.module, engine.target)
                        if directory != engine.directory and state["status"] == "COMPLETED"]
            if not previous:
                print("Nessuna run precedente completata per lo stesso modulo.")
                continue
            index = choose([directory.name for directory, _ in previous])
            if index:
                diff = scan_diff(previous[index[0]][1], engine.state)
                save_json(engine.directory / ("diff_" + previous[index[0]][0].name + ".json"), diff)
                from .diffing import export_diff
                export_diff(engine.directory / "diff" / previous[index[0]][0].name, diff)
                print(json.dumps(diff, indent=2))
        elif selected[0] == 3:
            engine.export()
            print("Report JSON e Markdown aggiornati nella run.")
        else:
            from .cleanup import dry_run, apply
            plan = dry_run(engine.project)
            print(json.dumps(plan, indent=2, ensure_ascii=True))
            print("Risultati, checkpoint e configurazioni sono protetti. Nessun file eliminato dall'anteprima.")
            if plan["reclaimable_bytes"]:
                answer = ask(f"Per eliminare solo i candidati scrivi ELIMINA {plan['plan_id']}: ")
                print(json.dumps(apply(plan, answer), indent=2))


def execute(projects: Projects, config: dict) -> None:
    names = projects.list()
    selected = choose(names, multiple=True)
    if not selected:
        return
    selections = []
    for index in selected:
        project, scope = projects.load(names[index])
        roots = projects.prepare(project, scope)
        domains = select_domains(roots, project.name)
        if not domains:
            return
        selections.append((project, scope, domains))
    keys = list(MODULES)
    statuses = {"AVAILABLE": "DISPONIBILE", "PARTIAL": "PARZIALE", "NOT_IMPLEMENTED": "NON IMPLEMENTATO"}
    print("\nMODULI")
    module_index = choose([f"{label} [{statuses[status]}]" for label, status in MODULES.values()] + ["SMART EXECUTION — SCEGLI FRA I SUGGERIMENTI"])
    if not module_index:
        return
    if module_index[0] == len(keys):
        execute_smart(selections, config)
        return
    module = keys[module_index[0]]
    if MODULES[module][1] == "NOT_IMPLEMENTED":
        print("Modulo NON IMPLEMENTATO: nessuna attività avviata.")
        return
    plans = []
    preflight_errors = []
    for project, scope, domains in selections:
        try:
            migrated = migrate_legacy(project, scope, config)
            if migrated:
                print(f"Storico copiato per dominio: {len(migrated)} run. Gli originali restano intatti.")
        except (OSError, DataError) as exc:
            print(f"Migrazione incompleta per {project.name}: {exc}. Gli originali restano consultabili.")
        seed_tasks = None
        for domain in domains:
            try:
                bounded = scope.for_target(domain)
                resume = None
                incomplete = [(directory, state) for directory, state in runs(project, module, domain) if state["status"] != "COMPLETED"]
                if config["execution"]["resume_enabled"] and incomplete:
                    directory, state = incomplete[0]
                    print(f"\nSCANSIONE PRECEDENTE TROVATA — {project.name} / {domain} / {module}")
                    print(f"Completati {len(state['completed'])}; rimanenti {len(state['pending'])}")
                    if state.get("legacy_scope_hash") and state["legacy_scope_hash"] != scope.digest:
                        print("Lo scope precedente è cambiato: gli input saranno nuovamente filtrati.")
                    action = choose(["RIPRENDI SCANSIONE", "NUOVA SCANSIONE"])
                    if not action:
                        return
                    if action[0] == 0:
                        resume = directory
                if resume:
                    engine = Engine(project, scope, config, module, resume=resume, target=domain)
                else:
                    if module == "subfinding":
                        if seed_tasks is None:
                            seed_tasks = seeds(scope, config)
                        tasks = passive_tasks(domain) + [task for task in seed_tasks if bounded.allowed(urlsplit(task["url"]).hostname or "")]
                    else:
                        inputs, urls = latest_discovery(project, bounded, domain)
                        print(f"Smart Execution — {domain}: {json.dumps(smart_reasons(inputs, urls), ensure_ascii=True)}")
                        tasks = controlled_tasks(project, bounded, module) or build_tasks(module, bounded, inputs, urls)
                        if not tasks:
                            print(f"{domain}: NO_INPUT — nessun input o risorsa controllata configurata per {module}.")
                            record_no_input(project, scope, module, domain)
                            preflight_errors.append({"project": project.name, "domain": domain, "status": "NO_INPUT", "processed": False, "errors": 0})
                            continue
                        tasks = select_session(project, bounded, tasks)
                        if not tasks:
                            return
                    engine = Engine(project, scope, config, module, tasks=tasks, target=domain)
                print(f"\nPROGETTO: {project.name} | DOMINIO: {domain} | MODULO: {module}")
                print(f"Autorizzati: {scope.raw_domains}\nNegati: {scope.excluded}")
                print("Il dominio selezionato e il suo ramo sono ulteriormente limitati dallo scope del progetto.")
                print(f"CIDR speciali espliciti: {[str(n) for n in scope.networks]}")
                print(f"Attività: {len(engine.state['pending'])}; ripresa: {bool(resume)}")
                if module == "authentication" and any(task.get("controlled_case") for task in engine.state["pending"]):
                    print("Questo piano include logout e invalidazione della sessione dell'account di laboratorio configurato.")
                print(f"Limiti HTTP: {json.dumps(config['http'])}; worker bounded, controlli con sessione/fixture seriali")
                print(f"Output: {engine.directory}")
                plans.append(engine)
            except (OSError, DataError) as exc:
                print(f"Dominio {domain} non pronto: {exc}")
                preflight_errors.append({"project": project.name, "domain": domain, "status": "FAILED", "processed": False, "errors": 1, "reason": str(exc)})
    if not plans:
        print("Nessun dominio pronto per l'esecuzione.")
        print_summary(preflight_errors)
        return
    if not confirm("Confermo autorizzazione allo scope e avvio dei controlli descritti [s/N]: "):
        return
    summary = run_batch(plans, print_monitor) + preflight_errors
    print_summary(summary)
    if any(row["status"] == "INTERRUPTED" for row in summary):
        return
    available = [engine for engine in plans if (engine.directory / "report.json").exists()]
    selected_result = choose([f"RISULTATI — {engine.project.name} / {engine.target}" for engine in available])
    if selected_result:
        post_run(available[selected_result[0]])


def select_session(project: Path, scope: Scope, tasks: list[dict]) -> list[dict]:
    if any(task.get("controlled_case") for task in tasks):
        return tasks  # I due account sono già definiti nel caso controllato.
    profiles = {name: profile for name, profile in load_profiles(project).items() if scope.allowed(urlsplit(profile.origin).hostname)}
    if not profiles:
        return tasks
    names = sorted(profiles)
    selected = choose(["ANONIMO"] + [f"{name} — ruolo {profiles[name].role}" for name in names])
    if not selected:
        return []
    if selected[0] == 0:
        return tasks
    name = names[selected[0] - 1]
    origin = urlsplit(profiles[name].origin)
    selected_tasks = [{**task, "session": name} for task in tasks
                      if (urlsplit(task["url"]).scheme, urlsplit(task["url"]).netloc) == (origin.scheme, origin.netloc)]
    print(f"Profilo {name}: {len(selected_tasks)} attività della sua origine; le altre non saranno inviate con questo profilo.")
    return selected_tasks


def execute_smart(selections: list, config: dict) -> None:
    """Ricognizione e analisi con due conferme e un checkpoint per l'intero piano."""
    for project, scope, domains in selections:
        previous = incomplete_plans(project)
        plan = SmartPlan(project, scope, config, domains)
        if previous:
            selected_plan = choose(["NUOVO PIANO"] + ["RIPRENDI " + path.stem for path in previous])
            if not selected_plan:
                return
            if selected_plan[0]:
                plan = SmartPlan(project, scope, config, domains, path=previous[selected_plan[0] - 1])
                if plan.state["status"] != "AWAITING_SELECTION":
                    if not confirm("Riprendere le attività residue del piano nello scope confermato? [s/N]: "):
                        return
                    print_summary(plan.run(print_monitor))
                    if plan.state["status"] == "INTERRUPTED":
                        return
                    if plan.state["phase"] == "ANALYSIS":
                        print(f"Piano salvato: {plan.path}")
                        continue
        missing = [domain for domain in domains if not any(latest_discovery(project, scope.for_target(domain), domain, config))]
        if missing and not plan.state["steps"]:
            print("Ricognizione necessaria per: " + ", ".join(missing))
            initial = seeds(scope, config)
            steps = [{"domain": domain, "module": "subfinding", "tasks": passive_tasks(domain) +
                      [task for task in initial if scope.for_target(domain).allowed(urlsplit(task["url"]).hostname or "")]} for domain in missing]
            steps = [step for step in steps if step["tasks"]]
            if not steps:
                print("NO_INPUT: nessun seed autorizzato o fonte utilizzabile.")
                continue
            if not confirm("Avviare fonti CT e ricognizione attiva dei domini indicati? [s/N]: "):
                return
            plan.add(steps, phase="RECON")
            print_summary(plan.run(print_monitor))
            if plan.state["status"] == "INTERRUPTED":
                return
        candidates, suggested = [], set()
        for domain in domains:
            bounded = scope.for_target(domain)
            inputs, urls = latest_discovery(project, bounded, domain, config)
            reasons = smart_reasons(inputs, urls)
            for module in ("xss", "sqli", "idor", "access", "ssrf", "traversal", "authentication", "cors"):
                controls = controlled_tasks(project, bounded, module)
                if controls:
                    reasons[module] = {"count": len(controls), "reason": "Risorse canary dell'operatore esplicitamente configurate."}
            if not reasons:
                print(f"{project.name} / {domain}: NO_INPUT; nessun controllo selezionabile.")
                continue
            for module, proposal in reasons.items():
                print(f"{domain} — {MODULES[module][0]}: {proposal['reason']} ({proposal['count']} input/URL)")
            suggested.update(reasons)
            candidates.append((project, scope, domain, inputs, urls, reasons))
        modules = [module for module in MODULES if module in suggested and MODULES[module][1] != "NOT_IMPLEMENTED"]
        selection = choose([MODULES[module][0] for module in modules], multiple=True)
        if not selection:
            return
        steps = []
        for _, _, domain, inputs, urls, reasons in candidates:
            for index in selection:
                module = modules[index]
                if module not in reasons:
                    continue
                bounded = scope.for_target(domain)
                tasks = controlled_tasks(project, bounded, module) or build_tasks(module, bounded, inputs, urls)
                tasks = select_session(project, bounded, tasks)
                if tasks:
                    steps.append({"domain": domain, "module": module, "tasks": tasks})
        if not steps:
            print("NO_INPUT: nessuna attività valida per i moduli scelti.")
            continue
        print("Piano Smart: " + ", ".join(f"{step['domain']}/{step['module']} ({len(step['tasks'])} attività)" for step in steps))
        if any(step["module"] == "authentication" and any(task.get("controlled_case") for task in step["tasks"]) for step in steps):
            print("Include logout dell'account di laboratorio esplicitamente configurato.")
        if not confirm("Confermo autorizzazione e avvio del piano Smart [s/N]: "):
            return
        plan.add(steps)
        print_summary(plan.run(print_monitor))
        print(f"Piano e report dei passi salvati: {plan.path}")


def entrypoint() -> None:
    """Console script installed editable in the project's virtual environment."""
    main(Path(__file__).resolve().parents[1])


def main(base: Path) -> None:
    parser = argparse.ArgumentParser(description="XITool 5.2 alpha — ricognizione e verifiche web autorizzate")
    parser.add_argument("--data-dir", type=Path, default=base / "targets")
    parser.add_argument("--config", type=Path, default=base / "config.yaml")
    parser.add_argument("--version", action="version", version=f"XITool {__version__}")
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
            # Il bianco brillante si applica al terminale; file e pipe restano privi di escape.
            menu = MAIN_MENU
            if sys.stdout.isatty() and os.environ.get("TERM") != "dumb" and "NO_COLOR" not in os.environ:
                menu = f"\033[97m{menu}\033[0m"
            print("\n" + menu)
            action = ask("Scelta: ")
            if action == "0":
                return
            if action == "1":
                create_project(projects)
            elif action == "2":
                open_projects(projects)
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
