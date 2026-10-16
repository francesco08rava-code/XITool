"""Regressioni del flusso incolla-domini, isolamento, migrazione e navigazione."""
import copy
import io
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from xitool.cli import create_project, edit_rules, execute, open_projects, select_domains, selection_indices
from xitool.execution import Engine, build_tasks, latest_discovery, load_state, migrate_legacy, run_batch, runs, scan_diff
from xitool.http import HTTPClient, Response
from xitool.scanners import MODULES, discover, scan
from xitool.scope import Scope, ScopeViolation, parse_rules
from xitool.storage import DEFAULTS, DataError, Projects, fingerprint, read_json, save_json, target_path

DOMAINS = ["pwapi.ex2b.com", "pay.ibex.exchange", "my.exness.com", "exnessaffiliates.com", "api.excalls.mobi", "exness.com"]


class RuleInputTests(unittest.TestCase):
    def test_one_domain(self):
        self.assertEqual(parse_rules("Example.COM.")["rules"], ["example.com"])

    def test_six_lines_and_separators(self):
        for separator in ("\n", ",", " ", ", "):
            with self.subTest(separator=separator):
                result = parse_rules(separator.join(DOMAINS))
                self.assertEqual(result["rules"], DOMAINS)
                self.assertEqual(result["invalid"], [])

    def test_deduplication_and_wildcards_remain_explicit(self):
        result = parse_rules("Example.com. example.COM *.example.com")
        self.assertEqual(result["rules"], ["example.com", "*.example.com"])
        self.assertEqual(result["duplicates"], 1)

    def test_invalid_csv_item_does_not_discard_other_explicit_domains(self):
        result = parse_rules("example.com,invalid,other.test")
        self.assertEqual(result["rules"], ["example.com", "other.test"])
        self.assertEqual(len(result["invalid"]), 1)

    def test_invalid_and_ambiguous_text(self):
        for text in ("visit example.com now", "email@example.com", "*.127.0.0.1", "foo..com", "https://user:secret@example.com/", "https://example.com:99999/"):
            with self.subTest(text=text):
                result = parse_rules(text)
                self.assertEqual(result["rules"], [])
                self.assertTrue(result["invalid"])
                self.assertNotIn("secret", str(result))

    def test_url_path_warning_and_table(self):
        result = parse_rules("https://EXAMPLE.com/path?id=1\napi.example.com\tDomain\tIn scope")
        self.assertEqual(result["rules"], ["example.com", "api.example.com"])
        self.assertEqual(len(result["warnings"]), 1)

    def test_full_paste_is_consumed_before_returning_to_menu(self):
        with patch("builtins.input", side_effect=["A", *DOMAINS, "", "0"]), patch("sys.stdout", new_callable=io.StringIO) as output:
            result = edit_rules("DOMINI AUTORIZZATI", required=True)
        self.assertEqual(result, DOMAINS)
        self.assertIn("Domini validi: 6", output.getvalue())
        self.assertNotIn("Scelta non valida", output.getvalue())

    def test_denied_paste_and_duplicates_across_batches(self):
        with patch("builtins.input", side_effect=["A", "admin.example.com *.private.example.com", "", "A", "ADMIN.EXAMPLE.COM", "", "0"]), patch("sys.stdout", new_callable=io.StringIO) as output:
            result = edit_rules("DOMINI NEGATI")
        self.assertEqual(result, ["admin.example.com", "*.private.example.com"])
        scope = Scope(["*.example.com"], result)
        self.assertFalse(scope.allowed("admin.example.com"))
        self.assertFalse(scope.allowed("x.private.example.com"))
        self.assertIn("Duplicati: 1", output.getvalue())

    def test_interrupted_batch_keeps_domains(self):
        for signal in (KeyboardInterrupt(), EOFError()):
            with self.subTest(signal=type(signal).__name__), patch("builtins.input", side_effect=["A", "example.com", signal, "0"]), patch("sys.stdout", new_callable=io.StringIO):
                self.assertEqual(edit_rules("DOMINI", required=True), ["example.com"])


class SelectionTests(unittest.TestCase):
    def test_numbers_ranges_and_invalid_limits(self):
        self.assertEqual(selection_indices("1, 3,5", 6), {0, 2, 4})
        self.assertEqual(selection_indices("1-4", 6), {0, 1, 2, 3})
        for text in ("", "0", "7", "4-1", "1,,2", "a", "1-99999999999"):
            with self.subTest(text=text), self.assertRaises(DataError):
                selection_indices(text, 6)

    def test_select_all(self):
        with patch("builtins.input", return_value="1"), patch("sys.stdout", new_callable=io.StringIO):
            self.assertEqual(select_domains(DOMAINS, "EXNESS"), DOMAINS)

    def test_manual_numbers_and_range(self):
        for selection, expected in (("1,3,5", [DOMAINS[i] for i in (0, 2, 4)]), ("1-4", DOMAINS[:4])):
            with self.subTest(selection=selection), patch("builtins.input", side_effect=["2", selection, "C"]), patch("sys.stdout", new_callable=io.StringIO) as output:
                self.assertEqual(select_domains(DOMAINS, "EXNESS"), expected)
                self.assertIn("[X]", output.getvalue())

    def test_zero_selection_rejected_and_toggle_preserves_state(self):
        with patch("builtins.input", side_effect=["2", "C", "A", "D", "1,3", "3", "C"]), patch("sys.stdout", new_callable=io.StringIO) as output:
            self.assertEqual(select_domains(DOMAINS, "EXNESS"), [DOMAINS[0]])
        self.assertIn("almeno un dominio", output.getvalue())

    def test_invalid_input_then_back(self):
        with patch("builtins.input", side_effect=["2", "invalid", "0"]), patch("sys.stdout", new_callable=io.StringIO):
            self.assertEqual(select_domains(DOMAINS, "EXNESS"), [])


class DomainExecutionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.projects = Projects(self.root / "targets")
        self.project = self.projects.create("Demo", ["example.com", "*.example.com", "api.example.com", "other.test"], ["denied.example.com"])
        self.scope = self.projects.load("Demo")[1]
        self.config = copy.deepcopy(DEFAULTS)
        self.config["http"].update(max_retries=0, requests_per_second=20)
        self.config["checkpoint"]["completed_items_interval"] = 1

    def engine(self, target, module="subfinding", tasks=None):
        return Engine(self.project, self.scope, self.config, module, target=target,
                      tasks=tasks or [{"url": f"https://{target}/", "depth": 0}])

    def respond(self, url, *args, **kwargs):
        return Response(url, 200, {"content-type": "text/html"}, '<a href="/search?q=x">search</a><a href="https://api.example.com/?id=1">api</a><a href="https://denied.example.com/">deny</a><form method="post"><input name="file"></form>')

    def test_creation_folders_and_unauthorized_manual_folder(self):
        for domain in self.scope.roots():
            self.assertTrue(target_path(self.project, domain).is_dir())
        (self.project / "rogue.test").mkdir()
        self.assertNotIn("rogue.test", self.scope.roots())
        with self.assertRaises(ScopeViolation):
            self.engine("rogue.test")

    def test_exact_root_does_not_imply_wildcard(self):
        scope = Scope(["my.exness.com"], [])
        bound = scope.for_target("my.exness.com")
        self.assertFalse(bound.allowed("child.my.exness.com"))

    def test_wildcard_only_root_never_authorizes_apex(self):
        scope = Scope(["*.example.com"], [])
        self.assertEqual(scope.roots(), ["example.com"])
        bound = scope.for_target("example.com")
        self.assertFalse(bound.allowed("example.com"))
        self.assertTrue(bound.allowed("child.example.com"))

    def test_fully_denied_roots_not_selectable(self):
        scope = Scope(["example.com", "*.example.com"], ["example.com", "*.example.com"])
        self.assertEqual(scope.roots(), [])

    def test_overlapping_roots_have_single_owner(self):
        bound = self.scope.for_target("example.com")
        self.assertFalse(bound.allowed("api.example.com"))
        self.assertFalse(bound.allowed("v2.api.example.com"))
        self.assertTrue(self.scope.for_target("api.example.com").allowed("v2.api.example.com"))
        self.assertFalse(bound.allowed("other.test"))

    def test_redirect_cannot_cross_selected_domain_even_if_project_allows_it(self):
        client = HTTPClient(self.scope.for_target("example.com"), self.config)
        client.limiter.wait = lambda: None
        with patch.object(client, "_request", return_value=Response("https://example.com/", 302, {"location": "https://other.test/"}, "")) as transport:
            with self.assertRaises(ScopeViolation):
                client.get("https://example.com/")
            self.assertEqual(transport.call_count, 1)

    def test_sequential_three_domains_separate_outputs(self):
        engines = [self.engine(target) for target in self.scope.roots()]
        order = []
        def reply(url, **kwargs):
            order.append(url)
            return self.respond(url)
        with patch("xitool.http.HTTPClient.get", side_effect=reply):
            summary = run_batch(engines)
        self.assertEqual(len(summary), 3)
        self.assertTrue(all(row["status"] == "COMPLETED" and row["errors"] == 0 for row in summary))
        positions = [min(i for i, url in enumerate(order) if url.startswith(f"https://{engine.target}/")) for engine in engines]
        self.assertEqual(positions, sorted(positions))
        for engine in engines:
            domain = engine.target
            state = load_state(engine.directory / "checkpoint.json")
            self.assertEqual(state["version"], 2)
            self.assertEqual(state["domain"], domain)
            self.assertTrue(all(self.scope.owner(host) == domain for host in state["hosts"]))
            self.assertTrue((target_path(self.project, domain) / "subfinding" / "all_subdomains.txt").exists())
            self.assertTrue((target_path(self.project, domain) / "reports" / f"{state['run_id']}.json").exists())
            self.assertEqual(len(runs(self.project, "subfinding", domain)), 1)
        self.assertEqual(runs(self.project), [])

    def test_domain_failure_does_not_block_next_domain(self):
        engines = [self.engine("example.com", "misconfiguration"), self.engine("other.test", "misconfiguration")]
        def scanner(module, task, client):
            if client.scope.target == "example.com":
                raise RuntimeError("simulazione")
            return []
        with patch("xitool.execution.scan", side_effect=scanner):
            summary = run_batch(engines)
        self.assertEqual([row["status"] for row in summary], ["FAILED", "COMPLETED"])
        self.assertEqual(load_state(engines[0].directory / "checkpoint.json")["status"], "FAILED")
        self.assertTrue((engines[1].directory / "report.json").exists())

    def test_rate_budget_is_preserved_when_switching_domains(self):
        config = copy.deepcopy(self.config)
        config["http"]["requests_per_second"] = 2
        engines = [Engine(self.project, self.scope, config, "misconfiguration", target=target, tasks=[{"url": f"https://{target}/"}]) for target in ("example.com", "other.test")]
        now = [200.0]
        sent = []
        def sleep(delay):
            now[0] += delay
        def transport(url, headers):
            sent.append(now[0])
            return self.respond(url)
        with patch("xitool.http.time.monotonic", side_effect=lambda: now[0]), patch("xitool.http.time.sleep", side_effect=sleep), patch("xitool.http.HTTPClient._request", side_effect=transport):
            summary = run_batch(engines)
        self.assertTrue(all(row["status"] == "COMPLETED" for row in summary))
        self.assertEqual(sent, [200.0, 200.5])

    def test_interrupt_keeps_other_domains_pending_and_resume_isolated(self):
        engines = [self.engine("example.com"), self.engine("other.test")]
        with patch("xitool.http.HTTPClient.get", side_effect=KeyboardInterrupt()):
            summary = run_batch(engines)
        self.assertEqual([row["status"] for row in summary], ["INTERRUPTED", "PENDING"])
        self.assertFalse(engines[1].directory.exists())
        resumed = Engine(self.project, self.scope, self.config, "subfinding", target="example.com", resume=engines[0].directory)
        with patch.object(resumed.client, "get", side_effect=self.respond):
            resumed.execute()
        self.assertEqual(resumed.state["status"], "COMPLETED")
        self.assertEqual(runs(self.project, target="other.test"), [])

    def test_resume_cannot_load_another_domain_checkpoint(self):
        engine = self.engine("example.com")
        with patch.object(engine.client, "get", side_effect=KeyboardInterrupt()):
            engine.execute()
        with self.assertRaises(DataError):
            Engine(self.project, self.scope, self.config, "subfinding", target="other.test", resume=engine.directory)

    def test_scope_change_archives_previous_checkpoint_before_filtering_findings(self):
        tasks = [{"url": "https://www.example.com/"}, {"url": "https://example.com/"}]
        engine = self.engine("example.com", "misconfiguration", tasks)
        with patch.object(engine.client, "get", side_effect=[self.respond(tasks[0]["url"]), KeyboardInterrupt()]):
            engine.execute()
        previous = load_state(engine.directory / "checkpoint.json")
        restricted = Scope(["example.com", "api.example.com", "other.test"], [])
        resumed = Engine(self.project, restricted, self.config, "misconfiguration", target="example.com", resume=engine.directory)
        self.assertEqual(resumed.state["results"], [])
        self.assertEqual(list(engine.directory.glob("checkpoint_before_*.json")), [])
        with patch.object(resumed.client, "get", side_effect=self.respond):
            resumed.execute()
        backups = list(engine.directory.glob("checkpoint_before_*.json"))
        self.assertEqual(len(backups), 1)
        self.assertEqual(read_json(backups[0])["data"], previous)
        self.assertEqual(len(previous["results"]), 1)

    def test_cache_body_is_released_after_domain_finishes(self):
        engine = self.engine("example.com", "misconfiguration")
        engine.client.cache[("fixture",)] = (0, Response("https://example.com/", 200, {}, "response-body"))
        with patch.object(engine.client, "get", side_effect=self.respond):
            engine.execute()
        self.assertEqual(engine.client.cache, {})

    def test_every_implemented_module_saves_in_its_domain(self):
        discovery = self.engine("example.com")
        with patch.object(discovery.client, "get", side_effect=self.respond):
            discovery.execute()
        bounded = self.scope.for_target("example.com")
        inputs, urls = latest_discovery(self.project, bounded, "example.com")
        inputs += [{"host": "example.com", "url": "https://example.com/?id=1", "method": "GET", "parameter": "id", "input_type": "identifier", "source": "query"},
                   {"host": "example.com", "url": "https://example.com/?url=x", "method": "GET", "parameter": "url", "input_type": "url", "source": "query"}]
        for module, (_, status) in MODULES.items():
            if module == "subfinding" or status == "NOT_IMPLEMENTED":
                continue
            with self.subTest(module=module):
                tasks = build_tasks(module, bounded, inputs, urls)
                self.assertTrue(tasks)
                engine = self.engine("example.com", module, tasks)
                with patch.object(engine.client, "get", side_effect=self.respond):
                    engine.execute()
                self.assertTrue((target_path(self.project, "example.com") / module / "findings.json").is_file())
                self.assertEqual(read_json(engine.directory / "report.json")["domain"], "example.com")

    def test_non_implemented_scanner_never_sends_request(self):
        client = HTTPClient(self.scope.for_target("example.com"), self.config)
        with patch.object(client, "get") as get:
            for module in ("sqli", "access", "unknown"):
                with self.subTest(module=module), self.assertRaises(DataError):
                    scan(module, {"url": "https://example.com/"}, client)
            get.assert_not_called()

    def test_user_modified_projection_is_not_overwritten(self):
        first = self.engine("example.com")
        with patch.object(first.client, "get", side_effect=self.respond):
            first.execute()
        path = target_path(self.project, "example.com") / "subfinding" / "all_subdomains.txt"
        path.write_text("risultato personale\n", encoding="utf-8")
        second = self.engine("example.com")
        with patch.object(second.client, "get", side_effect=self.respond):
            second.execute()
        self.assertEqual(path.read_text(encoding="utf-8"), "risultato personale\n")
        self.assertTrue((second.directory / "subfinding" / "all_subdomains.txt").exists())

    def test_open_projects_is_read_only_and_never_scans(self):
        engine = self.engine("example.com")
        with patch.object(engine.client, "get", side_effect=self.respond):
            engine.execute()
        before = {path.relative_to(self.project).as_posix(): path.read_bytes() for path in self.project.rglob("*") if path.is_file()}
        # Progetto; example.com (secondo root ordinato); Sub Finding; TXT; indietro x3.
        index = self.scope.roots().index("example.com") + 1
        with patch("builtins.input", side_effect=["1", str(index), "1", "1", "0", "0", "0"]), patch("sys.stdout", new_callable=io.StringIO), patch.object(Engine, "execute") as execute_scan:
            open_projects(self.projects)
            execute_scan.assert_not_called()
        after = {path.relative_to(self.project).as_posix(): path.read_bytes() for path in self.project.rglob("*") if path.is_file()}
        self.assertEqual(before, after)

    def test_legacy_run_migration_preserves_originals_and_is_idempotent(self):
        original = Engine(self.project, self.scope, self.config, "subfinding", tasks=[{"url": "https://example.com/", "depth": 0}, {"url": "https://other.test/", "depth": 0}])
        with patch.object(original.client, "get", side_effect=self.respond):
            original.execute()
        path = original.directory / "checkpoint.json"
        before = path.read_bytes()
        self.assertTrue(migrate_legacy(self.project, self.scope, self.config))
        self.assertEqual(path.read_bytes(), before)
        for domain in self.scope.roots():
            state = runs(self.project, "subfinding", domain)[0][1]
            self.assertEqual(state["domain"], domain)
            self.assertTrue(all(self.scope.for_target(domain).allowed(host) for host in state["hosts"]))
        self.assertEqual(migrate_legacy(self.project, self.scope, self.config), [])

    def test_incomplete_legacy_run_can_resume_for_only_one_domain(self):
        legacy = Engine(self.project, self.scope, self.config, "subfinding", tasks=[{"url": "https://example.com/", "depth": 0}, {"url": "https://other.test/", "depth": 0}])
        with patch.object(legacy.client, "get", side_effect=[self.respond("https://example.com/"), KeyboardInterrupt()]):
            legacy.execute()
        original = (legacy.directory / "checkpoint.json").read_bytes()
        migrate_legacy(self.project, self.scope, self.config)
        directory, state = runs(self.project, "subfinding", "other.test")[0]
        self.assertEqual(state["status"], "INTERRUPTED")
        resumed = Engine(self.project, self.scope, self.config, "subfinding", target="other.test", resume=directory)
        with patch.object(resumed.client, "get", side_effect=self.respond) as network:
            resumed.execute()
        self.assertTrue(all(call.args[0].startswith("https://other.test/") for call in network.call_args_list))
        self.assertEqual(resumed.state["status"], "COMPLETED")
        self.assertEqual((legacy.directory / "checkpoint.json").read_bytes(), original)

    def test_latest_projection_updates_without_replacing_previous_runs(self):
        first = self.engine("example.com")
        with patch.object(first.client, "get", return_value=Response("https://example.com/", 200, {"content-type": "text/html"}, '<form><input name="old"></form>')):
            first.execute()
        second = self.engine("example.com")
        with patch.object(second.client, "get", return_value=Response("https://example.com/", 200, {"content-type": "text/html"}, '<form><input name="new"></form>')):
            second.execute()
        folder = target_path(self.project, "example.com") / "subfinding"
        self.assertEqual(read_json(folder / "latest.json")["run_id"], second.state["run_id"])
        self.assertEqual([item["parameter"] for item in read_json(folder / "discovered_inputs.json")], ["new"])
        self.assertEqual([item["parameter"] for item in read_json(first.directory / "subfinding/discovered_inputs.json")], ["old"])

    def test_legacy_export_without_checkpoint_is_imported_without_fabricated_findings(self):
        folder = self.project / "subfinding"
        folder.mkdir()
        (folder / "all_subdomains.txt").write_text("example.com\nother.test\nevil.test\n", encoding="utf-8")
        save_json(folder / "discovered_inputs.json", [])
        self.assertTrue(migrate_legacy(self.project, self.scope, self.config))
        self.assertEqual(migrate_legacy(self.project, self.scope, self.config), [])
        state = runs(self.project, "subfinding", "example.com")[0][1]
        self.assertTrue(state["import_only"])
        self.assertEqual(state["results"], [])
        self.assertEqual(state["hosts"], ["example.com"])
        self.assertIn("evil.test", (folder / "all_subdomains.txt").read_text())

    def test_diff_between_domains_rejected(self):
        first = self.engine("example.com").state
        second = self.engine("other.test").state
        with self.assertRaises(DataError):
            scan_diff(first, second)

    def test_export_failure_is_saved_as_failed_without_losing_findings(self):
        engine = self.engine("example.com", "misconfiguration")
        with patch.object(engine.client, "get", side_effect=self.respond), patch.object(engine, "export", side_effect=OSError("disco pieno")):
            with self.assertRaises(OSError):
                engine.execute()
        state = load_state(engine.directory / "checkpoint.json")
        self.assertEqual(state["status"], "FAILED")
        self.assertTrue(state["results"])
        self.assertFalse((engine.output_root / ".execution.lock").exists())

    def test_project_creation_full_interactive_paste(self):
        with patch("builtins.input", side_effect=["EXNESS", "A", *DOMAINS, "", "0", "A", "admin.exness.com", "", "0", "s"]), patch("sys.stdout", new_callable=io.StringIO), patch("xitool.http.HTTPClient.get") as network:
            create_project(self.projects)
            network.assert_not_called()
        project, scope = self.projects.load("EXNESS")
        self.assertEqual(set(scope.domains), set(DOMAINS))
        self.assertEqual(scope.excluded, ["admin.exness.com"])
        self.assertTrue(all(target_path(project, domain).is_dir() for domain in DOMAINS))

    def test_all_domains_without_inputs_still_have_final_error_summary(self):
        with patch("builtins.input", side_effect=["1", "1", "2"]), patch("sys.stdout", new_callable=io.StringIO) as output, patch.object(Engine, "execute") as scanner:
            execute(self.projects, self.config)
            scanner.assert_not_called()
        self.assertIn("RIEPILOGO FINALE", output.getvalue())
        self.assertIn("non elaborati: 3", output.getvalue())


class InstallationTests(unittest.TestCase):
    def test_python_entry_point_from_another_directory(self):
        project = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            env = {**os.environ, "PYTHONIOENCODING": "utf-8", "NO_COLOR": "1"}
            process = subprocess.run([sys.executable, str(project / "main.py"), "--data-dir", str(root / "data")],
                                     input="0\n", cwd=root, env=env, text=True, encoding="utf-8", capture_output=True, timeout=10)
            self.assertEqual(process.returncode, 0, process.stderr)
            self.assertIn("XITool | Feel free", process.stdout)
            self.assertIn("[3] ESECUZIONE", process.stdout)
            self.assertFalse((root / "targets").exists())

    @unittest.skipUnless(os.name == "posix" and shutil.which("bash"), "Richiede Bash e filesystem POSIX; eseguire anche su Kali")
    def test_installer_syntax(self):
        script = Path(__file__).resolve().parents[1] / "install.sh"
        process = subprocess.run(["bash", "-n", str(script)], capture_output=True, text=True, timeout=10)
        self.assertEqual(process.returncode, 0, process.stderr)

    @unittest.skipUnless(os.name == "posix" and shutil.which("bash"), "Richiede Bash e filesystem POSIX; eseguire anche su Kali")
    def test_installer_launcher_and_existing_external_command(self):
        # I comandi pip/unittest sono simulati per evitare download e ricorsione nell'installer.
        project = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            clone, tools, home = root / "clone con spazi", root / "tools", root / "home"
            clone.mkdir()
            tools.mkdir()
            home.mkdir()
            shutil.copy2(project / "install.sh", clone / "install.sh")
            (clone / "requirements.txt").write_text("# fixture\n")
            (clone / "main.py").write_text("print('XITOOL_LAUNCHER_OK')\n")
            environment_python = tools / "environment-python"
            environment_python.write_text('#!/usr/bin/env bash\nif [[ "$1" == "-m" && ( "$2" == "pip" || "$2" == "unittest" ) ]]; then exit 0; fi\nexec ' + shlex.quote(sys.executable) + ' "$@"\n')
            environment_python.chmod(0o755)
            python = tools / "python3"
            python.write_text('#!/usr/bin/env bash\nif [[ "$1" == "-m" && "$2" == "venv" ]]; then mkdir -p "$3/bin"; cp ' + shlex.quote(str(environment_python)) + ' "$3/bin/python"; chmod 755 "$3/bin/python"; exit 0; fi\nexec ' + shlex.quote(sys.executable) + ' "$@"\n')
            python.chmod(0o755)
            env = {**os.environ, "HOME": str(home), "PATH": str(tools) + os.pathsep + os.environ["PATH"]}
            for iteration in range(2):
                if iteration:
                    (home / ".local/bin/XITool").unlink()
                    (home / ".local/bin/XITool").write_text("external-command\n")
                process = subprocess.run(["bash", str(clone / "install.sh")], cwd=root, env=env, capture_output=True, text=True, timeout=15)
                self.assertEqual(process.returncode, 0, process.stderr)
                launcher = clone / ".venv/bin/XITool"
                launched = subprocess.run(["bash", str(launcher)], cwd=root, env=env, capture_output=True, text=True, timeout=10)
                self.assertEqual(launched.stdout.strip(), "XITOOL_LAUNCHER_OK")
                if iteration:
                    self.assertEqual((home / ".local/bin/XITool").read_text(), "external-command\n")
                else:
                    linked = subprocess.run(["bash", str(home / ".local/bin/XITool")], cwd=root, env=env, capture_output=True, text=True, timeout=10)
                    self.assertEqual(linked.stdout.strip(), "XITOOL_LAUNCHER_OK")
