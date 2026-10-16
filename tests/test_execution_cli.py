"""Checkpoint, isolamento, report e flussi CLI con input e HTTP simulati."""
import copy
import io
import json
from pathlib import Path
import tempfile
import threading
import time
import unittest
from unittest.mock import Mock, patch

from xitool.cli import MAIN_MENU, choose, execute, main, show_file
from xitool.execution import Engine, build_tasks, latest_discovery, load_state, review, runs, scan_diff
from xitool.http import NetworkError, Response
from xitool.scope import Scope
from xitool.scanners import finding
from xitool.storage import DEFAULTS, DataError, Projects, fingerprint, read_json, save_json


class EngineTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.projects = Projects(self.root / "targets")
        self.project = self.projects.create("Demo", ["example.com", "*.example.com"], [])
        self.scope = self.projects.load("Demo")[1]
        self.config = copy.deepcopy(DEFAULTS)
        self.config["checkpoint"]["completed_items_interval"] = 1
        self.config["http"]["requests_per_second"] = 20

    def engine(self, module="misconfiguration", tasks=None):
        return Engine(self.project, self.scope, self.config, module,
                      tasks=tasks or [{"url": "https://example.com/"}, {"url": "https://api.example.com/"}])

    def result(self, task):
        return [finding("misconfiguration", task["url"], "test", "OBSERVED", {"ok": True}, "fixture")]

    def finish(self, engine):
        with patch("xitool.execution.scan", side_effect=lambda module, task, client: self.result(task)):
            return engine.execute()

    def test_checkpoint_report_and_history(self):
        first = self.engine()
        self.finish(first)
        state = load_state(first.directory / "checkpoint.json")
        self.assertEqual(state["status"], "COMPLETED")
        self.assertEqual(len(state["results"]), 2)
        self.assertEqual(len(state["pending"]), 0)
        self.assertTrue((first.directory / "report.md").exists())
        self.assertEqual(read_json(first.directory / "report.json")["project"], "Demo")
        second = self.engine()
        self.finish(second)
        self.assertNotEqual(first.directory, second.directory)
        self.assertEqual(len(runs(self.project)), 2)

    def test_interrupt_resume_without_losing_committed_results(self):
        engine = self.engine()
        with patch("xitool.execution.scan", side_effect=[self.result({"url": "https://example.com/"}), KeyboardInterrupt()]):
            state = engine.execute()
        self.assertEqual(state["status"], "INTERRUPTED")
        self.assertEqual(len(state["pending"]), 1)
        self.assertEqual(len(state["completed"]), 1)
        self.assertEqual(len(state["results"]), 1)
        resumed = Engine(self.project, self.scope, self.config, "misconfiguration", resume=engine.directory)
        with patch("xitool.execution.scan", side_effect=lambda module, task, client: self.result(task)) as scanner:
            resumed.execute()
        self.assertEqual(scanner.call_count, 1)
        self.assertEqual(len(resumed.state["results"]), 2)
        self.assertEqual(resumed.state["status"], "COMPLETED")

    def test_crash_saves_failed_and_can_resume(self):
        engine = self.engine()
        with patch("xitool.execution.scan", side_effect=RuntimeError("simulated crash")):
            with self.assertRaises(RuntimeError):
                engine.execute()
        state = load_state(engine.directory / "checkpoint.json")
        self.assertEqual(state["status"], "FAILED")
        self.assertEqual(len(state["pending"]), 2)
        self.assertFalse((self.project / ".execution.lock").exists())
        resumed = Engine(self.project, self.scope, self.config, "misconfiguration", resume=engine.directory)
        self.finish(resumed)
        self.assertEqual(resumed.state["status"], "COMPLETED")

    def test_corrupt_checkpoint_rejected(self):
        engine = self.engine()
        self.finish(engine)
        path = engine.directory / "checkpoint.json"
        payload = read_json(path)
        payload["data"]["pending"] = []
        payload["data"]["project"] = "other"
        save_json(path, payload)
        with self.assertRaises(DataError):
            load_state(path)

    def test_structurally_invalid_checkpoint_rejected(self):
        engine = self.engine()
        self.finish(engine)
        path = engine.directory / "checkpoint.json"
        original = read_json(path)["data"]
        for key, value in (("completed", [{}]), ("pending", [1]), ("results", [{"url": 1}]), ("inputs", [{}])):
            state = copy.deepcopy(original)
            state[key] = value
            save_json(path, {"sha256": fingerprint(state), "data": state})
            with self.subTest(key=key), self.assertRaises(DataError):
                load_state(path)

    def test_config_change_rejected(self):
        engine = self.engine()
        with patch("xitool.execution.scan", side_effect=KeyboardInterrupt()):
            engine.execute()
        config = copy.deepcopy(self.config)
        config["http"]["requests_per_second"] = 1
        with self.assertRaises(DataError):
            Engine(self.project, self.scope, config, "misconfiguration", resume=engine.directory)

    def test_resume_scope_change_prunes_queue_and_results(self):
        engine = self.engine()
        with patch("xitool.execution.scan", side_effect=[self.result({"url": "https://example.com/"}), KeyboardInterrupt()]):
            engine.execute()
        restricted = Scope(["example.com"], [])
        resumed = Engine(self.project, restricted, self.config, "misconfiguration", resume=engine.directory)
        self.assertEqual(resumed.state["pending"], [])
        self.assertEqual(len(resumed.state["results"]), 1)
        self.assertNotIn("api.example.com", resumed.state["hosts"])
        self.finish(resumed)

    def test_project_isolation_and_lock(self):
        other = self.projects.create("Other", ["other.example"], [])
        engine = self.engine()
        self.finish(engine)
        self.assertEqual(runs(other), [])
        (self.project / ".execution.lock").write_text("123", encoding="utf-8")
        with self.assertRaises(DataError):
            self.engine().execute()
        self.assertEqual((self.project / ".execution.lock").read_text(), "123")

    def test_manual_review_transitions(self):
        engine = self.engine("idor", [{"url": "https://example.com/?id=1", "parameter": "id", "input_type": "identifier"}])
        engine.execute()
        queue = read_json(engine.directory / "manual_review.json")
        self.assertEqual(queue[0]["status"], "PENDING_REVIEW")
        review(engine.directory, queue[0]["finding_id"], "IN_REVIEW")
        review(engine.directory, queue[0]["finding_id"], "CONFIRMED")
        engine.export()
        self.assertEqual(read_json(engine.directory / "report.json")["manual_review"][0]["status"], "CONFIRMED")
        self.assertEqual(engine.state["results"][0]["status"], "MANUAL_REVIEW")
        with self.assertRaises(DataError):
            review(engine.directory, queue[0]["finding_id"], "INVALID")

    def test_review_queue_grows_on_resume_preserving_decisions(self):
        tasks = [{"url": "https://example.com/?id=1", "parameter": "id", "input_type": "identifier"},
                 {"url": "https://example.com/?id=2", "parameter": "id", "input_type": "identifier"}]
        engine = self.engine("idor", tasks)
        from xitool.scanners import scan as actual_scan
        count = 0
        def interrupt(module, task, client):
            nonlocal count
            count += 1
            if count == 2:
                raise KeyboardInterrupt()
            return actual_scan(module, task, client)
        with patch("xitool.execution.scan", side_effect=interrupt):
            engine.execute()
        queue = read_json(engine.directory / "manual_review.json")
        review(engine.directory, queue[0]["finding_id"], "IN_REVIEW")
        resumed = Engine(self.project, self.scope, self.config, "idor", resume=engine.directory)
        resumed.execute()
        queue = read_json(engine.directory / "manual_review.json")
        self.assertEqual(len(queue), 2)
        self.assertEqual(queue[0]["status"], "IN_REVIEW")
        self.assertEqual(queue[1]["status"], "PENDING_REVIEW")

    def test_diff_identity_and_changed_evidence(self):
        first = self.engine()
        self.finish(first)
        after = copy.deepcopy(first.state)
        after["run_id"] = "next"
        after["results"][0]["timestamp"] = "different"
        diff = scan_diff(first.state, after)
        self.assertEqual(len(diff["results"]["unchanged"]), 2)
        after["results"][0]["evidence"] = {"ok": False}
        after["results"].pop()
        diff = scan_diff(first.state, after)
        self.assertEqual(len(diff["results"]["changed"]), 1)
        self.assertEqual(len(diff["results"]["not_detected"]), 1)
        after["project"] = "other"
        with self.assertRaises(DataError):
            scan_diff(first.state, after)

    def test_subfinding_filters_before_probing_and_exports(self):
        tasks = build_tasks("subfinding", self.scope, [], ["https://example.com/", "https://evil.org/"])
        self.assertEqual(len(tasks), 1)
        engine = self.engine("subfinding", tasks)
        html = '<a href="/search?q=x">Search</a><a href="https://evil.org/">out</a><form method="post"><input name="file"></form>'
        with patch.object(engine.client, "get", side_effect=lambda url: Response(url, 200, {"content-type": "text/html"}, html)) as request:
            engine.execute()
        self.assertTrue(all("evil" not in call.args[0] for call in request.call_args_list))
        self.assertTrue((engine.directory / "subfinding" / "discovered_inputs.json").exists())
        self.assertTrue((self.project / "subfinding" / "all_subdomains.txt").exists())
        inputs, urls = latest_discovery(self.project, self.scope)
        self.assertTrue(inputs)
        self.assertTrue(urls)
        self.assertTrue(all("evil" not in url for url in urls))

    def test_network_error_recorded_not_finding(self):
        engine = self.engine()
        with patch("xitool.execution.scan", side_effect=NetworkError("fixture")):
            engine.execute()
        self.assertEqual(len(engine.state["errors"]), 2)
        self.assertEqual(engine.state["results"], [])
        self.assertEqual(engine.state["status"], "COMPLETED")

    def test_unknown_input_or_module_not_started(self):
        with self.assertRaises(DataError):
            Engine(self.project, self.scope, self.config, "xss", tasks=[])
        with self.assertRaises(DataError):
            build_tasks("sqli", self.scope, [], ["https://example.com/"])

    def test_deduplicate_tasks(self):
        task = {"url": "https://example.com/"}
        engine = self.engine(tasks=[task, task])
        self.assertEqual(len(engine.state["pending"]), 1)

    def test_periodic_checkpoint_while_work_is_running(self):
        config = copy.deepcopy(self.config)
        config["checkpoint"]["interval_seconds"] = 0.02
        engine = Engine(self.project, self.scope, config, "misconfiguration", tasks=[{"url": "https://example.com/"}])
        observed = []
        timer_saved = threading.Event()
        actual_save = engine.save
        def save():
            actual_save()
            if threading.current_thread() is not threading.main_thread():
                timer_saved.set()
        engine.save = save
        def scanner(module, task, client):
            first = load_state(engine.directory / "checkpoint.json")["updated_at"]
            timer_saved.clear()
            self.assertTrue(timer_saved.wait(timeout=5), "Checkpoint periodico assente durante il lavoro")
            observed.append(load_state(engine.directory / "checkpoint.json")["updated_at"] != first)
            return self.result(task)
        with patch("xitool.execution.scan", side_effect=scanner):
            engine.execute()
        self.assertEqual(observed, [True])


class CLITests(unittest.TestCase):
    def test_choices_validate_empty_and_nonnumeric(self):
        for value in ("", "abc", "-1", "4", "1,broken"):
            with self.subTest(value=value), patch("builtins.input", return_value=value), patch("sys.stdout", new_callable=io.StringIO):
                with self.assertRaises(DataError):
                    choose(["a", "b"], multiple=True)
        with patch("builtins.input", return_value="2,1,2"), patch("sys.stdout", new_callable=io.StringIO):
            self.assertEqual(choose(["a", "b"], multiple=True), [0, 1])

    def test_main_menu_has_only_required_entries(self):
        self.assertEqual([line for line in MAIN_MENU.splitlines() if line.startswith("[")],
                         ["[1] CREA PROGETTO", "[2] APRI PROGETTI", "[3] ESECUZIONE", "[0] ESCI"])

    def test_confirmation_prevents_execution(self):
        with tempfile.TemporaryDirectory() as temporary:
            projects = Projects(Path(temporary) / "targets")
            project = projects.create("Demo", ["example.com"], [])
            # Un progetto, Sub Finding, nessun file passivo, nessun URL aggiunto, rifiuto.
            with patch("builtins.input", side_effect=["1", "1", "1", "", "", "n"]), patch("sys.stdout", new_callable=io.StringIO), patch.object(Engine, "execute") as start:
                execute(projects, copy.deepcopy(DEFAULTS))
                start.assert_not_called()
            self.assertFalse((project / "runs").exists())

    def test_multi_project_confirmed_separate_engines(self):
        with tempfile.TemporaryDirectory() as temporary:
            projects = Projects(Path(temporary) / "targets")
            projects.create("A", ["a.example"], [])
            projects.create("B", ["b.example"], [])
            with patch("builtins.input", side_effect=["1,2", "1", "1", "1", "", "", "", "", "s"]), patch("sys.stdout", new_callable=io.StringIO), patch.object(Engine, "execute") as start, patch("xitool.cli.post_run"):
                execute(projects, copy.deepcopy(DEFAULTS))
                self.assertEqual(start.call_count, 2)

    def test_file_view_escapes_terminal_controls(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = root / "hostile.txt"
            path.write_text("\x1b[2Jtest", encoding="utf-8")
            with patch("sys.stdout", new_callable=io.StringIO) as output:
                show_file(root, path)
            self.assertNotIn("\x1b", output.getvalue())

    def test_file_view_rejects_corrupt_json(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = root / "corrupt.json"
            path.write_text("{broken", encoding="utf-8")
            with self.assertRaises(DataError):
                show_file(root, path)

    def test_main_invalid_then_exit(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "config.yaml").write_text("{}", encoding="utf-8")
            with patch("sys.argv", ["main.py"]), patch("builtins.input", side_effect=["", "wrong", "0"]), patch("sys.stdout", new_callable=io.StringIO) as output:
                main(root)
            self.assertEqual(output.getvalue().count("Scelta non valida"), 2)
