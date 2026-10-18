"""Sensore HTTP reale locale e correlazione SSRF, senza traffico verso endpoint pubblici."""
import copy
import json
from pathlib import Path
import socket
import tempfile
import threading
import unittest
from unittest.mock import Mock, patch
from http.server import ThreadingHTTPServer
from urllib.request import urlopen
from urllib.parse import parse_qs, urlsplit

from xitool.callback_receiver import handler
from xitool.controlled import execute, tasks, load_cases
from xitool.http import HTTPClient, Response
from xitool.scope import Scope
from xitool.storage import DEFAULTS, DataError, Projects, save_json


class CallbackTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.project = Projects(Path(directory.name)).create("Callbacks", ["example.com"], [])
        self.scope = Scope(["example.com"], [])
        self.events = self.project / "callback_events.jsonl"
        self.events.write_text("", encoding="utf-8")
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), handler(self.events))
        thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        thread.start()
        def cleanup():
            self.server.shutdown()
            self.server.server_close()
            thread.join(timeout=2)
        self.addCleanup(cleanup)
        self.case = {"id": "public-callback", "module": "ssrf", "url": "https://example.com/?url=original",
                     "operator_owned": True, "parameter": "url", "callback_base": "https://callback.operator.test/xitool-callback/",
                     "events_file": "callback_events.jsonl", "expected_source_ips": ["127.0.0.1"]}
        save_json(self.project / "controlled_checks.json", {"version": 1, "checks": [self.case]})
        self.client = HTTPClient(self.scope, copy.deepcopy(DEFAULTS))
        self.client.limiter.wait = Mock()

    def test_real_sensor_correlates_nonce_timestamp_and_expected_source(self):
        planned = tasks(self.project, self.scope, "ssrf")[0]
        def target_response(url, **kwargs):
            callback_url = parse_qs(urlsplit(url).query)["url"][0]
            path = urlsplit(callback_url).path
            # Il trasporto della destinazione pubblica è sostituito dalla fixture locale del sensore.
            with urlopen(f"http://127.0.0.1:{self.server.server_address[1]}{path}", timeout=2) as received:
                self.assertEqual(received.status, 204)
            return Response(url, 200, {}, "accepted")
        public_dns = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 443))]
        with patch("xitool.http.HTTPClient._resolve", return_value=public_dns), patch.object(self.client, "get", side_effect=target_response):
            result = execute("ssrf", planned, self.client, self.project)[0]
        self.assertEqual(result["status"], "VERIFIED")
        row = json.loads(self.events.read_text())
        self.assertEqual(row["id"], result["evidence"]["correlation_id"])
        self.assertEqual(set(row), {"id", "received_at", "source_ip"})

    def test_private_callback_dns_is_rejected_before_target_request(self):
        planned = tasks(self.project, self.scope, "ssrf")[0]
        private_dns = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 443))]
        with patch("xitool.http.HTTPClient._resolve", return_value=private_dns), patch.object(self.client, "get") as get:
            with self.assertRaises(DataError):
                execute("ssrf", planned, self.client, self.project)
        get.assert_not_called()

    def test_missing_sensor_log_is_unsupported_without_target_request(self):
        self.events.unlink()
        with patch.object(self.client, "get") as get:
            result = execute("ssrf", tasks(self.project, self.scope, "ssrf")[0], self.client, self.project)[0]
        self.assertEqual(result["status"], "UNSUPPORTED")
        get.assert_not_called()

    def test_missing_callback_stays_partial_not_clean_or_verified(self):
        planned = tasks(self.project, self.scope, "ssrf")[0]
        public_dns = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 443))]
        with patch("xitool.http.HTTPClient._resolve", return_value=public_dns), patch.object(self.client, "get", return_value=Response(self.case["url"], 200, {}, "normal")):
            result = execute("ssrf", planned, self.client, self.project)[0]
        self.assertEqual(result["status"], "PARTIAL")

    def test_internal_literal_and_arbitrary_log_paths_are_invalid(self):
        for patch_value in ({"callback_base": "https://127.0.0.1/xitool-callback/"}, {"events_file": "../outside.jsonl"}):
            save_json(self.project / "controlled_checks.json", {"version": 1, "checks": [{**self.case, **patch_value}]})
            with self.assertRaises(DataError):
                load_cases(self.project, self.scope, "ssrf")
