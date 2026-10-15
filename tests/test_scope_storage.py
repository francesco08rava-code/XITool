"""Regressioni riproducibili di scope, filesystem e configurazione."""
import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from xitool.scope import Scope, ScopeViolation, normalize_host, normalize_rule
from xitool.storage import DEFAULTS, DataError, Projects, atomic_write, confined, load_config, read_json, save_json


class ScopeTests(unittest.TestCase):
    def setUp(self):
        self.scope = Scope(["example.com", "*.example.com", "testsite.it"], ["admin.example.com", "*.internal.example.com"])

    def test_scope_matrix(self):
        for host, expected in {"example.com": True, "api.example.com": True, "EXAMPLE.COM.": True,
                               "admin.example.com": False, "x.internal.example.com": False,
                               "fakeexample.com": False, "example.com.evil.org": False,
                               "google.com": False, "testsite.it": True, "internal.example.com": True}.items():
            with self.subTest(host=host):
                self.assertEqual(self.scope.allowed(host), expected)

    def test_wildcard_excludes_apex(self):
        scope = Scope(["*.example.com"], [])
        self.assertFalse(scope.allowed("example.com"))
        self.assertTrue(scope.allowed("a.b.example.com"))

    def test_exact_does_not_allow_children(self):
        self.assertFalse(Scope(["example.com"], []).allowed("api.example.com"))

    def test_excluded_exact_does_not_exclude_children(self):
        self.assertTrue(self.scope.allowed("test.admin.example.com"))

    def test_idna_and_duplicates(self):
        scope = Scope(["BÜCHER.de.", "xn--bcher-kva.de"], [])
        self.assertEqual(scope.domains, ["xn--bcher-kva.de"])
        self.assertTrue(scope.allowed("bücher.de"))

    def test_invalid_rules(self):
        for value in ("", "https://example.com", "*example.com", "foo.*.com", "a..com", "a b.com",
                      "example.com:80", "127.1", "2130706433", "0x7f000001", "*.127.0.0.1", "-a.com", "a_.com", " a.com"):
            with self.subTest(value=value), self.assertRaises(DataError):
                normalize_rule(value)

    def test_invalid_urls(self):
        for value in ("file:///etc/passwd", "ftp://example.com/", "http://user:pass@example.com/",
                      "http://example.com:bad/", "http://example.com:0/", "http://evil.org/",
                      "http://example.com\\@evil.org/", "http://example.com/\nHeader:bad", "http://example.com:8080/"):
            with self.subTest(value=value), self.assertRaises(ScopeViolation):
                self.scope.url(value, [80, 443])

    def test_url_normalization(self):
        self.assertEqual(self.scope.url("https://EXAMPLE.COM.:443?q=x#fragment"), "https://example.com/?q=x")

    def test_special_ips(self):
        for address in ("127.0.0.1", "10.0.0.1", "169.254.169.254", "::1", "fe80::1", "224.0.0.1", "0.0.0.0"):
            with self.subTest(ip=address), self.assertRaises(ScopeViolation):
                self.scope.validate_ip(address)
        self.scope.validate_ip("8.8.8.8")

    def test_explicit_lab_network_still_requires_hostname(self):
        scope = Scope(["lab.example"], [], ["127.0.0.1/32"])
        scope.validate_ip("127.0.0.1")
        self.assertFalse(scope.allowed("127.0.0.1"))
        with self.assertRaises(ScopeViolation):
            scope.validate_ip("127.0.0.2")

    def test_fingerprint_changes_with_scope(self):
        self.assertNotEqual(self.scope.digest, Scope(self.scope.domains, ["testsite.it"]).digest)


class StorageTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.projects = Projects(self.root / "targets")

    def test_creation_and_utc(self):
        path = self.projects.create("DemoLab", ["example.com", "example.com"], ["admin.example.com"])
        self.assertEqual(self.projects.list(), ["DemoLab"])
        path2, scope = self.projects.load("DemoLab")
        self.assertEqual(path, path2)
        self.assertEqual(scope.domains, ["example.com"])
        self.assertTrue(read_json(path / "scope.json")["created_at"].endswith("Z"))

    def test_duplicate_preserves_data(self):
        path = self.projects.create("Demo", ["example.com"], [])
        before = (path / "scope.json").read_bytes()
        with self.assertRaises(DataError):
            self.projects.create("demo", ["other.com"], [])
        self.assertEqual((path / "scope.json").read_bytes(), before)

    def test_bad_names(self):
        for name in ("", "..", "../other", "a/b", "a\\b", "a:b", "CON", "LPT1", "a" * 65, "space name"):
            with self.subTest(name=name), self.assertRaises(DataError):
                self.projects.path(name)

    def test_traversal(self):
        with self.assertRaises(DataError):
            confined(self.root, self.root / ".." / "outside")

    def test_symlink(self):
        target = self.root / "real"
        target.mkdir()
        try:
            (self.root / "link").symlink_to(target, target_is_directory=True)
        except OSError:
            self.skipTest("Creazione symlink non consentita dal sistema")
        with self.assertRaises(DataError):
            confined(self.root, self.root / "link" / "file")

    def test_interrupted_atomic_write_preserves_previous(self):
        path = self.root / "checkpoint.json"
        save_json(path, {"old": True})
        with patch("xitool.storage.os.replace", side_effect=OSError("disk full")):
            with self.assertRaises(OSError):
                save_json(path, {"old": False})
        self.assertEqual(read_json(path), {"old": True})
        self.assertEqual(list(self.root.glob(".xitool-*")), [])

    def test_corrupt_json(self):
        path = self.root / "bad.json"
        path.write_text("{broken", encoding="utf-8")
        with self.assertRaises(DataError):
            read_json(path)

    def test_config_defaults_and_validation(self):
        path = self.root / "config.yaml"
        path.write_text("http:\n  requests_per_second: 1.5\n", encoding="utf-8")
        config = load_config(path)
        self.assertEqual(config["http"]["requests_per_second"], 1.5)
        self.assertEqual(config["checkpoint"]["interval_seconds"], 30)
        for content in ("[]", "http: [broken", "http: {requests_per_second: 0}", "http: {max_retries: true}",
                        "execution: {require_confirmation: false}", "checkpoint: {enabled: false}",
                        "http: {allowed_ports: [0]}", "unknown: {}", "http: {max_retries: 1.5}", "http: {unknown: 1}"):
            path.write_text(content, encoding="utf-8")
            with self.subTest(config=content), self.assertRaises(DataError):
                load_config(path)
