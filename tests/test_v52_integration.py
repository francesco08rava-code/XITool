import os
import unittest
from lab_runner import run, metrics


class MetricsTests(unittest.TestCase):
    def test_null_denominators_and_errors_not_counted_as_true_negatives(self):
        values = metrics([{"module": "sql", "category": "candidate", "observed_positive": None, "ground_truth": False, "observed": "ERROR"}])
        self.assertEqual(values["sql:candidate"]["ERROR"], 1)
        self.assertEqual(values["sql:candidate"]["TN"], 0)
        self.assertIsNone(values["sql:candidate"]["precision"])


@unittest.skipUnless(os.environ.get("XITOOL_BROWSER_TESTS") == "1", "Laboratorio completo richiede browser opzionale")
class IntegratedLabTests(unittest.TestCase):
    def test_thirteen_modules_consume_discovery_and_preserve_isolation(self):
        result = run()
        self.assertEqual(len(result["modules"]), 13)
        self.assertTrue(result["success"], [r for r in result["cases"] if r["ground_truth"] != r["observed_positive"] and r["observed_positive"] is not None])
