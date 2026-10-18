"""Dataset etichettato limitato a fixture reali; nessuna precisione generale dichiarata."""
import json
from pathlib import Path
import sys
import unittest

root = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(root))
sys.path.insert(0, str(root / "tests"))
from test_v51 import SQLBodyTests
from test_v51_browser import DOMBrowserTests
from test_v51_e2e import PipelineTests


def main():
    suite = unittest.TestSuite(unittest.defaultTestLoader.loadTestsFromTestCase(cls)
                               for cls in (SQLBodyTests, DOMBrowserTests, PipelineTests))
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    rows = getattr(SQLBodyTests, "observations", []) + getattr(DOMBrowserTests, "observations", [])
    metrics = {}
    for module in ("sqli", "xss"):
        data = [row for row in rows if row["module"] == module]
        counts = {key: 0 for key in ("TP", "FP", "TN", "FN", "inconclusive")}
        for row in data:
            if row["inconclusive"]:
                counts["inconclusive"] += 1
            else:
                key = ("TP" if row["expected_positive"] else "FP") if row["observed_positive"] else ("FN" if row["expected_positive"] else "TN")
                counts[key] += 1
        expected = 4 if module == "sqli" else 3
        counts["unexecuted"] = max(0, expected - len(data))
        counts["precision"] = counts["TP"] / (counts["TP"] + counts["FP"]) if counts["TP"] + counts["FP"] else None
        counts["recall"] = counts["TP"] / (counts["TP"] + counts["FN"]) if counts["TP"] + counts["FN"] else None
        counts["definition"] = "Repeated SQL candidate differential; not SQL VERIFIED" if module == "sqli" else "Benign DOM browser execution from fragment"
        metrics[module] = counts
    report = {"success": result.wasSuccessful(), "test_count": result.testsRun, "skips": len(result.skipped),
              "fixtures": rows, "metrics": metrics,
              "limitations": "Seven synthetic local labelled cases only. Metrics are per stated detector, not general scanner accuracy. Pipeline covers crawl/inputs/plan/interrupt/resume/reports/diff, not all 13 controls in one application."}
    (root / "verification/V51_LOCAL_VALIDATION.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    raise SystemExit(0 if result.wasSuccessful() else 1)


if __name__ == "__main__":
    main()
