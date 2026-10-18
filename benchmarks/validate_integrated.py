"""Eseguire con browser abilitato; salva prove e dataset, mai bersagli pubblici."""
import sys
from pathlib import Path

root = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(root))
sys.path.insert(0, str(root / "tests"))
from lab_runner import run
from xitool.storage import save_json

paths = [root / "verification/V52_E2E_RESULTS.json", root / "verification/V52_ACCURACY_DATASET.json"]
for path in paths:
    save_json(path, {"success": False, "state": "RUNNING", "results_incomplete": True})
try:
    result = run(paths[0])
except BaseException as exc:
    for path in paths:
        save_json(path, {"success": False, "state": "FAILED", "fatal_error": type(exc).__name__, "results_incomplete": True})
    raise
save_json(root / "verification/V52_ACCURACY_DATASET.json", result)
print({"success": result["success"], "cases": len(result["cases"]), "modules": result["modules"]})
raise SystemExit(0 if result["success"] else 1)
