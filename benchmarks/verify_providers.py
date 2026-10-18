"""Interroga soltanto provider CT fissi; non visita né risolve il dominio cercato."""
import argparse
import copy
from pathlib import Path
import sys

root = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(root))
from xitool.passive import collect
from xitool.http import RateLimiter
from xitool.storage import DEFAULTS, save_json

parser = argparse.ArgumentParser()
parser.add_argument("--live", action="store_true", required=True)
parser.add_argument("--root", default="example.com")
parser.add_argument("--output", type=Path, default=root / "verification/V52_PROVIDER_LIVE.json")
args = parser.parse_args()
config = copy.deepcopy(DEFAULTS)
config["http"].update(timeout_seconds=5, connect_timeout_seconds=5, read_timeout_seconds=5, max_retries=0)
limiter = RateLimiter(1)
rows = [collect(name, args.root, config, limiter) for name in ("crtsh", "certspotter")]
save_json(args.output, {"root": args.root, "target_http_probed": False, "providers": rows})
print([{key: row.get(key) for key in ("provider", "status", "pages_completed", "unique_results", "error_category")} for row in rows])
