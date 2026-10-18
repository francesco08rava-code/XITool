"""Benchmark riproducibile: server loopback, nessun asset pubblico."""
import argparse
import copy
import json
from pathlib import Path
import statistics
import sys
import tempfile
import threading
import time
import tracemalloc
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


def process_peak_rss():
    if sys.platform == "win32":
        import ctypes
        from ctypes import wintypes
        class Counters(ctypes.Structure):
            _fields_ = [("cb", wintypes.DWORD), ("page_faults", wintypes.DWORD)] + [(name, ctypes.c_size_t) for name in (
                "peak_working_set", "working_set", "peak_paged", "paged", "peak_nonpaged", "nonpaged", "pagefile", "peak_pagefile")]
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.GetCurrentProcess.restype = wintypes.HANDLE
        query = ctypes.WinDLL("psapi", use_last_error=True).GetProcessMemoryInfo
        query.argtypes = [wintypes.HANDLE, ctypes.POINTER(Counters), wintypes.DWORD]
        query.restype = wintypes.BOOL
        counters = Counters()
        counters.cb = ctypes.sizeof(counters)
        return int(counters.peak_working_set) if query(kernel.GetCurrentProcess(), ctypes.byref(counters), counters.cb) else None
    import resource
    value = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return int(value if sys.platform == "darwin" else value * 1024)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--workers", type=int, default=5, choices=range(1, 11))
    parser.add_argument("--tasks", type=int, default=12, choices=range(1, 501))
    parser.add_argument("--repeats", type=int, default=3, choices=range(1, 6))
    parser.add_argument("--delay", type=float, default=.25)
    parser.add_argument("--scenario", choices=("normal", "slow", "timeout", "429", "intermittent"), default="normal")
    parser.add_argument("--interrupt", action="store_true", help="Interrupt after the first committed task, then resume")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    sys.path.insert(0, str(args.source.resolve()))
    from xitool import __version__
    from xitool.execution import Engine
    from xitool.scope import Scope
    from xitool.storage import DEFAULTS, Projects
    active = peak = requests = 0
    path_counts = {}
    guard = threading.Lock()
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            nonlocal active, peak, requests
            with guard:
                active += 1
                peak = max(peak, active)
                requests += 1
                path_counts[self.path] = path_counts.get(self.path, 0) + 1
                attempt = path_counts[self.path]
            try:
                time.sleep(1 if args.scenario == "timeout" else .5 if args.scenario == "slow" else args.delay)
                number = int(self.path.rsplit("resource", 1)[-1])
                status = 429 if args.scenario == "429" and number % 4 == 0 and attempt == 1 else 503 if args.scenario == "intermittent" and number % 4 == 0 and attempt == 1 else 200
                body = b"<html><title>Public fixture</title><body>ok</body></html>"
                self.send_response(status)
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                try:
                    self.wfile.write(body)
                except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
                    pass
            finally:
                with guard:
                    active -= 1
        def log_message(self, *args):
            pass
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    results = []
    try:
        for index in range(args.repeats):
            requests = peak = 0
            path_counts.clear()
            config = copy.deepcopy(DEFAULTS)
            config["http"].update(max_concurrency=args.workers, max_concurrency_per_host=args.workers,
                                   requests_per_second=20, max_retries=0, allowed_ports=[server.server_port])
            if args.scenario == "timeout":
                config["http"].update(timeout_seconds=.15, connect_timeout_seconds=.15, read_timeout_seconds=.15)
            if args.scenario in ("429", "intermittent"):
                config["http"]["max_retries"] = 1
            config["cache"]["enabled"] = False
            with tempfile.TemporaryDirectory() as directory:
                project = Projects(Path(directory)).create("Benchmark", ["127.0.0.1"], [])
                scope = Scope(["127.0.0.1"], [], ["127.0.0.1/32"])
                tasks = [{"url": f"http://127.0.0.1:{server.server_port}/resource{number}"} for number in range(args.tasks)]
                tracemalloc.start()
                started = time.perf_counter()
                engine = Engine(project, scope, config, "misconfiguration", target="127.0.0.1", tasks=tasks)
                if args.interrupt:
                    def interrupt(state):
                        if state["completed"]:
                            raise KeyboardInterrupt()
                    engine.execute(interrupt)
                    assert engine.state["status"] == "INTERRUPTED"
                    engine = Engine(project, scope, config, "misconfiguration", target="127.0.0.1", resume=engine.directory)
                engine.execute()
                elapsed = time.perf_counter() - started
                _, memory = tracemalloc.get_traced_memory()
                tracemalloc.stop()
                results.append({"seconds": elapsed, "python_peak_bytes": memory, "requests": requests,
                                "requests_per_second": requests / elapsed, "peak_active_http": peak,
                                "tasks_per_second": args.tasks / elapsed, "interrupted_and_resumed": args.interrupt,
                                "errors": len(engine.state["errors"]), "timeouts": engine.client.stats["timeouts"],
                                "completed": len(engine.state["completed"]),
                                "duplicates": len(engine.state["results"]) - len({row["id"] for row in engine.state["results"]}),
                                "repeated_http_requests": sum(max(0, count - 1) for count in path_counts.values()), "status": engine.state["status"]})
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
    report = {"version": __version__, "workers_configured": args.workers, "host_slots": args.workers,
              "tasks": args.tasks, "rate_limit": 20, "scenario": args.scenario, "server_delay_seconds": args.delay,
              "memory_metric": "tracemalloc Python allocations per run; separate OS process-lifetime peak RSS",
              "process_lifetime_peak_rss_bytes": process_peak_rss(), "runs": results,
              "median_seconds": statistics.median(row["seconds"] for row in results),
              "min_seconds": min(row["seconds"] for row in results), "max_seconds": max(row["seconds"] for row in results),
              "stdev_seconds": statistics.stdev(row["seconds"] for row in results) if len(results) > 1 else None,
              "median_python_peak_bytes": statistics.median(row["python_peak_bytes"] for row in results)}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
