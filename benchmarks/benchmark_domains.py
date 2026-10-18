"""Confronto due domini loopback e budget condiviso, medesimo script per ogni versione."""
import argparse
import copy
import json
from pathlib import Path
import sys
import tempfile
import threading
import time
import tracemalloc
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    sys.path.insert(0, str(args.source))
    from xitool import __version__
    from xitool.execution import Engine, run_batch
    from xitool.scope import Scope
    from xitool.storage import DEFAULTS, Projects
    from benchmark_local import process_peak_rss
    guard = threading.Lock()
    counts = {"active": 0, "peak": 0, "requests": 0}
    active_hosts, peaks = {}, {}
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            host = self.server.server_address[0]
            with guard:
                counts["active"] += 1
                counts["peak"] = max(counts["peak"], counts["active"])
                counts["requests"] += 1
                active_hosts[host] = active_hosts.get(host, 0) + 1
                peaks[host] = max(peaks.get(host, 0), active_hosts[host])
            try:
                time.sleep(.25)
                body = b"local public fixture"
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            finally:
                with guard:
                    counts["active"] -= 1
                    active_hosts[host] -= 1
        def log_message(self, *args):
            pass
    servers = []
    try:
        for host in ("127.0.0.1", "127.0.0.2"):
            server = ThreadingHTTPServer((host, 0), Handler)
            threading.Thread(target=server.serve_forever, daemon=True).start()
            servers.append(server)
        with tempfile.TemporaryDirectory() as directory:
            domains = [server.server_address[0] for server in servers]
            project = Projects(Path(directory)).create("DomainsBenchmark", domains, [])
            scope = Scope(domains, [], ["127.0.0.0/8"])
            config = copy.deepcopy(DEFAULTS)
            config["http"].update(max_concurrency=5, max_concurrency_per_host=2, requests_per_second=20,
                                   allowed_ports=[server.server_port for server in servers], max_retries=0)
            config["execution"]["max_concurrent_domains"] = 2
            config["cache"]["enabled"] = False
            tracemalloc.start()
            start = time.perf_counter()
            engines = [Engine(project, scope, config, "misconfiguration", target=host,
                              tasks=[{"url": f"http://{host}:{server.server_port}/resource{n}"} for n in range(12)])
                       for host, server in zip(domains, servers)]
            summaries = run_batch(engines)
            seconds = time.perf_counter() - start
            _, peak_memory = tracemalloc.get_traced_memory()
            tracemalloc.stop()
            report = {"version": __version__, "domains": 2, "tasks": 24, "seconds": seconds,
                      "throughput": 24 / seconds, "python_peak_bytes": peak_memory,
                      "process_lifetime_peak_rss_bytes": process_peak_rss(), "global_cap": 5, "host_cap": 2,
                      "observed_global_peak": counts["peak"], "observed_host_peaks": peaks,
                      "requests": counts["requests"], "completed": sum(len(e.state["completed"]) for e in engines),
                      "errors": sum(len(e.state["errors"]) for e in engines),
                      "duplicates": sum(len(e.state["results"]) - len({r["id"] for r in e.state["results"]}) for e in engines),
                      "summaries": summaries}
            args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    finally:
        for server in servers:
            server.shutdown()
            server.server_close()


if __name__ == "__main__":
    main()
