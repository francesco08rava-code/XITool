"""Batch di domini distinti con budget HTTP condiviso e cancellazione coordinata."""
from concurrent.futures import ThreadPoolExecutor, wait, FIRST_COMPLETED
import threading
from .http import RateLimiter
from .workers import RequestBudget


def execute(engines, serial, observer=None):
    maximum = min(engine.config["execution"]["max_concurrent_domains"] for engine in engines)
    limiter = RateLimiter(min(engine.config["http"]["requests_per_second"] for engine in engines))
    budget = RequestBudget(min(engine.config["http"]["max_concurrency"] for engine in engines),
                           min(engine.config["http"].get("max_concurrency_per_host", 2) for engine in engines))
    host_limiters = {}
    pending = list(enumerate(engines))
    active, results = {}, {}
    display_guard = threading.Lock()
    def display(value):
        if observer:
            with display_guard:
                observer(value)
    pool = ThreadPoolExecutor(max_workers=maximum, thread_name_prefix="xitool-domain")
    interrupted = False
    try:
        while pending or active:
            busy = {(engine.project, engine.target) for _, engine in active.values()}
            for index, engine in list(pending):
                if len(active) >= maximum:
                    break
                if (engine.project, engine.target) in busy:
                    continue
                pending.remove((index, engine))
                engine.client.host_limiters = host_limiters
                future = pool.submit(serial, [engine], display, limiter, budget)
                active[future] = (index, engine)
                busy.add((engine.project, engine.target))
            ready, _ = wait(active, timeout=.1, return_when=FIRST_COMPLETED)
            for future in ready:
                index, engine = active.pop(future)
                rows = future.result()
                results[index] = rows[0]
                if rows[0]["status"] == "INTERRUPTED":
                    interrupted = True
            if interrupted:
                break
    except KeyboardInterrupt:
        interrupted = True
    finally:
        if interrupted:
            for _, engine in active.values():
                engine.stop.set()
        pool.shutdown(wait=True, cancel_futures=True)
        for future, (index, engine) in active.items():
            if not future.cancelled():
                results[index] = future.result()[0]
            else:
                results[index] = {"project": engine.project.name, "domain": engine.target, "module": engine.module,
                                  "run_id": engine.state["run_id"], "status": "PENDING", "processed": False, "errors": 0}
        for index, engine in pending:
            results[index] = {"project": engine.project.name, "domain": engine.target, "module": engine.module,
                              "run_id": engine.state["run_id"], "status": "PENDING", "processed": False, "errors": 0}
    return [results[index] for index in sorted(results)]
