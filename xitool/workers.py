"""Worker limitati: checkpoint scritti solo dal coordinatore, client isolati."""
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
import threading
from urllib.parse import urlsplit

from .http import HTTPClient, NetworkError


class RequestBudget:
    def __init__(self, maximum, per_host):
        self.global_slots = threading.BoundedSemaphore(maximum)
        self.per_host = per_host
        self.hosts = {}
        self.guard = threading.Lock()

    @contextmanager
    def slot(self, host, cancel=None):
        with self.guard:
            if host not in self.hosts:
                # Non espellere un semaforo potenzialmente in uso.
                if len(self.hosts) >= 10000:
                    raise NetworkError("Limite host del budget raggiunto")
                self.hosts[host] = threading.BoundedSemaphore(self.per_host)
            gate = self.hosts[host]
        acquired = []
        try:
            for semaphore in (gate, self.global_slots):
                while not semaphore.acquire(timeout=.1):
                    if cancel and cancel.is_set():
                        raise NetworkError("Attività annullata", category="CANCELLED")
                acquired.append(semaphore)
                if cancel and cancel.is_set():
                    raise NetworkError("Attività annullata", category="CANCELLED")
            yield
        finally:
            for semaphore in reversed(acquired):
                semaphore.release()


class TaskPool:
    def __init__(self, engine):
        self.engine = engine
        self.maximum = engine.config["http"]["max_concurrency"]
        self.executor = ThreadPoolExecutor(max_workers=self.maximum, thread_name_prefix="xitool")
        self.pending = []
        self.clients = []

    def eligible(self, task):
        return (self.maximum > 1 and not task.get("controlled_case") and not task.get("session") and
                task.get("kind") not in ("passive", "dns") and not self.engine.state.get("dynamic_browser"))

    def take(self, task):
        if self.eligible(task) and not self.engine.stop.is_set():
            # Refill the bounded window after each committed item, preserving FIFO.
            scheduled = [candidate for candidate, _ in self.pending]
            for candidate in list(self.engine.state["pending"])[:self.maximum]:
                if not self.eligible(candidate):
                    break
                if candidate in scheduled:
                    continue
                if len(self.pending) >= self.maximum:
                    break
                client = HTTPClient(self.engine.scope, self.engine.config)
                client.limiter = self.engine.client.limiter
                client.host_limiters = self.engine.client.host_limiters
                client.budget = self.engine.client.budget
                client.cancel = self.engine.stop
                self.clients.append(client)
                self.pending.append((candidate, self.executor.submit(self.engine._perform, candidate, client)))
        if self.pending:
            candidate, future = self.pending.pop(0)
            if candidate != task:
                raise RuntimeError("Coda worker incoerente")
            result = future.result()
            self.account(result["client"])
            return result
        return self.engine._perform(task)

    def close(self):
        self.engine.stop.set()
        for _, future in self.pending:
            future.cancel()
        self.executor.shutdown(wait=True, cancel_futures=True)
        for client in list(self.clients):
            self.account(client)

    def account(self, client):
        for key, value in client.stats.items():
            self.engine.client.stats[key] += value
        client.cache.clear()
        self.clients.remove(client)
