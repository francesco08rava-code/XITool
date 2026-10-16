"""HTTP senza proxy ambientali, con IP fissato, limiti e cache volatile."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
import http.client
import socket
import ssl
import threading
import time
from typing import Callable
from urllib.parse import urljoin, urlsplit

from .scope import Scope, ScopeViolation
from .storage import DataError


class NetworkError(OSError):
    """Richiesta fallita senza esporre URL o segreti nei messaggi."""


@dataclass
class Response:
    url: str
    status: int
    headers: dict[str, str]
    body: str
    truncated: bool = False


class RateLimiter:
    def __init__(self, maximum: float):
        self.maximum = maximum
        self.current = maximum
        self.next_at = 0.0

    def wait(self) -> None:
        time.sleep(max(0.0, self.next_at - time.monotonic()))
        self.next_at = time.monotonic() + 1 / self.current

    def feedback(self, status: int = 0, retry_after: str = "") -> None:
        """Rallenta senza raffiche e applica Retry-After anche come data HTTP."""
        if status in (0, 429, 503):
            self.current = max(self.maximum / 32, self.current / 2)
            delay = 1 / self.current
            if retry_after:
                try:
                    delay = max(delay, float(retry_after))
                except ValueError:
                    try:
                        delay = max(delay, (parsedate_to_datetime(retry_after) - datetime.now(timezone.utc)).total_seconds())
                    except (ValueError, TypeError, OverflowError):
                        pass
            # Evita attese incontrollate: oltre cinque minuti la run si interrompe.
            if delay > 300:
                raise NetworkError("Retry-After oltre 300 secondi: riprendere più tardi")
            self.next_at = max(self.next_at, time.monotonic() + delay)
        else:
            self.current = min(self.maximum, self.current * 1.05)


class HTTPClient:
    def __init__(self, scope: Scope, config: dict, heartbeat: Callable[[], None] | None = None):
        self.scope = scope
        self.config = config
        self.limiter = RateLimiter(config["http"]["requests_per_second"])
        self.cache: dict[tuple, tuple[float, Response]] = {}
        self.stats = {"requests": 0, "errors": 0, "timeouts": 0, "cache_hits": 0}
        self.heartbeat = heartbeat or (lambda: None)
        self.started = time.monotonic()
        self._dns_thread: threading.Thread | None = None

    def _resolve(self, host: str, port: int) -> list:
        """Limita l'attesa DNS senza accumulare thread su un resolver bloccato."""
        if self._dns_thread is not None and self._dns_thread.is_alive():
            raise NetworkError("Risoluzione DNS precedente ancora bloccata")
        finished = threading.Event()
        result: list = []
        errors: list[OSError] = []
        def resolve() -> None:
            try:
                result.extend(socket.getaddrinfo(host, port, type=socket.SOCK_STREAM))
            except OSError as exc:
                errors.append(exc)
            finally:
                finished.set()
        self._dns_thread = threading.Thread(target=resolve, daemon=True)
        self._dns_thread.start()
        if not finished.wait(self.config["http"]["timeout_seconds"]):
            raise TimeoutError("Timeout DNS")
        self._dns_thread.join(timeout=0.1)
        if errors:
            raise errors[0]
        return result

    def _request(self, url: str, headers: dict[str, str]) -> Response:
        """Risolve una volta e usa l'IP verificato conservando Host e SNI originali."""
        settings = self.config["http"]
        started = time.monotonic()
        parsed = urlsplit(url)
        host = parsed.hostname or ""
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        addresses = self._resolve(host, port)
        if not addresses:
            raise NetworkError("DNS senza destinazioni")
        for address in addresses:
            self.scope.validate_ip(address[4][0])
        family, socktype, protocol, _, target = addresses[0]
        connection = http.client.HTTPConnection(host, port, timeout=settings["timeout_seconds"])
        stream = socket.socket(family, socktype, protocol)
        def abort() -> None:
            try:
                stream.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            stream.close()
        deadline = started + settings["timeout_seconds"]
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            stream.close()
            raise TimeoutError("Deadline richiesta superata")
        watchdog = threading.Timer(remaining, abort)
        watchdog.daemon = True
        watchdog.start()
        try:
            stream.settimeout(settings["timeout_seconds"])
            stream.connect(target)
            if stream.getpeername()[0] != target[0]:
                raise ScopeViolation("IP effettivo diverso dall'IP validato")
            if parsed.scheme == "https":
                stream = ssl.create_default_context().wrap_socket(stream, server_hostname=host)
            connection.sock = stream
            path = parsed.path or "/"
            if parsed.query:
                path += "?" + parsed.query
            connection.request("GET", path, headers={"User-Agent": "XITool/2.0 (authorized audit)",
                                                     "Accept-Encoding": "identity", **headers})
            response = connection.getresponse()
            raw_headers: dict[str, str] = {}
            for key, value in response.getheaders():
                key = key.lower()
                raw_headers[key] = raw_headers.get(key, "") + ("\n" if key in raw_headers else "") + value
            if raw_headers.get("content-encoding", "identity").lower() != "identity":
                raise NetworkError("Risposta compressa nonostante Accept-Encoding: identity; contenuto non analizzato")
            limit = settings["max_body_bytes"]
            # Il timeout per socket non limita uno stream lento: applica anche una deadline.
            chunks: list[bytes] = []
            length = 0
            while length <= limit:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError("Deadline risposta superata")
                stream.settimeout(remaining)
                block = response.read1(min(65536, limit + 1 - length))
                if not block:
                    break
                chunks.append(block)
                length += len(block)
                self.heartbeat()
            raw = b"".join(chunks)
            return Response(url, response.status, raw_headers, raw[:limit].decode("utf-8", errors="replace"), len(raw) > limit)
        finally:
            watchdog.cancel()
            connection.close()
            stream.close()

    def get(self, value: str, headers: dict[str, str] | None = None, cache: bool = True) -> Response:
        headers = headers or {}
        if any(key.lower() != "origin" or "\r" in val or "\n" in val for key, val in headers.items()):
            raise DataError("Sono ammessi soltanto header Origin di test")
        url = self.scope.url(value, self.config["http"]["allowed_ports"])
        key = (self.scope.digest, url, tuple(sorted(headers.items())))
        cached = self.cache.get(key)
        if cache and self.config["cache"]["enabled"] and cached and time.monotonic() - cached[0] < self.config["cache"]["ttl_seconds"]:
            self.scope.url(cached[1].url, self.config["http"]["allowed_ports"])
            self.stats["cache_hits"] += 1
            return cached[1]
        visited: set[str] = set()
        for _ in range(self.config["http"]["max_redirects"] + 1):
            if url in visited:
                raise NetworkError("Ciclo di redirect")
            visited.add(url)
            for attempt in range(self.config["http"]["max_retries"] + 1):
                self.heartbeat()
                self.limiter.wait()
                self.stats["requests"] += 1
                try:
                    result = self._request(url, headers)
                except ScopeViolation:
                    raise
                except (OSError, http.client.HTTPException) as exc:
                    self.stats["errors"] += 1
                    if isinstance(exc, (TimeoutError, socket.timeout)):
                        self.stats["timeouts"] += 1
                    self.limiter.feedback()
                    if attempt == self.config["http"]["max_retries"]:
                        raise NetworkError(f"Richiesta fallita ({type(exc).__name__})") from exc
                    continue
                self.limiter.feedback(result.status, result.headers.get("retry-after", ""))
                if result.status not in (429, 503) or attempt == self.config["http"]["max_retries"]:
                    break
            if result.status in (301, 302, 303, 307, 308) and result.headers.get("location"):
                url = self.scope.url(urljoin(url, result.headers["location"]), self.config["http"]["allowed_ports"])
                continue
            if cache and self.config["cache"]["enabled"] and result.status == 200 and "set-cookie" not in result.headers and not any(x in result.headers.get("cache-control", "").lower() for x in ("no-store", "private")):
                if len(self.cache) >= 64:
                    self.cache.pop(next(iter(self.cache)))
                self.cache[key] = (time.monotonic(), result)
            return result
        raise NetworkError("Limite redirect raggiunto")
