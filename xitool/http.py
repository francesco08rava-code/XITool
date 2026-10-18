"""HTTP senza proxy ambientali, con IP fissato, limiti e cache volatile."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
import http.client
import logging
import random
import re
import socket
import ssl
import threading
import uuid
import zlib
import time
from typing import Callable
from urllib.parse import parse_qsl, urljoin, urlsplit

from .scope import Scope, ScopeViolation, blocked_request
from .storage import DataError

# Daemon resolver threads may outlive a timed-out client. Bound them across workers.
_DNS_SLOTS = threading.BoundedSemaphore(10)


class NetworkError(OSError):
    """Richiesta fallita senza esporre URL o segreti nei messaggi."""
    def __init__(self, message, *, category=None):
        super().__init__(message)
        self.category = category


class TLSVerificationError(NetworkError):
    """Certificato non valido: nessuna connessione con verifica disabilitata."""


@dataclass
class Response:
    url: str
    status: int
    headers: dict[str, str]
    body: str
    truncated: bool = False
    elapsed_seconds: float | None = None
    redirects: list[dict] = field(default_factory=list)
    tls: dict = field(default_factory=dict)
    request_id: str | None = None


class RateLimiter:
    def __init__(self, maximum: float, jitter: float = 0.0, rng=None):
        self.maximum = maximum
        self.current = maximum
        self.next_at = 0.0
        self.failure_until = 0.0
        self.jitter = jitter
        self.rng = rng or random.Random()
        self.guard = threading.RLock()
        self.wait_guard = threading.Lock()

    def wait(self, cancel=None) -> None:
        # Only waiting callers serialize; feedback never waits behind a sleeping thread.
        with self.wait_guard:
            while True:
                with self.guard:
                    scheduled = self.next_at
                    delay = max(0.0, scheduled - time.monotonic())
                if cancel is not None:
                    if cancel.wait(delay):
                        raise NetworkError("Attività annullata", category="CANCELLED")
                else:
                    time.sleep(delay)
                with self.guard:
                    if self.next_at != scheduled:
                        continue  # Retry-After arrived while waiting.
                    self.next_at = max(scheduled, time.monotonic()) + 1 / self.current
                    return

    def feedback(self, status: int = 0, retry_after: str = "") -> None:
        with self.guard:
            self._feedback(status, retry_after)

    def _feedback(self, status: int = 0, retry_after: str = "") -> None:
        """Rallenta senza raffiche e applica Retry-After anche come data HTTP."""
        if status == 0 and time.monotonic() < self.failure_until:
            # Concurrent failures in one congestion interval share one reduction.
            # No acceleration and no bypass of a pending Retry-After.
            self.next_at = max(self.next_at, time.monotonic() + 1 / self.current)
            return
        if status in (0, 429, 503):
            self.current = max(self.maximum / 32, self.current / 2)
            delay = 1 / self.current
            if status == 0:
                self.failure_until = time.monotonic() + delay
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
            self.next_at = max(self.next_at, time.monotonic() + delay + self.rng.uniform(0, self.jitter))
        else:
            self.current = min(self.maximum, self.current * 1.05)


class HTTPClient:
    def __init__(self, scope: Scope, config: dict, heartbeat: Callable[[], None] | None = None):
        self.scope = scope
        self.config = config
        self.limiter = RateLimiter(config["http"]["requests_per_second"], config["http"].get("retry_jitter_seconds", 0.0))
        self.cache: dict[tuple, tuple[float, Response]] = {}
        self.stats = {"requests": 0, "errors": 0, "timeouts": 0, "cache_hits": 0, "scope_blocked": 0}
        self.heartbeat = heartbeat or (lambda: None)
        self.started = time.monotonic()
        self._dns_thread: threading.Thread | None = None
        self.profile = None
        self.method = "GET"
        self.request_ids = []
        self.host_limiters = {}
        from .workers import RequestBudget
        self.budget = RequestBudget(config["http"]["max_concurrency"], config["http"].get("max_concurrency_per_host", 2))
        self.cancel = None

    def head(self, value: str) -> Response:
        client = self.for_profile(self.profile)
        client.method = "HEAD"
        return client.get(value, cache=False)

    def post(self, value: str, body: bytes, content_type: str, *, authorized_urls: tuple[str, ...]) -> Response:
        """Opt-in esplicito per URL esatto; nessun redirect, cache o retry POST."""
        url = self._checked_url(value)
        if url not in authorized_urls or not isinstance(body, bytes) or len(body) > 65536:
            raise DataError("POST richiede URL autorizzato esatto e corpo entro 64 KiB")
        if content_type not in ("application/json", "application/x-www-form-urlencoded"):
            raise DataError("Tipo corpo POST non supportato")
        client = self.for_profile(self.profile)
        client.method, client.body, client.content_type = "POST", body, content_type
        return client.get(url, cache=False)

    def preflight(self, value: str, origin: str) -> Response:
        """Solo OPTIONS per un GET CORS; nessuna credenziale nella preflight."""
        original_method, profile = self.method, self.profile
        self.method, self.profile = "OPTIONS", None
        try:
            return self.get(value, {"Origin": origin, "Access-Control-Request-Method": "GET"}, cache=False)
        finally:
            self.method, self.profile = original_method, profile

    def for_profile(self, profile):
        client = HTTPClient(self.scope, self.config, self.heartbeat)
        client.profile = profile
        client.limiter = self.limiter
        client.stats = self.stats
        client.request_ids = self.request_ids
        client.host_limiters = self.host_limiters
        client.budget = self.budget
        client.cancel = self.cancel
        return client

    def _resolve(self, host: str, port: int) -> list:
        """Limita l'attesa DNS senza accumulare thread su un resolver bloccato."""
        if self._dns_thread is not None and self._dns_thread.is_alive():
            raise NetworkError("Risoluzione DNS precedente ancora bloccata")
        deadline = time.monotonic() + self.config["http"]["timeout_seconds"]
        dns_gate = _DNS_SLOTS
        while True:
            if self.cancel is not None and self.cancel.is_set():
                raise NetworkError("Attività annullata", category="CANCELLED")
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("Budget DNS esaurito")
            if dns_gate.acquire(timeout=min(.1, remaining)):
                break
        finished = threading.Event()
        result: list = []
        errors: list[OSError] = []
        def resolve() -> None:
            try:
                result.extend(socket.getaddrinfo(host, port, type=socket.SOCK_STREAM))
            except OSError as exc:
                errors.append(exc)
            finally:
                dns_gate.release()
                finished.set()
        self._dns_thread = threading.Thread(target=resolve, daemon=True)
        try:
            self._dns_thread.start()
        except BaseException:
            dns_gate.release()
            raise
        if not finished.wait(max(0, deadline - time.monotonic())):
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
        tls = {}
        try:
            stream.settimeout(min(settings["timeout_seconds"], settings.get("connect_timeout_seconds", settings["timeout_seconds"])))
            stream.connect(target)
            if stream.getpeername()[0] != target[0]:
                raise ScopeViolation("IP effettivo diverso dall'IP validato")
            if parsed.scheme == "https":
                stream = ssl.create_default_context().wrap_socket(stream, server_hostname=host)
                cipher = stream.cipher()
                tls = {"version": stream.version(), "cipher": cipher[0] if cipher else None,
                       "cipher_bits": cipher[2] if cipher else None, "certificate_not_after": stream.getpeercert().get("notAfter"),
                       "certificate_not_before": stream.getpeercert().get("notBefore"),
                       "hostname_verified": True, "certificate_verified": True, "coverage": "SINGLE_NEGOTIATION"}
            connection.sock = stream
            stream.settimeout(min(settings["timeout_seconds"], settings.get("read_timeout_seconds", settings["timeout_seconds"])))
            path = parsed.path or "/"
            if parsed.query:
                path += "?" + parsed.query
            request_headers = {"User-Agent": "XITool/5.2 (authorized audit)", "Accept-Encoding": "gzip, deflate", **headers}
            if self.method == "POST":
                request_headers["Content-Type"] = self.content_type
            connection.request(self.method, path, body=getattr(self, "body", None), headers=request_headers)
            response = connection.getresponse()
            raw_headers: dict[str, str] = {}
            for key, value in response.getheaders():
                key = key.lower()
                raw_headers[key] = raw_headers.get(key, "") + ("\n" if key in raw_headers else "") + value
            encoding = raw_headers.get("content-encoding", "identity").strip().lower()
            if encoding not in ("identity", "gzip", "x-gzip", "deflate"):
                raise NetworkError("Content-Encoding non supportato", category="PARSE_ERROR")
            if "content-length" in raw_headers and "transfer-encoding" in raw_headers:
                raise NetworkError("Framing HTTP ambiguo", category="PARSE_ERROR")
            declared = raw_headers.get("content-length")
            if declared is not None and not re.fullmatch(r"[0-9]+", declared):
                raise NetworkError("Content-Length invalido", category="PARSE_ERROR")
            if raw_headers.get("transfer-encoding", "").lower() not in ("", "chunked"):
                raise NetworkError("Transfer-Encoding non supportato", category="PARSE_ERROR")
            if raw_headers.get("content-type", "").partition(";")[0].strip().lower() in {
                    "application/zip", "application/gzip", "application/x-tar", "application/x-7z-compressed",
                    "application/vnd.rar", "application/octet-stream"}:
                raise DataError("Contenuto archivio/binario escluso prima della lettura del corpo")
            limit = settings["max_body_bytes"]
            decoder = zlib.decompressobj(31 if encoding in ("gzip", "x-gzip") else 15) if encoding != "identity" else None
            # Il timeout per socket non limita uno stream lento: applica anche una deadline.
            chunks: list[bytes] = []
            length = 0
            wire_length = 0
            while length <= limit and wire_length <= limit:
                if response.length == 0:
                    break  # Content-Length esaurito: il peer può avere già chiuso il socket.
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError("Deadline risposta superata")
                stream.settimeout(min(remaining, settings.get("read_timeout_seconds", settings["timeout_seconds"])))
                block = response.read1(min(65536, limit + 1 - length))
                if not block:
                    break
                wire_length += len(block)
                try:
                    decoded = decoder.decompress(block, limit + 1 - length) if decoder else block
                except zlib.error as exc:
                    raise NetworkError("Corpo compresso invalido", category="PARSE_ERROR") from exc
                chunks.append(decoded)
                length += len(decoded)
                self.heartbeat()
            truncated = length > limit or wire_length > limit
            if decoder and self.method != "HEAD" and not truncated and (not decoder.eof or decoder.unused_data):
                raise NetworkError("Corpo compresso incompleto o concatenato", category="PARSE_ERROR")
            if declared is not None and self.method != "HEAD" and response.status not in (204, 304) and not truncated and wire_length != int(declared):
                raise NetworkError("Corpo HTTP incompleto", category="PARSE_ERROR")
            raw = b"".join(chunks)
            return Response(url, response.status, raw_headers, raw[:limit].decode("utf-8", errors="replace"), truncated,
                            round(time.monotonic() - started, 4), tls=tls)
        except (OSError, http.client.HTTPException) as exc:
            if time.monotonic() >= deadline:
                raise TimeoutError("Deadline richiesta superata") from exc
            raise
        finally:
            watchdog.cancel()
            connection.close()
            stream.close()

    def _checked_url(self, value: str) -> str:
        try:
            url = self.scope.url(value, self.config["http"]["allowed_ports"])
            parsed = urlsplit(url)
            if blocked_request(url):
                raise ScopeViolation("Redirect o URL sensibile/potenzialmente mutativo bloccato")
            return url
        except ScopeViolation:
            self.stats["scope_blocked"] += 1
            logging.getLogger("xitool").warning('{"event":"scope_blocked","stage":"url"}')
            raise

    def get(self, value: str, headers: dict[str, str] | None = None, cache: bool = True) -> Response:
        if self.method not in ("GET", "HEAD", "OPTIONS", "POST"):
            raise DataError("Metodo HTTP non supportato dal motore conservativo")
        cache = cache and self.method == "GET"
        headers = headers or {}
        if any(not isinstance(key, str) or (key.lower() != "origin" and not (self.method == "OPTIONS" and key.lower() == "access-control-request-method" and val == "GET"))
               or not isinstance(val, str) or "\r" in val or "\n" in val for key, val in headers.items()):
            raise DataError("Sono ammessi soltanto header Origin di test")
        url = self._checked_url(value)
        if self.profile:
            cache = False
            self.profile.headers(url)  # Verifica profilo e scadenza prima del trasporto.
        key = (self.scope.digest, self.method, url, tuple(sorted(headers.items())))
        cached = self.cache.get(key)
        if cache and self.config["cache"]["enabled"] and cached and time.monotonic() - cached[0] < self.config["cache"]["ttl_seconds"]:
            self._checked_url(cached[1].url)
            self.stats["cache_hits"] += 1
            return cached[1]
        visited: set[str] = set()
        redirects = []
        for _ in range(self.config["http"]["max_redirects"] + 1):
            if url in visited:
                raise NetworkError("Ciclo di redirect")
            visited.add(url)
            for attempt in range((0 if self.method == "POST" else self.config["http"]["max_retries"]) + 1):
                self.heartbeat()
                host = urlsplit(url).hostname
                try:
                    with self.budget.slot(host, self.cancel):
                        with self.budget.guard:
                            if host not in self.host_limiters:
                                self.host_limiters[host] = RateLimiter(self.config["http"]["requests_per_second"])
                            host_limiter = self.host_limiters[host]
                        if self.cancel is None:
                            host_limiter.wait()
                            self.limiter.wait()
                        else:
                            host_limiter.wait(self.cancel)
                            self.limiter.wait(self.cancel)
                        self.stats["requests"] += 1
                        private_headers = self.profile.headers(url) if self.profile else {}
                        identity = uuid.uuid4().hex
                        result = self._request(url, {**headers, **private_headers, "X-XITool-Request-ID": identity})
                        result.request_id = identity
                        self.request_ids.append(identity)
                        del self.request_ids[:-256]
                except ScopeViolation:
                    self.stats["scope_blocked"] += 1
                    logging.getLogger("xitool").warning('{"event":"scope_blocked","stage":"destination"}')
                    raise
                except (OSError, http.client.HTTPException) as exc:
                    self.stats["errors"] += 1
                    if isinstance(exc, (TimeoutError, socket.timeout)):
                        self.stats["timeouts"] += 1
                    if isinstance(exc, ssl.SSLCertVerificationError):
                        raise TLSVerificationError("Verifica certificato TLS fallita") from exc
                    if self.cancel is not None and self.cancel.is_set():
                        raise NetworkError("Attività annullata", category="CANCELLED") from exc
                    if getattr(exc, "category", None) in ("PARSE_ERROR", "CANCELLED"):
                        raise
                    self.limiter.feedback()
                    if self.method == "POST" or attempt == self.config["http"]["max_retries"]:
                        raise NetworkError(f"Richiesta fallita ({type(exc).__name__})") from exc
                    continue
                self.limiter.feedback(result.status, result.headers.get("retry-after", ""))
                if self.method == "POST" or result.status not in (429, 503) or attempt == self.config["http"]["max_retries"]:
                    break
            if result.status in (301, 302, 303, 307, 308) and result.headers.get("location"):
                if self.method == "POST":
                    raise NetworkError("Redirect POST non seguito: nuova autorizzazione richiesta")
                destination = self._checked_url(urljoin(url, result.headers["location"]))
                if self.profile:
                    self.profile.headers(destination)  # Nessun trasferimento di cookie a un'altra origine.
                redirects.append({"url": url, "status": result.status, "destination": destination})
                url = destination
                continue
            from .errors import status_category
            result.error_category = status_category(result.status)
            result.redirects = redirects
            if cache and self.config["cache"]["enabled"] and result.status == 200 and "set-cookie" not in result.headers and not any(x in result.headers.get("cache-control", "").lower() for x in ("no-store", "private")):
                if len(self.cache) >= 64:
                    self.cache.pop(next(iter(self.cache)))
                self.cache[key] = (time.monotonic(), result)
            return result
        raise NetworkError("Limite redirect raggiunto")
