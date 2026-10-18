"""Tassonomia stabile: classi e status, senza messaggi remoti o credenziali."""
import json
import socket
import ssl

LABELS = {
    "NETWORK_TIMEOUT": "Tempo di attesa esaurito", "CONNECTION_ERROR": "Connessione non riuscita",
    "DNS_ERROR": "Risoluzione DNS non riuscita", "TLS_ERROR": "Verifica TLS non riuscita",
    "HTTP_RATE_LIMIT": "Limite richieste del server", "HTTP_SERVER_ERROR": "Errore del server",
    "PARSE_ERROR": "Risposta non interpretabile", "SCOPE_DENIED": "Destinazione fuori scope",
    "AUTH_REQUIRED": "Autorizzazione richiesta o negata", "DEPENDENCY_MISSING": "Dipendenza mancante",
    "CANCELLED": "Attività annullata", "INTERNAL_ERROR": "Errore interno",
}


def status_category(status):
    return "HTTP_RATE_LIMIT" if status == 429 else "HTTP_SERVER_ERROR" if status >= 500 else "AUTH_REQUIRED" if status in (401, 403) else None


def classify(exc):
    from .scope import ScopeViolation
    chain, seen = [], set()
    while exc is not None and id(exc) not in seen:
        seen.add(id(exc))
        chain.append(exc)
        exc = exc.__cause__
    for error in chain:
        if getattr(error, "category", None) in LABELS:
            return error.category
    for error in reversed(chain):
        if isinstance(error, ScopeViolation):
            return "SCOPE_DENIED"
        if isinstance(error, ssl.SSLError):
            return "TLS_ERROR"
        if isinstance(error, socket.gaierror):
            return "DNS_ERROR"
        if isinstance(error, TimeoutError):
            return "NETWORK_TIMEOUT"
        if isinstance(error, ImportError):
            return "DEPENDENCY_MISSING"
        if isinstance(error, (json.JSONDecodeError, UnicodeError)):
            return "PARSE_ERROR"
    return "CONNECTION_ERROR" if any(isinstance(error, OSError) for error in chain) else "INTERNAL_ERROR"
