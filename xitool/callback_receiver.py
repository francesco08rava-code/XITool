"""Sensore opzionale dietro un endpoint HTTPS pubblico controllato dall'operatore."""
import argparse
import json
import os
from pathlib import Path
import re
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

from .storage import DataError, confined, utcnow


def handler(events_file: Path):
    path = confined(events_file.parent, events_file)
    path.parent.mkdir(parents=True, exist_ok=True)
    lock = threading.Lock()
    class Receiver(BaseHTTPRequestHandler):
        def do_GET(self):
            match = re.fullmatch(r"/xitool-callback/([0-9a-f]{32})", self.path.split("?", 1)[0])
            if not match:
                self.send_error(404)
                return
            try:
                with lock:
                    if path.exists() and path.stat().st_size >= 8 * 1024 * 1024:
                        self.send_error(503)
                        return
                    descriptor = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
                    with os.fdopen(descriptor, "a", encoding="utf-8") as stream:
                        stream.write(json.dumps({"id": match[1], "received_at": utcnow(), "source_ip": self.client_address[0]}) + "\n")
                        stream.flush()
                        os.fsync(stream.fileno())
                self.send_response(204)
                self.end_headers()
            except OSError:
                self.send_error(503)
        def log_message(self, *args):
            pass  # Non registra URL, nonce o header in console.
    return Receiver


def main():
    parser = argparse.ArgumentParser(description="Ricevitore callback XITool: esporre solo tramite HTTPS dell'operatore")
    parser.add_argument("--events-file", type=Path, required=True)
    parser.add_argument("--bind", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8081)
    args = parser.parse_args()
    path = args.events_file.expanduser().absolute()
    server = ThreadingHTTPServer((args.bind, args.port), handler(path))
    try:
        print("Ricevitore avviato. XITool non configura tunnel o servizi pubblici automaticamente.")
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
