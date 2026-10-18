"""POSIX SIGINT at the CLI prompt, then clean exit; no scanning or existing data."""
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import threading

if os.name != "posix":
    raise SystemExit("Test SIGINT nativo richiede POSIX")
launcher = str(Path(sys.argv[1]).resolve())
with tempfile.TemporaryDirectory() as directory:
    process = subprocess.Popen([launcher, "--data-dir", str(Path(directory) / "targets")], cwd=directory,
                               stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    ready = threading.Event()
    cancelled = threading.Event()
    received = []
    def reader():
        while True:
            char = process.stdout.read(1)
            if not char:
                break
            received.append(char)
            if "Scelta:" in "".join(received[-40:]):
                ready.set()
            if "Operazione annullata" in "".join(received[-80:]):
                cancelled.set()
    thread = threading.Thread(target=reader, daemon=True)
    thread.start()
    try:
        if not ready.wait(15):
            raise RuntimeError("Launcher non pronto entro 15 secondi")
        process.send_signal(signal.SIGINT)
        if not cancelled.wait(5):
            raise RuntimeError("SIGINT non ricevuto dalla CLI")
        process.stdin.write("0\n")
        process.stdin.flush()
        code = process.wait(timeout=10)
        thread.join(2)
        if code != 0 or "Operazione annullata" not in "".join(received):
            raise RuntimeError("SIGINT/uscita non confermati")
        print("SIGINT e uscita confermati; nessuna scansione eseguita")
    finally:
        if process.poll() is None:
            process.kill()
            process.wait()
