#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")"
command -v python3 >/dev/null 2>&1 || { echo 'Python 3.10+ richiesto.' >&2; exit 1; }
python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)' || { echo 'Python 3.10+ richiesto.' >&2; exit 1; }
[[ -f requirements.txt && -f main.py ]] || { echo 'Distribuzione incompleta.' >&2; exit 1; }
python3 -m venv .venv || { echo 'Creazione ambiente fallita; verificare che python3-venv sia installato.' >&2; exit 1; }
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python -m unittest discover -s tests -v
echo 'Installazione completata. Avvio: .venv/bin/python main.py'
