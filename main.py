#!/usr/bin/env python3
"""Avvio della CLI di XITool."""
from pathlib import Path
import sys

try:
    from xitool.cli import main
except ModuleNotFoundError as exc:
    print(f"Dipendenza mancante: {exc.name}. Eseguire bash install.sh oppure pip install -r requirements.txt.")
    sys.exit(2)

if __name__ == "__main__":
    main(Path(__file__).resolve().parent)
