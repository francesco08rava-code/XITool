#!/usr/bin/env bash
set -euo pipefail
project_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
cd -- "$project_dir"
command -v python3 >/dev/null 2>&1 || { echo 'Python 3.10+ richiesto.' >&2; exit 1; }
python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)' || { echo 'Python 3.10+ richiesto.' >&2; exit 1; }
[[ -f requirements.txt && -f main.py ]] || { echo 'Distribuzione incompleta.' >&2; exit 1; }
[[ -w "$project_dir" ]] || { echo 'Cartella in sola lettura: clonare o copiare XITool nella home di Kali.' >&2; exit 1; }
if [[ -d .venv/Scripts && ! -x .venv/bin/python ]]; then
  echo 'La .venv esistente è per Windows. Usare un ambiente virtuale creato su Kali.' >&2
  exit 1
fi
python3 -m venv .venv || { echo 'Creazione ambiente fallita; verificare che python3-venv sia installato.' >&2; exit 1; }
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python -m unittest discover -s tests -v
# Il launcher segue la propria posizione, anche quando invocato tramite symlink.
cat > .venv/bin/XITool <<'LAUNCHER'
#!/usr/bin/env bash
set -euo pipefail
launcher_dir="$(dirname -- "$(readlink -f -- "${BASH_SOURCE[0]}")")"
exec "$launcher_dir/python" "$launcher_dir/../../main.py" "$@"
LAUNCHER
chmod 755 .venv/bin/XITool
mkdir -p -- "$HOME/.local/bin"
if [[ ! -e "$HOME/.local/bin/XITool" && ! -L "$HOME/.local/bin/XITool" ]]; then
  ln -s -- "$project_dir/.venv/bin/XITool" "$HOME/.local/bin/XITool"
else
  echo 'Il comando XITool esistente viene conservato. Launcher di questa copia: .venv/bin/XITool'
fi
echo 'Installazione completata. Avvio: .venv/bin/python main.py'
if [[ ":$PATH:" != *":$HOME/.local/bin:"* ]]; then
  echo 'Per usare il comando nel terminale corrente: export PATH="$HOME/.local/bin:$PATH"'
fi
