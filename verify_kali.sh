#!/usr/bin/env bash
set -euo pipefail
project_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
cd -- "$project_dir"
if [[ ! -r /etc/os-release ]] || ! grep -Eq '^ID="?kali"?$' /etc/os-release; then
  echo 'Ambiente diverso da Kali: nessuna compatibilità nativa Kali dichiarata.' >&2
  exit 2
fi
mkdir -p verification
phase=environment
finish() {
  result=$?
  trap - EXIT
  python3 - "$result" "$phase" "$browser" "$javascript" "$e2e" <<'PY'
import hashlib, json, platform, sys
from datetime import datetime, timezone
from pathlib import Path
status, phase = int(sys.argv[1]), sys.argv[2]
report = {
    'timestamp': datetime.now(timezone.utc).isoformat(), 'exit_code': status,
    'last_phase': phase, 'success': status == 0, 'python': platform.python_version(),
    'platform': platform.platform(), 'browser_requested': sys.argv[3] == '1',
    'javascript_requested': sys.argv[4] == '1', 'e2e_attempted': sys.argv[5] == '1',
    'venv_present': Path('.venv/bin/python').is_file(), 'launcher_present': Path('.venv/bin/XITool').is_file(),
    'limitations': 'Inspect skips and parent-shell aliases; success is limited to this machine and configuration.'
}
source_hashes = {str(path): hashlib.sha256(path.read_bytes()).hexdigest() for path in sorted(Path('xitool').glob('*.py'))}
report['source_sha256'] = hashlib.sha256(json.dumps(source_hashes, sort_keys=True).encode()).hexdigest()
Path('verification/KALI_SUMMARY.json').write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
Path('verification/KALI_INSTALL_REPORT.md').write_text('# Installazione Kali\n\n' + '\n'.join(f'- {key}: {value}' for key, value in report.items()) + '\n\nLog completo: KALI_TESTS.txt. Gli alias della shell chiamante richiedono type -a XITool nella sessione utente.\n', encoding='utf-8')
PY
  exit "$result"
}
trap finish EXIT
browser=0
javascript=0
e2e=0
for option in "$@"; do
  case "$option" in
    --browser) browser=1 ;;
    --javascript) javascript=1 ;;
    *) echo "Opzione sconosciuta: $option" >&2; exit 2 ;;
  esac
done
{
  date -u
  uname -a
  python3 --version
} > verification/KALI_ENVIRONMENT.txt
phase=syntax
bash -n install.sh verify_kali.sh
phase=install_and_baseline
bash install.sh 2>&1 | tee verification/KALI_INSTALL_AND_BASE_TESTS.txt
phase=launcher
probe_dir="$(mktemp -d)"
(
  cd -- "$probe_dir"
  "$project_dir/.venv/bin/XITool" --version
  "$project_dir/.venv/bin/XITool" --help
  if command -v zsh >/dev/null 2>&1; then
    zsh -fc 'exec "$1" --version' -- "$project_dir/.venv/bin/XITool"
  fi
) | tee verification/KALI_LAUNCHER.txt
rmdir -- "$probe_dir"
if [[ "$javascript" == 1 ]]; then
  phase=javascript_dependencies
  .venv/bin/python -m pip install -r requirements-javascript.txt
fi
if [[ "$browser" == 1 ]]; then
  phase=browser_dependencies
  .venv/bin/python -m pip install -r requirements-browser.txt
  .venv/bin/python -m playwright install chromium
fi
phase=full_tests
XITOOL_BROWSER_TESTS="$browser" .venv/bin/python -m unittest discover -s tests -v 2>&1 | tee verification/KALI_TESTS.txt
cp -- verification/KALI_TESTS.txt verification/KALI_ALL_TESTS.txt
phase=dependencies
.venv/bin/python -m pip check
if [[ "$browser" == 1 ]]; then
  phase=e2e
  e2e=1
  XITOOL_BROWSER_TESTS=1 .venv/bin/python benchmarks/validate_integrated.py 2>&1 | tee verification/KALI_E2E.txt
fi
phase=interrupt
.venv/bin/python benchmarks/verify_interrupt.py "$project_dir/.venv/bin/XITool" 2>&1 | tee verification/KALI_INTERRUPT.txt
phase=benchmark
.venv/bin/python benchmarks/benchmark_local.py --workers 5 --output verification/KALI_BENCHMARK.json
phase=completed
echo 'Log salvati in verification/. Verificare eventuali skip e gli esiti di ogni comando.'
