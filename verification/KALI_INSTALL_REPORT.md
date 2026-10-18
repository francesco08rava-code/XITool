# Installazione Kali — non verificata nativamente

VirtualBox non accessibile dalla sessione (E_ACCESSDENIED); Bash Windows non avvia MSYS (0xC0000022). Nessuna modifica alla VM. I test installer POSIX restano saltati. Verificati invece build/editable, dipendenze e console script Windows in venv pulito, senza PYTHONPATH, da directory diversa; exit code 0/2, guida e menu: V52_PACKAGE_LAUNCHER.json.

Su Kali in cartella scrivibile: bash verify_kali.sh --browser --javascript. Pip opera solo nel venv; entry point Python via pyproject, collegamento utente ~/.local/bin/XITool, nessun root o Python globale. Il collegamento preesistente è preservato e il conflitto segnalato; type -a XITool va eseguito anche nella propria shell, perché lo script non vede gli alias del processo padre. Nessuna modifica a .zshrc. unalias XITool è un'eventuale correzione manuale della sessione.

Lo script controlla OS/Python/sintassi, installazione, venv/dipendenze, launcher --help/--version da altra directory, Zsh se presente, unit/integration/browser/AST, E2E, SIGINT locale e benchmark; riepilogo con fase/exit code e hash sorgenti. Senza browser l'E2E completo non viene eseguito e questo è registrato. L'installazione editable richiede che il checkout resti disponibile; dopo spostamento ricreare/reinstallare il venv. Script preparato non equivale a compatibilità Kali dimostrata.
