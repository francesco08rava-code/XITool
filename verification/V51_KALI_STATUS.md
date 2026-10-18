# Verifica Kali — 18 ottobre 2026

Non verificato nativamente. Tentativi read-only: VBoxManage list runningvms → E_ACCESSDENIED / oggetto non pronto; WSL non installato. Bash di Git fallisce prima di eseguire -n per NtCreateDirectoryObject, codice 0xC0000022. Nessun cambiamento a impostazioni VirtualBox/rete.

verify_kali.sh ora registra fase corrente/exit code e riepilogo JSON, verifica sintassi in ambiente Bash effettivo, conserva log, verifica launcher da altra cartella, supporta dipendenze browser e parser JS opzionali, esegue suite completa e benchmark. La sintassi Bash e i segnali POSIX restano da confermare in ambiente nativo.

Nella VM, dalla copia aggiornata e scrivibile del progetto:

```bash
bash verify_kali.sh --browser --javascript
cat verification/KALI_SUMMARY.json
.venv/bin/XITool --version
```

Non usare una cartella condivisa in sola lettura per creare .venv. Lo script si ferma al primo errore e il riepilogo indica la fase. Un esito positivo riguarda quella VM e configurazione; controllare comunque skip e log. I browser/AST sono facoltativi nell'uso normale; per verificare tutte le relative fixture vanno installati e abilitati.
