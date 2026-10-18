# Audit iniziale V5 — 17 ottobre 2026

Checkout effettivo: 4.0.0a1, HEAD c7bb4706910037b994800fc1104594e38aa94e61, con modifiche V3/V4 non committate. README, report V4, installer, entry point e componenti esistenti analizzati prima delle modifiche applicative.

Baseline rieseguita: **250 test, 247 superati, 3 saltati, zero errori, 57,994 s**, inclusi 9 test Chrome headless. Skip: Bash syntax, installazione/launcher POSIX e creazione symlink non consentita. Log originale conservato in verification/V5_BASELINE.txt.

Entry point: main.py → cli.main; install.sh crea .venv/bin/XITool e conserva launcher globali preesistenti; callback_receiver ha un entry point separato per il sensore dell'operatore. Il menu principale resta 1/2/3/0.

Architettura: storage/Projects e Scope centralizzano progetti e autorizzazioni; HTTPClient fissa l'IP validato e applica TLS/limiti/cache anonima; DNSResolver A/AAAA/CNAME con TTL e distinzione dei guasti; passive.py consulta due provider CT; Engine gestisce task/checkpoint/export per dominio; scanners/controlled/browser_lab/callback_checks producono osservazioni o prove circoscritte; SmartPlan conserva le dipendenze e la ripresa. Tutti i 13 moduli logici sono presenti; crawler integrato in Sub Finding.

Operativo: CT tracciato, DNS/probe, HTML/JS/DOM opzionale, GET query, form non inviati, JSON osservato, casi controllati XSS/SQL/account/file/callback/logout/CORS, report e checkpoint isolati. Limiti specifici dei 13 moduli documentati nel report V4: nessuna copertura universale o stato ottimizzato dedotto dal numero di test.

Problemi riproducibili dall'ispezione e da coprire con nuove regressioni:

- max_concurrency viene accettato ma Engine esegue un task per volta.
- RateLimiter e client mutable non sono thread-safe: non basta aggiungere thread al ciclo.
- Scan Diff non esporta il formato richiesto e considera variabili transitorie nei confronti finding.
- Non esiste un punteggio di confidenza motivato o una priorità di revisione distinta dalla severità.
- Crawler non ha proiezione autonoma e OpenAPI non considera servers/basePath.
- Smart non registra la versione del motore per verificare la ripresa.
- Report aggregati e formati TXT sono limitati.

Rischi: race fra checkpoint e worker; credenziali/client condivisi; duplicazione di richieste dopo un'interruzione; backpressure insufficiente; falsa equivalenza fra coda completata e verifica completa; possibilità di falsi positivi delle euristiche. I casi con effetti sullo stato (logout, POST fixture) devono rimanere seriali.

Piano: preservare il trasporto validato; introdurre worker bounded con client isolati e rate condiviso sincronizzato; aggiornare ricognizione/crawler e output compatibili; aggiungere classificazione spiegabile a tutti i moduli, diff conservativo, report e versionamento Smart; test per fase, benchmark HTTP controllato V4/V5 e verifica finale. Async nativo valutato: thread pool bounded preferito per conservare il client sincrono con pinning IP e gli scanner esistenti. Nessuna riscrittura del trasporto con librerie nuove.

Kali: da verificare solo se accessibile; l'ultimo tentativo VirtualBox V4 aveva restituito E_ACCESSDENIED. Non si dichiarerà una prova nativa sulla base dei test Windows.
