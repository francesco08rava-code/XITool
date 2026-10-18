# Audit V5.1 — 18 ottobre 2026

Base: 5.0.0a1, commit c7bb4706910037b994800fc1104594e38aa94e61; checkout contiene modifiche V3/V4/V5 non committate, conservate. Nessun commit/push.

Baseline ripetuta prima delle modifiche: 281 test, 278 superati, 3 saltati, zero fallimenti/errori, 81.449 secondi. Browser Chrome abilitato; log V51_BASELINE.txt. Skip: due controlli installer Bash/POSIX e symlink Windows. Python 3.12, Windows; Kali non verificato.

Letti report V3/V4/V5, configurazione e punti di integrazione: CLI → Projects/Scope → Engine → HTTP/DNS/provider/scanner → checkpoint → proiezioni/report/diff. SmartPlan orchestra Engine; TaskPool e domain_workers condividono budget e rate. Trasporto mantiene TLS verificato, pinning e scope a ogni redirect. Limiti correnti: 5 worker, 2 per host, 1 dominio, 2 richieste/s, 1000 task, 600 secondi, risposte 1 MiB.

Bug confermato: deduplicate_inputs ignora location. Inventario OpenAPI perde metodi/parametri/template. DNS non conserva catena CNAME dalle risposte. Provider non distinguono pagine richieste/completate. Diff non include DNS/API. Nessun componente cleanup. Permissions-Policy assente. Catalogo segreti senza versione. JS attuale regex, Smart sequenziale, CORS browser semplice e SQL fixture GET: limiti reali, non capacità complete.

Backup V5: work/v5-source-snapshot nell'area di lavoro. I dati targets non sono copiati né modificati. Suite e benchmark vengono eseguiti separatamente. Tutti i test di rete di questo intervento usano loopback; nessun target pubblico viene scansionato.

Piano: B integrità/metadati comuni; C input e API; D controlli contestuali/canary senza ampliare scansioni attive; E piano esplicito; F confronto identico; G diff/cleanup; H regressione/lab; I script Kali; J rapporto con limiti. Nessuna equivalenza tra test superati e completezza universale.
