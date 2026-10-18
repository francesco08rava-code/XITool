# Laboratorio integrato V5.2

Esito finale: success=True, 71 casi, tutti i 13 componenti rappresentati. Ripetizione: XITOOL_BROWSER_TESTS=1 python benchmarks/validate_integrated.py (browser installato; Chrome opzionale tramite XITOOL_BROWSER_CHANNEL=chrome). Nessun servizio esterno richiesto.

Riusa ControlledServerTests per account/SQLite/canary, TLSTests per handshake, browser e DNS del trasporto reale. CT è una fixture deterministica ai soli endpoint fissi; DNS è UDP reale, HTTP/TLS/SQLite/file e browser sono reali. Nessun mock di un risultato VERIFIED. Il mapping DNS di sistema è sostituito solo per i nomi sintetici .lab.test, dopo le risposte UDP del laboratorio. Callback locale usa un opener senza proxy e rifiuta destinazioni diverse dalla propria origine.

Pipeline: progetto/scope → CT → DNS → probing dei soli host risolti derivati dalla fonte → HTML/JS/API/form → inventario v2 → task ricavati dagli URL/input reali → piano Smart → interruzione con lavoro residuo → ripresa → scanner con manifest/account espliciti → JSON/MD/TXT → seconda run reale e diff. Include SPA fetch/DOM, metodi OpenAPI GET/POST stesso URL, endpoint statici non messi in coda, TLS valido/scaduto/hostname errato, callback correlati/duplicati/nonce errato/log assente, errore connessione e timeout.

Isolamento: due progetti, nessun profilo/checkpoint nel secondo; domini .lab.test e 127.0.0.1 separati nei checkpoint; SHA dei report precedenti controllati anche dopo errori; ripresa senza finding duplicati; dipendenza con errore blocca il passo successivo. La conferma della CLI è verificata anche dai test di regressione esistenti; il runner programmatico opera su fixture esplicitamente possedute, non simula un consenso per bersagli esterni.

Una sola applicazione HTTP integrata più origini/servizi laterali DNS/TLS controllati: non è una simulazione di un intero ambiente aziendale. Il browser CORS esercita GET semplice; OPTIONS è verificato sul server reale separatamente, non si dichiara una matrice completa di preflight custom nel browser.

| Componente | Casi | Esiti osservati |
|---|---:|---|
| access | 5 | {'VERIFIED': 1, 'NO_ISSUES_OBSERVED': 1, 'PARTIAL': 2, 'ERROR': 1} |
| authentication | 4 | {'VERIFIED': 1, 'NO_ISSUES_OBSERVED': 1, 'ERROR': 1, 'PARTIAL': 1} |
| cors | 6 | {'VERIFIED': 1, 'OBSERVED': 3, 'NO_ISSUES_OBSERVED': 1, 'ERROR': 1} |
| crawler | 6 | {'OBSERVED': 3, 'COMPLETED': 2, 'ERROR': 1} |
| idor | 5 | {'VERIFIED': 1, 'NO_ISSUES_OBSERVED': 1, 'PARTIAL': 2, 'ERROR': 1} |
| misconfiguration | 7 | {'OBSERVED': 5, 'ERROR': 1, 'TIMEOUT': 1} |
| sensitive | 3 | {'MANUAL_REVIEW': 1, 'OBSERVED': 1, 'ERROR': 1} |
| smart | 3 | {'COMPLETED': 1, 'OBSERVED': 1, 'ERROR': 1} |
| sqli | 8 | {'POTENTIAL': 3, 'PARTIAL': 4, 'ERROR': 1} |
| ssrf | 6 | {'VERIFIED': 2, 'PARTIAL': 2, 'UNSUPPORTED': 1, 'ERROR': 1} |
| subfinding | 6 | {'ERROR': 1, 'OBSERVED': 5} |
| traversal | 6 | {'VERIFIED': 2, 'NO_ISSUES_OBSERVED': 1, 'PARTIAL': 2, 'ERROR': 1} |
| xss | 6 | {'VERIFIED': 2, 'NO_ISSUES_OBSERVED': 3, 'ERROR': 1} |
