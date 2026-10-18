# XITool 5.1.0a1 — rapporto finale

18 ottobre 2026. Modifiche direttamente in `C:\Users\Pc\Desktop\XITool`. Base Git `c7bb4706910037b994800fc1104594e38aa94e61`, con modifiche V3/V4/V5 preesistenti conservate. Nessun commit, stage o push. Il manifest V51_SOURCE_MANIFEST.json identifica il codice effettivo non committato; il commit base da solo non lo identifica.

## Esito e classificazione

**Sperimentale (alpha), non release candidate o stabile.** Miglioramenti operativi verificati, ma non completamento integrale di ogni scanner/requisito V5.1. Tutti i 13 componenti sono esaminati nella matrice sotto; nessuna etichetta OTTIMIZZATO/COMPLETO è assegnata per il solo aumento dei test. Limiti residui e peggioramenti sono espliciti.

Baseline reale: 281 test, 278 superati, 3 saltati, nessun fallimento, 81.449 s. Finale: **303 test, 300 superati, 0 fallimenti/errori, 3 saltati, 266.685 s**. Compresi 12 test browser Chrome reali (9 precedenti + 3 DOM), 3 handshake TLS, 4 test DNS UDP reali. Suite controlli V5: 27 superati dopo il cambio worker. Nessun test precedente rimosso.

Ambiente: Windows, Python 3.12.14; dipendenze {'PyYAML': '6.0.3', 'dnspython': '2.9.0', 'playwright': '1.64.0', 'tree-sitter': '0.26.0', 'tree-sitter-javascript': '0.25.0'}. Parser AST opzionale, nessuna nuova dipendenza obbligatoria per il funzionamento base. Kali nativo non verificato. Log: V51_BASELINE.txt, V51_TESTS.txt, V51_WORKER_CHECKS.txt, V51_LOCAL_VALIDATION.txt.

## Modifiche comuni e compatibilità

- Input v2: identità progetto/dominio/URL/metodo/posizione/nome, provenienza aggregata, first/last seen, reachability esplicita. Query, body, JSON, path e parametri dichiarati sono distinti. Default/esempi/valori non vengono salvati. Il bug che fondeva posizioni diverse è corretto.
- OpenAPI conserva metodi, server/basePath, template e parametri path/query/header/cookie/body/JSON senza eseguire le operazioni dichiarate. Gli input documentali non vengono automaticamente convertiti in test attivi.
- Parser Tree-sitter opzionale per chiamate letterali e template statici fetch/axios/XHR; commenti e stringhe che contengono codice non sono endpoint. Codice scaricato mai eseguito. Fallback letterale se dipendenze assenti. Risoluzione generale di costanti/alias non implementata.
- Provider CT: pagine richieste/completate, provenance, disponibilità osservata e successo vuoto separato da errore. Nessun nuovo provider contattato. DNS conserva catene CNAME ricevute senza nuove query fuori scope; host inventory aggiunge last_seen, seed e dati DNS.
- Worker: finestra bounded riempita progressivamente, niente barriera fra gruppi; FIFO e commit soltanto dal coordinatore conservati. Cancellazione mantiene task non committati per la ripresa. Feedback rate non resta bloccato dietro un worker addormentato; Retry-After può aggiornare un'attesa già iniziata.
- Smart: step_id, dipendenze esplicite dalla ricognizione dello stesso dominio, budget, conteggi input/risultati/errori. Una dipendenza incompleta blocca l'analisi relativa. Configurazione, scope, identità, integrità e versione continuano a essere validati. Esecuzione dei passi ancora ordinata, non DAG concorrente arbitrario.
- Diff aggiunge DNS, raggiungibilità e dichiarazioni API; guasti/incompletezza restano mancata osservazione, mai prova di rimozione o risoluzione. JSON aggiuntivi DNS/API insieme ai formati precedenti.
- Menu principale invariato; APRI PROGETTI in sola lettura. Versione 5.1.0a1 e User-Agent 5.1. I dati precedenti restano consultabili; cambio versione impedisce ripresa incompatibile e richiede nuova run. Nessuna migrazione o cancellazione distruttiva di dati targets.

## Matrice dei 13 componenti

| Componente | V5 → V5.1 / evidenza positiva e negativa | Limiti residui e motivazione |
|---|---|---|
| Sub Finding | Due provider → metadati richieste/pagine/vuoto/errore più precisi, CNAME ricevuti e last_seen; test provider, DNS UDP, wildcard e errori preservati. | Restano due provider e paginazione limitata; nessun nuovo test esterno positivo. Nuove API valutate richiedono chiavi/consenso e non sono dichiarate operative. Catena osservata non è un audit DNS autoritativo completo. |
| Crawler/Input Discovery | Regex e identità senza location → AST opzionale, identità v2, OpenAPI metodi/parametri/template; test commenti, JSON/path, privacy, query/body distinti; pipeline su due host. | Costanti/alias JS e scope semantico generale mancanti; niente interazioni arbitrarie, shadow DOM completo o storico remoto. HTML/SPA/robots/sitemap della V5 preservati. |
| XSS | GET e form/JSON browser → aggiunta prova DOM da location.hash su fixture: vulnerabile esegue nonce due volte, textContent e CSP non eseguono. | Nessuna analisi completa taint/source-sink di SPA generiche. Sink non strumentato dichiarato tale; solo prova di esecuzione dal frammento sul laboratorio. |
| SQL Injection | Fixture GET → anche form/JSON autorizzati su SQLite read-only; due vulnerabili e due parametrizzati reali. | Differenziale ripetibile è POTENTIAL, mai VERIFIED automatico. Nessun dump/write/file; DB e operatori ulteriori non coperti. Parametrizzato resta PARTIAL con indicatore di rifiuto coerente, non una garanzia generale. |
| IDOR/BOLA | Due account/canary → risultato con matrice esplicita risorsa/GET/ruolo/atteso/osservato/esito; vecchi test positivi, diniego, sessione scaduta e shell preservati. | Operazione GET; risorse/account predisposti, nessuna enumerazione o proprietà inferita automaticamente. |
| Broken Access Control | Matrice atteso consentito/negato ora esplicitata nel report; isolamento account e confronti validi preservati. | Non inferisce tutti i ruoli/operazioni applicative. Mancano matrici multi-operazione generali; HTTP 200 da solo non è prova. |
| SSRF | Non ampliata la generazione attiva; beneficia di budget/cancellazione/report comuni. Prove nonce/tempo/sorgente, eventi duplicati, assenza log e callback locale esistenti preservate. | Sensore HTTPS pubblico fidato non disponibile; end-to-end pubblico non verificato. Heartbeat sensore non implementato; log presente non dimostra salute. Assenza callback rimane inconclusiva. |
| Path Traversal | Canary file reale e baseline ripetute preservati con nuova orchestrazione/worker controlli seriali; test lettura, diniego e instabilità mantenuti. | Nessuna generazione di percorsi sensibili. Matrice esaustiva encoding non aggiunta; verifiche limitate agli URL innocui predisposti. |
| Misconfiguration | Aggiunti Permissions-Policy con applicabilità documento/non-documento e copertura TLS esplicita. Test HTML/JSON; vecchi handshake valido/scaduto/hostname errato mantenuti. | Osservazione di header non è vulnerabilità; una connessione negoziata non è audit completo TLS/cipher. Parsing semantico completo delle policy mancante. |
| Sensitive Data | Catalogo versionato con ulteriori forme token, dedup e placeholder; test valori sintetici ripetuti, placeholder e redazione. | Firme euristiche, nessuna validazione credenziali. Forme note possono essere esempi; catalogo non esaustivo. |
| Authentication | Cookie/sessioni/logout e cache isolata preservati; nuove identità input impediscono di confondere posizioni e metadati con richieste dimostrate. | Nessun login/MFA/rinnovo automatico aggiunto. Fixture controllate, non audit di ogni flusso autenticato; expiry osservata non dimostra stato server. |
| CORS | Browser semplice e preflight HTTP precedenti preservati con trasporto/rate/cancellazione aggiornati; test lettura canary, blocco e wildcard pubblica mantenuti. | Matrice browser completa di preflight/header custom non aggiunta. GET semplice su due origini controllate non copre ogni configurazione. |
| Smart Execution | Metadati generici → ID/dipendenze/budget/contatori espliciti; compatibilità/integrità e pipeline reale con interruzione/ripresa/report/diff. | Rimane selezione euristica confermata dall'operatore; passi seriali. Non costruisce credenziali/fixture né automatizza decisioni di autorizzazione. |

## Prestazioni

Stesso script applicato a snapshot V5 e V5.1, stessa configurazione per ciascuno scenario; una ripetizione, senza suite concorrenti. Risultati grezzi V5_MATRIX_* e V51_MATRIX_*, confronto V51_BENCHMARKS.md / V51_BENCHMARK_COMPARISON.json. Conservati V51_PRE_WINDOW_MATRIX_* del tentativo preliminare, senza selezionare solo risultati favorevoli.

12 task: 1.464 → 1.084 s; 100: 10.517 → 6.642 s; **500: 55.014 → 33.903 s (−38.4%)**. Due domini: 2.140 → 1.883 s, 24 task, picco globale 4 su cap 5 e per host 2 su cap 2, zero errori/duplicati. 500 task: throughput 9.09 → 14.75 richieste/s, picco allocazioni Python 7343067 → 7816794 B (**aumento**). RSS separata nei JSON.

Lentezza: −23.4%; 429: −3.2%; errori intermittenti: −3.5%. **Timeout su ogni richiesta: 12.337 → 14.303 s (+15.9%)**, 12 errori/timeout attesi su entrambe le versioni, nessun retry aggiuntivo. La sequenza di feedback/adattamento con coda progressiva può aumentare le attese nei guasti; non è stata aggirata per migliorare la misura. Non si dichiara ottimizzazione universale, significatività statistica o riduzione memoria. Task processato non equivale a scansione riuscita.

## Laboratorio ed esattezza misurata

La suite esegue SQLite reale anche su GET preesistenti; validate_local.py esegue nuovi form/JSON, DOM Chrome e pipeline reale su 127.0.0.1/127.0.0.2. Pipeline: creazione progetto/scope, crawl HTML/API/form, inventario input, Smart, checkpoint, interruzione con lavoro residuo, ripresa, JSON/MD/TXT e diff incompleto conservativo. DNS UDP, sessioni/ruoli/canary, callback e CORS sono test reali separati della suite; **non esiste una singola applicazione integrata con tutti i 13 controlli**. Il confronto diff finale usa una copia della run reale alterata in modo deterministico, non una seconda applicazione pubblica.

Dataset etichettato: 7 casi sintetici. SQL candidate detector: TP=2, TN=2, FP=0, FN=0; precision/recall=1 sul solo differenziale controllato. DOM execution: TP=1, TN=2, FP=0, FN=0; precision/recall=1 sulle sole tre pagine. Nessun caso non eseguito/inconclusivo nel dataset finale. **Non è una stima dell'accuratezza generale degli scanner**, né il 100% delle vulnerabilità reali. SQL non viene aggregato a XSS come prova VERIFIED. JSON con righe/esiti in V51_LOCAL_VALIDATION.json.

## Gestione file e sicurezza

Pulizia nel sottomenu risultati: inventario/dimensioni/categorie, anteprima firmata, conferma esatta ELIMINA + plan_id, ricalcolo prima della cancellazione, controllo identità/misure del file, percorso confinato, link/reparse point esclusi, solo unlink di file consentiti e vecchi. Mai cancellazione ricorsiva. Config, risultati, checkpoint, piani e file sconosciuti sono protetti. Namespace cache/tmp/log richiedono nome e marcatore di proprietà; cache HTTP resta in memoria. Run senza checkpoint sono segnalate solo per revisione, mai eliminate. .git/.venv/node_modules esclusi dal conteggio: spazio totale significa spazio inventariato.

Test: dry-run senza cancellazione, conferma errata, alterazione piano, file modificato, config/risultati/user file protetti, marcatore assente, root non riconosciuta, reparse simulato (symlink reale solo dove permesso dalla piattaforma) e errore PermissionError simulato per file bloccato con audit. Le cancellazioni di sviluppo riguardano soltanto fixture temporanee; nessun dato utente ripulito. Limite: non promette sicurezza contro un processo locale ostile che modifica continuamente le directory tra controllo e unlink.

Scope centrale, TLS verificato, pinning/all-IP/peer e controllo redirect conservati. POST solo fixture loopback espressamente autorizzate, controlli account seriali, browser senza egress. Nessun target pubblico scansionato né nuovi provider contattati. Nessun segreto persistito o utilizzato. Nessun test precedente eliminato.

## File principali e migrazioni

Nuovi: inputs.py, javascript.py, cleanup.py, requirements-javascript.txt; test_v51.py, test_v51_browser.py, test_v51_e2e.py; benchmark_domains.py, validate_local.py. Modificati: __init__, http, workers, execution, scanners, inventory, passive, dns, recon_output, signatures, controlled, browser_lab, plans, diffing, cli, benchmark_local.py, verify_kali.sh, README e CONTROLLED_CHECKS. Audit/rapporti/log/JSON in verification. Config operativa preservata. Nessuna modifica ai progetti esistenti.

Input precedenti si leggono come legacy e si normalizzano in memoria nelle nuove run; nessuna riscrittura dei checkpoint V5. Report storici consultabili, ripresa incompatibile rifiutata. Proiezioni e report nuovi mantengono i nomi precedenti e aggiungono file/campi.

## Kali e riproduzione

Kali non verificato: VirtualBox E_ACCESSDENIED; WSL assente; Bash Windows non avvia il runtime MSYS. Non è stato possibile neppure confermare bash -n da questo host. Nessuna modifica invasiva alla VM. V51_KALI_STATUS.md registra dettagli/procedura.

Nella VM aggiornata, cartella scrivibile: `bash verify_kali.sh --browser --javascript`. Verificare KALI_SUMMARY.json, log completi e skip, quindi `.venv/bin/XITool --version`. Script con fase/exit code, sintassi Bash nativa, installazione, launcher da altra cartella, browser/AST opzionali, suite e benchmark. Un comando preparato non è una certificazione Kali.

Per regressione: impostare XITOOL_BROWSER_TESTS=1 e usare `python -m unittest discover -s tests -v`; Chrome opzionale con XITOOL_BROWSER_CHANNEL=chrome, altrimenti Chromium Playwright installato. `python benchmarks/validate_local.py` salva il dataset. Benchmark ripetibile con --source, --tasks 12/100/500, --scenario e --output; snapshot V5 conservato nell'area di lavoro, non pubblicato nel repo.

## Restante lavoro

AST con costanti/alias e metodi di rete dinamici; taint DOM generale; storico online; copertura DB/input/ruoli/encoding più ampia; heartbeat e sensore HTTPS SSRF dell'operatore; CORS browser preflight completo; laboratorio unico di tutti i moduli; maggiori ripetizioni prestazionali e gestione migliore dei timeout senza indebolire backoff; verifica POSIX/Kali nativa. Per questi motivi la consegna rimane sperimentale.

La prima prova del nuovo harness era fallita perché tentava di interrompere una run già terminata con un solo task; la fixture ora contiene due task distinti per dominio e verifica lavoro residuo e ripresa. I log iniziali V51_LOCAL_VALIDATION_INITIAL.* sono conservati, insieme all’esito finale positivo.
