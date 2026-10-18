# XITool 3.0.0a2 — completamento verificabile

Data: 16 ottobre 2026. Modifiche applicate direttamente alla cartella XITool sul Desktop. Nessun push o commit Git. Il menu principale e la struttura Progetto → Domini → Moduli → Risultati sono conservati.

## Esito della verifica

Suite finale applicativa: **196 test eseguiti, 193 superati, zero fallimenti/errori, 3 saltati; 44,181 secondi**. Ambiente Windows/Python 3.12, PyYAML, dnspython, Playwright 1.64 e Chromium del canale Chrome. I sei test browser sono stati eseguiti realmente, non saltati. I tre skip riguardano symlink reali e controlli Bash/installer POSIX. Kali nativo non è stato verificato da questo ambiente.

La fixture di lettura file è stata successivamente resa un vero file temporaneo predisposto, invece di una risposta canary in memoria; la verifica mirata dei controlli viene registrata in fondo al rapporto.

Baseline prima di questo intervento: 150 test, 147 superati e 3 saltati, 168,898 secondi. Nei cicli intermedi sono stati corretti due casi di test configurati per il modulo sbagliato e una regressione HTTP concreta individuata dalla preflight CORS; nessun test fallito rimane nascosto come superato.

## Verifica esterna separata dai test automatici

Su example.com, interrogando soltanto provider CT e resolver, senza probing HTTP del dominio:

- CertSpotter: due pagine effettivamente ricevute, due hostname grezzi (example.com e www.example.com), raccolta della fonte completata. Uno è il seed; non viene conteggiato come nuova scoperta dal motore.
- crt.sh: NetworkError da questo ambiente, sia nella prima prova sia dopo la correzione HTTP. Non significa indisponibilità globale del servizio. Nessun hostname attribuito a questa fonte.
- DNS A/AAAA/CNAME tramite dnspython: NoNameservers nell'ambiente di sviluppo. Non è un NXDOMAIN e non dimostra inesistenza dell'host. DNS reale positivo non verificato qui.

Le chiamate ai provider usano il client effettivo, con TLS e limiti; non il tool di ricerca web come sostituto del motore. Nessuna scansione dei domini pubblici dell'operatore. La prova esterna è manuale e separata dalla suite automatica, che usa esclusivamente mock e server locali.

## Piano e fasi realizzate

1. Audit del flusso CLI → scope → coda → HTTP/DNS → discovery/scanner → checkpoint/export. Baseline eseguita; mantenuta l'architettura.
2. Fondamenta: esiti distinti dall'elaborazione della coda, sessioni con riferimenti env, origine esatta, nessuna cache autenticata e policy URL condivisa.
3. Ricognizione: completezza delle fonti, errori DNS distinti, provenienza URL e discovery DOM facoltativa verificata in Chromium.
4. Analisi: preflight CORS, TLS osservato, encoding XSS, SQL baseline stabile, placeholder e protezione da archivi/dump.
5. Verifiche controllate: due account validi, canary, file innocuo, SQLite read-only, logout, browser XSS/CORS e correlazione SSRF con sensore.
6. Integrazione: piano Smart persistente, ripresa dei passi, report aggregato, NO_INPUT salvato come controllo non avviato e consultazione in sola lettura.

Le fasi sono verificate nei perimetri descritti, non dichiarate universalmente complete. L'assenza di credenziali, risorse o callback dell'operatore non viene sostituita da dati dimostrativi durante le scansioni reali.

## Tabella richiesta

| Modulo | Implementazione | Test effettivo | Stato reale |
|---|---|---|---|
| Sub Finding | crt.sh/CertSpotter, fonti/orari, seed distinti, DNS/probe, errori e raccolta incompleta | PassiveTests, ReconEngineTests; CertSpotter live positivo; crt.sh/DNS live non positivi | PARZIALE |
| Crawler | HTML/form/JS/sitemap/robots/JSON osservato, URL raggiunti separati; DOM opzionale con GET validati | LocalCrawlerTests; BrowserLabTests.test_dynamic_dom_links_are_collected_without_out_of_scope_http | PARZIALE: mancano storico URL, interazioni e GraphQL/shadow DOM completi |
| XSS | Marcatore inerte, encoding/stabilità; prova di esecuzione innocua su fixture browser | BrowserLabTests: vulnerabile positivo, encoding e CSP negativi in Chromium reale | PARZIALE: browser solo fixture loopback, non POST/JSON/DOM XSS generici |
| SQL Injection | Errori DB, GET invariati ripetuti, hash/stabilità; differenziale booleano read-only in laboratorio | SQLite reale: fixture vulnerabile differenziale e fixture parametrizzata negativa | PARZIALE: differenziale POTENTIAL, mai VERIFIED senza prova ulteriore |
| IDOR | Due account controllati, reference valida per entrambi e risorsa canary con negazione attesa | ControlledServerTests.test_actual_idor_controlled_resource_read_is_verified; shell 200/account scaduto inconclusivi | PARZIALE: richiede casi espliciti, niente enumerazione |
| Broken Access Control | Ruoli/account e permessi attesi, reference, doppia lettura | ControlledServerTests.test_actual_role_control_is_verified; rifiuto account valido negativo | PARZIALE: richiede risorse dell'operatore |
| SSRF | Nonce, callback HTTPS pubblico controllato, sensore, timestamp e sorgente attesa; DNS privato bloccato | CallbackTests: ricevitore HTTP reale locale e correlazione; destinazione pubblica sostituita dalla fixture | PARZIALE: nessuna prova pubblica end-to-end dell'operatore |
| Path Traversal | Baseline e due letture di file canary predisposto con accesso negato atteso | ControlledServerTests.test_prepared_file_fixture_is_checked_without_generating_system_paths | PARZIALE: verifica la fixture, non file arbitrari o diagnosi universale di traversal |
| Misconfiguration | Header/policy, HTTPS/redirect, TLS/cipher/certificato osservati, cache/listing | Workflow HTTP locale, test trasporto TLS/DNS/IP; nessun audit nativo di tutti i protocolli | PARZIALE: niente enumerazione completa protocolli/cipher TLS |
| Sensitive Data | Firme/entropia, placeholder ignorati, conteggi oscurati e riferimenti config; archivi esclusi | ScannerV3Tests e CompletionTests: segreti minimizzati, placeholder e archivi | PARZIALE: catalogo limitato, nessuna credenziale usata |
| Authentication | Cookie/scadenza/cache/login, profili env, logout e invalidazione controllati | Logout locale efficace negativo, inefficace positivo, sessione iniziale invalida senza logout | PARZIALE: logout solo fixture loopback confermata |
| CORS | Due Origin, credenziali/Vary, OPTIONS; lettura canary nel browser con cookie reale di test | BrowserLabTests: lettura cross-origin positiva e ACAO errato bloccato dal browser | PARZIALE: browser solo origini loopback controllate |
| Smart Execution | Ricognizione, suggerimenti, due conferme, piano/checkpoint aggregato, ripresa e report | PlanTests: interrompi/riprendi, salta completati, errore di un dominio, scope e integrità; sola lettura | PARZIALE: nessuna interazione automatica e scope/config del piano devono coincidere |

PARZIALE rispetto alla specifica complessiva non significa simulato: le funzioni della colonna Implementazione esistono e i test indicati ne mostrano il comportamento. Non viene usata l'etichetta FUNZIONANTE per suggerire una copertura non provata.

## Bug e limiti corretti

- Zero scoperte non maschera più un provider fallito o raccolta incompleta, anche aprendo un TXT vuoto.
- DNS NoNameservers/timeout non viene trattato come normale assenza di host.
- Un URL estratto da JS o aggiunto al DOM non è automaticamente presentato come raggiunto.
- Cookie e token non vengono trasferiti su redirect a origini diverse né memorizzati nella cache.
- HTTP 200 senza canary, account scaduto e riferimenti non validi restano inconclusivi.
- Letture con Content-Length completato e Connection: close non tentano più operazioni sul socket già chiuso: corretto il falso NetworkError, emerso su OPTIONS 501.
- SQL baseline instabile o pagina 403 senza errori non viene descritta come negativo pulito.
- Placeholder di credenziali non vengono segnalati come token reali automaticamente.
- Archivi/dump noti sono esclusi anche nei redirect; MIME archivi/binari rifiutati prima di leggere il corpo.
- Smart conserva il riferimento alla run prima di avviarla e riprende solo i passi incompleti.
- NO_INPUT produce un report NOT_STARTED, senza inventare una scansione o finding.
- Configurazioni di un altro dominio non vengono eseguite nel dominio selezionato.

## File modificati o aggiunti in questo intervento

Nuovi moduli: sessions.py, controlled.py, browser_lab.py, dynamic.py, callback_checks.py, callback_receiver.py, outcomes.py, plans.py.

Modificati: http.py, execution.py, scanners.py, recon_output.py, passive.py, scope.py, storage.py, cli.py e __init__.py. Il motore, DNS e la struttura multi-dominio esistenti sono stati estesi, non ricreati da zero. main.py, install.sh e config.yaml non richiedono una riscrittura.

Test: nuovi test_controlled.py, test_callbacks.py, test_browser_lab.py e test_completion.py; aggiornati test_execution_cli.py, test_http_scanners.py, test_multidomain.py e test_v3.py per le funzionalità realmente aggiunte. I rifiuti dei moduli non supportati e i controlli di scope rimangono testati.

Documentazione/configurazione: README.md, CONTROLLED_CHECKS.md, V3_COMPLETION_REPORT.md, riferimenti in DEVELOPMENT.md/V3_REPORT.md, requirements-browser.txt e tre esempi in examples/. .gitignore aggiunge esclusioni per .env e profili locali; targets/ era già esclusa. Nessuna credenziale reale nei file di esempio.

## Uso e dipendenze

Base: PyYAML e dnspython. Browser facoltativo: requirements-browser.txt, Playwright e un Chromium supportato, installati separatamente. Browser testato qui sul canale Chrome; non richiede il profilo personale dell'operatore. Variabili opzionali: XITOOL_BROWSER_TESTS, XITOOL_BROWSER_CHANNEL, XITOOL_DYNAMIC_BROWSER, XITOOL_CERTSPOTTER_AUTH. Nessuna variabile viene stampata con il suo valore.

Guida operativa in CONTROLLED_CHECKS.md e schemi examples/. Gli esempi hanno operator_owned=false e non vengono caricati automaticamente. Configurare soltanto risorse effettivamente proprie e i relativi env. L'esecuzione richiede conferma; i casi di logout sono segnalati prima dell'avvio.

Per aggiornare Kali dopo un push autorizzato: git pull --ff-only, bash install.sh, .venv/bin/python main.py. Il launcher esplicito .venv/bin/XITool e quello globale rimangono compatibili. Nessun push è stato effettuato.

## Problemi ancora presenti e verifiche mancanti

- Kali/VirtualBox nativo, Zsh e installer POSIX non verificati direttamente: tre test saltati su Windows.
- crt.sh non raggiunto positivamente e DNS esterno UDP non funzionante in questo ambiente; CertSpotter live verificato. Eventuali credenziali API e limiti commerciali restano dell'operatore.
- Callback pubblico HTTPS end-to-end dell'operatore non fornito: sensore/correlazione testati localmente, nessun target pubblico sottoposto a SSRF.
- Browser dinamico limitato a 10 risorse/pagina e GET; niente interazioni, POST, account browser personali, storico URL o copertura completa GraphQL/shadow DOM.
- Prove browser XSS/CORS, SQL read-only e logout limitate alle fixture loopback dichiarate; non sono scanner attivi universali su Internet.
- La lettura della fixture file non dimostra accesso ad altri file; SQL differenziale rimane POTENTIAL.
- TLS osserva la negoziazione effettuata, non tutte le combinazioni server possibili.
- L'affidabilità delle prove controllate dipende da canary, permessi attesi, account, proxy e log effettivamente predisposti dall'operatore. Nessun sistema di login o infrastruttura callback viene inventato dal tool.
- Le euristiche URL non possono riconoscere tutti i segreti o effetti collaterali; NON importare dati riservati. I dati minimi di rete nei log del sensore vanno conservati con permessi adeguati e ruotati.

## Riferimenti tecnici

[Playwright BrowserContext](https://playwright.dev/python/docs/api/class-browsercontext), [Playwright Page](https://playwright.dev/python/docs/api/class-page), [CertSpotter CT API](https://sslmate.com/help/reference/ct_search_api_v1), [dnspython Resolver](https://dnspython.readthedocs.io/en/stable/resolver-class.html), [OWASP WSTG](https://wstg.owasp.org/latest/), [MDN CORS](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Access-Control-Allow-Origin).

## Verifica mirata finale della fixture file

Dopo aver predisposto un vero file canary temporaneo, i 18 test di test_controlled.py sono stati rieseguiti: **18 superati, zero fallimenti/errori, 4,737 secondi**. Il test file legge ora effettivamente quel file dal server di laboratorio; nessun file di sistema o dato di terzi è usato.
