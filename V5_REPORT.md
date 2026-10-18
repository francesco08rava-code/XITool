# XITool V5 — rapporto tecnico

## Stato e revisione

**5.0.0a1**, 17 ottobre 2026. Cartella modificata: `C:\Users\Pc\Desktop\XITool`. Base Git `c7bb4706910037b994800fc1104594e38aa94e61`, con modifiche V3/V4 già presenti e conservate. Nessun commit/push. Il manifest `verification/V5_SOURCE_MANIFEST.json` identifica i sorgenti/test/configurazione effettivamente consegnati; il commit da solo non identifica questo checkout non committato.

Ambiente: Windows 11, Python 3.12.14; PyYAML 6.0.3, dnspython 2.9.0, Playwright 1.64.0 e Chrome headless. Nessuna nuova dipendenza runtime obbligatoria. ThreadPoolExecutor/semafori della libreria standard conservano il trasporto con pinning IP; non è stato introdotto un client async alternativo.

Baseline verificata prima delle modifiche: **250 test, 247 superati, 3 saltati, nessun fallimento, 57,994 s**. Audit iniziale in V5_AUDIT.md, copia del codice V4 conservata nell'area di lavoro per il confronto controllato.

Finale: **281 test, 278 superati, zero fallimenti/errori, 3 saltati, 72.011 s**, inclusi 9 test browser reali. Nessun test precedente eliminato. Aggiunti 31 test V5, fra cui concorrenza/stop/ripresa, domini distinti, DNS UDP reale, diff, priorità, cookie oscurati, OpenAPI, permessi positivi e compatibilità Smart.

Log riproducibili: verification/V5_BASELINE.txt e V5_TESTS.txt. Durante lo sviluppo sono state trovate e corrette regressioni: firma dei limitatori personalizzati, secondo Ctrl+C al termine del salvataggio, metadati degli header mescolati ai riferimenti JavaScript e completezza del diff quando la baseline era incompleta. I risultati finali sostituiscono gli esiti intermedi, senza rimuovere test.

**Non viene dichiarata una release stabile né il completamento di ogni funzione avanzata della specifica.** Tutti i 13 moduli sono stati esaminati; le capacità sotto sono operative e verificate nei casi dichiarati, ma gli stati complessivi restano PARZIALE dove la specifica e la matrice di verifica non sono interamente coperte. Nessuna etichetta OTTIMIZZATO E VERIFICATO è stata assegnata sulla sola base del totale dei test.

## Prestazioni misurate

Server HTTP loopback controllato, 250 ms di ritardo per risposta, 12 URL diversi, cache disabilitata, limite 20 richieste/s, tre ripetizioni per versione. V4 con 1 worker; V5 con 5 worker e 5 slot per host **solo nel benchmark**. La configurazione operativa mantiene 2 richieste/s e 2 slot per host. Il tempo comprende Engine, checkpoint ed export, non soltanto il socket.

| Misura | V4 | V5 |
|---|---:|---:|
| Tempo mediano, 12 task | 3.167 s | 1.474 s |
| Richieste/s sul tempo totale mediano | 3.789 | 8.138 |
| Picco HTTP simultaneo osservato | 1 | 5 |
| Picco mediano allocazioni Python | 159910 B | 223040 B |
| Picco RSS del processo (intera esecuzione) | 31.16 MiB | 32.38 MiB |
| Richieste / task completati per ripetizione | 12 / 12 | 12 / 12 |
| Errori / timeout / duplicati | 0 / 0 / 0 | 0 / 0 / 0 |

Tempo ridotto del 53.4%, rapporto 2.15× in questo laboratorio; non è una previsione sulle applicazioni pubbliche. Il costo di memoria aumenta con i worker: non viene nascosto. Tracemalloc misura allocazioni Python per ripetizione; RSS misura il picco del processo nell'intera esecuzione di ciascuna versione, inclusi import e tre ripetizioni.

I JSON prima/dopo contengono tutte le misure grezze. Una prova preliminare era stata eseguita mentre altre suite usavano il disco: è conservata come V5_BENCHMARK_PRELIMINARY_* e non usata per il confronto principale. Il confronto definitivo è stato ripetuto senza suite concorrenti. Nessun obiettivo arbitrario o benchmark contro target esterni.

Ripetizione della V5:

```bash
./.venv/bin/python benchmarks/benchmark_local.py --workers 5 --output verification/benchmark_v5.json
```

Per confrontare altre versioni, usare lo stesso script con `--source /percorso/copia_precedente --workers 1`; serve una copia reale dei sorgenti precedenti. I JSON consegnati identificano versione, parametri, metriche e numero di task.

## Implementazione comune

- Worker bounded: al massimo una finestra di task pari al limite configurato; client e cache per worker isolati; budget HTTP globale/per host condiviso, rate sincronizzato, backpressure e nessuna coda illimitata di future.
- Configurazione CLI: 5 worker, 2 slot per host, 1 dominio simultaneo. La libreria conserva fallback di 1 worker; execution.max_concurrent_domains consente 1–5 domini. Domini uguali non vengono eseguiti contemporaneamente nello stesso batch. Anche fra domini il budget HTTP resta condiviso, inclusi i provider CT.
- Solo il coordinatore modifica pending/completed, risultati e checkpoint. Cancellazione: si fermano le nuove attività, si attendono le richieste in volo entro i timeout e si preservano i task non committati. Test reali provano assenza di perdita di risultati alla ripresa. Richieste read-only già effettuate possono essere ripetute dopo crash/stop.
- Sessioni, controlli predisposti, POST/logout, DNS/provider e browser dinamico rimangono seriali nel singolo dominio. Non vengono condivisi client mutabili fra account.
- Scadenza cooperativa della run, limiti di risposte/DOM/task, backoff/Retry-After e cache anonima conservati. Nessun tentativo di superare rate limit o WAF.
- Nuovo modello ordinale: fattori osservabili, punteggio clamp 0–100, severità separata e priorità spiegata. Un'etichetta VERIFIED senza un indicatore di prova non ottiene priorità alta. Il punteggio non è probabilità statistica né CVSS.
- Human FALSE_POSITIVE è una classificazione separata; non cancella la prova originale e non trasforma un CONFIRMED umano in VERIFIED automatico.
- Fingerprint normalizzata per risorsa/controllo/parametro e provenienza conservata nei riepiloghi. La deduplica fra moduli è deliberatamente conservativa: controlli diversi non vengono fusi soltanto perché hanno lo stesso URL.

## Stato dei 13 moduli

| Modulo — stato complessivo | Operativo / migliorato nella V5 | Test ed evidenze | Mancanze e limiti |
|---|---|---|---|
| 1. Sub Finding — PARZIALE | Due provider indipendenti con stato/tempo/conteggi/limiti, seed esclusi, host nuovi/risolti/raggiunti/fuori scope, DNS e probe autorizzati; nuove viste e compatibilità con nomi V4. | PassiveTests, ReconEngineTests, LocalDNSTests, WorkerTests e regressioni multi-dominio; JSON valido/malformato, sovrapposizioni, errori, wildcard, redirect e ripresa. | Due fonti. crt.sh ed esterno DNS restano non verificati positivamente nell'ambiente; titoli conservati come presenza, non testo completo. Raccolta limitata non dichiarata completa. |
| 2. Crawler/Input Discovery — PARZIALE | Proiezione crawler autonoma, rete browser distinta da ipotesi/storico, nomi header/cookie senza valori, stato input, OpenAPI servers/default/basePath, REST/GraphQL osservato e DOM limitato. | DiscoveryTests: OpenAPI, privacy, storico e rete; BrowserLabTests: SPA/link dinamici, blocco esterno; suite crawler reale HTML/robots/sitemap/JSON e checkpoint. | JS euristico, niente AST completo/shadow DOM/interazioni. Parametri OpenAPI templati non generati; niente mutazioni. Storico da export locale, non provider storico online. RSS browser non limitato rigidamente. |
| 3. XSS — PARZIALE | GET osservati, baseline/ripetizione, indizi HTML/JS encoding/attributi URL; browser innocuo doppio su fixture GET/form/JSON. Priorità basata sulla prova. | BrowserLabTests: vulnerabile, escaped, CSP, form e JSON; regressioni input assente, risposta troncata, scope e POST non autorizzato. | Analisi contestuale euristica, niente analisi completa source/sink DOM. Browser su HTML raccolto e rete bloccata; nessun test generico di tutti i flussi SPA pubblici. |
| 4. SQL Injection — PARZIALE | Errori DB osservati e baseline stabili; confronto read-only su fixture SQLite, evidenze e valutazione comune. | ControlledServerTests: SQLite vulnerabile/parametrizzato; ControlledEdgeTests: 403 e instabilità; motore comune per timeout/errori/checkpoint. | Differenziale POTENTIAL, non semantica SQL automaticamente provata. Nessuna estrazione/modifica DB/file e niente scanner completo di ogni DB/input. |
| 5. IDOR/BOLA — PARZIALE | ID/UUID/path osservati, due account con riferimenti validi prima/dopo; confronto di permessi positivi o negativi espliciti. | Server reale per lettura canary, diniego, scadenza; PermissionMatrixTests per accesso consentito atteso; false shell/404/login inconclusive. | Richiede risorse/account/canary propri; niente enumerazione massiva o inferenza automatica del proprietario. |
| 6. Broken Access Control — PARZIALE | Matrice esplicita ora supporta expected_other_access true/false; diniego inatteso diventa revisione, accesso consentito atteso non vulnerabilità. | PermissionMatrixTests reali: accesso positivo corretto e diniego inatteso; test V4 per violazione reale, 403, login 200 e sessioni invalide. | Combinazioni di ruoli configurate dall'operatore; non inferisce l'intero modello applicativo e non equipara HTTP 200 a un accesso valido. |
| 7. SSRF — PARZIALE | Nonce/tempo/sorgente/eventi univoci e request ID correlati; IP attesi normalizzati; sensore controllato e callback pubblico validato. | Ricevitore locale reale, nonce errato/duplicato/assente, log mancante, destinazione privata respinta. | Nessun sensore HTTPS pubblico dell'operatore disponibile per prova end-to-end. Log/proxy devono essere fidati. Nessun metadata cloud o destinazione interna usata. |
| 8. Path Traversal — PARZIALE | File canary reale, baseline ripetuta e stabile; 403 ripetuto coerente con il divieto atteso trattato separatamente da assenza o guasto. | Fixture temporanea reale, instabilità non verificata, errori motore; regressioni scope e conservazione risultati. | Solo URL/risorse innocue predisposte; niente generazione di percorsi di sistema o matrice esaustiva di encoding/file/normalizzazione lato server. |
| 9. Misconfiguration — PARZIALE | Header/policy/redirect/TLS e attributi cookie condivisi con Authentication; priorità senza severità arbitraria. | Tre handshake TLS reali valido/scaduto/hostname errato; test HSTS, downgrade, cookie/cache e scope. | Una negoziazione TLS non equivale a audit di tutti i protocolli/cipher; analisi CSP e contesto restano limitati. |
| 10. Sensitive Data — PARZIALE | Catalogo/placeholder/entropia a supporto, conteggi deduplicati, valori oscurati; worker reali e report con provenienza/priorità. | Token sintetici, placeholder, alta entropia non sensibile, duplicati, archivi/MIME esclusi; WorkerTests su server reale. | Tre firme principali, euristiche non complete. Nessuna verifica o utilizzo delle credenziali trovate. Niente scansione di archivi. |
| 11. Authentication — PARZIALE | Cookie policy condivisa, expiry/deletion osservati, sessioni isolate, redirect, cache anonima, logout e invalidazione di fixture. | SessionTests/ControlledServerTests, DiscoveryTests privacy/attributi; vecchi token dopo logout e account invalido testati realmente. | Niente login/rinnovo/MFA automatici; expiry cookie osservata non dimostra da sola validità server. Logout solo fixture confermata. |
| 12. CORS — PARZIALE | Due origini, ACAO/ACAC/Vary/preflight, risposta comparabile, browser controllato e classificazione comune. Client per worker evita mutazioni concorrenti del metodo OPTIONS. | Preflight HTTP reale consentito/negato, browser legge o blocca il canary con cookie; wildcard pubblica non vulnerabilità. | Browser attuale GET semplice, non matrice completa di preflight/browser/applicazioni pubbliche. |
| 13. Smart Execution — PARZIALE | Piano con dipendenze e conferme, ricognizione compatibile per scope/config/versione, versioni dei moduli registrate, checkpoint, ripresa, task anonimi concorrenti, report deduplicati e priorità. | PlanTests e SmartCompatibilityTests: compatibilità, corruzione, ripresa, duplicati, errori dominio; WorkerTests: stop/ripresa e domini distinti. | Classificazione euristica; nessuna interazione applicativa o generazione automatica di fixture/credenziali. Piani eseguiti per passi ordinati, non DAG parallelo arbitrario. |

## Scan Diff e report

Scan Diff resta limitato a stesso progetto/dominio/modulo. Confronta hostname, URL, metodi/parametri e finding. Fingerprint equivalenti e campi transitori (timestamp/request ID/nonce) sono trattati conservativamente. La completezza richiede entrambe le run complete e compatibili e, per Sub Finding, entrambe le fonti previste riuscite. Un host/finding non osservato non è mai dichiarato eliminato/risolto.

Dal menu post-esecuzione vengono prodotti new_subdomains.txt, changed_endpoints.json, new_findings.json, unresolved_findings.json, diff.json e diff_report.md nella run. I finding non riprodotti restano irrisolti da verificare.

Report JSON/Markdown/TXT per run e batch: progetto, dominio, scope, versione, moduli eseguiti/non eseguiti, errori, prove minimizzate, confidenza/priorità, limiti e provenienza. Smart ha report JSON/Markdown del piano; il report TXT completo è nelle run/batch. I report aggregati sono snapshot del batch corrente, non un inventario perpetuamente aggiornato. La revisione umana successiva si consulta nel report della run.

Scope comune e pinning IP conservati: host esatti/wildcard/deny, schema/porta/percorso, redirect fuori scope, IP privati, peer e rebinding simulato sono coperti dalla regressione. Cache/sessioni non condividono risposte private; browser e callback non usano il profilo personale dell'operatore. Password/token/cookie/canary non vengono esportati in chiaro nelle prove controllate; corpi e titoli completi sono minimizzati. Le euristiche non possono riconoscere qualsiasi dato personale nascosto in URL/contenuti: non fornire dati privati come seed.

## File, dipendenze e migrazione

Nuovi moduli: workers.py, domain_workers.py, assessment.py, diffing.py, crawl_output.py, reporting.py, cookie_policy.py. Aggiornati HTTP/Engine, CLI, storage/config, provider/probe, inventory/dynamic, scanner/controlli/callback e piani. Nuovi test_v5.py, test_v5_dns.py, benchmarks/benchmark_local.py e verify_kali.sh. Aggiornati README/CONTROLLED_CHECKS/DEVELOPMENT. Nessun file applicativo o test precedente eliminato; nessuna nuova dipendenza runtime obbligatoria.

Checkpoint/piani V4 restano consultabili. Non riprendere con fingerprint/versioni incompatibili: creare una nuova run/piano V5. Non alterare manualmente checksum o versioni. File personali e vecchi risultati non sovrascritti dalla pubblicazione delle viste. Non sovrascritto alcun launcher globale preesistente.

## Kali, skip e risorse non disponibili

Kali nativo **NON VERIFICATO**: VBoxManage restituisce E_ACCESSDENIED/VirtualBox object non disponibile; WSL non installato. Anche Bash MSYS di Git non parte nel sandbox (NtCreateDirectoryObject, 0xC0000022), quindi non viene usato come prova POSIX o di sintassi.

I tre skip finali: test_installer_syntax, test_installer_launcher_and_existing_external_command (Bash e filesystem POSIX richiesti), test_symlink (creazione non consentita dal sistema). Nessun test scanner fallito nascosto come skip. Lo script verify_kali.sh viene consegnato ma non dichiarato eseguito con successo.

Provider esterni: la V5 non effettua nuove scansioni di target pubblici né una nuova verifica live dei provider. La precedente prova reale V4 di CertSpotter è documentata e conservata; crt.sh e DNS esterno rimangono NON VERIFICATI positivamente, distinti dai nuovi test DNS locali reali. L'integrazione di ulteriori provider non è necessaria per nascondere un guasto ambientale.

Valutato SecurityTrails: API documentata con autenticazione e quote, nessuna chiave operatore configurata; non aggiunto né interrogato automaticamente. Fonti storiche online non abilitate: si usa export locale esplicito. Nessun asset finanziario/bug bounty dell'operatore usato per integrazioni invasive.

## Problemi residui

- Compatibilità nativa Kali/installazione/launcher e dipendenze browser Linux non dimostrate; procedura sotto.
- crt.sh/DNS esterno e callback HTTPS pubblico operatore non verificati positivamente in questo ambiente.
- Limiti specifici dei 13 moduli nella tabella: JS/DOM/API e scanner non esaustivi, catalogo ristretto, fixture e permessi da predisporre.
- Thread pool bounded, non motore HTTP asyncio. Cache dei worker non riutilizzata indiscriminatamente fra moduli/run/account. Memoria maggiore con più worker; nessun limite RSS rigido di Chromium.
- Deadline cooperativa e task in volo ripetibili dopo stop/crash. Nessuna garanzia exactly-once per logout/POST di laboratorio.
- La classificazione/punteggio è ordinale, non probabilistica, e la severità resta UNKNOWN senza un contesto valutato. Non esiste deduplica semantica universale fra controlli differenti.
- Stato completato di coda, esito tecnico e completezza della raccolta rimangono distinti. Mancanza di finding non equivale ad assenza di vulnerabilità.

## Comandi operativi

Su Kali, dopo aver trasferito/pubblicato i sorgenti aggiornati in una cartella scrivibile:

```bash
cd ~/XITool-git
bash install.sh
./.venv/bin/XITool --version
./.venv/bin/XITool
./.venv/bin/python -m unittest discover -s tests -v
./.venv/bin/python -m pip install -r requirements-browser.txt
./.venv/bin/python -m playwright install chromium
XITOOL_BROWSER_TESTS=1 ./.venv/bin/python -m unittest discover -s tests -v
bash verify_kali.sh --browser
```

Il sistema può richiedere librerie Chromium: installarle secondo la diagnostica Playwright; non è stato eseguito sudo o installato un sistema Linux nell'host. verify_kali.sh richiede Kali, registra installazione/test, controlla il launcher da una directory temporanea e misura il benchmark. Non conclude che un launcher globale precedente punti a questa copia.

Windows/VS Code:

```powershell
cd C:\Users\Pc\Desktop\XITool
py -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe main.py --version
.\.venv\Scripts\python.exe main.py
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
```

Per i nove test browser su Windows: installare requirements-browser.txt; impostare `$env:XITOOL_BROWSER_TESTS="1"` e, con Chrome installato, `$env:XITOOL_BROWSER_CHANNEL="chrome"`. Senza la componente opzionale i test browser sono saltati con motivo esplicito; quel totale non equivale alla suite finale qui riportata.

Riferimenti primari: [Katana](https://github.com/projectdiscovery/katana), [metodi/limiti Katana e strumenti ProjectDiscovery](https://projectdiscovery.io/open-source), [autenticazione SecurityTrails](https://docs.securitytrails.com/docs/authentication), [quote/rate SecurityTrails](https://docs.securitytrails.com/docs/quotas-rate-limits). I riferimenti non sono componenti incorporati né equivalenza di copertura con XITool. Restano validi i riferimenti e le prove storiche nel report V4.
