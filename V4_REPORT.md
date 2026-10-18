# XITool V4 — verifica tecnica del 17 ottobre 2026

## Esito globale

Versione **4.0.0a1**, sviluppo direttamente in `C:\Users\Pc\Desktop\XITool`. Base Git `c7bb4706910037b994800fc1104594e38aa94e61`, ramo main; checkout con modifiche V3 preesistenti conservate e modifiche V4 non committate. Nessun commit, push o scansione dei domini finanziari dell'operatore.

**Questo intervento migliora tutti i 13 moduli, ma non completa integralmente la specifica V4 e non costituisce una release stabile.** Le etichette dei moduli rimangono PARZIALE: la presenza di controlli operativi e test superati non dimostra tutti i requisiti richiesti. Le prove esterne e i test di laboratorio sono distinti di seguito.

| Verifica | Totale | Superati | Falliti/errori | Saltati | Durata |
|---|---:|---:|---:|---:|---:|
| Baseline prima delle modifiche | 196 | 193 | 0 | 3 | 265,023 s |
| Prima regressione V4 | 224 | 221 | 0 | 3 | 46,144 s |
| Validazione finale dei sorgenti V4 | **250** | **247** | **0** | **3** | **57,818 s** |

Nessun test precedente eliminato. Aggiunti 51 test in test_v4.py/test_v4_tls.py e 3 test browser POST. La suite finale comprende **9 test browser reali**, con Playwright e Chrome headless, oltre a HTTP/TLS locali, SQLite e ricevitore callback. I mock verificano condizioni deterministiche e guasti; non dimostrano compatibilità universale con servizi esterni. Una verifica intermedia ha trovato un errore nel nuovo test del nonce errato: il mock del tempo interferiva con il costruttore HTTP. È stato isolato e il test passa nella suite finale.

Ambiente: Windows, Python del runtime locale Codex; PyYAML, dnspython, Playwright e Chrome. Versioni precise e impronte dei sorgenti in `verification/V4_SOURCE_MANIFEST.json`. Log completo finale in `verification/V4_TESTS.txt`; baseline in `verification/V4_BASELINE.txt`.

### Test saltati e Kali

1. `test_installer_syntax`: richiede Bash/filesystem POSIX.
2. `test_installer_launcher_and_existing_external_command`: richiede Bash/filesystem POSIX.
3. `test_symlink`: il sistema non consente la creazione del symlink della fixture.

Kali **non verificato nativamente**. VirtualBox è installato, ma `VBoxManage list runningvms` restituisce E_ACCESSDENIED, oggetto VirtualBox non disponibile. Non è stato possibile entrare nel guest e verificare installazione, launcher, permessi, percorsi, browser e interruzione/ripresa su Kali. La suite Windows non sostituisce queste prove. Nessuna impostazione della VM è stata modificata.

### Prove esterne separate

Verifica del 17 ottobre, seed `example.com`, senza HTTP probing del seed:

- CertSpotter: 2 richieste, raccolta completata, 40 nomi grezzi, 2 host unici (`example.com`, `www.example.com`), seed escluso 1; wildcard CT registrata separatamente.
- crt.sh: NetworkError, zero pagine raccolte; **fonte fallita**, non prova di assenza di nomi.
- DNS A/AAAA/CNAME: NoNameservers; `resolution_status=RESOLVER_ERROR`, non NXDOMAIN.

Risposta minimizzata in `verification/V4_LIVE_PROVIDERS.json`. Non sono state attivate fonti aggiuntive né nuove API storiche. Non è stata dimostrata una raccolta esterna completa.

## Infrastruttura e bug corretti

- GET/HEAD/OPTIONS e POST esplicito per URL esatto autorizzato, corpo massimo 64 KiB. Il POST è senza retry, redirect o cache; la CLI lo usa solo per fixture XSS loopback confermate.
- Timeout totale, connessione e lettura configurabili. Conservata la deadline totale contro stream lenti; limite globale e per host, un solo worker effettivo.
- Gzip/x-gzip e deflate zlib con limite su byte ricevuti ed espansi. Test reale di decompressione fortemente espansiva: output troncato entro il limite.
- Rifiuto di framing Content-Length/Transfer-Encoding ambiguo, Content-Length invalido, stream corti, compressione corrotta/incompleta/concatenata e codifiche non supportate. HTTP chunked e connessioni chiuse verificati su server reale.
- ID univoco trasmesso nelle richieste; ID nei probe e nelle evidenze delle run. Un cache hit conserva l'identità della risposta originaria.
- TLS con verifica del certificato e hostname attiva; metadati della singola negoziazione, notBefore/notAfter, cipher e versione. Certificati scaduti o errati rifiutati, senza retry o disabilitazione della verifica.
- DNS distingue NXDOMAIN, NoNameservers, SERVFAIL documentato dalla risposta DNS, timeout e guasti di rete; TTL e stato del resolver esportati.
- Conteggi CT grezzi/unici/seed esclusi e stati host separati. Un guasto del provider non viene etichettato come HTTP irraggiungibile del seed.
- Crawler più selettivo sulle chiamate JavaScript; canonical, documenti API e storico locale separati da raggiungibilità.
- Schema finding esteso con resource/check_type e request_ids, mantenendo campi precedenti e isolamento di progetto/dominio/run.
- Le prove XSS troncate non diventano POTENTIAL; esecuzione browser positiva richiesta due volte su risposte stabili.
- Riferimento del secondo account verificato anche dopo il confronto IDOR/access, per non dare un negativo se la sessione scade durante il test.
- Baseline traversal ripetuta: pagine instabili non producono una conferma di lettura canary.
- Callback duplicati identici deduplicati; nonce errato non può confermare SSRF.
- Firme sensitive spostate in un catalogo separato; esposizioni identiche non gonfiano i conteggi, entropia da sola non produce un segreto.
- Smart rifiuta moduli/task non disponibili prima di mutare il piano; verifica dominio/modulo/progetto/config/scope del checkpoint anche per passi completati. Report JSON aggregato deduplicato, oltre al Markdown.

## Stato dei 13 moduli

La colonna test distingue prove positive e negative; la regressione finale comprende anche test_execution_cli, test_http_scanners, test_multidomain, test_scope_storage e test_completion. Tutti i controlli sono integrati nel flusso esistente, senza nuovo menu principale o applicazione separata.

| Modulo e stato | Funzioni operative e miglioramenti | Prove positive / negative / regressione | Mancanze, limiti e motivo dello stato |
|---|---|---|---|
| **1. Sub Finding — PARZIALE** | Due provider CT isolati, dedup/IDNA, provenienza, timestamp, seed esclusi, conteggi, DNS/probe autorizzati, stati DISCOVERED/DNS_RESOLVED/DNS_FAILED/HTTP_REACHABLE/HTTP_UNREACHABLE/OUT_OF_SCOPE. SEED distinto. | PassiveTests/test_v3: JSON valido, pagination, duplicati, wildcard, errori e ripresa; DNSEdgeTests: NXDOMAIN, NoNameservers, SERVFAIL, timeout/rete; InventoryTests: seed, conteggi e provider fallito distinto da host irraggiungibile. CertSpotter reale riuscito. | crt.sh e DNS esterno non verificati positivamente nell'ambiente. Due soli provider; limiti di pagine/host dichiarati, nessuna completezza universale. Non promuovibile senza le verifiche mancanti. |
| **2. Crawler/Input Discovery — PARZIALE** | HTML/link/form non inviati/script, robots/sitemap, canonical, URL relativi, fetch/XHR/axios letterali, JSON osservato, OpenAPI/GraphQL documentali, browser DOM isolato e export storico locale non accodato. | ScannerTests/InventoryTests: HTML, form, JS, canonical, API, storico non raggiunto, fuori scope; BrowserLabTests: link DOM reale e blocco uscita; test_v3/Engine: checkpoint/budget. | JS euristico, non parser AST; niente calcolo di URL dinamici, shadow DOM completo, interazioni o provider storico online. OpenAPI limitato ai paths concreti del documento e origine base; non implementa tutte le regole servers/basePath o template. GraphQL osservato, nessuna introspezione/mutazione generata. |
| **3. XSS — PARZIALE** | Query GET osservate con marker inerte, confronto/ripetizione, contesti euristici, encoding HTML; GET/form/JSON su fixture loopback confermata e doppia prova browser innocua. | BrowserLabTests: GET vulnerabile, escaped, CSP, JSON vulnerabile/escaped, form vulnerabile; InventoryTests: risposte troncate; ControlledEdgeTests: POST senza autorizzazione rifiutato; regressioni input assente/scope. | Contesto HTML/attributo/script/JSON euristico; nessuna analisi completa di stringhe JS, URL o source/sink DOM. Browser limitato all'HTML raccolto: script esterni e flussi applicativi complessi non riprodotti. |
| **4. SQL Injection — PARZIALE** | Errori DB osservati con GET invariato, baseline ripetuta; differenziale booleano ripetuto su fixture read-only. Esposizione del rigetto coerente delle espressioni. | ControlledServerTests: SQLite vulnerabile e parametrizzato reali; ControlledEdgeTests: baseline instabile e 403; CompletionTests: errore/non stabilità. Timeout gestito e persistito dal motore comune. | Differenziale resta POTENTIAL: non prova automaticamente la semantica SQL interna. Nessuna estrazione/modifica DB/file. Non copre tutti gli input o database né JSON/form SQL; matrice di timeout/falsi positivi non esaustiva per il modulo. |
| **5. IDOR/BOLA — PARZIALE** | ID/UUID osservati, due account validi, risorse canary e permesso atteso; letture ripetute e validità dell'altro account ricontrollata alla fine. | ControlledServerTests: lettura effettiva e account invalido; ControlledEdgeTests: 403 con account valido, risorsa 404 e scadenza durante confronto; sessioni non salvate nei report. | Solo risorse/configurazioni predisposte. Nessuna enumerazione o generazione di oggetti. Non copre tutti i riferimenti JSON/path o le regole applicative; configurazione operatore necessaria. |
| **6. Broken Access Control — PARZIALE** | Profili/ruoli, righe esplicite di permesso negato per risorsa, prove minimizzate, stessa protezione dalle sessioni scadute. | ControlledServerTests: violazione reale e 403 corretto; ControlledEdgeTests: shell/login HTML 200, sessione che scade durante la prova; test manifest/scope/checkpoint. | Matrice come elenco di casi owner/other con expected_other_access=false; niente generazione automatica fra ruoli o permesso positivo configurabile. Non verifica l'intero modello di autorizzazione di un'applicazione. |
| **7. SSRF — PARZIALE** | Parametri URL candidati; sensore operatore, nonce, tempo, sorgente TCP attesa, conteggio univoco eventi, limiti al log e callback pubblico validato. | CallbackTests: ricevitore HTTP locale reale, correlazione, log mancante e DNS callback privato; CallbackEdgeTests: duplicato identico e nonce errato; assenza callback rimane PARTIAL. | Trasporto della destinazione pubblica sostituito nella fixture. Nessun sensore HTTPS pubblico operatore disponibile per una prova end-to-end. Log/sensore/proxy devono essere fidati; log esistente non dimostra salute del processo. Nessuna destinazione privata/metadata. |
| **8. Path Traversal — PARZIALE** | Canary innocuo su file reale predisposto, due baseline uguali e due letture, confronto rispetto all'accesso negato atteso. | ControlledServerTests: lettura da file temporaneo reale, niente percorsi generati; ControlledEdgeTests: baseline instabile non verifica; errore rete gestito dal motore. | Nessuna generazione di varianti encoding/traversal; URL predisposte dall'operatore. Una lettura canary prova solo quella risorsa. Mancano fixture dedicate per ogni variante consentito/negato/mancante/encoding, perciò matrice richiesta incompleta. |
| **9. Misconfiguration — PARZIALE** | Header/policy, HSTS anche disabilitato, nosniff, referrer riconosciuta, cache, redirect/downgrade, informazioni minimizzate, singola negoziazione TLS verificata. | TLSTests: tre handshake reali valido/scaduto/hostname errato con trust della sola fixture e hostname check attivo; WireTests: errore TLS non ritentato; InventoryTests: downgrade/HSTS zero; regressioni header. | Valutazione contestuale limitata, CSP euristica e cookie analizzati nel modulo auth. Nessun audit esaustivo dei protocolli/cipher o validazione semantica completa di tutte le policy. Severità resta UNKNOWN. |
| **10. Sensitive Data — PARZIALE** | Catalogo versionabile di tre firme, entropia come supporto ad assegnazioni nominate, placeholder, dedup e oscuramento totale dei valori. | InventoryTests: token sintetico ripetuto e casuale ad alta entropia non sensibile; ScannerTests/CompletionTests: placeholder, niente segreti salvati, MIME binari/archivi/redirect esclusi. | Catalogo ristretto e placeholder euristici: possibile falso positivo su dati dimostrativi non riconosciuti. Evidenze sono conteggi e indicatori oscurati, senza convalida delle credenziali. Non equivale a un motore di firme esteso o scansione di archivi. |
| **11. Authentication — PARZIALE** | Attributi cookie, Max-Age/Expires osservati, profili env isolati, scadenza locale, redirect login e logout/invalidation espliciti su fixture. | SessionTests: header privati, cache, origine/scadenza/missing credentials; ControlledServerTests: logout efficace/inefficace e sessione iniziale invalida; login 200 non prova accesso. | Nessun login automatico, rinnovo sessione, cookie jar o audit completo di autenticazione/MFA. Expiry del profilo non dimostra tutte le condizioni server. Logout solo loopback e confermato. |
| **12. CORS — PARZIALE** | Due Origin, wildcard/credenziali/Vary, OPTIONS, controllo di comparabilità; browser con cookie e canary su due origini di laboratorio. | BrowserLabTests: risposta realmente leggibile o bloccata; WireTests: preflight HTTP reale 204/403; ScannerTests: wildcard non trattata come vulnerabilità. | Verifica browser attuale di fetch GET semplice, non matrice completa dei preflight nel browser o di tutte le policy/sessioni. Wildcard pubblica è una configurazione osservata, non da sola una vulnerabilità. |
| **13. Smart Execution — PARZIALE** | Discovery reale, motivazioni, scelta/conferma, checkpoint piano, ripresa, isolamento dominio/config/scope, rifiuto moduli mancanti, report JSON e Markdown deduplicati. | PlanTests: interruzione/ripresa senza ripetere passi completati, errore dominio, config/scope/integrità, sola lettura; InventoryTests: modulo non disponibile, dedup aggregato e checkpoint di altro dominio rifiutato; test_multidomain/CLI regressione. | Un worker effettivo; niente parallelismo; pianificazione fondata sulle limitate classificazioni osservate. Le matrici corrotte/malformate e gli arresti improvvisi non sono esplorati esaustivamente. Dopo crash possono ripetersi richieste successive all'ultimo checkpoint. |

## Prestazioni, compatibilità e dipendenze

Nessuna nuova dipendenza di runtime obbligatoria. Base PyYAML/dnspython; Playwright opzionale. I certificati TLS e la chiave **pubblicamente nota e soltanto di laboratorio** sono fixture statiche, non credenziali operative; per eseguire i test TLS non serve cryptography.

Default: un worker, massimo 2 richieste/s globale e per host, timeout totale/connessione/lettura 10 s, corpo ricevuto ed espanso entro 1 MiB, massimo 50 attività di discovery e 1000 task. La configurazione max_concurrency non abilita parallelismo effettivo. Cache volatile per client/scope/metodo/Origin; risposte con sessioni, Set-Cookie, private/no-store non memorizzate. Cache e risposte autenticate non condivise fra progetti.

Riduzione del carico tramite deduplica, cache e rifiuto prima del corpo degli archivi/MIME binari. Nessun benchmark prestazionale comparabile: la differenza 265 s/58 s dipende dall'ambiente e non dimostra un'accelerazione di 4,5 volte. Rate/backoff non aggirano protezioni.

Nuove chiavi timeout cambiano la fingerprint della configurazione. Checkpoint V3 incompatibili richiedono una nuova run; i risultati storici restano conservati. POST senza retry non garantisce semantica exactly-once dopo un arresto improvviso: non usarlo per azioni operative con effetti collaterali, solo fixture predisposte.

File V4: http.py, dns.py, passive.py, recon_output.py, scanners.py, controlled.py, browser_lab.py, callback_checks.py, plans.py, execution.py, storage.py, __init__.py, config.yaml; nuovi inventory.py/signatures.py; test_v4.py/test_v4_tls.py e fixture TLS; estensione test_browser_lab.py; README/CONTROLLED_CHECKS/DEVELOPMENT e questo report. L'elenco Git include anche il precedente lavoro V3 non committato: non è una misura delle sole modifiche V4.

## Problemi residui trasversali

- Compatibilità nativa Kali/POSIX, crt.sh e resolver esterno ancora non dimostrati positivamente.
- Matrici complete richieste dalla specifica non ancora coperte per tutti i 13 moduli; dettagli nella tabella. Non viene dichiarato OTTIMIZZATO E VERIFICATO per nessuno sulla sola base del totale dei test.
- Il riconoscimento di azioni mutative/segreti negli URL resta euristico. Non fornire URL privati o azioni operative come seed; GET può avere effetti lato applicazione.
- Brotli, deflate raw e codifiche composte/concatenate non supportati: errore esplicito, niente risultati inventati.
- Crawler JavaScript/DOM/API e analizzatori di contesto non completi. Storico soltanto da file operatore, prime 1000 righe.
- Prove browser staticamente raccolte e isolate non riproducono un'applicazione completa con risorse/sessioni/interazioni complesse.
- Manifest, export storici, log callback e account controllati richiedono risorse e configurazione attendibili dell'operatore. Non vengono create credenziali o dati reali di terzi.
- Fixture positive/negative non garantiscono efficacia universale su server pubblici. Nessuna diagnosi generale ricavata solo da HTTP 200, assenza di callback o riflessione.

## Installazione, avvio e test

Su Kali, dopo aver trasferito questi sorgenti aggiornati in una cartella scrivibile del guest:

```bash
cd ~/XITool-git
bash install.sh
./.venv/bin/XITool
./.venv/bin/python -m unittest discover -s tests -v
```

Il comando globale precedente può puntare a una copia vecchia: usare il launcher esplicito qui sopra. Non riutilizzare una .venv Windows su Kali. Il repository remoto non contiene queste modifiche finché l'operatore non le pubblica.

Browser opzionale su Kali:

```bash
./.venv/bin/python -m pip install -r requirements-browser.txt
./.venv/bin/python -m playwright install --with-deps chromium
XITOOL_BROWSER_TESTS=1 ./.venv/bin/python -m unittest discover -s tests -v
```

Su Windows, nel terminale VS Code della cartella XITool:

```powershell
py -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe main.py --version
.\.venv\Scripts\python.exe main.py
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
```

Per ripetere anche i nove test browser, installare requirements-browser.txt e un Chromium Playwright oppure usare Chrome installato:

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements-browser.txt
$env:XITOOL_BROWSER_TESTS="1"
$env:XITOOL_BROWSER_CHANNEL="chrome"
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
```

Senza la componente opzionale i test browser vengono saltati con motivo esplicito: non confrontare quel totale con una verifica che li include.

## Riferimenti primari consultati

[Subfinder](https://github.com/projectdiscovery/subfinder), [Amass](https://github.com/owasp-amass/amass), [Assetfinder](https://github.com/tomnomnom/assetfinder), [dnsx](https://github.com/projectdiscovery/dnsx), [httpx](https://github.com/projectdiscovery/httpx), [Katana](https://github.com/projectdiscovery/katana), [Hakrawler](https://github.com/hakluke/hakrawler), [Gospider](https://github.com/jaeles-project/gospider): riferimenti di ricognizione/inventario, non componenti installati o incorporati.

[Dalfox](https://github.com/hahwul/dalfox), [XSStrike](https://github.com/s0md3v/XSStrike), [SQLmap](https://github.com/sqlmapproject/sqlmap), [Nuclei](https://github.com/projectdiscovery/nuclei), [Nikto](https://github.com/sullo/nikto), [testssl.sh](https://github.com/testssl/testssl.sh), [Gitleaks](https://github.com/gitleaks/gitleaks), [TruffleHog](https://github.com/trufflesecurity/trufflehog), [CORScanner](https://github.com/chenjj/CORScanner): consultazione delle descrizioni pubbliche, senza equiparare la copertura di XITool a questi strumenti.

[OWASP WSTG](https://wstg.owasp.org/), [MDN CORS](https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/CORS), [MDN Content-Encoding](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Content-Encoding): riferimenti per separare osservazione/prova, preflight browser e codifica del contenuto.
