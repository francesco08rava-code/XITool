# XITool 5.2.0a1 — consolidamento Alpha

Aggiornamento direttamente sul progetto esistente. Menu e dati precedenti preservati. Laboratorio integrato dei 13 componenti, catalogo etichettato per contratto, regressione CORS senza ACAO corretta, AST const/alias/scope, URL statici non accodati automaticamente, stati CT e tassonomia errori, DNS globalmente bounded e confronto timeout ripetuto.

Avvio dalla cartella: `python main.py`. Installazione su Kali in checkout scrivibile: `bash install.sh`, quindi `XITool --version`, `XITool --help`, `XITool`. La verifica completa si prepara con `bash verify_kali.sh --browser --javascript`. **Kali nativo non è stato verificato da questa sessione Windows.**

Il console script è installato editable nel venv, con collegamento utente ~/.local/bin/XITool. Non si sovrascrivono comandi esterni. Controllare `type -a XITool` nella propria shell per alias/conflitti; nessuna modifica automatica a .zshrc. Dopo spostamento del checkout ricreare/reinstallare il venv. Pip opera nel venv, non nel Python di sistema.

Dipendenze browser/AST facoltative: requirements-browser.txt / requirements-javascript.txt. `python benchmarks/validate_integrated.py` richiede browser disponibile e salva i risultati/dataset V52. Per la suite completa: `XITOOL_BROWSER_TESTS=1 python -m unittest discover -s tests -v`. Su Windows impostare la variabile con la sintassi della propria shell; Chrome disponibile con XITOOL_BROWSER_CHANNEL=chrome.

Fonti CT predefinite crtsh/certspotter, configurabili tramite discovery.ct_providers (anche [] per disabilitarle). I nuovi stati distinguono successo vuoto, errore, rate limit e timeout; nessun provider aggiuntivo viene contattato. http.retry_jitter_seconds opzionale 0–1, default 0. I rate di produzione restano 2 richieste/s e cap host 2.

Dettagli verificabili: verification/V52_FINAL_REPORT.md, V52_E2E_REPORT.md, V52_ACCURACY_REPORT.md e V52_PERFORMANCE_REPORT.md. Rimane Alpha: nessuna accuratezza generale dedotta dalle fixture, nessun completamento universale dei 13 scanner e nessun commit/push automatico. Le sezioni seguenti sono documentazione storica.

---

# XITool 5.1.0a1 — aggiornamento sperimentale

Modifiche V5.1: identità input distinta per posizione, metodi/parametri OpenAPI (dichiarazioni separate da richieste osservate), parser JavaScript AST opzionale, prova DOM XSS da frammento su laboratorio, SQL form/JSON read-only su fixture, matrice permessi, Permissions-Policy, firme versionate, feedback rate non bloccato dalle attese, diff DNS/API e pulizia con anteprima/conferma.

Il menu principale resta invariato. Pulizia sicura è nel sottomenu risultati dopo un'esecuzione; APRI PROGETTI resta in sola lettura. L'anteprima conserva risultati, checkpoint e configurazioni. I cache HTTP correnti sono in memoria; nessuna falsa promessa di spazio recuperabile. File disco sconosciuti sono protetti. I namespace gestiti .xitool-cache/.xitool-tmp/.xitool-logs richiedono un marcatore di proprietà e nomi/retention compatibili; non aggiungere marcatori a cartelle di documenti personali.

Per il parser AST opzionale: `python -m pip install -r requirements-javascript.txt`. Senza dipendenze opzionali rimane la discovery letterale precedente. L'AST non valuta script, non risolve ancora costanti/alias/flussi dinamici e non prova la raggiungibilità.

Su Kali: `bash verify_kali.sh --browser --javascript`. Lo script produce KALI_SUMMARY.json e log separati. La compatibilità nativa va provata nella VM; non è dimostrata dai test Windows.

I checkpoint V5 restano consultabili; la ripresa dopo cambio versione richiede una nuova run. Nessuna migrazione distruttiva. Dettagli e limiti: verification/V51_AUDIT.md e verification/V51_FINAL_REPORT.md. Le informazioni V5 sotto sono storiche.

---

# XITool 5.0.0a1

CLI per ricognizione e verifiche web su asset autorizzati. Report corrente: [V5_REPORT.md](V5_REPORT.md); audit iniziale: [V5_AUDIT.md](V5_AUDIT.md). Questa è una **alpha**: capacità operative e limitazioni sono descritte separatamente, senza promettere copertura universale o compatibilità Kali già verificata.

## Installazione e avvio

Kali, nella copia aggiornata e scrivibile del progetto:

```bash
cd ~/XITool-git
bash install.sh
./.venv/bin/XITool
```

Da qualsiasi directory: `~/XITool-git/.venv/bin/XITool`. L'installer crea `~/.local/bin/XITool` se assente e conserva launcher preesistenti. Se il comando globale apre una vecchia copia, usare il percorso esplicito; verificare `XITool --version` e il PATH. Non riutilizzare la .venv Windows su Kali. Python 3.10+, python3-venv; base PyYAML/dnspython.

Windows, terminale VS Code:

```powershell
cd C:\Users\Pc\Desktop\XITool
py -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe main.py --version
.\.venv\Scripts\python.exe main.py
```

Nessun commit o push automatico. `git pull` su Kali riceverà questi cambiamenti soltanto dopo la loro pubblicazione da parte dell'operatore.

## Utilizzo

Il menu principale resta CREA PROGETTO, APRI PROGETTI, ESECUZIONE, ESCI. Domini multipli/incollaggio multilinea, deny, selezione multipla e intervalli. APRI PROGETTI consulta soltanto i risultati; mostra anche CRAWLER / INPUT DISCOVERY quando disponibile. ESECUZIONE richiede conferma del piano.

Struttura: `targets/PROGETTO/scope.json`, poi `DOMINIO/subfinding`, `crawler`, moduli, `runs`, `reports`. Smart salva i piani in `PROGETTO/plans`; i report aggregati dei batch in `PROGETTO/reports/batch_*.json/md/txt`. Le viste correnti non sovrascrivono file personali modificati: la run originale conserva gli output.

## Scope e trasporto

- Host esatto e wildcard sono distinti; `*.example.com` non autorizza l'apex. I deny prevalgono. Una scoperta non autorizza l'host.
- Scope URL conserva schema/porta/percorso; IP speciali richiedono CIDR espliciti. Porte non standard richiedono configurazione.
- Ogni richiesta/redirect passa dal validatore comune; IP risolto fissato al socket, peer controllato, TLS e hostname verificati, niente proxy ambientali.
- URL con credenziali riconoscibili, azioni mutative note, archivi/dump e MIME binari sono esclusi. Le euristiche non riconoscono ogni azione o dato personale: fornire risorse appropriate e non URL privati.
- GET/HEAD/OPTIONS; POST solo URL esatto autorizzato, corpo limitato e fixture XSS confermata dalla CLI. Niente retry/redirect/cache POST. Nessun invio automatico di form o mutazioni GraphQL.
- Cache volatile anonima separata per client/scope/metodo/Origin; sessioni, Set-Cookie, private/no-store esclusi. Profili env separati, nessun trasferimento di credenziali ad altre origini.
- Gzip e deflate zlib limitati su byte ricevuti/espansi. Framing ambiguo e compressione corrotta/incompleta rifiutati. Brotli, deflate raw e codifiche composte non supportati.

## Concorrenza effettiva

`config.yaml` usa 5 worker massimi, 2 richieste simultanee per host, 1 dominio simultaneo e 2 richieste/s globali. La configurazione minima della libreria mantiene 1 worker come fallback. `execution.max_concurrent_domains` è configurabile da 1 a 5; anche fra domini si condividono budget e rate. Task dello stesso dominio restano ordinati.

Worker con client isolati, semafori globali/per host, coda bounded e commit dei risultati da un solo coordinatore. I casi controllati, le sessioni, DNS/provider e browser dinamico restano seriali nel singolo dominio. Il trasporto conserva il pinning IP: è usato un thread pool, non una riscrittura async.

Timeout totale/connessione/lettura, massimo 1 MiB di risposta, profondità 2 e 50 attività discovery per dominio come default. `execution.max_duration_seconds=600` è un limite cooperativo: una richiesta già in volo può terminare entro il proprio timeout. Rate e Retry-After riducono il carico. Nessun aggiramento di WAF/protezioni.

Ctrl+C salva lo stato dopo aver arrestato i worker. I task in volo non committati rimangono pendenti; dopo crash/interruzione possono essere ripetuti. POST/logout di fixture non hanno garanzia exactly-once. Checkpoint e Smart verificano scope, configurazione e versione: V4 incompatibili restano leggibili, ma richiedono una nuova run V5.

## Ricognizione e discovery

Sub Finding consulta crt.sh e CertSpotter dopo la conferma. Provenienza, stato, tempo, pagine, limiti, conteggi grezzi/unici/seed e DNS/probe separati. Fonti fallite non equivalgono a zero host. Seed mai conteggiato come nuova scoperta. Wildcard CT separate; DNS A/AAAA/CNAME, TTL, wildcard e guasti del resolver distinti.

Nuove viste compatibili: seed_domains, discovered_subdomains, resolved_subdomains, live_subdomains, out_of_scope, providers.json, dns_results.json e summary.json. Restano anche i nomi precedenti. Probe con status/redirect/Content-Type/tempo/byte trattenuti/TLS; i titoli sono rilevati ma non esportati integralmente per minimizzare dati personali.

Crawler: HTML, form/input non inviati, script, robots/sitemap, canonical/paginazione tramite link, JS letterale fetch/XHR/axios, JSON osservato e identificatori nei percorsi. OpenAPI considera servers/default delle variabili e Swagger basePath; GraphQL solo osservato. Nessuna operazione API generata. Cookie/header osservati come nomi e metadati, senza valori né trasformazione automatica in input attaccabili.

`crawler/` contiene discovered_urls.txt, verified_urls.txt, historical_urls.txt, forms.json, parameters.json, api_endpoints.json, javascript_endpoints.json e crawl_summary.json. Uno storico può essere importato da `PROGETTO/historical_urls.txt` (1 MiB, prime 1000 righe), senza consultare servizi nuovi o visitare automaticamente gli URL. Storico, ipotesi JS, osservazioni DOM/rete e URL raggiunti sono distinti.

Browser opzionale:

```bash
./.venv/bin/python -m pip install -r requirements-browser.txt
./.venv/bin/python -m playwright install chromium
XITOOL_DYNAMIC_BROWSER=1 ./.venv/bin/XITool
```

Contesto effimero, niente profilo personale, uscite dirette bloccate. GET document/script/fetch/xhr attraverso il client validato; massimo 10 risorse per rendering. DOM serializzato limitato dal budget risposta; nessun limite RSS rigido del processo Chromium. Niente clic, POST, WebSocket, service worker o interazioni mutative. JS è euristico, non un interprete completo. Shadow DOM e applicazioni complesse non sono interamente coperti.

## Scanner, verifiche e priorità

I 13 moduli logici sono Sub Finding, Crawler/Input Discovery, XSS, SQLi, IDOR, Access Control, SSRF, Traversal, Misconfiguration, Sensitive Data, Authentication, CORS e Smart. Dettagli, prove e limiti per ciascuno nel report V5.

Le prove approfondite richiedono risorse dell'operatore, profili e canary: [CONTROLLED_CHECKS.md](CONTROLLED_CHECKS.md). XSS GET/form/JSON e CORS usano un browser isolato sulle fixture; SQL confronta SQLite read-only predisposto e resta POTENTIAL; account/file/logout/callback vengono confermati solo con evidenza circoscritta. Nessuna enumerazione massiva, lettura di file sensibili o uso di credenziali trovate. Senza configurazione: candidati, NO_INPUT o UNSUPPORTED, mai verifiche inventate.

Ogni finding ha evidenza minimizzata, limiti, origine/run, severità separata, confidenza ordinale 0–100 con fattori e priorità motivata. Il punteggio è `max(0,min(100,somma fattori))`, non una probabilità né CVSS. Le priorità sono HIGH/MEDIUM/LOW REVIEW PRIORITY e INCONCLUSIVE. FALSE_POSITIVE umano resta distinto dall'osservazione automatica; CONFIRMED umano non produce automaticamente VERIFIED.

COMPLETED significa coda elaborata, non assenza di vulnerabilità. Errori, raccolta incompleta, risposte troncate e mancanza di prove restano espliciti. Entropia, errore SQL, HTTP 200, wildcard CORS o riflessione non costituiscono da soli una vulnerabilità verificata.

## Smart, Scan Diff e report

Smart usa ricognizione compatibile, suggerimenti motivati, selezione/conferma e un checkpoint dell'intero piano. Una modifica delle versioni/configurazione/scope richiede un nuovo piano. Non inventa input, non invia form e non assume valido un account solo perché risponde HTTP 200.

Dopo l'esecuzione, RISULTATI → Scan Diff confronta run dello stesso progetto/dominio/modulo ed esporta `runs/RUN/diff/RUN_PRECEDENTE/`. Host nuovi/invariati/non osservati, metodi/parametri e finding nuovi/presenti/modificati/non riprodotti. Timestamp, request ID e nonce non generano cambiamenti semantici. Nessun finding assente viene dichiarato risolto, soprattutto con provider falliti o run incompleta.

Report JSON/Markdown/TXT per run e batch; scope, versione, attività eseguite/non eseguite, errori, evidenze, confidenza/priorità, limiti e provenienza. I batch sono snapshot, non dashboard aggiornata automaticamente dopo ogni revisione umana.

## Verifica

```bash
./.venv/bin/python -m unittest discover -s tests -v
XITOOL_BROWSER_TESTS=1 ./.venv/bin/python -m unittest discover -s tests -v
./.venv/bin/python benchmarks/benchmark_local.py --workers 5 --output verification/benchmark.json
bash verify_kali.sh --browser
```

Il browser richiede le dipendenze opzionali. Su Windows con Chrome installato impostare `XITOOL_BROWSER_CHANNEL=chrome` e `XITOOL_BROWSER_TESTS=1`. I test usano server HTTP/TLS/DNS locali, SQLite, sensore e browser controllati; niente target bug bounty pubblici. Kali nativo non verificato nell'ambiente di sviluppo: script e motivi degli skip sono documentati nel report. Non dedurre velocità da durate di suite diverse: usare il benchmark dedicato.
