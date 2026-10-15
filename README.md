# XITool 2.0.0a1

Toolkit CLI Python per ricognizione e verifiche web autorizzate. Questa è una **prima versione alpha funzionante**, non il completamento di tutti i criteri della specifica V2.0. Non usa Subfinder o Dalfox. Nessuno scanner dichiara automaticamente una vulnerabilità `VERIFIED`.

## Requisiti, installazione e avvio

Kali Linux, Python **3.10+**, modulo `venv`, accesso a PyPI durante l'installazione. Unica dipendenza: PyYAML 6.x. Nessun servizio, database, Docker o privilegio root richiesto.

```bash
bash install.sh
.venv/bin/python main.py
```

Alternativa manuale, anche su altri sistemi:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python -m unittest discover -s tests -v
.venv/bin/python main.py
```

Su Windows usare `.venv\Scripts\python.exe` al posto di `.venv/bin/python`. Il codice è stato verificato su Windows/Python 3.12; l'installer Bash e il comportamento del filesystem su Kali richiedono ancora una prova diretta su Kali.

```bash
.venv/bin/python main.py --version
.venv/bin/python main.py --config config.yaml --data-dir targets
```

## Menu e progetti

Il menu principale contiene esclusivamente **CREA PROGETTO**, **APRI PROGETTI**, **ESECUZIONE** ed **ESCI**. Non esiste un menu Settings.

Creare un progetto con nome di 1–64 caratteri ASCII, numeri, `_` o `-`. Per ogni elenco di domini usare A per aggiungere, R per rimuovere e 0 per terminare. Vengono normalizzate le regole, rimossi i duplicati e segnalati i conflitti che negano interamente una regola autorizzata. Le esclusioni prevalgono sempre, anche quando il conflitto è solo parziale. Confermare con `s` per creare il progetto. Questa operazione non contatta i target.

I progetti sono separati in `targets/<nome>/scope.json`. Il formato descritto nella specifica è mantenuto; `excluded_hosts` può mancare nei dati preesistenti e viene interpretato come elenco vuoto. Non vengono migrati formati legacy sconosciuti.

APRI PROGETTI è un visualizzatore in sola lettura: directory, TXT, JSON, CSV, YAML, LOG, JSONL e Markdown. Paginazione ogni 25 righe, limite di 16 KiB per riga, rifiuto dei symlink e dei percorsi esterni. JSON e YAML sono validati prima della visualizzazione; un file non valido produce un errore leggibile. Non vengono eseguiti script.

## Scope e rete

`example.com` autorizza esclusivamente l'host esatto. `*.example.com` autorizza tutti i suoi sottodomini, **senza** autorizzare l'apice. Una regola negata esatta non nega automaticamente i sottodomini. Sono normalizzati maiuscole, singolo punto finale e nomi IDNA tramite la libreria standard Python. Schemi diversi da HTTP/HTTPS, credenziali nell'URL, porte non consentite e host fuori scope vengono rifiutati.

Il client condiviso applica lo scope a ogni richiesta e a ogni redirect. Risolve il nome, valida tutti gli indirizzi restituiti e connette direttamente a uno di quegli indirizzi, senza una seconda risoluzione. Host HTTP e SNI TLS conservano il nome originale. I certificati TLS sono verificati. Non vengono usati proxy ambientali, cookie jar o sessioni autenticate.

Gli IP privati, loopback, link-local e speciali sono bloccati per impostazione predefinita. Per un laboratorio autorizzato, aggiungere manualmente un CIDR preciso a `scope.json`, **oltre** all'autorizzazione del relativo hostname/IP:

```json
{
  "name": "LocalLab",
  "domains": ["127.0.0.1"],
  "excluded_hosts": [],
  "allowed_ip_ranges": ["127.0.0.1/32"],
  "created_at": "2026-10-15T00:00:00Z"
}
```

La data è esemplificativa: i progetti creati dalla CLI usano l'ora UTC reale. Per una porta di laboratorio non standard occorre aggiungerla anche a `http.allowed_ports` in `config.yaml`. Multicast e indirizzi non specificati rimangono rifiutati.

## Esecuzione e Smart Execution

Selezionare uno o più progetti con numeri separati da virgole, poi un modulo. Ogni progetto conserva scope, input, run, risultati e cache separati. La validazione avviene prima della conferma complessiva; rispondere `s` solo dopo aver controllato scope, esclusioni, CIDR, attività, limiti e output. I progetti vengono eseguiti uno dopo l'altro. Ctrl+C durante una scansione salva e interrompe anche l'avvio dei progetti successivi.

Per i moduli successivi a Sub Finding vengono caricati gli input della più recente discovery **completata** e nuovamente filtrati. Smart Execution mostra proposte e conteggi in base a testo, identificatori, URL, file e autenticazione. Esegue il solo modulo selezionato e confermato. Non avvia in sequenza tutti i moduli suggeriti e non interpreta la classificazione come vulnerabilità.

## Moduli: stato reale

| Modulo | Stato | Comportamento implementato |
| --- | --- | --- |
| Sub Finding | PARTIAL | Importazione passiva da TXT locale, filtro scope, probing HTTPS/HTTP, crawl limitato, discovery statica |
| XSS | PARTIAL | Baseline e marcatore inerte su query GET osservate; riflessione e caratteri non codificati; contesto euristico |
| SQL Injection | NOT_IMPLEMENTED | Menu visibile, avvio rifiutato |
| IDOR | PARTIAL | Candidati con identificatori nella coda manuale; nessun accesso tra account |
| Broken Access Control | NOT_IMPLEMENTED | Menu visibile, avvio rifiutato |
| SSRF | PARTIAL | Classificazione degli input URL e coda manuale; nessun payload SSRF |
| Path Traversal | PARTIAL | Classificazione degli input file/percorso e coda manuale; nessuna lettura di file remoti |
| Security Misconfiguration | PARTIAL | Header mancanti, HTTPS osservato e firma di directory listing; nessun audit TLS approfondito |
| Sensitive Data Exposure | PARTIAL | Tre famiglie di firme, conteggi e revisione; valori non memorizzati né utilizzati |
| Authentication | PARTIAL | Attributi Secure/HttpOnly/SameSite dei cookie e risposte 401/403; nessun confronto account |
| CORS | PARTIAL | Baseline e Origin di test `https://xitool.invalid`; riflessione e credenziali come candidato |

`PARTIAL` descrive un'operazione realmente implementata, con i limiti della colonna precedente. IDOR/SSRF/Traversal sono esclusivamente strumenti di triage in questa alpha.

### Sub Finding e discovery

Il TXT passivo contiene **un hostname per riga**, senza URL o wildcard. La CLI richiede il percorso; vuoto significa usare i soli domini esatti autorizzati. Nessun provider online è integrato: ottenere il file da una fonte passiva consentita è attualmente un passaggio esterno. Con uno scope composto soltanto da wildcard servono host importati o URL iniziali espliciti. Non vengono inventati nomi né effettuato brute force DNS.

Ogni host filtrato è sondato su HTTPS e HTTP se le porte standard sono abilitate; si possono aggiungere URL iniziali autorizzati. Un errore HTTP non dimostra che il nome non esiste. La discovery raccoglie query GET, campi dei form, metodi e action, link e riferimenti letterali nei file JavaScript pubblici. Non esegue JavaScript, non invia form e non visita automaticamente le action dei form. Non effettua reverse engineering completo di API o applicazioni SPA.

Limiti predefiniti: profondità 2, 50 attività di discovery, 1 MiB per risposta, 1.000 link e 1.000 campi per risposta, massimo aggregato di input pari a `execution.max_tasks`. I limiti di crawl/input raggiunti sono segnalati nel report; il taglio del parser a 1.000 elementi per pagina non è conteggiato separatamente. Le risposte possono essere troncate e la discovery non è esaustiva.

Ogni run Sub Finding contiene:

```text
targets/<progetto>/runs/<run_id>/subfinding/
  all_subdomains.txt
  live_subdomains.txt
  domains_with_inputs.txt
  discovered_inputs.json
```

Gli host fuori scope non entrano negli output. Gli host autorizzati osservati sono conservati anche se non sondati o non raggiungibili. Gli input scoperti **non** sono finding di vulnerabilità. Gli endpoint registrati sono le URL effettivamente raggiunte, non l'inventario completo di tutti i riferimenti non visitati.

Per compatibilità con i percorsi richiesti, la **prima run completata** copia i quattro file anche in `targets/<progetto>/subfinding/`, se la directory non esiste. Questa copia iniziale **non viene aggiornata né sovrascritta**. Per risultati correnti usare sempre la directory della run o `latest_discovery`, come fa la CLI.

### XSS e precisione

Vengono modificati soltanto parametri già osservati in query GET, non campi di form. Il marcatore non contiene codice eseguibile. Una riflessione non codificata in risposta HTML con baseline e probe entrambi HTTP 200 genera al massimo `POTENTIAL`; una riflessione codificata resta `OBSERVED`. Le evidenze conservano indicatori e status, senza il corpo della risposta. Non c'è verifica in browser: **nessuna XSS VERIFIED** viene generata.

Gli stati condivisi usati sono `OBSERVED`, `POTENTIAL` e `MANUAL_REVIEW`; gli errori sono salvati separatamente. `VERIFIED` e `FALSE_POSITIVE` non vengono assegnati automaticamente. Non vengono prodotte percentuali di confidenza. Per CORS, `*` da solo non determina una vulnerabilità.

## Autosave, checkpoint e ripresa

Ogni run ha identificatore UTC e componente casuale. `metadata.json` conserva la configurazione identificativa iniziale; `checkpoint.json` contiene versione, progetto/modulo, stato, coda, completati, dati e risultati, contatori e impronte di scope/configurazione. Lo snapshot usa checksum SHA-256 per rilevare corruzione accidentale; non costituisce autenticazione contro modifiche locali intenzionali.

Un thread salva ogni 30 secondi; il worker salva anche ogni 10 attività, alla fine e su Ctrl+C o errore Python. I file sono scritti in un temporaneo adiacente, sincronizzati e sostituiti atomicamente. Un'interruzione brutale può perdere il lavoro dopo l'ultimo checkpoint. Le attività non registrate possono essere ripetute: non è garantita l'esecuzione esattamente una volta. I/O fallito viene segnalato; nessun programma può garantire nuovi salvataggi se il disco è pieno o non scrivibile.

Rientrando in ESECUZIONE con stesso progetto e modulo viene proposta la run incompleta più recente. La ripresa controlla formato, checksum, identità e configurazione. Una configurazione cambiata richiede il ripristino dei valori precedenti o una nuova scansione. Uno scope cambiato causa un nuovo filtro di coda, risultati, host e input: gli elementi non più autorizzati vengono rimossi dalla run in ripresa. I metadati iniziali restano conservati. Una nuova scansione non sovrascrive una run precedente.

Il lock `.execution.lock` impedisce due esecuzioni contemporanee nello stesso progetto. Dopo una terminazione forzata può rimanere: **verificare che il PID indicato non sia più in esecuzione**, poi rimuovere manualmente quel singolo lock. Il programma non presume automaticamente che un lock sia obsoleto. Non usare processi esterni per modificare scope, file o symlink durante la scansione: lo scope attivo è lo snapshot confermato, non una configurazione aggiornata in tempo reale.

## Rate limiting, cache e monitor

Il limite massimo configurato non viene superato e le richieste sono distanziate senza raffiche. HTTP 429/503 e timeout riducono la velocità, i successi la recuperano gradualmente. `Retry-After` numerico o in formato data è rispettato; un'attesa superiore a cinque minuti produce un errore dell'attività, da riprovare in una nuova run quando appropriato. I retry sono limitati e le destinazioni dei redirect vengono validate separatamente.

Il worker è **sequenziale**: `max_concurrency` è un tetto e attualmente resta una sola richiesta in volo. La riduzione adattiva della concorrenza oltre questo livello non è implementata. DNS ha timeout e al massimo un resolver daemon bloccato per client; un watchdog limita la durata di ciascuna richiesta. Sono supportate risposte in chiaro secondo `Accept-Encoding: identity`; il client non decodifica contenuti compressi restituiti contro tale richiesta.

La cache è **solo in memoria e per run**, separata per progetto/client, scope, URL e Origin. TTL predefinito 300 secondi, massimo 64 risposte. Non salva risposte con Set-Cookie o direttive `private`/`no-store`; non esistono sessioni autenticate. Le prove XSS e le richieste CORS con Origin bypassano la cache. La cache non viene ripristinata alla ripresa.

Il monitor si aggiorna tra le attività e mostra progetto, modulo, stato, completati/rimanenti, finding/input, richieste al secondo, errori HTTP, timeout, cache hit, ultimo checkpoint e limite corrente. La discovery resta a progresso indeterminato mentre può aggiungere attività. I contatori HTTP descrivono la **sessione di esecuzione corrente**, non la somma delle sessioni prima e dopo una ripresa. Il monitor non ha ridisegno continuo mentre una richiesta è in corso, né un rilevatore separato di stalli; timeout e watchdog limitano le attese di rete. Il filesystem e i resolver di sistema possono comunque avere limiti propri.

## Revisione, diff e report

Al termine di una run il sottomenu RISULTATI permette di leggere file, aggiornare la coda manuale, confrontare una run precedente dello stesso progetto/modulo e rigenerare report. Le valutazioni manuali hanno stati `PENDING_REVIEW`, `IN_REVIEW`, `CONFIRMED`, `DISMISSED`, sono salvate atomicamente e mantenute alla ripresa. `CONFIRMED` registra la valutazione umana: non cambia retroattivamente il finding automatico in `VERIFIED`. Non è ancora presente l'inserimento di note o prove manuali aggiuntive.

Il diff confronta host, host attivi, endpoint, input e finding per identificatori stabili, ignorando timestamp e run ID. Distingue nuovi, non più rilevati, modificati e invariati. Segnala cambiamenti di scope/configurazione. Non assegna automaticamente «risolto» o «non più riproducibile». URL semanticamente equivalenti con diverso ordine della query possono essere considerate diverse in questa alpha.

Ogni run conserva `findings.json`, `manual_review.json`, `events.jsonl`, `report.json` e `report.md`. I report includono scope, stato, riepilogo, evidenze, errori e limiti. `COMPLETED` significa che la coda è stata processata: verificare sempre gli errori e i limiti raggiunti. Rigenerare un report aggiorna i file della stessa run; le altre run restano distinte.

I valori di cookie e segreti riconosciuti nel contenuto non vengono salvati. URL con parametri di autenticazione riconoscibili sono esclusi, così come percorsi riconoscibili di logout/cancellazione/acquisto. **La classificazione non può riconoscere ogni segreto né ogni GET con effetti collaterali**: scegliere seed e scope di verifica appropriati e non importare URL contenenti credenziali o dati riservati. Le URL operative, compresi i valori di query non riconosciuti come sensibili, vengono persistite per consentire la ripresa. Non vengono inviati POST, brute force o payload di esfiltrazione.

Lo snapshot JSON ha un limite di 32 MiB; suddividere scansioni molto grandi. I dati applicativi restano nei progetti e vanno trattati secondo le autorizzazioni del programma di verifica.

## Test e sviluppo rimanente

```bash
.venv/bin/python -m unittest discover -s tests -v
```

I test usano mock e server effimeri su `127.0.0.1` con autorizzazione esplicita. Non eseguono scansioni verso target pubblici. Coprono scope, IDNA, IP speciali, DNS fissato, redirect, cache, rate limiting, filesystem, checkpoint/ripresa, crash simulati, conferme, multiprogetto, scanner, revisioni, diff e report. Il test dei symlink reali viene saltato quando il sistema non consente di crearli. Non sono prove di spegnimento improvviso o di tutti i possibili guasti del filesystem.

Per il dettaglio delle fasi e delle verifiche eseguite vedere `DEVELOPMENT.md`. Restano: provider passivi online, convalida XSS in browser isolato, workflow con account/ruoli e fixture autorizzate, controlli TLS completi, monitor continuo, selezione multipla delle proposte Smart, revisione di run storiche direttamente dalla CLI, e validazione su Kali. Le run storiche sono già leggibili dal file manager; la modifica della coda manuale dalla CLI è disponibile nel sottomenu della run appena eseguita.

Usare esclusivamente in laboratori, bug bounty e verifiche per cui si possiede autorizzazione esplicita. I risultati automatici richiedono interpretazione nel contesto del target.
