# XITool 2.0.0a2

Toolkit CLI Python per ricognizione e verifiche web autorizzate, con risultati e checkpoint separati per dominio. Versione alpha: gli scanner parziali sono indicati esplicitamente e nessun risultato viene dichiarato automaticamente `VERIFIED`. Non usa Subfinder o Dalfox.

## Installazione e avvio

Kali Linux, Python **3.10+**, modulo `venv` e accesso a PyPI durante l'installazione. Unica dipendenza: PyYAML 6.x. Non sono necessari privilegi root per installare il progetto.

```bash
cd ~/XITool-git
bash install.sh
.venv/bin/python main.py
```

L'installer crea l'ambiente, installa le dipendenze ed esegue i test prima di completare l'installazione. Rifiuta cartelle in sola lettura e riconosce una `.venv` Windows incompatibile con Kali. Le impostazioni tecniche restano in `config.yaml`; non esiste un menu Settings.

Genera anche `.venv/bin/XITool`, utilizzabile da qualsiasi directory. Se `~/.local/bin/XITool` non esiste, crea un collegamento a questo launcher. Un comando preesistente, anche configurato esternamente, viene conservato: se punta a un'altra copia continuerà ad avviarla. Per scegliere esplicitamente questa installazione:

```bash
~/XITool-git/.venv/bin/XITool
```

Se necessario, aggiungere la directory dei comandi al PATH del terminale: `export PATH="$HOME/.local/bin:$PATH"`.

Installazione manuale:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python -m unittest discover -s tests -v
.venv/bin/python main.py
```

Su Windows usare `.venv\Scripts\python.exe` al posto di `.venv/bin/python`. La verifica corrente è su Windows/Python 3.12 con HTTP locale; installer e launcher richiedono ancora una prova nativa su Kali. `.gitattributes` mantiene LF negli script distribuiti tramite Git.

Opzioni: `--config`, `--data-dir`, `--version`. Configurazione e dati predefiniti sono relativi a `main.py`: l'avvio funziona da una directory differente. I percorsi relativi passati esplicitamente nelle opzioni si riferiscono alla directory corrente.

## Menu e inserimento domini

Il menu principale mantiene esclusivamente:

```text
[1] CREA PROGETTO
[2] APRI PROGETTI
[3] ESECUZIONE

[0] ESCI
```

Nome progetto: 1–64 caratteri ASCII fra lettere, numeri, `_` e `-`, senza traversal o nomi riservati. Per autorizzati e negati usare A per aggiungere, R per rimuovere e 0 per terminare.

Dopo A, incollare uno o più domini e **premere INVIO su una riga vuota**. Tutte le righe sono lette prima di tornare al menu. Supportati: righe, virgole, spazi, wildcard esplicite e prima colonna di tabelle separate da TAB o `|`. Le frasi ambigue sono rifiutate. Il riepilogo mostra validi, duplicati e non validi; errori o interruzioni del batch non cancellano le voci già valide.

URL HTTP/HTTPS sono ridotti all'host. Lo scarto di percorso, query, frammento o porta viene segnalato: la regola riguarda l'intero host. Credenziali URL rifiutate; nessuna wildcard implicita. Confermare con `s` il riepilogo completo per creare il progetto, senza contattare target. Le regole non confermate restano soltanto in memoria.

## Struttura per dominio

```text
targets/EXNESS/
  scope.json
  pwapi.ex2b.com/
    subfinding/
      all_subdomains.txt
      live_subdomains.txt
      domains_with_inputs.txt
      discovered_inputs.json
      latest.json
    xss/
      findings.json
      manual_review.json
      latest.json
    reports/<run_id>.json, <run_id>.md
    runs/<run_id>/
      metadata.json
      checkpoint.json
      events.jsonl
      findings.json
      manual_review.json
      report.json
      report.md
      subfinding/       # nelle run Sub Finding
  my.exness.com/
    ...
```

Le cartelle dei root sono automatiche; i moduli vengono creati quando servono. Nomi DNS completi e normalizzati; solo IPv6 e nomi riservati richiedono codifica sicura, con rifiuto delle collisioni. Una cartella aggiunta manualmente non autorizza un target.

`scope.json` mantiene `name`, `domains`, `excluded_hosts`, `created_at` e l'eventuale `allowed_ip_ranges`; `excluded_hosts` mancante equivale a elenco vuoto. I root derivano dallo scope, non dal filesystem. Dominio esatto e relativa wildcard condividono la cartella base senza modificarne le autorizzazioni; root interamente negati non vengono proposti.

La vista `<dominio>/<modulo>/` rappresenta l'ultima run completata. `latest.json` contiene origine e impronte dei file. File preesistenti o modificati dall'utente non vengono sovrascritti: i nuovi dati restano nella run. Un indice non corrispondente è segnalato in lettura; gli snapshot della cronologia restano disponibili anche su export interrotto.

## Esecuzione e scope

Flusso: **progetto → domini → modulo → conferma → esecuzione → risultati**. La selezione multiprogetto è mantenuta con domini indipendenti.

Scegliere TUTTI I DOMINI oppure SELEZIONA DOMINI. La modalità manuale supporta singoli numeri, `1,3,5`, `1-4`, toggle, A per tutti, D per nessuno, C per confermare. `[X]` indica la selezione; conferma vuota rifiutata.

Ogni dominio ha input, run, risultati, lock, cache e checkpoint separati. File passivo e URL aggiuntivi sono richiesti una volta per progetto e filtrati per root. Dopo il riepilogo serve un'unica conferma di avvio. Un dominio alla volta; errori su uno non bloccano i successivi. Ctrl+C salva e lascia gli altri non elaborati. Riepilogo finale con successi, errori e attese.

Il root selezionato limita ulteriormente scope, link, form action e redirect. Nei root sovrapposti l'host appartiene al root configurato più specifico: gli host di `api.example.com` non vengono duplicati sotto `example.com`.

- `example.com`: solo l'host esatto.
- `*.example.com`: sottodomini, senza l'apice.
- Un deny prevale sempre; un deny esatto non nega automaticamente i discendenti.
- Un sottodominio scoperto non diventa automaticamente autorizzato.
- Case, singolo punto finale e IDNA sono normalizzati.

Il client condiviso ammette HTTP/HTTPS e porte configurate. Ogni redirect è validato. Risolve il nome, verifica tutti gli IP e connette direttamente all'indirizzo validato, senza seconda risoluzione. Peer corrispondente, Host/SNI originali e certificati TLS verificati dal sistema. Nessun proxy ambientale, cookie jar o sessione autenticata.

IP privati, loopback e speciali sono bloccati salvo CIDR esplicito in `allowed_ip_ranges`, oltre all'autorizzazione dell'hostname/IP. Esempio di laboratorio: dominio `127.0.0.1` e CIDR `127.0.0.1/32`; le porte non standard vanno aggiunte a `http.allowed_ports`. Multicast e indirizzi non specificati restano vietati. Lo scope attivo è quello confermato, non ricaricato continuamente durante la scansione.

## Moduli reali

| Modulo | Stato | Implementazione |
| --- | --- | --- |
| Sub Finding | PARZIALE | TXT passivo locale, scope, probing HTTP/HTTPS, crawl limitato, query/form/JS statico |
| XSS | PARZIALE | Baseline e marcatore inerte su query GET; contesto euristico; nessun browser |
| SQL Injection | NON IMPLEMENTATO | Bloccato prima delle richieste |
| IDOR | PARZIALE | Classificazione identificatori e coda manuale, senza confronto account |
| Broken Access Control | NON IMPLEMENTATO | Bloccato prima delle richieste |
| SSRF | PARZIALE | Classificazione input URL, senza payload SSRF |
| Path Traversal | PARZIALE | Classificazione file/percorso, senza lettura file remoti |
| Misconfiguration | PARZIALE | Header, HTTPS e firma directory listing; nessun audit TLS approfondito |
| Sensitive Data Exposure | PARZIALE | Tre famiglie di firme pubbliche, conteggi mascherati e revisione |
| Authentication | PARZIALE | Attributi cookie e hint 401/403, senza account |
| CORS | PARZIALE | Baseline e Origin `https://xitool.invalid`; riflessione/credenziali come candidato |

Il menu distingue anche DISPONIBILE, senza promuovere scanner incompleti. Gli identificatori interni `PARTIAL` e `NOT_IMPLEMENTED` restano compatibili. Tutti i moduli operativi usano client, scope e checkpoint comuni e salvano nel dominio corretto.

Sub Finding non integra provider passivi online: importare un TXT da fonte consentita, un host per riga. Nessun brute force DNS o nome inventato. Con sole wildcard servono host importati o URL iniziali autorizzati. Irraggiungibilità non significa inesistenza. La discovery non invia form né esegue JavaScript, analizza riferimenti letterali pubblici.

Limiti: profondità 2, 50 attività per dominio, 1 MiB/risposta, 1.000 link/campi per pagina, input aggregati limitati da `execution.max_tasks`. Limiti crawl/input segnalati; limite parser non conteggiato separatamente. Gli endpoint registrati sono quelli raggiunti, non tutti i riferimenti non visitati. Gli input non sono vulnerabilità.

Gli scanner successivi caricano solo l'ultima discovery completata dello stesso dominio, filtrandola di nuovo. Smart Execution propone moduli per tipo di input, esegue solo quello scelto/confermato; selezione multipla dei suggerimenti non implementata.

XSS usa solo query GET osservate, senza form. Riflessione non codificata in HTML con baseline/probe HTTP 200: al massimo POTENTIAL; codificata: OBSERVED. Nessun codice eseguito in browser. CORS `*` da solo non è una vulnerabilità. Stati automatici: OBSERVED, POTENTIAL, MANUAL_REVIEW; errori separati e nessuna confidenza percentuale arbitraria.

## Checkpoint e migrazione

ID run univoco UTC; snapshot coerente di coda/risultati con SHA-256 contro corruzione accidentale. Versione 1 per il vecchio formato, versione 2 con identità del dominio verificata. Autosave ogni 30 secondi, 10 attività e su interruzione/errore; file temporaneo adiacente, flush/fsync, sostituzione atomica. Limite snapshot 32 MiB. Dopo kill/spegnimento può mancare il lavoro successivo all'ultimo salvataggio e alcune richieste possono ripetersi. Disco pieno e permessi sono segnalati; il checkpoint valido precedente resta recuperabile.

La ripresa riguarda stesso progetto/dominio/modulo. Configurazione diversa: ripristinare o creare nuova run. Scope diverso: nuovo filtro e backup `checkpoint_before_<impronta>.json` prima di scrivere lo stato filtrato, dopo la conferma; i dati precedenti restano nel backup. Metadati iniziali conservati.

Lock `<dominio>/.execution.lock` contro doppie esecuzioni. Dopo kill verificare il PID prima di rimuovere manualmente quel singolo lock. Un vecchio lock di progetto impedisce la migrazione.

Entrando in ESECUZIONE lo storico `targets/<progetto>/runs/` viene copiato e filtrato, senza modificare gli originali. Provenienza e impronta sono in `metadata.json`; importazioni già presenti non vengono duplicate. Conteggi legacy non attribuibili ai domini restano nei metadati, senza ripartizioni artificiali. Anche i vecchi file `subfinding/` senza checkpoint sono importabili: `import_only` distingue l'import dalla scansione e la data è quella dell'importazione. Non sostituiscono viste correnti già generate. Formati sconosciuti/corrotti sono segnalati e gli originali restano consultabili.

## Consultazione, revisione, diff e report

APRI PROGETTI: progetto → dominio → modulo → file, con disponibilità, report e cronologia. Sub Finding espone i quattro output. Lo storico precedente rimane leggibile. È sola lettura: non migra, crea file o avvia scanner. TXT, JSON, CSV, YAML, LOG, JSONL e Markdown sono paginati ogni 25 righe, limite 16 KiB/riga. Symlink/traversal rifiutati, JSON/YAML corrotti segnalati, escape del terminale neutralizzati.

RISULTATI dopo il batch permette anche Manual Review, Scan Diff e rigenerazione report. Stati umani: PENDING_REVIEW, IN_REVIEW, CONFIRMED, DISMISSED; conservati alla ripresa. CONFIRMED non trasforma l'esito automatico in VERIFIED. Note/prove manuali aggiuntive e modifica delle code dalla sezione APRI PROGETTI non implementate.

Diff soltanto nello stesso progetto/dominio/modulo: nuovi, non più rilevati, modificati e invariati, ignorando timestamp/run ID. Non assegna «risolto» o «non più riproducibile». Ordine diverso della query può ancora produrre identità distinte.

Report Markdown/JSON: scope, dominio, stato, riepilogo, evidenze, errori e limiti. COMPLETED significa coda processata, non assenza di errori. Un export fallito porta a FAILED quando il checkpoint è scrivibile, preservando i finding persistiti. Ogni run mantiene finding, review, eventi e report distinti.

## Rate limit, cache e monitor

Richieste distanziate, tetto configurato, rallentamento 429/503/timeout, recupero graduale, Retry-After numerico/data. Il budget HTTP e il backoff del batch sono conservati anche nel cambio di dominio; cache e contatori restano separati. Attese oltre cinque minuti generano un errore dell'attività; retry/redirect limitati. Worker sequenziale; adattamento di concorrenza oltre uno non implementato. Timeout DNS e watchdog; risposte compresse contro Accept-Encoding identity rifiutate, senza analizzarle come testo.

Cache solo in memoria per dominio/run, separata per scope, URL e Origin: TTL 300 secondi, 64 risposte. Niente Set-Cookie, private/no-store o autenticazione. Probe XSS/CORS bypassano la cache; corpi rilasciati al termine di ogni dominio, nessun ripristino da checkpoint.

Monitor fra attività: indice del dominio, progetto/root/modulo, attività, finding/input, richieste/sec, errori HTTP e attività, timeout, cache hit, checkpoint e rate. Discovery indeterminata mentre aggiunge lavoro. Contatori della sessione corrente, media dall'avvio effettivo; nessun ridisegno continuo o rilevatore dedicato di stalli.

## Test e limiti residui

```bash
.venv/bin/python -m unittest discover -s tests -v
```

Mock e server autorizzati su loopback, senza target pubblici. Verifiche di incollaggio, selezione, isolamento, scanner, redirect/DNS/IP, interruzione/ripresa, migrazione, sola lettura, export/diff/cache e avvio da altra directory. Test Bash/launcher POSIX e symlink vengono saltati quando non supportati: non sono dichiarati superati. Risultati esatti in DEVELOPMENT.md.

Restano da provare nativamente su Kali installer/launcher. Restano parziali provider online, XSS in browser, confronti account/ruoli, TLS approfondito, monitor continuo e selezione multipla Smart. SQL Injection e Broken Access Control non implementati.

Cookie e segreti riconosciuti nei corpi non vengono salvati. Parametri di autenticazione e percorsi GET mutativi riconoscibili sono esclusi. La classificazione non riconosce ogni segreto o GET con effetti collaterali: URL e query non riconosciute come sensibili sono persistite per la ripresa. Non importare credenziali o dati riservati. Nessun POST, brute force o payload di esfiltrazione.

Usare esclusivamente per laboratori e verifiche esplicitamente autorizzate; interpretare le osservazioni nel contesto del target.
