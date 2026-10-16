# Refactor multi-dominio — XITool 2.0.0a2 — 16 ottobre 2026

## Risultato e verifica

Implementazione incrementale nel repository esistente: nessuna ricostruzione del progetto e nessuna nuova dipendenza. Il menu principale conserva le quattro voci richieste. Il banner bianco `XITool | Feel free` è mantenuto. Non sono state eseguite scansioni su target pubblici, né push o commit su GitHub.

**Ultima esecuzione: 110 test, 107 superati, zero fallimenti/errori, 3 saltati; durata 73,417 secondi.** Ambiente Windows/Python 3.12, PyYAML disponibile nell'ambiente di test. I test di rete usano mock e laboratori autorizzati su loopback.

I tre test saltati sono: creazione di symlink reali, sintassi dell'installer con Bash, installazione/launcher su filesystem POSIX. Questo ambiente non consente la verifica nativa della VM Kali. I due test POSIX sono inclusi nella suite per l'esecuzione su Kali; nel test dell'installer pip e unittest sono simulati per evitare download e ricorsione. Non sono dichiarati superati qui. Avvio Python reale da una directory differente e laboratorio HTTP reale con cartelle per dominio: superati.

Il primo ciclo del refactor ha rilevato un errore nel nuovo simulatore CORS, che non accettava il secondo argomento posizionale degli header. È stato corretto il simulatore e ripetuta la suite. L'esecuzione finale riportata sopra riguarda l'ultimo codice applicativo.

## Analisi preliminare e correzioni

Sono stati esaminati tutti i moduli Python applicativi, gli entry point, i tre moduli di test preesistenti, `config.yaml`, `requirements.txt` e `install.sh`. Il motore era sequenziale e già centralizzava HTTP/scope/checkpoint, ma salvava a livello progetto. I moduli effettivi sono rimasti quelli dichiarati nel README; non sono stati aggiunti scanner fittizi.

Bug e limiti corretti:

1. **Incollaggio multilinea:** A leggeva una sola riga e le successive finivano nei menu. Ora la modalità dedicata consuma le righe fino alla riga vuota, normalizza, deduplica e mostra il riepilogo, anche per i deny. Formati supportati: singolo, multilinea, virgole/spazi, prima colonna TAB/pipe, URL con avviso sull'eliminazione di percorso/query/porta. Frasi ambigue e credenziali URL vengono rifiutate.
2. **Risultati mescolati:** la CLI usa un Engine per root, con output, lock, report, cache e checkpoint indipendenti. Le cartelle nascono dallo scope; cartelle manuali non diventano autorizzazioni.
3. **Attraversamento fra root:** il client conserva lo scope globale e applica in più il root scelto. Anche link, form action e redirect verso un altro root autorizzato del progetto vengono esclusi da quella scansione. Nei root sovrapposti prevale il root configurato più specifico, evitando doppia attribuzione.
4. **Viste correnti obsolete:** l'export iniziale non veniva aggiornato. Ogni root ora ha una vista corrente legata alla run con impronte; viene aggiornata solo se i file precedenti non sono stati modificati. Lo snapshot per run rimane distinto. Il file manager rileva indici incompleti o modificati.
5. **Ripresa e conservazione:** l'identità del dominio viene verificata nei checkpoint versione 2. Cambi di scope filtrano il lavoro attivo dopo aver conservato il checkpoint precedente; configurazioni incompatibili vengono rifiutate. Il vecchio formato versione 1 rimane leggibile.
6. **Migrazione:** copie filtrate dei vecchi run, originali invariati e import idempotente. Supportati anche export Sub Finding senza checkpoint, marcati import-only. ID completati e contatori HTTP non attribuibili ai singoli domini non vengono ripartiti artificialmente: i valori legacy rimangono nei metadati.
7. **Errori e interruzioni:** un errore di dominio non blocca gli altri; Ctrl+C salva e ferma il batch lasciando gli altri in attesa. Un fallimento dell'export marca FAILED se il checkpoint resta scrivibile, senza eliminare i finding persistiti. Il riepilogo compare anche quando tutti i domini sono privi di input.
8. **Crawl duplicato:** una URL fallita non viene rimessa in coda solo perché è riapparsa a un'altra profondità.
9. **Traffico:** cambiare dominio non azzera più budget/backoff HTTP. Il batch condivide il limite conservativo, mantenendo cache e contatori dei domini separati.
10. **Memoria e monitor:** le risposte in cache sono rilasciate al termine di un dominio; la media HTTP parte dall'avvio effettivo e rimane riferita alla durata della sessione dopo la conclusione. Eliminato l'attributo temporale non utilizzato del motore.
11. **Scanner e risposte inattese:** moduli sconosciuti/non implementati bloccati prima delle richieste, parametri invalidi segnalati, risposte compresse contro Accept-Encoding identity rifiutate invece di essere interpretate come testo.
12. **Installazione:** directory in sola lettura e venv Windows riconosciute; launcher relativo alla propria installazione, collegamento locale soltanto se non esiste un comando esterno, LF fissato per script Python/Bash tramite Git.
13. **Origine degli input:** quando la stessa query GET compareva anche in un form, la deduplicazione poteva sostituire l'origine osservata con quella del form e far saltare un controllo pertinente. Il merge ora è condiviso e conserva la priorità di query/link già osservati, senza inviare form.

## File modificati

| File | Responsabilità della modifica |
| --- | --- |
| `xitool/cli.py` | Inserimento batch, selezioni/intervalli, flusso progetto-domini-modulo, consultazione per dominio, riepilogo e monitor |
| `xitool/scope.py` | Parsing prudente degli elenchi, root autorizzati, proprietario più specifico e scope vincolato al root |
| `xitool/storage.py` | Creazione cartelle root, nomi sicuri, collisioni e compatibilità dei progetti |
| `xitool/execution.py` | Versione 2 dei checkpoint, isolamento, batch, migrazione, export correnti, report per root, backup e gestione errori |
| `xitool/http.py` | Rifiuto di risposte compresse inattese |
| `xitool/scanners.py` | Guardie prima dell'HTTP e deduplicazione condivisa che conserva le query osservate |
| `xitool/__init__.py` | Versione 2.0.0a2 |
| `install.sh` | Diagnostica, venv e launcher portabile, preservazione del comando esterno |
| `tests/test_execution_cli.py` | Adeguamento dei flussi di conferma e selezione multiprogetto |
| `tests/test_http_scanners.py` | Workflow HTTP locale reale per dominio e regressione query GET presente anche nei form |
| `tests/test_multidomain.py` — nuovo | Regressioni dedicate alla nuova funzionalità, alla migrazione e al launcher; separazione concreta dai test precedenti |
| `.gitattributes` — nuovo | Terminatori LF per compatibilità Windows/Kali |
| `README.md` | Uso, layout, migrazione, moduli reali e limitazioni |
| `DEVELOPMENT.md` | Questo rapporto; lo storico della consegna precedente è conservato sotto |

`main.py`, `requirements.txt`, `config.yaml` e i test di scope/storage precedenti sono stati analizzati e riutilizzati. Nessuna dipendenza aggiunta, nessuna directory segnaposto per scanner futuri, nessun risultato utente eliminato. Configurazione e dati runtime non sono inclusi nel pacchetto come risultati reali.

## Nuovo layout e migrazione

```text
targets/<progetto>/scope.json
targets/<progetto>/<dominio>/subfinding/<quattro output e latest.json>
targets/<progetto>/<dominio>/<modulo>/findings.json
targets/<progetto>/<dominio>/reports/<run_id>.json e .md
targets/<progetto>/<dominio>/runs/<run_id>/<checkpoint, eventi, finding, review, report>
```

I root sono derivati dai domini autorizzati normalizzati, con esclusioni prevalenti. `example.com` non autorizza sottodomini; `*.example.com` non autorizza l'apice. Nessuna wildcard è aggiunta implicitamente. La cartella usa il nome DNS completo; IPv6/nomi riservati sono codificati e le collisioni sono rifiutate.

La preparazione delle cartelle e la copia dello storico avvengono nella creazione/ESECUZIONE, non nella sezione APRI PROGETTI. Lo storico originale per progetto rimane consultabile senza modifiche. Il vecchio Engine senza target resta compatibile per gli usi programmatici legacy; la CLI corrente crea esclusivamente Engine vincolati a un root.

## Test pertinenti effettivamente eseguiti

- Sei domini incollati consecutivamente attraverso la creazione completa, senza ritorni prematuri al menu; stesso meccanismo per i negati, duplicati fra batch, singolo dominio, virgole/spazi, URL, tabelle, errori e Ctrl+C/Ctrl+D durante l'inserimento.
- Scelte tutti, `1,3,5`, `1-4`, A/D, toggle, selezione vuota e ritorno indietro.
- Creazione delle sei cartelle complete senza contatti di rete; cartella non autorizzata esclusa; wildcard senza apice, deny e root sovrapposti.
- Batch di tre domini sequenziali, output/report/cronologie separati; errore di uno seguito dal successo di un altro; Ctrl+C e domini successivi PENDING.
- Blocchi redirect fra domini, scope su tutte le richieste, DNS/IP/peer e destinazioni speciali, timeout/retry/backoff; budget HTTP conservato fra domini.
- Tutti i nove moduli realmente operativi/parziali esercitati con input pertinenti, report nel dominio corretto e scanner non implementati bloccati prima dell'HTTP.
- Discovery e sette scanner in un laboratorio HTTP reale autorizzato su loopback, nella struttura versione 2.
- Ripresa per dominio, rigetto del checkpoint di un altro dominio, scope/config cambiati, backup pre-filtro, scritture interrotte e crash simulati.
- Migrazione di run completata e interrotta, ripresa di un solo dominio importato, import di vecchi export senza checkpoint, originali byte-per-byte invariati e seconda migrazione senza duplicati.
- Consultazione APRI PROGETTI con verifica che nessun file cambi e nessun Engine sia eseguito; aggiornamento della vista corrente senza sovrascrivere run precedenti o file modificati dall'utente.
- Errori di export, cache rilasciata, revisione manuale e diff; avvio reale da un'altra directory.

Il fallimento di rete o di una singola attività resta un errore documentato, non un finding di vulnerabilità. COMPLETED indica coda processata; il riepilogo segnala separatamente domini con errori.

## Moduli e lavori ancora aperti

Operativi ma **PARZIALI**: Sub Finding (import passivo locale e discovery), XSS (riflessione senza browser), IDOR/SSRF/Path Traversal (classificazione e revisione), Misconfiguration, Sensitive Data Exposure, Authentication e CORS. **NON IMPLEMENTATI**: SQL Injection e Broken Access Control. Smart Execution propone controlli in base agli input ma non esegue una selezione multipla automatica. Nessun esito viene promosso a VERIFIED senza prova.

Restano da verificare nativamente su Kali i due test POSIX dell'installer/launcher e i symlink. Restano limiti già espliciti: provider passivi online assenti, nessun browser di verifica XSS o confronto account/ruoli, TLS non approfondito e monitor aggiornato fra attività. La migrazione supporta i formati XITool noti, non schemi arbitrari. Non sono stati simulati spegnimenti reali o tutti i guasti possibili del filesystem.

## Comandi per la versione aggiornata

Dopo aver trasferito i file aggiornati nella propria copia Kali:

```bash
cd ~/XITool-git
bash install.sh
.venv/bin/python main.py
```

Da un'altra directory: `~/XITool-git/.venv/bin/XITool`. Verifica manuale della suite: `.venv/bin/python -m unittest discover -s tests -v`. Le modifiche locali sono pronte da revisionare; **nessun push è stato effettuato**.

---

# Storico della consegna precedente


# Report di sviluppo — 15 ottobre 2026

## Stato della consegna

**2.0.0a1: alpha operativa, specifica V2.0 non completata.** La directory fornita conteneva solo `outputs/` e `work/`, senza repository sorgente, progetti, dipendenze o test esistenti. È stato creato un progetto autonomo in `outputs/XITool`, senza alterare file preesistenti dell'utente. Non sono stati creati moduli scanner vuoti.

La validazione finale di questo incremento ha eseguito **67 test: 66 superati, 0 falliti, 1 saltato**. Il salto riguarda la creazione di symlink reali, non consentita dall'ambiente Windows corrente. I test usano HTTP simulato e due laboratori effimeri su loopback; nessun target pubblico è stato scansionato. Il solo download esterno è stato quello di PyYAML, autorizzato per l'ambiente di test.

## Fasi e file

Le verifiche elencate qui sono quelle effettivamente eseguite nella suite cumulativa. I moduli applicativi nuovi separano responsabilità concrete; i tre file di test separano i gruppi di regressioni. Tutti i file applicativi di questa consegna sono nuovi, essendo vuota la directory iniziale.

| Fase | Funzioni e file creati/modificati | Verifica eseguita | Stato, limiti e prosecuzione |
| --- | --- | --- | --- |
| 1 — Analisi | Esame directory e lettura integrale della specifica allegata; nessun codice precedente da riutilizzare | Ispezione filesystem | Conclusa. Proseguito con un progetto autonomo. |
| 2 — Fondamenta | `main.py`, `xitool/cli.py`, `xitool/storage.py`, `xitool/__init__.py`: menu, progetti, visualizzazione file, configurazione | Creazione, nomi invalidi, duplicati, traversal, menu, paginazione, controlli terminale, JSON corrotto | Implementata. Symlink reale da riverificare su Linux. |
| 3 — Scope | `xitool/scope.py`: regole esatte/wildcard, esclusioni, IDNA, URL, IP/CIDR | Matrice autorizzazioni, domini simili, IDNA, URL invalidi, IP speciali, scope modificato in ripresa | Implementata per i formati documentati. Nessuna migrazione di schemi legacy sconosciuti. |
| 4 — HTTP | `xitool/http.py`: connessione all'IP validato, verifica peer, TLS, redirect, retry, timeout DNS, watchdog | DNS mock, assenza di seconda risoluzione, redirect negato, mismatch peer, resolver bloccato, HTTP reale loopback | Implementata con limiti: client GET anonimo, nessun test TLS end-to-end con certificato locale; installer/Kali da verificare. |
| 5 — Execution | `xitool/execution.py`, CLI: code per progetto, selezione multipla, conferme, lock e run univoche | Conferma negativa senza avvio, selezione multiprogetto, isolamento, lock, duplicati, storico | Implementata in modalità sequenziale. Concorrenza maggiore di uno non implementata. |
| 6 — Checkpoint | `storage.py`, `execution.py`: scrittura atomica, checksum, salvataggio per tempo/numero, Ctrl+C, ripresa | Scrittura interrotta simulata, Ctrl+C, crash Python, ripresa, scope/config cambiati, JSON e struttura corrotti, autosave durante attività | Implementata per i casi testati. Spegnimento e guasti reali disco non testati; lock residuo dopo kill da rimuovere manualmente. |
| 7 — Sub Finding | `scanners.py`, `execution.py`, CLI: import passivo locale, probing, crawl limitato, form/query/JS, quattro export | Scope prima del probing, parsing HTML e JS, export, laboratorio HTTP completo | **Parziale**: nessun provider passivo online. Prossimo lavoro: integrazione controllata di fonti passive. |
| 8 — XSS | `scanners.py`: baseline, marcatore inerte, contesto euristico, separazione osservazione/candidato | Riflessione non codificata, riflessione codificata, controllo locale con query | **Parziale**: nessuna verifica di esecuzione nel browser; nessun risultato VERIFIED. |
| 9 — Smart Execution | `scanners.py`, CLI: classificazione e conteggi dei moduli pertinenti | Classificazione, esclusione form/POST dai candidati XSS | **Parziale**: propone e applica il modulo scelto; manca una selezione multipla dei moduli proposti. |
| 10 — Precisione e prestazioni | HTTP/scanner: cache volatile TTL e Origin separato, backoff e Retry-After, evidenze conservative | TTL, cookie non in cache, Origin separato, retry timeout, 429 limitati, distanza richieste, wildcard CORS non confermata | **Parziale**: non sono implementati confronti statistici di risposte dinamiche né adattamento di concorrenza oltre il worker singolo. |
| 11 — Risultati | `execution.py`, CLI: finding, Manual Review Queue, diff, report Markdown/JSON | Stati manuali, preservazione delle decisioni e nuovi finding in ripresa, diff stabile/modificato, report reali nel laboratorio | Implementazione di base. Manca inserimento prove manuali e modifica di code storiche dalla CLI senza nuova esecuzione. |
| 12 — Monitor | `Engine.monitor`, CLI: contatori e progresso indeterminato per discovery, rate corrente/checkpoint | Monitor esercitato dalle esecuzioni e dai test CLI; indici esposti nei report | **Parziale**: aggiornamento fra attività, senza ridisegno continuo o rilevatore dedicato di stalli. |
| 13 — Altri moduli | `scanners.py`: classificazione IDOR/SSRF/Traversal; osservazioni header, cookie, firme e CORS | Nessuna richiesta nel triage IDOR, segreti/cookie non persistiti, CORS, workflow locale di sette moduli | **Parziale**. SQL Injection e Broken Access Control NOT_IMPLEMENTED. Mancano confronti account e fixture per test contestuali. |
| 14 — Validazione | Tre moduli in `tests/`, `README.md`, questo report; `install.sh`, `requirements.txt`, `.gitignore` | Suite finale cumulativa: 67 test, 66 pass, 1 skip, nessun fail | Validato **l'incremento alpha**, non tutti i criteri di accettazione V2.0. Installazione Kali ancora da eseguire. |

## Test e correzioni durante lo sviluppo

Primo ciclo: 62 test, 60 superati, 1 fallito e 1 saltato. Il fallimento era un test temporale che presumeva concluso il salvataggio dopo 80 ms. È stato sostituito da una sincronizzazione sul completamento effettivo del salvataggio periodico, con timeout esplicito. Il test ora verifica che un checkpoint cambi mentre il worker sta ancora lavorando.

È stato inoltre individuato e corretto un problema di export: una coda manuale già creata all'interruzione non aggiungeva i nuovi finding prodotti dopo la ripresa. Ora viene ricostruita per ID, preservando le valutazioni precedenti. Una regressione dedicata controlla entrambi i comportamenti.

Secondo ciclo: 63 test, 62 superati, 1 saltato. Successivamente sono state aggiunte quattro verifiche: checkpoint strutturalmente malformato, JSON corrotto nel file manager, timeout DNS senza accumulo di thread, workflow HTTP locale completo. Ultimo ciclo: **67 test, 66 superati, 1 saltato**.

Comando riproducibile dalla directory del progetto, con dipendenze installate:

```bash
python -m unittest discover -s tests -v
```

Ambiente effettivo: runtime Python 3.12 disponibile nell'app su Windows e PyYAML 6.0.3 installato nell'area di lavoro per i test. Il laboratorio completo ha eseguito Sub Finding, XSS, IDOR, Path Traversal, Misconfiguration, Authentication, CORS e Sensitive Data Exposure, verificando risultati/report e assenza dei valori dei cookie nei report.

## Limiti aperti e prossima fase

Non sono presenti errori bloccanti nei casi coperti dai test. Non è stato dimostrato che tutte le condizioni della specifica siano soddisfatte. Prima di una release stabile occorrono almeno:

1. Verifica nativa su Kali dell'installer, dei symlink, dei permessi e delle interruzioni di processo reali.
2. Provider passivi online espliciti, con gestione degli errori e limiti del servizio.
3. Verifica XSS in un browser isolato e autorizzato, con prove di esecuzione e regressioni dei falsi positivi.
4. Workflow con account/ruoli e risorse di laboratorio per IDOR/BAC; fixture controllate per SSRF/Traversal.
5. Monitor continuo e selezione multipla delle proposte Smart Execution.
6. Revisione storica dalla CLI, note/prove manuali e aggiornamento sicuro della vista di export di progetto. L'export completo per run è già presente e immutato fra run distinte.
7. Ampliamento delle prove TLS, delle risposte dinamiche, degli errori I/O, della normalizzazione URL e del trattamento di dati sensibili arbitrari nelle URL.

La prossima fase consigliata è la validazione su Kali della base già implementata, seguita dall'integrazione dei provider passivi. Non sono stati aggiunti segnaposto operativi per sostituire questi lavori.
