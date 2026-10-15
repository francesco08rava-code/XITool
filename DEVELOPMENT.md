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
