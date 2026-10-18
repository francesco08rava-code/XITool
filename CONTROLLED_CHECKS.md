# V5.2 — callback locale esplicito per laboratorio

I controlli SSRF pubblici mantengono il requisito HTTPS pubblico del callback. Un caso separato con fixture_only true ammette esclusivamente target e callback su IP loopback letterali, target sotto /xitool-lab/, callback sotto /xitool-callback/, scope/porta e CIDR loopback esplicitamente autorizzati. Non ammette callback privati per un target pubblico, né metadata endpoint. Profilo/nonce/log appartengono al laboratorio dell'operatore. Log assente → UNSUPPORTED, callback assente/nonce errato → inconclusivo, mai automaticamente sicuro. I duplicati del medesimo evento non moltiplicano le prove.

La bridge CORS preserva la negazione quando ACAO è assente: Playwright altrimenti sintetizza header permissivi. VERIFIED richiede anche policy originale, cookie/origine previsti e lettura canary nel browser. Il catalogo integrato registra casi positivi, negativi ed errori senza salvare canary/token/cookie nei report.

---

# Estensioni V5.1

SQL su fixture loopback sotto /xitool-lab/ accetta lo stesso oggetto request autorizzato della fixture XSS: method POST, authorized true, content_type application/json oppure application/x-www-form-urlencoded, fields con parametro numerico iniziale stringa. Richiesti fixture_only/read_only_fixture true. Si eseguono sei confronti di sola lettura predisposti; il differenziale rimane POTENTIAL, non VERIFIED.

DOM XSS di laboratorio: caso xss con parameter "fragment" e dom_source "fragment", fixture_only/operator_owned true, URL loopback /xitool-lab/. Non combinare con request POST. Il browser riceve HTML realmente raccolto e tre contesti isolati: baseline e due frammenti con nonce innocuo. VERIFIED richiede esecuzione ripetuta e baseline negativa. La prova dimostra l'esecuzione dal frammento; non identifica automaticamente l'intera catena dei sink.

---

# Configurazione dei controlli approfonditi

Questi controlli usano risorse reali predisposte dall'operatore. Non creano account, non scoprono credenziali e non inventano canary. Gli esempi non sono configurazioni operative: operator_owned=false e logout_confirmed=false li rendono inattivi finché non vengono adattati e confermati.

## Sessioni

Creare session_profiles.json nella cartella del progetto, accanto a scope.json. Lo schema è in examples/session_profiles.example.json. Il campo header_env contiene **nomi di variabili d'ambiente**, non valori. Il valore di Authorization deve includere l'eventuale prefisso Bearer; Cookie deve contenere la stringa cookie dell'account di test. Non incollare password o token nel JSON, nei report o in questa chat.

Ogni profilo è vincolato a schema, host e porta esatti. Su destinazioni pubbliche è richiesto HTTPS; HTTP con credenziali è ammesso solo a un IP loopback di laboratorio, già autorizzato anche come CIDR. Un redirect verso un'altra origine interrompe il controllo, senza trasferire il token. Nessuna cache delle risposte autenticate, nessun cookie jar automatico, nessun login automatico. expires_at facoltativo deve essere un timestamp ISO con fuso; scadenza locale e 401/403/login sono distinti dalla prova di validità del proprio account.

Se esistono profili per l'origine scelta, il menu propone ANONIMO o il profilo. I task delle altre origini non vengono eseguiti con quel profilo. Nei casi di confronto i due account sono già indicati dal manifest e non vengono sostituiti dalla selezione generica.

## Casi controllati

Creare controlled_checks.json nel progetto, copiando **solo i casi che si intende configurare** da examples/controlled_checks.example.json. Adattare origini, risorse e variabili, quindi impostare operator_owned=true soltanto per risorse effettivamente controllate. Massimo 25 casi; ID univoco per modulo. Le definizioni sono improntate nella coda: modificarle richiede una nuova run.

I canary sono marcatori innocui univoci di 16–128 caratteri ASCII fra lettere, cifre, _ e -, custoditi nell'ambiente. Devono identificare le proprie risorse di test, non dati di altre persone. Nei report vengono conservati hash, esiti e differenze minimizzate, non il canary originale o i corpi privati.

Scegliere il normale modulo in ESECUZIONE. Se esistono casi validi per quel modulo/dominio, vengono eseguiti quelli; altrimenti rimangono i controlli standard o NO_INPUT. L'esecuzione richiede comunque la conferma finale. Un manifest invalido provoca un errore esplicito: non viene ignorato silenziosamente.

### IDOR e controllo dei ruoli

Servono owner_profile, other_profile, url e proof_env della risorsa del primo account, più other_reference_url e other_proof_env di una risorsa distinta del secondo account. expected_other_access è booleano: false verifica un divieto atteso, true un accesso consentito atteso. Una lettura consentita attesa non è una vulnerabilità; un diniego inatteso richiede revisione, non VERIFIED. Entrambi i profili devono appartenere alla stessa origine della risorsa.

Il tool verifica il riferimento del secondo account, legge due volte la risorsa con l'owner e due volte con l'altro account e ricontrolla il riferimento del secondo account alla fine. Una sessione che scade durante il confronto resta inconclusiva. VERIFIED richiede account validi e lettura ripetuta del canary che dovrebbe essere negata. Un rifiuto 401/403 con secondo account valido è NO_ISSUES_OBSERVED per quella risorsa. Un account scaduto, shell HTTP 200 senza canary o dati inconcludenti producono PARTIAL. Non vengono cambiati o enumerati ID.

### XSS nel browser

Caso esplicito con module=xss, parameter presente nella query e fixture_only=true. Consentito esclusivamente su IP loopback sotto /xitool-lab/, autorizzato dal CIDR e dalla porta. Serve il browser opzionale.

Il client raccoglie baseline e due risposte al payload innocuo, poi Chromium le esegue in contesti effimeri. Il payload comunica soltanto un nonce al processo di verifica, senza leggere cookie, token o dati personali. Il browser non effettua richieste di rete proprie; script esterni, WebSocket e service worker sono bloccati. La CSP reale viene conservata. VERIFIED richiede esecuzione del nonce in entrambe le prove stabili e non nella baseline; encoding/CSP corretti non producono una conferma. Non è una verifica XSS generica su siti pubblici. Form e JSON sono ammessi soltanto nella fixture loopback esplicita descritta sotto.

### SQL di laboratorio

Caso module=sqli con parametro numerico singolo, fixture_only=true e read_only_fixture=true, solo su loopback sotto /xitool-lab/. La fixture deve essere realmente predisposta per un SELECT read-only su dati canary propri.

Vengono confrontati due GET baseline, due varianti con AND 1=1 e due con AND 1=2. Il canary deve essere stabile e cambiare secondo il confronto atteso. Il risultato resta POTENTIAL: il differenziale non dimostra da solo la semantica interna del server. Non esistono estrazione database, query di scrittura, lettura tabelle arbitrarie o file del server. Fuori da questa modalità il modulo osserva soltanto errori DB e stabilità dei GET invariati.

### Lettura di file predisposti

Caso traversal con baseline_url, url della prova, proof_env, fixture_only=true ed expected_probe_access=false. Entrambe le risorse devono appartenere alla stessa origine e al percorso /xitool-lab/. Il tool non genera percorsi di sistema o varianti di file.

Confronta due baseline uguali e due letture della risorsa canary. VERIFIED riguarda soltanto l'accesso alla fixture contrariamente al permesso atteso, non l'accesso a qualsiasi file né una diagnosi universale di path traversal. La configurazione deve rappresentare un vero test predisposto con canary non disponibile nella baseline.

### Logout e invalidazione

Caso authentication con profilo, risorsa privata canary, logout_url=/xitool-lab/end-session, fixture_only=true e logout_confirmed=true. Solo IP loopback. Il menu segnala che il piano include un logout prima della conferma.

Prima viene provata la validità della sessione. Se manca, il logout non viene inviato. Dopo il logout sono eseguiti due controlli con la stessa vecchia credenziale: negazione/login è invalidazione osservata; canary ancora leggibile è VERIFIED per la sessione di laboratorio. Nessun logout automatico di account pubblici o di terzi.

### CORS nel browser

Caso cors con url della risorsa canary, caller_url su una seconda origine loopback, profile contenente soltanto Cookie, proof_env e expected_cross_origin_access=false. Entrambi i percorsi devono iniziare con /xitool-lab/ e le porte devono essere autorizzate.

Il tool raccoglie realmente la risposta privata con Origin della pagina caller. Chromium riceve il solo cookie di test in un contesto nuovo e tenta una fetch con credentials=include. Le risposte raccolte mantengono ACAO/ACAC/CSP e passano dai controlli CORS reali del browser. Il bridge serve la risposta privata soltanto se il browser ha inviato cookie e Origin attesi. VERIFIED richiede lettura del canary dalla seconda origine. Tutte le altre destinazioni sono bloccate; il cookie non viene esportato.

## Sensore SSRF

È un'integrazione opzionale con **HTTPS pubblico controllato dall'operatore**. Non vengono configurati tunnel o servizi esterni automaticamente. Non usare servizi metadata cloud, indirizzi interni o risorse altrui.

1. Predisporre un'origine HTTPS pubblica che inoltri /xitool-callback/ al sensore controllato.
2. Creare un file JSONL vuoto nella cartella del progetto e limitarne l'accesso all'operatore.
3. Avviare separatamente il ricevitore:

```bash
.venv/bin/python -m xitool.callback_receiver --events-file targets/PROGETTO/callback_events.jsonl
```

Per default ascolta solo su 127.0.0.1:8081, da esporre tramite il proprio reverse proxy HTTPS. Accetta solo un percorso con nonce esadecimale, registra ID/data/IP TCP del mittente e rifiuta altri percorsi. Non registra query, header o corpi. Il log si ferma a 8 MiB e va ruotato dall'operatore.

4. Configurare il caso ssrf: url e parameter osservato, callback_base=https://ORIGINE-PROPRIA/xitool-callback/, events_file (nome JSONL locale) ed expected_source_ips.
5. expected_source_ips indica il peer TCP atteso dal sensore: può essere il proprio proxy fidato. Non confonderlo con l'IP originale del target. Il tool non si fida di X-Forwarded-For. L'attendibilità del sensore e del file è responsabilità della configurazione dell'operatore.

Prima della prova il DNS del callback deve risolvere solo a IP pubblici; nessuna eccezione CIDR. Il tool invia al target un URL HTTPS con nonce univoco e cerca per tre secondi un evento corrispondente, successivo all'avvio e dalla sorgente attesa. Non visita direttamente l'URL callback per generare una prova. Un log mancante è UNSUPPORTED e non causa richieste al target; callback assente o tardivo è PARTIAL, non un negativo pulito. Il log conserva eventuali eventi tardivi per revisione manuale.

La correlazione è stata provata con sensore HTTP reale locale e trasporto della destinazione pubblica sostituito dalla fixture di test. Non è stata eseguita una prova end-to-end su un callback pubblico dell'operatore, non essendo stato fornito.

## Browser DOM e Smart Execution

Installare requirements-browser.txt e Chromium separatamente. XITOOL_DYNAMIC_BROWSER=1 abilita la discovery DOM nelle nuove run: GET validati dal client, massimo 10 risorse/pagina, nessun form inviato. Non recupera automaticamente sessioni o cookie del browser personale. I test browser sono opzionali e si attivano con XITOOL_BROWSER_TESTS=1.

Smart crea un piano persistente per progetto. Se manca la ricognizione propone la relativa fase e chiede conferma, poi ricarica gli input e propone i controlli pertinenti, compresi i casi configurati. La seconda conferma autorizza l'analisi scelta. Una ripresa salta i passi completati e riapre i checkpoint delle run incomplete. Scope, configurazione e domini devono coincidere. I piani sono consultabili da APRI PROGETTI in sola lettura.

Un esito NO_INPUT viene salvato come NOT_STARTED nei report del dominio: non è una scansione riuscita senza vulnerabilità. Una raccolta parziale, account invalido o browser non disponibile rimangono espliciti nei report. I risultati devono essere interpretati nel perimetro della prova effettivamente eseguita.

## XSS su form e JSON della fixture — V4

Nel caso XSS aggiungere facoltativamente `request` con questa struttura:

```json
{
  "method": "POST",
  "content_type": "application/json",
  "fields": {"q": "baseline"},
  "authorized": true
}
```

Il campo `parameter` del caso deve essere `q` nell'esempio; usare `application/x-www-form-urlencoded` per un form. URL sotto `/xitool-lab/` su IP loopback, `operator_owned=true`, `fixture_only=true`, scope/CIDR/porta autorizzati rimangono obbligatori. Questa opzione autorizza espressamente tre POST alla sola fixture: baseline e due prove. Nessun POST viene ritentato o seguito su redirect. Campi stringa limitati, niente nomi sensibili come password/token e niente dati di account. Il browser esegue le risposte HTML raccolte conservando CSP e bloccando richieste esterne; non è una riproduzione completa dell'applicazione o del suo flusso DOM.

I casi IDOR/access costituiscono righe esplicite della matrice di permessi: una risorsa, un proprietario, un altro ruolo e accesso atteso negato per caso. V5 supporta anche righe con permesso positivo atteso; le combinazioni fra ruoli restano configurate esplicitamente. Per i callback il numero di eventi unici è riportato; copie identiche dello stesso evento non diventano prove indipendenti. Il sensore deve essere fidato e il suo log protetto dall'operatore.

## V5 — esecuzione e valutazione

Sessioni, casi controllati, browser e POST restano seriali nel singolo dominio anche quando i task anonimi usano più worker. Le risposte non vengono condivise fra account. Il report aggiunge confidenza ordinale, fattori e priorità separata dalla severità; non sono probabilità o CVSS. La revisione FALSE_POSITIVE è una valutazione umana distinta dal risultato automatico. I checkpoint V4 restano consultabili; per l’esecuzione usare una nuova run/piano V5.
