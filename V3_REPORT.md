# Rapporto corrente: 3.0.0a2

Leggere [V3_COMPLETION_REPORT.md](V3_COMPLETION_REPORT.md) per implementazione e verifiche attuali. Quanto segue è lo storico 3.0.0a1, superato dal rapporto corrente.

---

# Verifica V3 — 16 ottobre 2026

## Cartella e ambito

Modifiche applicate direttamente a C:\Users\Pc\Desktop\XITool, versione 3.0.0a1. Nessun commit/push, nessuna scansione dei domini pubblici dell'operatore. Provider crt.sh e CertSpotter integrati dopo consenso esplicito all'invio dei domini ai relativi endpoint. La disponibilità live non è stata provata: i test dei provider verificano il client con trasporto HTTP controllato, senza inventare risultati reali.

## Analisi iniziale e piano

Base verificata prima delle modifiche: 110 test eseguiti, 107 passati, 3 saltati, nessun fallimento; 13,471 s dopo aver configurato correttamente la directory temporanea e la rete loopback del sandbox. Il primo tentativo aveva errori di permesso sul TEMP isolato: non era una regressione del progetto.

Analisi: scope/IP/redirect e checkpoint già centralizzati; struttura per dominio presente; Sub Finding non aveva provider online e mescolava seed e scoperte; SQL e access control non implementati; IDOR/SSRF/Traversal erano solo classificatori; XSS non verificava stabilità; CORS aveva una sola origine; crawler senza sitemap/robots; input JSON/percorso e confidenza/metodo mancanti.

Ordine seguito:

1. Preservare motore, scope, struttura e checkpoint, correggere la semantica seed/scoperte e i limiti URL.
2. Aggiungere due fonti CT, DNS autorizzato, probing e output distinti; aggiornare crawler/input discovery.
3. Rendere ripetibili le osservazioni XSS/CORS, ampliare header/cookie/firme; implementare SQL soltanto come osservazione DB non invasiva.
4. Conservare i limiti espliciti dei moduli avanzati; nessun confronto account o laboratorio fittizio.
5. Suggerimenti Smart motivati e selezionabili, test locali, documentazione con stato reale.

## Cambiamenti verificabili

- Seed non conteggiato in all_subdomains/live_subdomains; file iniziali/risolti/raggiungibili/autorizzati/fuori scope distinti.
- Fonti indipendenti crt.sh e CertSpotter, deduplica, normalizzazione, provenienza, paginazione limitata, wildcard certificati distinte dagli host, errori e dati parziali conservati.
- Le attività passive possono partire con sola wildcard senza visitare l'apice. Nessun host fuori scope passa al DNS o al probing.
- DNS A/AAAA/CNAME con timeout, NXDOMAIN, cache TTL e due campioni wildcard solo entro autorizzazione. Il trasporto HTTP rivalida gli IP.
- Probe HTTPS/HTTP con status/redirect/durata/presenza titolo e indizi header. Niente testo titolo o valori arbitrari degli header persistiti.
- Sitemap XML senza entità, robots informativo, JSON di risposta separato dagli input richiesta, ID numerici/UUID nei percorsi, fonte/posizione/stato scope.
- XSS: baseline, marcatore inerte, ripetizione e contesto euristico; mai VERIFIED.
- SQL: firme DB e ripetizione dello stesso GET, senza input modificati; soltanto OBSERVED/MANUAL_REVIEW.
- CORS: due origini innocue, credenziali e Vary; wildcard non promossa a vulnerabilità.
- Cookie: SameSite, Max-Age, scadenza e no-store; valori cookie mai riportati. Misconfiguration: indizi di configurazione HSTS/CSP/nosniff e versioni.
- Sensitive: entropia su assegnazioni riconoscibili e riferimenti config; solo conteggi, nessun uso di credenziali.
- Scope URL conserva origine e percorso; rifiuta percorsi ambigui/encoding. Blocchi URL/IP/redirect registrati senza dati riservati; redirect sensibili/mutativi riconoscibili fermati prima della richiesta successiva.
- Incollaggio diretto al menu domini supportato, mantenendo il caso dei percorsi URL.
- Smart Execution con motivazioni, selezione multipla e conferma finale. I singoli moduli mantengono checkpoint e output per dominio.

## Stato reale dei moduli

La tabella completa con funzioni, mancanze e test concreti è in README.md, sezione “Stato reale e prove”. Nessuno scanner avanzato è dichiarato completo; i controlli disponibili sono PARZIALI. Broken Access Control resta NON IMPLEMENTATO e bloccato prima del trasporto. IDOR/SSRF/Traversal sono esplicitamente candidati per revisione, senza verifiche automatiche inventate.

Fasi V3: fondamenta e ricognizione potenziate; analisi di sicurezza migliorata ma parziale; confronti account, browser XSS e verifiche avanzate di laboratorio non implementati; integrazione Smart parziale. Non si dichiara completata l'intera specifica V3.

## Test

Suite completa: **148 test, 145 superati, 0 fallimenti/errori, 3 saltati**, durata 156,678 s. Dopo le ultime due regressioni aggiunte (schema provider malformato ed errori provider conservati alla ripresa con sola wildcard), tutti i **40 test V3** sono stati rieseguiti: 40 superati in 3,690 s. La suite presente contiene ora 150 test distinti; non viene dichiarata una singola esecuzione completa da 150 test. Controllo whitespace Git superato; avvio reale main.py --version conferma 3.0.0a1. Il rallentamento transitorio del disco durante alcuni cicli di test è stato localizzato nel fsync dei file, non in richieste a target pubblici.

Copertura aggiunta: parser CT e paginazione/fallimenti, wildcard di certificato, DNS cache/timeout/NXDOMAIN/scope, wildcard DNS, seed/out-of-scope, interruzione provider e ripresa, scope percorso/origine, GET SQL invariato, XSS instabile, CORS due origini, cookie mascherati, entropia mascherata, Smart senza consenso, incollaggio diretto e crawler reale su loopback con robots/sitemap/JSON senza POST.

Limiti di verifica: Windows/Python 3.12; test Bash/installer POSIX e symlink saltati. Kali non è controllabile direttamente da questo ambiente. Il comando `.venv/bin/python main.py` e il launcher sono mantenuti; eseguire install.sh su Kali per i controlli nativi. Nessuna verifica live dei provider dichiarata.

## File modificati e aggiunti

| File | Modifica |
| --- | --- |
| xitool/passive.py | Nuovo: due adapter CT e limiti/errori/provenienza |
| xitool/dns.py | Nuovo: DNS A/AAAA/CNAME, TTL e wildcard |
| xitool/recon_output.py | Nuovo: categorie e output di ricognizione |
| xitool/execution.py | Integrazione provider/DNS/probe, coda e output/report/checkpoint |
| xitool/scanners.py | Crawler, SQL osservabile, XSS/CORS, cookie/header/firme e schema |
| xitool/scope.py | Conservazione e applicazione di scope URL con percorso |
| xitool/storage.py | Persistenza delle regole complete |
| xitool/http.py | Metadati risposta, redirect e blocchi registrati |
| xitool/cli.py | Menu/inserimento, avvio automatico, consultazione categorie e Smart |
| xitool/__init__.py | Versione 3.0.0a1 |
| requirements.txt | dnspython aggiunto |
| tests/test_v3.py | Nuovi test mirati e server locale |
| tests/test_multidomain.py | Aggiornate aspettative scope URL e SQL ora parziale |
| tests/test_execution_cli.py | Rifiuto del modulo access control, SQL ora osservabile |
| README.md | Uso, scope, output, tabella moduli e limiti reali |
| DEVELOPMENT.md | Collegamento al report V3 e storico conservato |
| V3_REPORT.md | Questo report |

main.py, install.sh, config.yaml e formato base dei checkpoint non sono stati riscritti inutilmente. I dati operativi e la cronologia Git non sono stati modificati.

## Riferimenti consultati

- CT Search API SSLMate: https://sslmate.com/help/reference/ct_search_api_v1
- Implementazione JSON crt.sh: https://github.com/crtsh/certwatch_db/blob/master/fnc/web_apis.fnc
- Resolver dnspython: https://dnspython.readthedocs.io/en/stable/resolver-class.html
- OWASP WSTG XSS: https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/07-Injection/01-Reflected_Cross_Site_Scripting/
- OWASP WSTG SQL: https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/07-Injection/05-SQL_Injection/
- MDN CORS/Vary: https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Access-Control-Allow-Origin

Le verifiche implementate coprono soltanto il sottoinsieme documentato nella tabella, non tutte le tecniche trattate da queste fonti.
