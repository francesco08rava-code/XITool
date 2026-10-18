# XITool V5.2 — rapporto finale

## 1. Versione

**5.2.0a1**, Windows-11-10.0.26200-SP0, Python 3.12.14. Base Git c7bb4706910037b994800fc1104594e38aa94e61; checkout non committato V3/V4/V5/V5.1 preservato. Identità effettiva: V52_SOURCE_MANIFEST.json, SHA b4392deeaea9e005ed2b8ab22eb85cc67a270483af58b289d7fe3f341de02bb2. Nessun stage/commit/push. Dipendenze: {'PyYAML': '6.0.3', 'dnspython': '2.9.0', 'playwright': '1.64.0', 'tree-sitter': '0.26.0', 'tree-sitter-javascript': '0.25.0'}; nessuna nuova dipendenza runtime obbligatoria, setuptools è un requisito di build dell'entry point.

## 2. Riepilogo

Raggiunti: laboratorio riproducibile dei 13 componenti con 71 casi, trasferimento dati reale fra fasi, accuratezza per contratto, falso positivo CORS corretto, AST e input più precisi, tassonomia errori, timeout/DNS bounded e packaging/launcher verificato su Windows. Provider: CertSpotter raggiunto live, crt.sh timeout. Benchmark finali con sorgenti identificati e più ripetizioni.

Parziali: copertura di scanner/applicazioni generali, preflight browser avanzato, deadline run preemptive, ripresa per pagina CT e sensore HTTPS pubblico. Non raggiunto: verifica nativa Kali/Bash/Zsh/SIGINT, per blocco ambientale. Non si dichiara completamento integrale o stabilità universale. Nessun fallimento della suite finale; limitazioni esplicite nelle sezioni sotto.

## 3. Moduli

| Modulo | Modifiche | Test e risultati | Limitazioni | Stato |
|---|---|---|---|---|
| access | Ruoli/canary/denial/invalidità account nel piano comune e report preservati. | 5 casi integrati, più regressioni esistenti; {'VERIFIED': 1, 'NO_ISSUES_OBSERVED': 1, 'PARTIAL': 2, 'ERROR': 1} | Matrice di ruoli/GET configurata; modello autorizzativo non inferito automaticamente. | PARTIAL |
| authentication | Logout efficace/inefficace, sessione scaduta e isolamento account/cache preservati. | 4 casi integrati, più regressioni esistenti; {'VERIFIED': 1, 'NO_ISSUES_OBSERVED': 1, 'ERROR': 1, 'PARTIAL': 1} | Account/sessioni/logout propri; niente MFA/login/rinnovo automatici. | PARTIAL |
| cors | Corretto falso VERIFIED su ACAO assente, policy originale richiesta; browser e OPTIONS reali. | 6 casi integrati, più regressioni esistenti; {'VERIFIED': 1, 'OBSERVED': 3, 'NO_ISSUES_OBSERVED': 1, 'ERROR': 1} | GET browser più OPTIONS HTTP, non matrice completa preflight custom/browser. | PARTIAL |
| crawler | AST const/alias/scope, metodi API distinti, qualità e blocco accodamento statico. | 6 casi integrati, più regressioni esistenti; {'OBSERVED': 3, 'COMPLETED': 2, 'ERROR': 1} | AST conservativo, niente esecuzione JS statica o interazioni arbitrarie; nessuna stima di copertura generale. | PARTIAL |
| idor | Proprietario/altro utente/denial/shell/sessione scaduta/errori integrati. | 5 casi integrati, più regressioni esistenti; {'VERIFIED': 1, 'NO_ISSUES_OBSERVED': 1, 'PARTIAL': 2, 'ERROR': 1} | Due account/canary espliciti, GET e risorse predisposte; nessuna enumerazione. | PARTIAL |
| misconfiguration | Header sì/no, TLS valido/scaduto/hostname errato e timeout nel percorso. | 7 casi integrati, più regressioni esistenti; {'OBSERVED': 5, 'ERROR': 1, 'TIMEOUT': 1} | Header e singole negoziazioni TLS; nessun audit completo cipher/protocolli. | PARTIAL |
| sensitive | Token sintetico/placeholder/duplicato/redazione nello stesso catalogo. | 3 casi integrati, più regressioni esistenti; {'MANUAL_REVIEW': 1, 'OBSERVED': 1, 'ERROR': 1} | Firme candidate oscurate; nessuna convalida credenziali o accuratezza reale generale. | PARTIAL |
| smart | Errori di dipendenza bloccano analisi; pipeline da discovery, stop/resume, diff e isolamento. | 3 casi integrati, più regressioni esistenti; {'COMPLETED': 1, 'OBSERVED': 1, 'ERROR': 1} | Passi ordinati con dipendenze; budget run cooperativo e nessuna exactly-once mutativa. | PARTIAL |
| sqli | GET/form/JSON reali nello stesso lab, parametrizzato e baseline instabile. | 8 casi integrati, più regressioni esistenti; {'POTENTIAL': 3, 'PARTIAL': 4, 'ERROR': 1} | POTENTIAL differenziale su SQLite di laboratorio, non VERIFIED o copertura di ogni DB. | PARTIAL |
| ssrf | Callback HTTP reale locale con nonce, duplicati, mismatch e sensore assente; gate di scope testati. | 6 casi integrati, più regressioni esistenti; {'VERIFIED': 2, 'PARTIAL': 2, 'UNSUPPORTED': 1, 'ERROR': 1} | Modalità locale solo loopback esplicito; sensore HTTPS pubblico operatore non disponibile. | PARTIAL |
| subfinding | Stati CT espliciti/disabilitazione, DNS globale bounded, pipeline CT→UDP→HTTP. | 6 casi integrati, più regressioni esistenti; {'ERROR': 1, 'OBSERVED': 5} | Due provider; crt.sh non verificato positivo live; checkpoint del provider per task, non per pagina. | PARTIAL |
| traversal | File canary reale, diniego, missing, encoding e baseline instabile integrati. | 6 casi integrati, più regressioni esistenti; {'VERIFIED': 2, 'NO_ISSUES_OBSERVED': 1, 'PARTIAL': 2, 'ERROR': 1} | Canary innocuo, encoding predisposto e baseline; non matrice esaustiva di filesystem. | PARTIAL |
| xss | Fixture integrate reflection/escape/CSP/DOM, prove browser reali e errori. | 6 casi integrati, più regressioni esistenti; {'VERIFIED': 2, 'NO_ISSUES_OBSERVED': 3, 'ERROR': 1} | Prove browser su fixture; nessuna analisi taint universale di tutte le SPA. | PARTIAL |

## 4. Test

Baseline ripetuta prima delle modifiche: 303 test, 300 superati, 3 saltati, zero fallimenti/errori, 491.143 s. Manifest V51 coincidente in tutti i 56 file. Finale: **325 test, 322 superati, 0 fallimenti/errori, 3 saltati, 130.347 s**. Nessun test precedente eliminato. Log V52_TESTS.txt; controlli intermedi V52_CORE_FINAL.txt e V52_PHASE_BC/DE_TESTS.txt.

Browser: 12 test dedicati precedenti, più il test integrato che esegue otto scenari browser (cinque XSS, due CORS, una SPA). DNS: quattro test UDP dedicati più UDP nel lab. TLS: tre handshake dedicati più tre nel lab. Provider: 13 test dedicati PassiveTests/ProviderStatesTests, più integrazione e controlli del trasporto. E2E completo ripetuto separatamente: V52_E2E_FINAL.txt e V52_E2E_RESULTS.json. Skip: due test installer Bash/POSIX e symlink reale su Windows. Linux nativo: non eseguito.

## 5. Accuratezza

71 fixture etichettate con input/condizioni/evidenza/esito/motivo. V52_ACCURACY_REPORT.md contiene TP/FP/TN/FN, precision, recall, specificity, FPR, FNR e copertura conclusiva per modulo/contratto; JSON con denominatori nulli espliciti e conteggi di errore/timeout/unsupported/inconclusivi/revisione. Nessun aggregato improprio fra SQL candidato, osservazioni di header/firme e prove browser/canary. POTENTIAL non viene trasformato in VERIFIED. Non rappresenta l'accuratezza su applicazioni reali.

Il falso positivo CORS riproducibile iniziale è conservato in V52_ACCURACY_BEFORE_CORS_FIX.json e coperto dalla regressione integrata. Playwright sintetizzava header CORS permissivi quando assenti: bridge corretta più controllo indipendente della policy originale. Vecchio e nuovo catalogo hanno dimensioni diverse: nessuna percentuale di miglioramento generale ricavata dal confronto.

## 6. Prestazioni

V51/V52 timeout, mediane: 14.283/12.887 s, variazione -9.8%. 500 task: 33.758/34.717 s, +2.8%. La tabella completa include 12/100/500, lentezza, 429, intermittenti, interruzione/ripresa e due domini, range/deviazioni, memoria, throughput, errori e completati. Nessun risultato duplicato o task perso nei casi verificati. V52_PERFORMANCE_REPORT.md e JSON grezzi conservano anche i peggioramenti e le misure preliminari.

Backoff e rate non rimossi: riduzione condivisa per burst contemporanei, Retry-After rispettato, min rate invariato, jitter configurabile/default zero. Errori permanenti TLS/parsing e POST non ripetuti. Watchdog per tentativo e limite globale resolver daemon. La deadline run rimane cooperativa: una richiesta OS già in volo può oltrepassare l'istante del budget o continuare DNS in background entro il cap. Nessuna promessa hard real-time, di riduzione memoria o di prestazioni generali.

## 7. Kali

Installazione editable/entry point, pip check, --version, --help, menu e propagazione exit 0/2 verificati in venv Windows pulito senza PYTHONPATH e da altra cartella: V52_PACKAGE_LAUNCHER.json. Script generici senza username hardcoded; pip solo nel venv, niente root/PEP 668 globale. Collegamento ~/.local/bin/XITool preserva comandi esistenti e segnala conflitti; nessuna modifica automatica ai file shell. Alias della shell padre da controllare manualmente con type -a XITool.

Kali non accessibile (VirtualBox E_ACCESSDENIED); Bash/MSYS fallisce con 0xC0000022 prima di -n. Non si dichiara nemmeno il successo del parsing Bash da Windows. verify_kali.sh --browser --javascript prepara OS/Python/venv/dipendenze/launcher/Bash/Zsh/test/E2E/SIGINT/benchmark e report con fase/exit/hash. KALI_SUMMARY.json/KALI_TESTS.txt/KALI_INSTALL_REPORT.md marcano chiaramente NOT_EXECUTED finché non eseguiti nella VM.

## 8. Sicurezza

Default deny/deny prioritario, scope per dominio, pinning IP/peer, redirect e TLS verificati preservati. CNAME esterno osservato ma non interrogato. Solo fixture sintetiche per verifiche di vulnerabilità; nessuna scansione pubblica. Il live è solo CT su provider autorizzati, non sul dominio cercato. Sessioni isolate, cache anonima separata, valori sensibili non persistiti. Callback locale richiede fixture_only, target/callback IP loopback, percorso laboratorio e CIDR esplicito; non è un'eccezione per callback privati su target pubblici.

Checkpoint/versioni/scope/config/integrità controllati; vecchi dati consultabili, ripresa incompatibile rifiutata. Cleanup con anteprima/conferma e protezione risultati/config/checkpoint invariato e verificato dalla regressione. Nessun dato utente eliminato o modificato dal laboratorio. Nel lab sono controllati hash dei report prima/dopo errori, separazione progetti/domini e assenza duplicati dopo ripresa.

## 9. File

Nuovi: benchmarks/validate_integrated.py, benchmarks/verify_interrupt.py, benchmarks/verify_providers.py, pyproject.toml, tests/lab_app.py, tests/lab_runner.py, tests/lab_sources.py, tests/test_v52.py, tests/test_v52_integration.py, xitool/errors.py.

Modificati rispetto al manifest V51: benchmarks/benchmark_local.py, install.sh, verify_kali.sh, xitool/__init__.py, xitool/browser_lab.py, xitool/callback_checks.py, xitool/cli.py, xitool/controlled.py, xitool/diffing.py, xitool/execution.py, xitool/http.py, xitool/inputs.py, xitool/javascript.py, xitool/passive.py, xitool/plans.py, xitool/recon_output.py, xitool/scanners.py, xitool/sessions.py, xitool/storage.py, xitool/workers.py. README/DEVELOPMENT/CONTROLLED_CHECKS aggiornati; rapporti/log/dataset in verification. Eliminate: nessuna sorgente precedente. Dati targets esistenti preservati. Nessuna migrazione distruttiva o riscrittura di checkpoint V51. Nuovi campi config hanno default compatibili; nuovo engine version richiede nuove run per ripresa dopo aggiornamento. L'installazione editable richiede checkout disponibile.

## 10. Problemi residui

Kali/POSIX non verificati; crt.sh non verificato positivo live; sensore HTTPS pubblico non disponibile; AST e alias conservativi, non interpretazione generale; browser CORS semplice più OPTIONS separato; modelli auth/ruoli/SQL/filesystem limitati alle fixture esplicite; catalogo sintetico non rappresentativo; deadline run cooperativa e DNS OS non interrompibile; checkpoint CT non per pagina; campione prestazionale piccolo e nessuna garanzia memoria/throughput in produzione. Questi limiti non sono nascosti dietro il totale dei test.

## 11. Classificazione finale

**Alpha.** Integrazione e prove più ampie, correzione di un falso positivo reale e miglioramento timeout misurato, ma assenza di verifica nativa Kali e limitazioni sostanziali dei moduli impediscono la qualifica release candidate/stable. Nessun commit o push effettuato.
