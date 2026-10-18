# Accuratezza sulle fixture

Catalogo: 71 casi etichettati, 13 componenti. Condizioni, input, comportamento/evidenza attesi, risultato e motivo tecnico sono in V52_ACCURACY_DATASET.json. Ground truth null indica contratto non binario (errore, sensore assente, baseline/sessione non utilizzabile); non viene contato come TN.

Le metriche sono per modulo e contratto, senza aggregazione fra categorie diverse. SQL misura un differenziale candidato POTENTIAL; Sensitive misura firme oscurate; Misconfiguration presenza header; infrastruttura contratti di pipeline. Soltanto le prove browser/canary ammesse possono essere VERIFIED. MANUAL_REVIEW e stato automatico sono conservati separatamente dalle etichette metriche. Non si dichiara accuratezza generale su sistemi reali.

| Modulo:contratto | TP | FP | TN | FN | Precision | Recall | Specificity | FPR | FNR | Inconclusivi | Errori | Timeout | Unsupported | Copertura conclusiva |
|---|---:|---:|---:|---:|---|---|---|---|---|---:|---:|---:|---:|---|
| access:canary_or_browser_proof | 1 | 0 | 1 | 0 | 1.000 | 1.000 | 1.000 | 0.000 | 0.000 | 2 | 1 | 0 | 0 | 0.400 |
| authentication:canary_or_browser_proof | 1 | 0 | 1 | 0 | 1.000 | 1.000 | 1.000 | 0.000 | 0.000 | 1 | 1 | 0 | 0 | 0.500 |
| cors:canary_or_browser_proof | 1 | 0 | 1 | 0 | 1.000 | 1.000 | 1.000 | 0.000 | 0.000 | 0 | 1 | 0 | 0 | 0.667 |
| cors:preflight_contract | 1 | 0 | 1 | 0 | 1.000 | 1.000 | 1.000 | 0.000 | 0.000 | 0 | 0 | 0 | 0 | 1.000 |
| cors:public_wildcard_false_positive_guard | 0 | 0 | 1 | 0 | n/d | n/d | 1.000 | 0.000 | n/d | 0 | 0 | 0 | 0 | 1.000 |
| crawler:dynamic_contract | 2 | 0 | 0 | 0 | 1.000 | 1.000 | n/d | n/d | 0.000 | 0 | 0 | 0 | 0 | 1.000 |
| crawler:input_contract | 1 | 0 | 0 | 0 | 1.000 | 1.000 | n/d | n/d | 0.000 | 0 | 0 | 0 | 0 | 1.000 |
| crawler:scope_contract | 0 | 0 | 2 | 0 | n/d | n/d | 1.000 | 0.000 | n/d | 0 | 0 | 0 | 0 | 1.000 |
| crawler:technical_error | 0 | 0 | 0 | 0 | n/d | n/d | n/d | n/d | n/d | 0 | 1 | 0 | 0 | 0.000 |
| idor:canary_or_browser_proof | 1 | 0 | 1 | 0 | 1.000 | 1.000 | 1.000 | 0.000 | 0.000 | 2 | 1 | 0 | 0 | 0.400 |
| misconfiguration:missing_security_headers | 1 | 0 | 1 | 0 | 1.000 | 1.000 | 1.000 | 0.000 | 0.000 | 0 | 1 | 1 | 0 | 0.500 |
| misconfiguration:tls_acceptance_contract | 1 | 0 | 2 | 0 | 1.000 | 1.000 | 1.000 | 0.000 | 0.000 | 0 | 0 | 0 | 0 | 1.000 |
| sensitive:redacted_pattern_detector | 1 | 0 | 1 | 0 | 1.000 | 1.000 | 1.000 | 0.000 | 0.000 | 0 | 1 | 0 | 0 | 0.667 |
| smart:dedup_contract | 0 | 0 | 1 | 0 | n/d | n/d | 1.000 | 0.000 | n/d | 0 | 0 | 0 | 0 | 1.000 |
| smart:execution_contract | 1 | 0 | 0 | 0 | 1.000 | 1.000 | n/d | n/d | 0.000 | 0 | 0 | 0 | 0 | 1.000 |
| smart:technical_error | 0 | 0 | 0 | 0 | n/d | n/d | n/d | n/d | n/d | 0 | 1 | 0 | 0 | 0.000 |
| sqli:sql_candidate_differential | 3 | 0 | 3 | 0 | 1.000 | 1.000 | 1.000 | 0.000 | 0.000 | 1 | 1 | 0 | 0 | 0.750 |
| ssrf:canary_or_browser_proof | 2 | 0 | 0 | 0 | 1.000 | 1.000 | n/d | n/d | 0.000 | 2 | 1 | 0 | 1 | 0.333 |
| subfinding:dns_contract | 0 | 0 | 1 | 0 | n/d | n/d | 1.000 | 0.000 | n/d | 0 | 0 | 0 | 0 | 1.000 |
| subfinding:provider_availability | 0 | 0 | 0 | 0 | n/d | n/d | n/d | n/d | n/d | 0 | 1 | 0 | 0 | 0.000 |
| subfinding:provider_dns_contract | 1 | 0 | 0 | 0 | 1.000 | 1.000 | n/d | n/d | 0.000 | 0 | 0 | 0 | 0 | 1.000 |
| subfinding:reachability | 1 | 0 | 0 | 0 | 1.000 | 1.000 | n/d | n/d | 0.000 | 0 | 0 | 0 | 0 | 1.000 |
| subfinding:scope_contract | 0 | 0 | 1 | 0 | n/d | n/d | 1.000 | 0.000 | n/d | 0 | 0 | 0 | 0 | 1.000 |
| subfinding:seed_discovery | 0 | 0 | 1 | 0 | n/d | n/d | 1.000 | 0.000 | n/d | 0 | 0 | 0 | 0 | 1.000 |
| traversal:canary_or_browser_proof | 2 | 0 | 1 | 0 | 1.000 | 1.000 | 1.000 | 0.000 | 0.000 | 2 | 1 | 0 | 0 | 0.500 |
| xss:canary_or_browser_proof | 2 | 0 | 3 | 0 | 1.000 | 1.000 | 1.000 | 0.000 | 0.000 | 0 | 1 | 0 | 0 | 0.833 |

Denominatori nulli → null nel JSON / n/d nel report. Errori, timeout, inconclusivi, non eseguiti e unsupported sono distinti; observed_status_counts conserva anche i MANUAL_REVIEW che appartengono a un detector di firme. Il dataset non è un campione rappresentativo e non autorizza percentuali di affidabilità generale.

Regressione reale trovata: la fixture CORS senza ACAO veniva dichiarata VERIFIED. Il codice installato Playwright _maybeAddCorsHeaders aggiunge automaticamente ACAO/ACAC permissivi alle risposte fulfill senza ACAO. La bridge ora mantiene la negazione con ACAO vuoto e richiede anche la policy originale valida per VERIFIED. Stessa fixture privata, canary/cookie/origini sintetici, ora nessuna lettura. V52_ACCURACY_BEFORE_CORS_FIX.json conserva il falso positivo iniziale; il test integrato fallisce se ricompare. Non si confrontano percentuali aggregate dei cataloghi di dimensione diversa.
