# V5 / V5.1 — confronto controllato

Stesso script e configurazione per entrambe le versioni, 5 worker, cap host 5 e 20 richieste/s nel benchmark singolo dominio; configurazione operativa invariata a 2 richieste/s e cap host 2. Una ripetizione per scenario: misure indicative, non stime statistiche. Nessuna suite concorrente. Normal/slow: 250/500 ms; timeout: server 1 s, deadline 150 ms. 429/503 su prima richiesta di ogni quarta risorsa, un retry.

| Scenario | V5 s | V51 s | Riduzione | Throughput V5/V51 | Python peak V5/V51 B | Errori V5/V51 | Completati V5/V51 | Duplicati |
|---|---:|---:|---:|---|---|---|---|---|
| NORMAL_12 | 1.464 | 1.084 | 25.9% | 8.20/11.07 | 492966/529659 | 0/0 | 12/12 | 0/0 |
| NORMAL_100 | 10.517 | 6.642 | 36.8% | 9.51/15.05 | 1752405/1882889 | 0/0 | 100/100 | 0/0 |
| NORMAL_500 | 55.014 | 33.903 | 38.4% | 9.09/14.75 | 7343067/7816794 | 0/0 | 500/500 | 0/0 |
| slow | 2.242 | 1.719 | 23.4% | 5.35/6.98 | 492486/530856 | 0/0 | 12/12 | 0/0 |
| timeout | 12.337 | 14.303 | -15.9% | 0.97/0.84 | 387481/388080 | 12/12 | 12/12 | 0/0 |
| 429 | 2.899 | 2.807 | 3.2% | 5.17/5.34 | 491499/523237 | 0/0 | 12/12 | 0/0 |
| intermittent | 2.903 | 2.801 | 3.5% | 5.17/5.36 | 491637/507597 | 0/0 | 12/12 | 0/0 |

Due domini, 24 task: 2.140 → 1.883 s. Budget globale 5, cap host 2; picco osservato 4 globale, {'127.0.0.1': 2, '127.0.0.2': 2} per host. 24 completati, nessun errore o duplicato.

RSS è picco del processo, tracemalloc è allocazione Python: non sono misure equivalenti. I JSON grezzi conservano entrambi. La memoria può aumentare con le nuove evidenze; non si dichiara una riduzione generale. Timeout: 12 task processati con 12 errori/timeout non sono 12 scansioni riuscite. I retry 429/503 sono contati a parte, non come duplicati di finding.

I file V51_PRE_WINDOW_MATRIX conservano il confronto iniziale prima della coda progressiva; non vengono usati come risultato finale. La modifica principale elimina la barriera tra gruppi, conservando ordine di commit e finestra bounded.
