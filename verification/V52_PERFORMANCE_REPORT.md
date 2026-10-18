# Prestazioni V5.1 / V5.2

Stesso benchmark, snapshot reale V5.1 e codice V5.2 congelato identificato da V52_BENCHMARK_SOURCE.json. Nessuna suite concorrente. Tre ripetizioni per scenario, due per 500 task. Limite 20 richieste/s, 5 worker/slot host nel benchmark; config operativa resta 2 richieste/s e 2 slot host. Cache disabilitata. HTTP reale su loopback.

| Scenario | Mediana V51/V52 s | Range V51 s | Range V52 s | Variazione tempo | Python peak V51/V52 B | Errori V51/V52 |
|---|---|---|---|---|---|---|
| NORMAL_12 | 1.056/1.102 | 1.032–1.061 | 1.067–1.118 | +4.3% | 260873/267514 | 0/0 |
| NORMAL_100 | 6.628/6.702 | 6.622–6.731 | 6.668–6.707 | +1.1% | 1557232/1579616 | 0/0 |
| NORMAL_500 | 33.758/34.717 | 33.687–33.828 | 34.659–34.775 | +2.8% | 7670398.5/7876464.0 | 0/0 |
| slow | 1.695/1.727 | 1.693–1.705 | 1.704–1.756 | +1.9% | 260124/267115 | 0/0 |
| timeout | 14.283/12.887 | 14.267–14.317 | 9.765–12.916 | -9.8% | 148135/152442 | 12/12 |
| 429 | 2.773/2.793 | 2.772–2.790 | 2.784–2.818 | +0.7% | 233857/245888 | 0/0 |
| intermittent | 2.792/2.800 | 2.774–2.946 | 2.800–2.821 | +0.3% | 234819/244423 | 0/0 |
| interrupt_resume | 1.588/1.576 | 1.521–1.589 | 1.533–1.643 | -0.8% | 274835/283190 | 0/0 |

Due domini/24 task, mediana di tre esecuzioni: 1.905 → 2.030 s. Budget globale 5, cap host 2; rispettati in tutte le prove. Zero errori e duplicati.

I JSON grezzi contengono deviazione standard, throughput richieste e task, timeout, richieste ripetute, completati, picchi Python e RSS di processo. RSS non è equivalente a tracemalloc; nessuna riduzione memoria generale dichiarata. Campione piccolo, nessuna previsione su applicazioni pubbliche o significatività statistica universale.

Timeout: tutte le 12 richieste falliscono intenzionalmente su entrambe le versioni. Completati significa task processati, non scansioni riuscite. Ripresa: le richieste GET non committate possono essere ripetute; finding/completed non duplicati. Nessuna garanzia exactly-once per operazioni con effetti.

Correzione: i fallimenti contemporanei nello stesso intervallo di congestione condividono una riduzione del rate. Il rate non accelera su errore e Retry-After resta vincolante. Attese cancellabili, jitter configurabile 0–1 s (default 0 riproducibile), retry solo GET/HEAD/OPTIONS per errori transitori e 429/503; POST, TLS non valido e errori di parsing non vengono ripetuti. Watchdog totale per tentativo include DNS, connessione e lettura; budget DNS comprende anche attesa slot. Run/module deadline resta cooperativa, non una preemption rigida di ogni chiamata OS.

Limite globale di dieci resolver daemon bloccati, anche fra client/worker diversi; un resolver OS già partito può sopravvivere al timeout fino al ritorno del sistema. Il cap evita accumulo illimitato. I precedenti file INITIAL/PRE_DNS conservano misure di sviluppo; il primo comando PowerShell di ripresa aveva uno splat errato, poi corretto senza modificare i carichi. Non sono usati come risultato finale.
